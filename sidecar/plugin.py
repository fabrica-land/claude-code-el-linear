"""Linear webhook sidecar plugin for el-sidecar.

Receives Linear webhooks, verifies HMAC-SHA256 signatures, deduplicates
by webhookId, and surfaces events to Claude Code sessions via the sidecar
event queue.

Routes:
    POST /linear  -- Receive Linear webhook payloads

Env vars:
    LINEAR_WEBHOOK_SECRET   -- Webhook signing secret (optional; skips
                               verification if unset)
    LINEAR_RESOURCE_TYPES   -- Comma-separated resource types to accept
                               (default: Issue,Comment)
"""

import hashlib
import hmac
import json
import os
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WEBHOOK_SECRET = os.environ.get('LINEAR_WEBHOOK_SECRET', '')
RESOURCE_TYPES = set(
    t.strip()
    for t in os.environ.get('LINEAR_RESOURCE_TYPES', 'Issue,Comment').split(',')
    if t.strip()
)

# Maximum number of webhookIds to track for dedup
MAX_DEDUP_IDS = 1000
# Expire dedup entries after 1 hour (Linear retries are within minutes)
DEDUP_EXPIRY_SECS = 3600

# Sidecar API reference (set during register())
_api = {}  # type: dict

# ---------------------------------------------------------------------------
# Dedup tracking (bounded, time-based expiry)
# ---------------------------------------------------------------------------

# {webhookId: timestamp_added}
_seen_ids = {}  # type: dict[str, float]
_seen_lock = threading.Lock()


def _is_duplicate(webhook_id):
    """Check if we've already processed this webhookId. Thread-safe.
    Returns True if duplicate, False if new (and records it)."""
    if not webhook_id:
        return False
    now = time.time()
    with _seen_lock:
        # Expire old entries if we're at capacity
        if len(_seen_ids) >= MAX_DEDUP_IDS:
            cutoff = now - DEDUP_EXPIRY_SECS
            expired = [k for k, v in _seen_ids.items() if v < cutoff]
            for k in expired:
                del _seen_ids[k]
            # If still at capacity after expiry, drop oldest
            if len(_seen_ids) >= MAX_DEDUP_IDS:
                oldest_key = min(_seen_ids, key=_seen_ids.get)
                del _seen_ids[oldest_key]
        if webhook_id in _seen_ids:
            return True
        _seen_ids[webhook_id] = now
        return False


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _verify_signature(raw_body, signature_header):
    """Verify Linear's HMAC-SHA256 webhook signature.
    Returns True if valid, False if invalid.
    If no secret is configured, returns True (skip verification)."""
    if not WEBHOOK_SECRET:
        return True
    if not signature_header:
        return False
    expected = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# Human-readable summary generation
# ---------------------------------------------------------------------------


def _build_issue_summary(action, data, updated_from, actor_name):
    """Build a human-readable summary for an Issue event."""
    identifier = data.get('identifier', '')
    title = data.get('title', '')
    if action == 'create':
        return f"Issue {identifier} created: '{title}' (by {actor_name})"
    if action == 'remove':
        return f"Issue {identifier} deleted (by {actor_name})"
    # action == 'update': describe what changed
    changes = []
    if updated_from:
        if 'stateId' in updated_from or 'state' in updated_from:
            # Linear sends the new state in data, old state info in updatedFrom
            new_state = data.get('state', {}).get('name', '')
            if new_state:
                changes.append(f"status -> {new_state}")
        if 'assigneeId' in updated_from or 'assignee' in updated_from:
            new_assignee = data.get('assignee', {})
            assignee_name = new_assignee.get('name', 'Unassigned') if new_assignee else 'Unassigned'
            changes.append(f"assignee -> {assignee_name}")
        if 'priority' in updated_from:
            priority_labels = {0: 'No priority', 1: 'Urgent', 2: 'High', 3: 'Medium', 4: 'Low'}
            new_priority = data.get('priority', 0)
            changes.append(f"priority -> {priority_labels.get(new_priority, str(new_priority))}")
        if 'title' in updated_from:
            changes.append(f"title -> '{title}'")
        if 'labelIds' in updated_from:
            label_names = [l.get('name', '') for l in data.get('labels', []) if l.get('name')]
            if label_names:
                changes.append(f"labels -> [{', '.join(label_names)}]")
            else:
                changes.append("labels changed")
        if 'dueDate' in updated_from:
            due = data.get('dueDate', 'none')
            changes.append(f"due date -> {due}")
        if 'cycleId' in updated_from:
            cycle = data.get('cycle', {})
            cycle_name = cycle.get('name', 'none') if cycle else 'none'
            changes.append(f"cycle -> {cycle_name}")
        if 'projectId' in updated_from:
            project = data.get('project', {})
            project_name = project.get('name', 'none') if project else 'none'
            changes.append(f"project -> {project_name}")
        if 'description' in updated_from:
            changes.append("description updated")
        # Catch-all for fields not explicitly handled
        if not changes:
            changed_fields = list(updated_from.keys())
            changes.append(f"fields changed: {', '.join(changed_fields[:5])}")
    if not changes:
        changes.append("updated")
    change_str = ', '.join(changes)
    return f"Issue {identifier} updated: {change_str} (by {actor_name})"


def _build_comment_summary(action, data, actor_name):
    """Build a human-readable summary for a Comment event."""
    # Comment body
    body = data.get('body', '')
    # Truncate long comments
    if len(body) > 120:
        body = body[:117] + '...'
    # Try to get the issue identifier from the nested issue data
    issue = data.get('issue', {})
    issue_id = issue.get('identifier', '') if issue else ''
    if action == 'create':
        if issue_id:
            return f"Comment on {issue_id} by {actor_name}: '{body}'"
        return f"New comment by {actor_name}: '{body}'"
    if action == 'remove':
        if issue_id:
            return f"Comment on {issue_id} deleted (by {actor_name})"
        return f"Comment deleted (by {actor_name})"
    # update
    if issue_id:
        return f"Comment on {issue_id} edited by {actor_name}: '{body}'"
    return f"Comment edited by {actor_name}: '{body}'"


def _build_project_summary(action, data, actor_name):
    """Build a human-readable summary for a Project event."""
    name = data.get('name', '')
    if action == 'create':
        return f"Project created: '{name}' (by {actor_name})"
    if action == 'remove':
        return f"Project '{name}' deleted (by {actor_name})"
    return f"Project '{name}' updated (by {actor_name})"


def _build_generic_summary(action, resource_type, data, actor_name):
    """Build a generic summary for any resource type."""
    name = data.get('name', data.get('title', data.get('identifier', '')))
    if name:
        return f"{resource_type} '{name}' {action}d (by {actor_name})"
    return f"{resource_type} {action}d (by {actor_name})"


def _build_summary(action, resource_type, data, updated_from, actor_name):
    """Route to the appropriate summary builder based on resource type."""
    if resource_type == 'Issue':
        return _build_issue_summary(action, data, updated_from, actor_name)
    if resource_type == 'Comment':
        return _build_comment_summary(action, data, actor_name)
    if resource_type == 'Project':
        return _build_project_summary(action, data, actor_name)
    return _build_generic_summary(action, resource_type, data, actor_name)


# ---------------------------------------------------------------------------
# Webhook handler
# ---------------------------------------------------------------------------


def _handle_webhook(handler):
    """POST /linear -- Linear webhook endpoint.

    Validates signature, deduplicates, filters by resource type,
    builds a human-readable summary, and inserts into the event queue.
    """
    # Read raw body for signature verification
    raw_body = handler._read_body()
    if isinstance(raw_body, str):
        raw_bytes = raw_body.encode('utf-8')
    else:
        raw_bytes = raw_body
    # Get headers - handler is an http.server.BaseHTTPRequestHandler
    signature = handler.headers.get('Linear-Signature', '')
    delivery_id = handler.headers.get('Linear-Delivery', '')
    event_type = handler.headers.get('Linear-Event', '')
    # Verify signature
    if not _verify_signature(raw_bytes, signature):
        sys.stderr.write(f"[el-linear] Signature verification failed for delivery {delivery_id}\n")
        handler._send_json({"error": "invalid signature"}, 403)
        return
    # Parse JSON
    try:
        if isinstance(raw_body, bytes):
            payload = json.loads(raw_body.decode('utf-8'))
        else:
            payload = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        sys.stderr.write(f"[el-linear] Malformed JSON in delivery {delivery_id}\n")
        handler._send_json({"error": "invalid json"}, 400)
        return
    # Ack immediately (Linear has 5s timeout)
    handler._send_json({"ok": True})
    # Extract fields
    action = payload.get('action', '')
    resource_type = payload.get('type', event_type or '')
    webhook_id = payload.get('webhookId', '')
    url = payload.get('url', '')
    actor = payload.get('actor', {})
    actor_name = actor.get('name', 'Unknown') if actor else 'Unknown'
    data = payload.get('data', {})
    updated_from = payload.get('updatedFrom', {})
    # Filter by resource type
    if resource_type not in RESOURCE_TYPES:
        sys.stderr.write(f"[el-linear] Filtered out {resource_type} event (not in {RESOURCE_TYPES})\n")
        return
    # Dedup by webhookId
    if _is_duplicate(webhook_id):
        sys.stderr.write(f"[el-linear] Duplicate webhookId: {webhook_id}\n")
        return
    # Build summary
    summary = _build_summary(action, resource_type, data, updated_from, actor_name)
    # Build event type string: "update:issue", "create:comment", etc.
    event_type_str = f"{action}:{resource_type.lower()}"
    # Build metadata JSON for the full payload
    metadata = {
        'webhook_id': webhook_id,
        'delivery_id': delivery_id,
        'action': action,
        'resource_type': resource_type,
        'url': url,
        'actor': actor,
        'data': data,
    }
    if updated_from:
        metadata['updated_from'] = updated_from
    # Insert event
    inserted = _api['insert_event'](
        source='linear',
        type=event_type_str,
        text=summary,
        metadata=json.dumps(metadata),
    )
    if inserted:
        _api['notify_waiters']()
        sys.stderr.write(f"[el-linear] Event: {summary}\n")
    else:
        sys.stderr.write(f"[el-linear] Event not inserted (already exists?): {webhook_id}\n")


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


def register(api):
    """Register this Linear webhook plugin with el-sidecar.

    api is a dict providing:
        insert_event(source, **fields)  -- insert an event with enrichment
        notify_waiters()                -- wake up drain long-poll
        register_route(method, path, handler)  -- register an HTTP route
        register_poller(name, func)     -- register a background poller
        register_init(name, func)       -- register a startup hook
        register_on_pick(name, func)    -- register a drain callback
        get_db()                        -- get a DB connection
        db_lock                         -- threading lock for DB access
    """
    global _api
    _api = api
    # Register webhook route
    api['register_route']('POST', '/linear', _handle_webhook)
    sig_status = 'verified' if WEBHOOK_SECRET else 'unverified (no secret)'
    sys.stderr.write(
        f"[el-linear] Registered (signature={sig_status}, "
        f"types={','.join(sorted(RESOURCE_TYPES))})\n"
    )

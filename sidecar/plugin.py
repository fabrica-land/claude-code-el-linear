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
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Supports multiple secrets (comma-separated) for multiple webhooks
WEBHOOK_SECRETS = [
    s.strip()
    for s in os.environ.get('LINEAR_WEBHOOK_SECRETS', os.environ.get('LINEAR_WEBHOOK_SECRET', '')).split(',')
    if s.strip()
]
RESOURCE_TYPES = set(
    t.strip()
    for t in os.environ.get('LINEAR_RESOURCE_TYPES', 'Issue,Comment,AgentSessionEvent,AppUserNotification').split(',')
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
        if len(_seen_ids) >= MAX_DEDUP_IDS:
            cutoff = now - DEDUP_EXPIRY_SECS
            expired = [k for k, v in _seen_ids.items() if v < cutoff]
            for k in expired:
                del _seen_ids[k]
            if len(_seen_ids) >= MAX_DEDUP_IDS:
                oldest_key = min(_seen_ids, key=lambda k: _seen_ids[k])
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
    Tries all configured secrets (supports multiple webhooks).
    If no secrets are configured, returns True (skip verification)."""
    if not WEBHOOK_SECRETS:
        return True
    if not signature_header:
        return False
    for secret in WEBHOOK_SECRETS:
        expected = hmac.new(
            secret.encode('utf-8'),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected, signature_header):
            return True
    return False


# ---------------------------------------------------------------------------
# Human-readable summary generation
# ---------------------------------------------------------------------------

PRIORITY_LABELS = {0: 'No priority', 1: 'Urgent', 2: 'High', 3: 'Medium', 4: 'Low'}


def _build_issue_summary(action, data, updated_from, actor_name):
    """Build a human-readable summary for an Issue event."""
    identifier = data.get('identifier', '')
    title = data.get('title', '')
    if action == 'create':
        return f"Issue {identifier} created: '{title}' (by {actor_name})"
    if action == 'remove':
        return f"Issue {identifier} deleted (by {actor_name})"
    changes = []
    if updated_from:
        if 'stateId' in updated_from or 'state' in updated_from:
            new_state = data.get('state', {}).get('name', '')
            if new_state:
                changes.append(f"status -> {new_state}")
        if 'assigneeId' in updated_from or 'assignee' in updated_from:
            new_assignee = data.get('assignee', {})
            assignee_name = new_assignee.get('name', 'Unassigned') if new_assignee else 'Unassigned'
            changes.append(f"assignee -> {assignee_name}")
        if 'priority' in updated_from:
            new_priority = data.get('priority', 0)
            changes.append(f"priority -> {PRIORITY_LABELS.get(new_priority, str(new_priority))}")
        if 'title' in updated_from:
            changes.append(f"title -> '{title}'")
        if 'labelIds' in updated_from:
            label_names = [lbl.get('name', '') for lbl in data.get('labels', []) if lbl.get('name')]
            if label_names:
                changes.append(f"labels -> [{', '.join(label_names)}]")
            else:
                changes.append("labels changed")
        if 'dueDate' in updated_from:
            changes.append(f"due date -> {data.get('dueDate', 'none')}")
        if 'cycleId' in updated_from:
            cycle = data.get('cycle', {})
            changes.append(f"cycle -> {cycle.get('name', 'none') if cycle else 'none'}")
        if 'projectId' in updated_from:
            project = data.get('project', {})
            changes.append(f"project -> {project.get('name', 'none') if project else 'none'}")
        if 'delegateId' in updated_from:
            delegate = data.get('delegate')
            if delegate:
                delegate_name = delegate.get('name') or delegate.get('email') or delegate.get('id', 'unknown')
                changes.append(f"delegated to {delegate_name}")
            else:
                changes.append("delegation removed")
        if 'description' in updated_from:
            changes.append("description updated")
        if not changes:
            changed_fields = list(updated_from.keys())
            changes.append(f"fields changed: {', '.join(changed_fields[:5])}")
    if not changes:
        changes.append("updated")
    return f"Issue {identifier} updated: {', '.join(changes)} (by {actor_name})"


def _build_comment_summary(action, data, actor_name):
    """Build a human-readable summary for a Comment event."""
    body = data.get('body', '')
    if len(body) > 120:
        body = body[:117] + '...'
    issue = data.get('issue', {})
    issue_id = issue.get('identifier', '') if issue else ''
    if action == 'create':
        return f"Comment on {issue_id} by {actor_name}: '{body}'" if issue_id else f"New comment by {actor_name}: '{body}'"
    if action == 'remove':
        return f"Comment on {issue_id} deleted (by {actor_name})" if issue_id else f"Comment deleted (by {actor_name})"
    return f"Comment on {issue_id} edited by {actor_name}: '{body}'" if issue_id else f"Comment edited by {actor_name}: '{body}'"


def _build_summary(action, resource_type, data, updated_from, actor_name):
    """Route to the appropriate summary builder based on resource type."""
    if resource_type == 'Issue':
        return _build_issue_summary(action, data, updated_from, actor_name)
    if resource_type == 'Comment':
        return _build_comment_summary(action, data, actor_name)
    name = data.get('name', data.get('title', data.get('identifier', '')))
    if name:
        return f"{resource_type} '{name}' {action}d (by {actor_name})"
    return f"{resource_type} {action}d (by {actor_name})"


# ---------------------------------------------------------------------------
# Webhook handler
# ---------------------------------------------------------------------------


def _handle_webhook(handler):
    """POST /linear -- Linear webhook endpoint.

    Validates signature, deduplicates, filters by resource type,
    builds a human-readable summary, and inserts into the event queue.
    """
    raw_body = handler._read_body()
    if isinstance(raw_body, str):
        raw_bytes = raw_body.encode('utf-8')
    else:
        raw_bytes = raw_body
    signature = handler.headers.get('Linear-Signature', '')
    delivery_id = handler.headers.get('Linear-Delivery', '')
    event_type = handler.headers.get('Linear-Event', '')
    if not _verify_signature(raw_bytes, signature):
        sys.stderr.write(f"[el-linear] Signature verification failed for delivery {delivery_id}\n")
        handler._send_json({"error": "invalid signature"}, 403)
        return
    try:
        payload = json.loads(raw_bytes.decode('utf-8') if isinstance(raw_body, bytes) else raw_body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        sys.stderr.write(f"[el-linear] Malformed JSON in delivery {delivery_id}\n")
        handler._send_json({"error": "invalid json"}, 400)
        return
    # Ack immediately (Linear has 5s timeout)
    handler._send_json({"ok": True})
    action = payload.get('action', '')
    resource_type = payload.get('type', event_type or '')
    webhook_id = payload.get('webhookId', '')
    url = payload.get('url', '')
    actor = payload.get('actor', {})
    actor_name = actor.get('name', 'Unknown') if actor else 'Unknown'
    data = payload.get('data', {})
    updated_from = payload.get('updatedFrom', {})
    if resource_type not in RESOURCE_TYPES:
        sys.stderr.write(f"[el-linear] Filtered out {resource_type} event (not in {RESOURCE_TYPES})\n")
        return
    if _is_duplicate(webhook_id):
        sys.stderr.write(f"[el-linear] Duplicate webhookId: {webhook_id}\n")
        return
    summary = _build_summary(action, resource_type, data, updated_from, actor_name)
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
    inserted = _api['insert_event'](
        source='linear',
        type=f'{action}:{resource_type.lower()}',
        text=summary,
        metadata=json.dumps(metadata),
    )
    if inserted:
        _api['notify_waiters']()
        sys.stderr.write(f"[el-linear] Event: {summary}\n")
    else:
        sys.stderr.write(f"[el-linear] Event not inserted (already exists?): {webhook_id}\n")


# ---------------------------------------------------------------------------
# Ngrok tunnel auto-repair
# ---------------------------------------------------------------------------

NGROK_API = 'http://localhost:4040/api'
NGROK_TUNNEL_NAME = os.environ.get('LINEAR_NGROK_TUNNEL', 'linear')
NGROK_SUBDOMAIN = os.environ.get('LINEAR_NGROK_SUBDOMAIN', '')


def _check_ngrok_tunnel():
    """Check if the ngrok 'linear' tunnel points to the current sidecar port.
    If stale, delete and recreate it. Runs in a background thread after startup."""
    time.sleep(3)
    sidecar_json = os.path.join(os.getcwd(), '.claude', 'sidecar.json')
    try:
        with open(sidecar_json) as f:
            port = json.load(f)['port']
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        sys.stderr.write("[el-linear] Cannot read sidecar.json for ngrok check\n")
        return
    try:
        resp = urllib.request.urlopen(f'{NGROK_API}/tunnels', timeout=3)
        tunnels = json.loads(resp.read()).get('tunnels', [])
    except (urllib.error.URLError, OSError):
        sys.stderr.write("[el-linear] ngrok not running — skipping tunnel check\n")
        return
    expected_addr = f'http://localhost:{port}'
    for tunnel in tunnels:
        if tunnel.get('name') == NGROK_TUNNEL_NAME:
            current_addr = tunnel.get('config', {}).get('addr', '')
            if current_addr == expected_addr:
                sys.stderr.write(f"[el-linear] ngrok tunnel '{NGROK_TUNNEL_NAME}' OK -> {expected_addr}\n")
                return
            sys.stderr.write(f"[el-linear] ngrok tunnel stale: {current_addr} -> updating to {expected_addr}\n")
            try:
                req = urllib.request.Request(f'{NGROK_API}/tunnels/{NGROK_TUNNEL_NAME}', method='DELETE')
                urllib.request.urlopen(req, timeout=5)
            except (urllib.error.URLError, OSError) as e:
                sys.stderr.write(f"[el-linear] Failed to delete stale tunnel: {e}\n")
                return
            break
    if not NGROK_SUBDOMAIN:
        sys.stderr.write(f"[el-linear] No LINEAR_NGROK_SUBDOMAIN set — cannot create tunnel\n")
        return
    tunnel_config = json.dumps({
        'name': NGROK_TUNNEL_NAME,
        'proto': 'http',
        'addr': expected_addr,
        'hostname': f'{NGROK_SUBDOMAIN}.ngrok.io',
    }).encode()
    try:
        req = urllib.request.Request(
            f'{NGROK_API}/tunnels',
            data=tunnel_config,
            headers={'Content-Type': 'application/json'},
        )
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        public_url = resp.get('public_url', '?')
        sys.stderr.write(f"[el-linear] ngrok tunnel created: {public_url} -> {expected_addr}\n")
    except (urllib.error.URLError, OSError) as e:
        sys.stderr.write(f"[el-linear] Failed to create ngrok tunnel: {e}\n")


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


def register(api):
    """Register this Linear webhook plugin with el-sidecar."""
    global _api
    _api = api
    api['register_route']('POST', '/linear', _handle_webhook)
    api['register_init']('linear-ngrok', lambda: threading.Thread(
        target=_check_ngrok_tunnel, daemon=True, name='linear-ngrok-check',
    ).start())
    sig_status = f'verified ({len(WEBHOOK_SECRETS)} secret(s))' if WEBHOOK_SECRETS else 'unverified (no secret)'
    sys.stderr.write(
        f"[el-linear] Registered (signature={sig_status}, "
        f"types={','.join(sorted(RESOURCE_TYPES))})\n"
    )

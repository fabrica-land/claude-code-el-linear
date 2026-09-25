# el-linear

Linear webhook sidecar plugin for the [el](https://github.com/mividtim/claude-code-event-listeners) event system. Receives Linear webhooks and surfaces issue and comment activity as events to Claude Code sessions.

## Features

- Receives Linear webhooks via `POST /linear`
- HMAC-SHA256 signature verification (optional, graceful if no secret)
- Deduplication by `webhookId` (bounded, time-expiring)
- Configurable resource type filtering (default: Issue, Comment)
- Human-readable event summaries with change details
- Thread-safe, fast response (well within Linear's 5s timeout)

## Installation

Install via Claude Code plugin system:

```
claude plugins install mividtim/claude-code-el-linear
```

Or for local development, add an entry to `~/.claude/plugins/installed_plugins.json` pointing to this directory.

## Configuration

Set environment variables (or add to your shell profile):

| Variable | Required | Default | Description |
|---|---|---|---|
| `LINEAR_WEBHOOK_SECRET` | No | _(empty)_ | Webhook signing secret from Linear. If unset, signature verification is skipped. |
| `LINEAR_RESOURCE_TYPES` | No | `Issue,Comment` | Comma-separated resource types to accept. |

## Linear Webhook Setup

1. Go to Linear Settings > API > Webhooks
2. Create a new webhook pointing to your sidecar's public URL:
   - URL: `https://<your-ngrok-or-public-url>/linear`
   - Select the resource types you want to receive (Issues, Comments, etc.)
3. Copy the signing secret and set `LINEAR_WEBHOOK_SECRET`

## Event Format

Events are inserted into the sidecar queue with:

- **source**: `linear`
- **type**: `{action}:{resource_type}` (e.g., `update:issue`, `create:comment`)
- **text**: Human-readable summary

### Example Summaries

```
Issue ENG-2751 updated: status -> In Progress (by Tim Garthwaite)
Issue ENG-2800 created: 'Fix login bug' (by Tim Garthwaite)
Comment on ENG-2737 by Tim Garthwaite: 'Looks good, let's ship it'
Issue ENG-2751 updated: assignee -> Andy Bland, priority -> High (by Tim Garthwaite)
```

## Development

### Testing with curl

```bash
# Basic webhook (no signature verification)
curl -X POST http://localhost:55952/linear \
  -H 'Content-Type: application/json' \
  -H 'Linear-Event: Issue' \
  -H 'Linear-Delivery: test-001' \
  -d '{
    "action": "update",
    "type": "Issue",
    "webhookId": "test-001",
    "actor": {"name": "Tim Garthwaite"},
    "data": {"identifier": "ENG-2751", "title": "Fix login bug", "state": {"name": "In Progress"}},
    "updatedFrom": {"stateId": "old-state-id"}
  }'

# Check events arrived
curl http://localhost:55952/events?wait=false
```

### Testing with signature

```bash
# Generate signature
SECRET="your-webhook-secret"
BODY='{"action":"create","type":"Issue","webhookId":"test-sig","actor":{"name":"Test"},"data":{"identifier":"ENG-100","title":"Test"}}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')

curl -X POST http://localhost:55952/linear \
  -H 'Content-Type: application/json' \
  -H "Linear-Signature: $SIG" \
  -H 'Linear-Event: Issue' \
  -d "$BODY"
```

## License

MIT

## License

MIT © Fabrica, Inc. — see [LICENSE](LICENSE). Created and maintained by Tim Garthwaite.

# MCP recorder and replay

`asgi-lua` can store replayable MCP request decisions as JSONL. This is useful
when developing a local MCP gateway policy because each observed request becomes
a deterministic regression fixture.

Record one request fixture:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json --out traces/session.jsonl
```

Record live traffic while proxying:

```bash
uv run asgi-lua mcp config init
uv run asgi-lua mcp proxy \
  --config asgi-lua.toml
```

Record with state, context, response metadata, or custom metadata:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json \
  --state state.json \
  --context context.json \
  --response response.json \
  --metadata metadata.json \
  --out traces/session.jsonl
```

Replay the log against the recorded policy path:

```bash
uv run asgi-lua mcp replay traces/session.jsonl
```

Replay the same requests against a candidate policy:

```bash
uv run asgi-lua mcp replay traces/session.jsonl --script candidate.lua
```

The replay command exits with status `1` when any current decision differs from
the recorded decision.

## Audit logs and redaction

Write a redacted audit log while recording:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json \
  --out traces/session.jsonl \
  --audit-out traces/audit.jsonl
```

Audit events are compact JSONL records designed for local-dev visibility. They
include request method/path/headers, MCP method/tool, decision action, allowed
status, policy source, and optional response or metadata fields.

Audit logs are redacted by default. The redactor masks likely secret keys such
as `authorization`, `cookie`, `x-api-key`, `token`, `secret`, and `password`,
plus common bearer tokens, OpenAI-style `sk-` tokens, GitHub tokens, and AWS
access key IDs.

Replay records are exact by default so they remain deterministic. To redact the
record itself:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json \
  --out traces/session.redacted.jsonl \
  --redact
```

Redacted replay records may not reproduce auth-sensitive decisions exactly.

## JSONL record shape

Each line is one JSON object:

```json
{
  "type": "asgi-lua.request_record",
  "version": 1,
  "recorded_at": "2026-06-12T00:00:00+00:00",
  "policy": {
    "source": "policy.asgi-lua/policy.lua"
  },
  "request": {
    "method": "POST",
    "path": "/mcp",
    "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"
  },
  "result": {
    "action": "continue",
    "decision": {
      "action": "continue"
    }
  }
}
```

When a state snapshot is supplied, the record stores it as `state.input` and
replay starts from the same state.

Audit events have this shape:

```json
{
  "type": "asgi-lua.audit",
  "version": 1,
  "time": "2026-06-12T00:00:00+00:00",
  "policy": {
    "source": "policy.asgi-lua/policy.lua"
  },
  "request": {
    "method": "POST",
    "path": "/mcp",
    "headers": {
      "authorization": "[REDACTED]"
    }
  },
  "mcp": {
    "body_kind": "object",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "notification": false,
    "operation": "tools",
    "operation_detail": "call",
    "params_keys": ["arguments", "name"],
    "request_id": 1,
    "target": "safe_read_file",
    "tool": "safe_read_file"
  },
  "decision": {
    "action": "continue",
    "allowed": true,
    "status": null
  }
}
```

The `mcp` object is extracted from the JSON-RPC envelope and common MCP params.
It records names and key lists, not full params or tool arguments, so audit logs
remain useful without becoming a second copy of the request body.

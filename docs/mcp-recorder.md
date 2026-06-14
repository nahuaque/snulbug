# MCP evidence record, replay, and inspect

This is the detailed reference for `snulbug mcp evidence record`, `replay`,
`inspect`, and `diff`. Start with the
[MCP evidence workflow](mcp-evidence.md) for the group-level overview.

`snulbug mcp evidence` stores replayable MCP request decisions as JSONL. This is
useful when developing a local MCP gateway policy because each observed request
becomes a deterministic regression fixture.

Record one request fixture:

```bash
uv run snulbug mcp evidence record policy.snulbug/policy.lua request.json --out traces/session.jsonl
```

Record live traffic while proxying:

```bash
uv run snulbug mcp config init
uv run snulbug mcp proxy \
  --config snulbug.toml
```

Record with state, context, response metadata, or custom metadata:

```bash
uv run snulbug mcp evidence record policy.snulbug/policy.lua request.json \
  --state state.json \
  --context context.json \
  --response response.json \
  --metadata metadata.json \
  --out traces/session.jsonl
```

Replay the log against the recorded policy path:

```bash
uv run snulbug mcp evidence replay traces/session.jsonl
```

Replay the same requests against a candidate policy:

```bash
uv run snulbug mcp evidence replay traces/session.jsonl --script candidate.lua
```

The replay command exits with status `1` when any current decision differs from
the recorded decision.

Diff two policy files against request fixtures:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/
```

Use per-fixture state snapshots when reviewing stateful policies:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/ \
  --state-snapshots snapshots/
```

Inspect a captured replay or audit log without a running proxy:

```bash
uv run snulbug mcp evidence inspect traces/session.jsonl
uv run snulbug mcp evidence inspect traces/audit.jsonl --kind audit
```

The inspection report summarizes decisions, MCP methods, tools, targets, reason
codes, HTTP statuses, invalid JSON, batch requests, upstream errors, and example
events for notable findings.

Write a Markdown session report:

```bash
uv run snulbug mcp evidence inspect traces/audit.jsonl \
  --kind audit \
  --report-out traces/session-report.md
```

The report is built from the redacted inspection summary. It includes counts,
top methods/tools/targets, findings, and representative examples without
copying request bodies, headers, params, or tool arguments into the report.

## Learn a policy from a captured session

Compile a replay or audit log into a policy bundle:

```bash
uv run snulbug mcp policy learn traces/session.jsonl --out learned-policy.snulbug
```

The generated bundle contains `policy.lua`, `manifest.json`, and `LEARNED.md`.
It includes only allowed observed traffic: MCP methods, tool names,
resource/prompt targets, and tool argument key names. Blocked requests are
excluded from the allowlist and summarized in the report.

Switch the proxy to the learned policy after review:

```bash
uv run snulbug mcp proxy \
  --config snulbug.toml \
  --policy learned-policy.snulbug/policy.lua
```

## Audit logs and redaction

Write a redacted audit log while recording:

```bash
uv run snulbug mcp evidence record policy.snulbug/policy.lua request.json \
  --out traces/session.jsonl \
  --audit-out traces/audit.jsonl
```

Audit events are compact JSONL records designed for local-dev visibility. They
include request method/path/headers, MCP method/tool, decision action, allowed
status, policy source, tunnel provider metadata when present, and optional
response or metadata fields.

Audit logs and CLI-created replay records are redacted by default. The redactor masks likely secret keys such
as `authorization`, `cookie`, `x-api-key`, `token`, `secret`, and `password`,
plus common bearer tokens, OpenAI-style `sk-` tokens, GitHub tokens, and AWS
access key IDs.

To write an exact replay record for local debugging, opt in explicitly:

```bash
uv run snulbug mcp evidence record policy.snulbug/policy.lua request.json \
  --out traces/session.exact.jsonl \
  --no-redact
```

Exact replay records may contain bearer tokens, cookies, API keys, and tool
arguments. Redacted replay records may not reproduce auth-sensitive decisions
exactly.

## JSONL record shape

Each line is one JSON object:

```json
{
  "type": "snulbug.request_record",
  "version": 1,
  "recorded_at": "2026-06-12T00:00:00+00:00",
  "policy": {
    "source": "policy.snulbug/policy.lua"
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
  "type": "snulbug.audit",
  "version": 1,
  "time": "2026-06-12T00:00:00+00:00",
  "policy": {
    "source": "policy.snulbug/policy.lua"
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
    "reason": "MCP tool is allowed",
    "reason_code": "mcp.tool_allowed",
    "status": null
  }
}
```

The `mcp` object is extracted from the JSON-RPC envelope and common MCP params.
It records names and key lists, not full params or tool arguments, so audit logs
remain useful without becoming a second copy of the request body.

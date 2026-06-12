# MCP recorder and replay

`asgi-lua` can store replayable MCP request decisions as JSONL. This is useful
when developing a local MCP gateway policy because each observed request becomes
a deterministic regression fixture.

Record one request fixture:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json --out traces/session.jsonl
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

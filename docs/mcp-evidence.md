# MCP evidence workflow

`snulbug mcp evidence` is the regression and review layer for MCP policy work.
It records replayable decisions, replays captured sessions, inspects redacted
logs, previews policy or lease impact, and diffs policy candidates against
fixtures.

## Commands

| Command | Use it for |
| --- | --- |
| `snulbug mcp evidence record` | Append one replayable request decision to JSONL. |
| `snulbug mcp evidence replay` | Re-run a captured session against its recorded or candidate policy. |
| `snulbug mcp evidence inspect` | Summarize replay or audit JSONL offline. |
| `snulbug mcp evidence impact` | Preview policy or lease blast radius against captured traffic. |
| `snulbug mcp evidence diff` | Compare two Lua policies against request fixtures. |

## Recommended loop

Capture live replay and audit logs through the proxy:

```bash
uv run snulbug mcp share run --config snulbug.toml
```

Inspect the session before changing policy:

```bash
uv run snulbug mcp evidence inspect traces/session.jsonl
uv run snulbug mcp evidence inspect traces/audit.jsonl --kind audit
uv run snulbug mcp evidence inspect traces/audit.jsonl \
  --kind audit \
  --report-out traces/session-report.md
```

Replay captured traffic after editing or replacing a policy:

```bash
uv run snulbug mcp evidence replay traces/session.jsonl
uv run snulbug mcp evidence replay traces/session.jsonl --script candidate.lua
```

Preview candidate policy and lease impact:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy candidate-policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

Use fixture diffing for small policy review gates:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/
```

## Evidence types

Replay records are deterministic fixtures. They capture the normalized request,
policy source, decision, trace metadata, and optional state snapshots. Use them
for replay, learning, impact checks, and CI gates.

Audit records are redacted operational events. They capture MCP-aware fields
such as method, tool, target, reason code, tunnel provider, upstream identity,
and response status without storing full request parameters or tool arguments.
Use them for offline inspection, decision reports, and amendment workflows.

Both CLI-created replay records and audit logs are redacted by default. Use
exact replay records only for local debugging when you are comfortable storing
auth-sensitive values.

## Common review gates

Before enabling a learned or amended policy:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua
```

Before requiring task leases:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl --lease leases.json
```

Before merging a hand-edited Lua policy:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/
```

## Deep references

- [Record, replay, inspect, and JSONL record shape](mcp-recorder.md)
- [Impact preview details](mcp-impact.md)
- [MCP policy workflow](mcp-policy.md)
- [MCP reverse proxy live recording options](mcp-proxy.md)

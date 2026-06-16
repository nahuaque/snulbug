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
snulbug mcp share run --config snulbug.toml
```

Inspect the session before changing policy:

```bash
snulbug mcp evidence inspect traces/session.jsonl
snulbug mcp evidence inspect traces/audit.jsonl --kind audit
snulbug mcp evidence inspect traces/audit.jsonl \
  --kind audit \
  --report-out traces/session-report.md
```

Replay captured traffic after editing or replacing a policy:

```bash
snulbug mcp evidence replay traces/session.jsonl
snulbug mcp evidence replay traces/session.jsonl --script candidate.lua
```

Preview candidate policy and lease impact:

```bash
snulbug mcp evidence impact traces/session.jsonl \
  --policy candidate-policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

Use fixture diffing for small policy review gates:

```bash
snulbug mcp evidence diff active.lua draft.lua fixtures/
```

Write a reviewable Markdown diff when the policy change should go through the
same review path as code:

```bash
snulbug mcp evidence diff active.lua draft.lua fixtures/ \
  --report-out traces/policy-diff.md
```

The diff report now includes a capability delta for newly allowed fixtures,
summarizing changes such as newly allowed tools, MCP path patterns, and
tool argument shapes. For example: `newly allows 2 tools, 1 path pattern, 3
argument shapes`.

## Evidence types

Replay records are deterministic fixtures. They capture the normalized request,
policy source, decision, trace metadata, and optional state snapshots. Use them
for replay, learning, impact checks, and CI gates.

Audit records are redacted operational events. They capture MCP-aware fields
such as method, tool, target, reason code, tunnel provider, upstream identity,
and response status without storing full request parameters or tool arguments.
Use them for offline inspection, decision reports, and amendment workflows.

For approval-driven amendments, prefer replay records when available:

```bash
snulbug mcp policy amend learned-policy.snulbug traces/session.jsonl \
  --source approved-confirmations \
  --out approval-candidate.snulbug
```

The generated candidate is still deterministic: approved confirmations add the
observed path, MCP method, target/tool name, and argument-key shape, then flow
through the normal bundle review and lifecycle commands.

Both CLI-created replay records and audit logs are redacted by default. Use
exact replay records only for local debugging when you are comfortable storing
auth-sensitive values.

## Common review gates

Before enabling a learned or amended policy:

```bash
snulbug mcp evidence impact traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua
```

Before requiring task leases:

```bash
snulbug mcp evidence impact traces/session.jsonl --lease leases.json
```

Before merging a hand-edited Lua policy:

```bash
snulbug mcp evidence diff active.lua draft.lua fixtures/ \
  --report-out traces/policy-diff.md
```

## Deep references

- [Record, replay, inspect, and JSONL record shape](mcp-recorder.md)
- [Impact preview details](mcp-impact.md)
- [MCP policy workflow](mcp-policy.md)
- [MCP reverse proxy live recording options](mcp-proxy.md)

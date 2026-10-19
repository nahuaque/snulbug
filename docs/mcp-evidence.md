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

Evidence commands also support exporter plugins:

```bash
snulbug mcp evidence inspect traces/session.jsonl \
  --export markdown=traces/session-report.md \
  --export json=traces/session-report.json
```

See [Evidence exporter plugins](evidence-exporters.md) for the Python extension
point.

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

## Request failure explanations

An allowed policy decision does not mean a request succeeded. For example, Lua
can admit a call and the upstream can then refuse the connection. The existing
audit event keeps `decision.reason_code` unchanged and adds an `explanation`:

```json
{
  "decision": {"allowed": true, "reason_code": "policy.allowed"},
  "explanation": {
    "outcome": "failed",
    "stage": "upstream_transport",
    "reason_code": "upstream.connection_refused",
    "execution": "not_forwarded"
  }
}
```

The explanation also includes a fixed summary, next steps, and the recorded
evidence basis. The same logic powers the console's Live Decisions, terminal
decision lines (`failure.stage` / `failure.code`), `evidence inspect`, and
`share report`. Expand a failed decision in the web console for its stage,
upstream, original policy reason, and suggested next steps. There is no separate
incident store, diagnosis command, or permission mechanism.

| Recorded evidence | Explanation |
| --- | --- |
| Auth, lease, confirmation, or request controls deny the request | The corresponding admission gate, rather than upstream failure |
| Upstream credential resolution fails | `upstream.credentials_unavailable`; inspect the existing broker reference |
| DNS, connection refusal, TLS, or timeout exceptions | A stable transport reason without exception text |
| Upstream returns HTTP 401/403 | `upstream.auth_rejected`; inspect upstream credentials, not the client's gateway authorization |
| Response policy or output-schema checks block the result | `response_policy`; the upstream may already have performed an action |
| A bounded JSON-RPC envelope contains `error` or `result.isError` | An upstream MCP error, even when HTTP status is 200 |
| A facade returns tools from healthy siblings after another fails | A partial catalog with the failing upstream identified |
| Only an HTTP error status is available | `request.failure_unattributed`, not an invented root cause |

Transport observations use the existing proxy metadata in replay/audit logs.
They retain no exception messages, upstream error bodies, or tool-output text.
MCP envelope inspection is best-effort and bounded to 128 KiB; it does not parse
arbitrary SSE transcripts or inspect larger payloads for diagnostic content.
Large fanouts retain at most 20 exchange observations, prioritizing failures
and marking truncation. Third-party transport failures without a recognized
exception type remain generic.

`execution` describes observed forwarding, not a guarantee about tool side
effects. A timeout, protocol failure, or disconnected stream can have an unknown
outcome; receiving an error response also does not prove that nothing changed.
No diagnostic operation retries a tool call, widens policy, renews a lease, or
approves a request. Verify side effects before repeating a call.

Policy-admission counts remain separate from failure/outcome counts. Ordinary
tool/JSON-RPC errors are warnings in evidence findings, not automatically a
failed share-health check. Historical logs with only a status cannot recover
missing transport evidence. Requests rejected by ngrok before reaching snulbug
and ordinary HTTP mounts outside the MCP stack are not covered by these MCP
request explanations; use share doctor/provider or mounted-app diagnostics.

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

# MCP evidence impact preview

This is the detailed reference for `snulbug mcp evidence impact`. Start with
the [MCP evidence workflow](mcp-evidence.md) for the group-level overview.

`snulbug mcp evidence impact` previews how a candidate policy or task lease would behave
against a captured replay log before you enable it live.

Use it when reviewing:

- a learned policy before switching the proxy to it
- an amended candidate bundle before promotion
- a task-scoped lease before requiring leases for a session
- a policy change in CI

## Preview a Candidate Policy

```bash
uv run snulbug mcp evidence impact \
  traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua
```

The report includes:

- changed decisions
- newly allowed requests
- newly blocked requests
- action changes
- replay failures
- affected MCP tools and targets

By default, the command exits non-zero when it finds error-level impact, such as
newly blocked requests or replay failures. Use `--no-fail` for exploratory
review:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy candidate-policy.snulbug/policy.lua \
  --no-fail
```

## Preview Lease Coverage

```bash
uv run snulbug mcp evidence impact \
  traces/session.jsonl \
  --lease leases.json
```

Lease impact is tokenless and dry-run. It asks whether each captured
`tools/call` would be covered by any active lease in the file. It does not
require captured lease tokens and does not increment lease `use_count`.

The report includes:

- total `tools/call` requests
- covered and uncovered calls
- coverage percentage
- uncovered examples with reason codes
- risky grants such as wildcard tools, shell-like tool names, broad paths, and
  unconstrained argument grants

## Policy and Lease Together

```bash
uv run snulbug mcp evidence impact \
  traces/session.jsonl \
  --policy candidate-policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

This is the review step to run before:

- switching `snulbug.toml` to a learned or amended policy
- setting `lease_required = true`
- exposing the proxy through ngrok, Cloudflare Tunnel, Tailscale Funnel,
  Pinggy, Holepunch, or another tunnel/peer bridge

## CI Pattern

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

Use `--compact` for machine-readable JSON:

```bash
uv run snulbug mcp evidence impact traces/session.jsonl \
  --policy policy.snulbug/policy.lua \
  --compact
```

The JSON output includes `ok`, `policy`, `lease`, and `findings` fields. Treat
`ok = false` as a review gate failure unless the change is intentionally
expanding or narrowing access.

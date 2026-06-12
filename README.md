<p align="center">
  <img src="assets/snulbug.png" alt="snulbug logo" width="220">
</p>

# snulbug

`snulbug` is a local-dev MCP policy proxy. Put it between an MCP client and one
or more local MCP servers before you hand an agent a broad toolset or expose a
server through a public tunnel.

It gives you a tight loop for agent-tool safety:

- start with a conservative `tunnel-safe` policy
- watch live allow/block decisions while traffic flows
- record redacted replay and audit logs
- learn a least-privilege policy from observed traffic
- amend blocked requests into reviewable candidate bundles
- use task-scoped leases for temporary tool/path grants

The standalone ASGI Lua middleware is still available, but it is an
implementation surface. The main use case is protecting local MCP traffic.

## Install

```bash
pip install "snulbug[proxy]"
```

For Redis-backed policy state:

```bash
pip install "snulbug[redis]"
```

For local development from this repository:

```bash
uv sync --extra dev
```

`snulbug` supports Python 3.10 through 3.13.

## One-Command Lab

Run the full MCP policy lifecycle without wiring up a real server:

```bash
uv run snulbug mcp lab
```

The lab creates fake MCP upstreams behind one facade, records traffic, learns a
least-privilege policy, amends a blocked request into a candidate policy, and
writes replay/audit/report artifacts under `.snulbug-lab/`.

## Quickstart

Ask the CLI for a copy-paste workflow before wiring a client or harness:

```bash
uv run snulbug mcp guide --workflow tunnel
uv run snulbug mcp guide --workflow learn-amend-impact --compact
```

For a tunnel-exposed local MCP server, `tunnel-safe` is the recommended default:

```bash
uv run snulbug mcp quickstart \
  --preset tunnel-safe \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
uv run snulbug mcp proxy --config snulbug.toml
```

Point the MCP client at:

```text
http://127.0.0.1:8080/mcp
```

Send:

```text
Authorization: Bearer local-dev-secret
```

Expose the proxy, not the upstream server:

```bash
uv run snulbug tunnel init --provider ngrok --hostname YOUR-TUNNEL.ngrok.app
ngrok http 8080 --url https://YOUR-TUNNEL.ngrok.app --traffic-policy-file ngrok-traffic-policy.yml
```

Before sharing the tunnel URL, run the doctor:

```bash
uv run snulbug tunnel doctor \
  --provider ngrok \
  --url https://YOUR-TUNNEL.ngrok.app/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

See the full [local MCP policy gateway quickstart](docs/quickstart.md) for
client setup, facade mode, recording, replay, inspection, and tunnel notes.

## Live Use

Watch decisions while proxying:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Create a task-scoped lease when you want an MCP client or agent to do one
bounded job:

```bash
uv run snulbug mcp lease create \
  --file leases.json \
  --task "Read project docs only" \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --ttl 30m
```

Send the returned `x-snulbug-lease` header with MCP requests. Set
`lease_required = true` in `snulbug.toml` when every `tools/call` must carry an
active lease.

After a session, inspect the logs:

```bash
uv run snulbug mcp inspect traces/session.jsonl
uv run snulbug mcp inspect traces/audit.jsonl --kind audit
```

Learn a least-privilege bundle from observed traffic:

```bash
uv run snulbug mcp learn traces/session.jsonl --out learned-policy.snulbug
uv run snulbug bundle validate learned-policy.snulbug
uv run snulbug bundle test learned-policy.snulbug
```

Preview the blast radius before enabling a candidate policy or lease:

```bash
uv run snulbug mcp impact traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

When the learned policy blocks a legitimate request, generate a candidate
amendment instead of editing the active policy in place:

```bash
uv run snulbug mcp amend \
  learned-policy.snulbug \
  traces/audit.jsonl \
  --out candidate-policy.snulbug
```

## What It Enforces

Request-side policy:

- bearer challenges and auth checks
- MCP method and tool allowlists
- JSON-RPC batch rejection
- project path constraints for tool arguments
- schema-aware validation of `tools/call` arguments from MCP `inputSchema`
- task-scoped capability leases with expiring tool/path grants
- small stateful policies such as rate limits and idempotency keys

Response-side policy:

- redaction of likely secrets from tool/resource/prompt results
- maximum MCP response body size
- optional blocking for instruction-like tool output
- `tools/list` description and schema pinning to catch silent upstream changes
- human confirmation for risky calls, with allow-once or session approval

Workflow:

- redacted replay logs for deterministic policy testing
- audit JSONL with MCP-aware fields
- provider-aware tunnel audit fields for ngrok, Cloudflare, Tailscale, Holepunch, and generic forwarders
- optional Cloudflare Access origin-side audit/enforcement
- learned least-privilege bundles from observed traffic
- candidate amendments for blocked legitimate requests
- a decision console for live local tunnel traffic

## Documentation

Start with:

- [Quickstart: local MCP policy gateway](docs/quickstart.md)
- [MCP CLI guide for agents and harnesses](docs/mcp-guide.md)
- [Tunnel init](docs/tunnel-init.md)
- [Tunnel doctor](docs/tunnel-doctor.md)
- [MCP reverse proxy](docs/mcp-proxy.md)
- [MCP client setup recipes](docs/mcp-client-recipes.md)
- [MCP learn and amend mode](docs/mcp-learn.md)
- [MCP impact preview](docs/mcp-impact.md)
- [MCP recorder and replay](docs/mcp-recorder.md)
- [MCP presets](docs/mcp-presets.md)
- [Security model](docs/security-model.md)
- [Positioning and comparisons](docs/comparison.md)

Reference docs:

- [ASGI middleware getting started](docs/getting-started.md)
- [Lua request API](docs/lua-request-api.md)
- [Action reference](docs/actions.md)
- [State adapters](docs/state.md)
- [Policy bundles](docs/bundles.md)
- [MCP gateway example](docs/mcp-gateway.md)
- [End-to-end MCP policy proxy demo](examples/mcp_proxy_demo/README.md)
- [Release process](docs/release.md)

`snulbug` is currently alpha software. Until 1.0, action schemas and trace
fields may evolve.

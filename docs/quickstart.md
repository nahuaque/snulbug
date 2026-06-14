# Quickstart: local MCP policy gateway

This path puts `snulbug` in front of a local HTTP MCP server so you can add
bearer auth, tool allowlists, live decisions, replayable records, redacted audit
logs, and offline inspection without changing the MCP server.

```text
MCP client
  -> snulbug reverse proxy
      -> local HTTP MCP server
```

## 1. Install

`snulbug` is not published on PyPI yet. Use `uv` from the source tree:

```bash
uv sync
uv run snulbug --help
```

From another `uv` project, install from GitHub:

```bash
uv add "snulbug[discovery] @ git+https://github.com/lbruhacs/snulbug"
```

The commands below use `uv run` from this repository.

For a self-describing workflow that an agentic harness can parse:

```bash
uv run snulbug mcp guide --workflow share --compact
```

For a temporary share session, let snulbug generate the policy, random bearer
token, task lease, provider setup, client config, and close-out commands:

```bash
uv run snulbug mcp share create \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

The command writes a self-contained directory under `.snulbug/shares/`. Run the
primary lifecycle from that directory:

```bash
uv run snulbug mcp share run .snulbug/shares/share-...
uv run snulbug mcp share status .snulbug/shares/share-...
uv run snulbug mcp policy amend \
  .snulbug/shares/share-.../policy.snulbug \
  .snulbug/shares/share-.../traces/audit.jsonl \
  --out .snulbug/shares/share-.../policy.snulbug \
  --force
export SNULBUG_BUNDLE_SECRET=...
uv run snulbug mcp share promote .snulbug/shares/share-... --to proposed --key-id local-review
uv run snulbug mcp share promote .snulbug/shares/share-... --to approved --key-id local-review
uv run snulbug mcp share activate .snulbug/shares/share-... --key-id local-review
uv run snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

Before handing the generated client config to an MCP client, also run
`snulbug mcp share doctor` and inspect `snulbug mcp share client`.

## 2. Run the policy lab

Before wiring in a real MCP server, run the one-command lab:

```bash
uv run snulbug mcp share lab
```

It starts two fake MCP upstreams behind a single facade, records policy
decisions, generates a learned policy, amends a blocked request into a candidate
policy, and writes replay/audit/report artifacts under `.snulbug-lab/`.

## 3. Create the starter

Generate the policy bundle, proxy config, trace directory, and first-run
instructions:

```bash
uv run snulbug mcp share quickstart \
  --upstream http://127.0.0.1:9000 \
  --preset tunnel-safe \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

This creates:

```text
policy.snulbug/
snulbug.toml
traces/
```

It also validates and tests the generated policy bundle by default. Use
`--no-validate` only when you want the fastest possible scaffold.

The quickstart command is intentionally conservative. It refuses to overwrite an
existing policy or config unless you pass `--force`.

## 4. Review the policy

The generated policy can come from any MCP preset. For a tunnel-exposed local
server, `tunnel-safe` is the recommended default because it requires bearer
auth, rejects JSON-RPC batches, allows configured safe tools, and applies a
small rate limit.
To create a similar policy manually:

```bash
uv run snulbug mcp policy preset tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --rate-limit 60 \
  --rate-window 60
```

Validate it before putting traffic through it:

```bash
uv run snulbug bundle validate policy.snulbug
uv run snulbug bundle test policy.snulbug
```

## 5. Review proxy config

The quickstart writes `snulbug.toml`. To create only the starter config
manually:

```bash
uv run snulbug mcp share config init
```

Edit `snulbug.toml` so `upstream` points at your local HTTP MCP server:

```toml
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
redact_records = true
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true

[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[[mcp.events.sinks]]
type = "console"
format = "text"
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
tunnel_provider = "auto"
tunnel_public_url = ""
cloudflare_access = "off"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = false
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_emails = []
cloudflare_access_allowed_domains = []
timeout = 30.0
```

Use SQLite if you want bounded local policy state to survive proxy restarts:

```toml
state = "sqlite:policy-state.sqlite3"
```

## 6. Run the proxy

Start your MCP server on the configured upstream port, then run:

```bash
uv run snulbug mcp share run --config snulbug.toml
```

Point the MCP client at:

```text
http://127.0.0.1:8080/mcp
```

Send this header from the client:

```text
Authorization: Bearer local-dev-secret
```

To expose a protected local MCP server through a public tunnel, create a share
session. The share command writes the `tunnel-safe` policy, bearer token, task
lease, provider setup files, client config, audit paths, and closeout commands:

```bash
uv run snulbug mcp share create \
  --provider ngrok \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
export SNULBUG_SHARE_TOKEN=...
uv run snulbug mcp share run .snulbug/shares/share-...
(cd .snulbug/shares/share-.../tunnel && \
  ngrok http 8080 --traffic-policy-file ngrok-traffic-policy.yml)
```

Copy the exact `Forwarding` HTTPS URL printed by ngrok. Random free ngrok URLs
commonly use domains such as `ngrok-free.dev` or `ngrok-free.app`; do not
rewrite them into an `ngrok.app` hostname.

Use curl as a minimal MCP client to verify `tools/list` through the tunnel:

```bash
NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
curl -sS "${NGROK_URL}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_SHARE_TOKEN}" \
  -H "x-snulbug-lease: YOUR_SHARE_LEASE_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Before sharing the generated client config, verify the boundary:

```bash
uv run snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${NGROK_URL}/mcp"
uv run snulbug mcp share client .snulbug/shares/share-...
```

Then point the client at the tunnel URL plus `/mcp` and keep the same bearer
header.

## 7. Watch and inspect

With a `console` event sink, the proxy prints one redacted policy decision per
request, including the MCP method, operation target, action, and reason code.
When traffic arrives through ngrok, Cloudflare Tunnel, Tailscale Funnel,
LocalXpose, Pinggy, Holepunch, or a generic forwarder, audit events also include
provider-aware `tunnel` fields such as provider, public URL or peer bridge URL,
source IP, forwarding chain, and edge request id when available. Set
`tunnel_provider` and `tunnel_public_url` in `snulbug.toml` when you want
explicit values instead of auto-detection.

If the tunnel is protected by Cloudflare Access, enable origin-side checks:

```toml
[mcp.proxy]
tunnel_provider = "cloudflare"
cloudflare_access = "enforce"
cloudflare_access_require_email = true
cloudflare_access_allowed_domains = ["example.com"]
```

Use `cloudflare_access = "audit"` first if you want to see what would be
blocked before turning on enforcement.

Return-path controls are enabled in the generated config. Tool/resource/prompt
results are capped by `response_max_bytes`, likely secrets are redacted before
they reach the client, and `tools/list` descriptions/schemas are pinned on first
sight so silent upstream tool changes are surfaced. Set
`response_block_instructions = true` when you want suspicious instruction-like
tool output to be blocked rather than only recorded in metadata.

Request argument schema checks are enabled too. After the first successful
`tools/list`, snulbug validates later `tools/call` arguments against each
tool's MCP `inputSchema` and rejects malformed calls before the upstream server
sees them.

Task-scoped leases are configured but optional by default. Create one when you
want to hand an agent a temporary, narrow capability:

```bash
uv run snulbug mcp share lease create \
  --file leases.json \
  --task "Read README only" \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --ttl 30m
```

Send the returned `x-snulbug-lease` header with MCP requests. Set
`lease_required = true` in `snulbug.toml` when every `tools/call` should require
an active task lease.

If your policy uses `action = "confirm"` for risky calls, enable confirmation in
`snulbug.toml`:

```toml
[mcp.proxy]
confirm = true
```

Confirmation prompts support allow once, allow for this proxy session, or deny.
Without `confirm = true`, confirmation decisions reject by default.

After a session, inspect the captured replay and audit logs:

```bash
uv run snulbug mcp evidence inspect traces/session.jsonl
uv run snulbug mcp evidence inspect traces/audit.jsonl --kind audit
uv run snulbug mcp evidence inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Replay records and audit logs are redacted by default. Keep that default for
normal local development. Set `redact_records = false` only when you need exact
auth-sensitive replay artifacts for a short-lived local debugging session.

## Next steps

- [End-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md)
  runs a standalone HTTP MCP upstream behind the generated proxy policy.
- [MCP CLI guide for agents and harnesses](mcp-guide.md) shows copy-paste and
  compact JSON workflows.
- [MCP client setup recipes](mcp-client-recipes.md) shows local, tunneled,
  header-authenticated, recording, and managed stdio upstream patterns.
- [MCP reverse proxy](mcp-proxy.md) documents every proxy flag and config key.
- [MCP policy workflow](mcp-policy.md) covers presets, learning, amendments,
  and lifecycle promotion.
- [MCP evidence workflow](mcp-evidence.md) covers captured sessions, offline
  replay, impact checks, policy diffs, and session reports.
- [MCP schema discovery](mcp-schemas.md) covers upstream contract review and
  schema-derived policies.
- [Getting started](getting-started.md) shows the generic ASGI middleware path
  for FastAPI, Starlette, Uvicorn, Hypercorn, Daphne, or any ASGI app.

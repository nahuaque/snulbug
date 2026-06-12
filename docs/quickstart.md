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

For a published install:

```bash
pip install "snulbug[proxy]"
```

From this repository:

```bash
uv sync --extra dev
```

The commands below use `uv run` for local repository development. With a
published install, drop the `uv run` prefix.

## 2. Run the policy lab

Before wiring in a real MCP server, run the one-command lab:

```bash
uv run snulbug mcp lab
```

It starts two fake MCP upstreams behind a single facade, records policy
decisions, generates a learned policy, amends a blocked request into a candidate
policy, and writes replay/audit/report artifacts under `.snulbug-lab/`.

## 3. Create the starter

Generate the policy bundle, proxy config, trace directory, and first-run
instructions:

```bash
uv run snulbug mcp quickstart \
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
uv run snulbug mcp init tunnel-safe \
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
uv run snulbug mcp config init
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
audit_out = "traces/audit.jsonl"
redact_records = true
decision_console = true
decision_console_format = "text"
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
timeout = 30.0
```

Use SQLite if you want bounded local policy state to survive proxy restarts:

```toml
state = "sqlite:policy-state.sqlite3"
```

## 6. Run the proxy

Start your MCP server on the configured upstream port, then run:

```bash
uv run snulbug mcp proxy --config snulbug.toml
```

Point the MCP client at:

```text
http://127.0.0.1:8080/mcp
```

Send this header from the client:

```text
Authorization: Bearer local-dev-secret
```

To expose the protected proxy through a tunnel, expose the proxy port, not the
upstream MCP server:

```bash
ngrok http 8080
```

Then point the client at the tunnel URL plus `/mcp` and keep the same bearer
header.

## 7. Watch and inspect

With `decision_console = true`, the proxy prints one redacted policy decision
per request, including the MCP method, operation target, action, and reason
code.

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

If your policy uses `action = "confirm"` for risky calls, run the proxy with
confirmation enabled:

```bash
uv run snulbug mcp proxy --config snulbug.toml --confirm
```

Confirmation prompts support allow once, allow for this proxy session, or deny.
Without `--confirm`, confirmation decisions reject by default.

After a session, inspect the captured replay and audit logs:

```bash
uv run snulbug mcp inspect traces/session.jsonl
uv run snulbug mcp inspect traces/audit.jsonl --kind audit
uv run snulbug mcp inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Replay records and audit logs are redacted by default. Keep that default for
normal local development. Use `--no-redact-records` only when you need exact
auth-sensitive replay artifacts for a short-lived local debugging session.

## Next steps

- [End-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md)
  runs a standalone HTTP MCP upstream behind the generated proxy policy.
- [MCP client setup recipes](mcp-client-recipes.md) shows local, tunneled,
  header-authenticated, recording, and managed stdio upstream patterns.
- [MCP reverse proxy](mcp-proxy.md) documents every proxy flag and config key.
- [MCP recorder and replay](mcp-recorder.md) covers captured sessions,
  redaction, replay, and offline inspection.
- [MCP presets](mcp-presets.md) documents the built-in policy generators.
- [Getting started](getting-started.md) shows the generic ASGI middleware path
  for FastAPI, Starlette, Uvicorn, Hypercorn, Daphne, or any ASGI app.

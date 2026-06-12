# Quickstart: local MCP policy gateway

This path puts `asgi-lua` in front of a local HTTP MCP server so you can add
bearer auth, tool allowlists, live decisions, replayable records, redacted audit
logs, and offline inspection without changing the MCP server.

```text
MCP client
  -> asgi-lua reverse proxy
      -> local HTTP MCP server
```

## 1. Install

For a published install:

```bash
pip install "asgi-lua[proxy]"
```

From this repository:

```bash
uv sync --extra dev
```

The commands below use `uv run` for local repository development. With a
published install, drop the `uv run` prefix.

## 2. Create the starter

Generate the policy bundle, proxy config, trace directory, and first-run
instructions:

```bash
uv run asgi-lua mcp quickstart \
  --upstream http://127.0.0.1:9000 \
  --preset tunnel-safe \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

This creates:

```text
policy.asgi-lua/
asgi-lua.toml
traces/
```

It also validates and tests the generated policy bundle by default. Use
`--no-validate` only when you want the fastest possible scaffold.

The quickstart command is intentionally conservative. It refuses to overwrite an
existing policy or config unless you pass `--force`.

## 3. Review the policy

The generated policy can come from any MCP preset. For a tunnel-exposed local
server, `tunnel-safe` is the recommended default because it requires bearer
auth, rejects JSON-RPC batches, allows configured safe tools, and applies a
small rate limit.
To create a similar policy manually:

```bash
uv run asgi-lua mcp init tunnel-safe \
  --output policy.asgi-lua \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --rate-limit 60 \
  --rate-window 60
```

Validate it before putting traffic through it:

```bash
uv run asgi-lua bundle validate policy.asgi-lua
uv run asgi-lua bundle test policy.asgi-lua
```

## 4. Review proxy config

The quickstart writes `asgi-lua.toml`. To create only the starter config
manually:

```bash
uv run asgi-lua mcp config init
```

Edit `asgi-lua.toml` so `upstream` points at your local HTTP MCP server:

```toml
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.asgi-lua/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
redact_records = true
decision_console = true
decision_console_format = "text"
max_body_bytes = 65536
timeout = 30.0
```

Use SQLite if you want bounded local policy state to survive proxy restarts:

```toml
state = "sqlite:policy-state.sqlite3"
```

## 5. Run the proxy

Start your MCP server on the configured upstream port, then run:

```bash
uv run asgi-lua mcp proxy --config asgi-lua.toml
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

## 6. Watch and inspect

With `decision_console = true`, the proxy prints one redacted policy decision
per request, including the MCP method, operation target, action, and reason
code.

After a session, inspect the captured replay and audit logs:

```bash
uv run asgi-lua mcp inspect traces/session.jsonl
uv run asgi-lua mcp inspect traces/audit.jsonl --kind audit
uv run asgi-lua mcp inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Replay records and audit logs are redacted by default. Keep that default for
normal local development. Use `--no-redact-records` only when you need exact
auth-sensitive replay artifacts for a short-lived local debugging session.

## Next steps

- [End-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md)
  runs a standalone HTTP MCP upstream behind the generated proxy policy.
- [MCP client setup recipes](mcp-client-recipes.md) shows local, tunneled,
  header-authenticated, recording, and stdio-only client patterns.
- [MCP reverse proxy](mcp-proxy.md) documents every proxy flag and config key.
- [MCP recorder and replay](mcp-recorder.md) covers captured sessions,
  redaction, replay, and offline inspection.
- [MCP presets](mcp-presets.md) documents the built-in policy generators.
- [Getting started](getting-started.md) shows the generic ASGI middleware path
  for FastAPI, Starlette, Uvicorn, Hypercorn, Daphne, or any ASGI app.

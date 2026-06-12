# MCP reverse proxy

Reverse proxy mode lets `asgi-lua` protect a local MCP HTTP server even when the
server is not a Python ASGI app.

Install the proxy runner:

```bash
pip install "asgi-lua[proxy]"
```

Copy a starter policy:

```bash
asgi-lua mcp init local-dev-safe --output policy.asgi-lua
```

Or generate one with project-specific values:

```bash
asgi-lua mcp init local-dev-safe \
  --output policy.asgi-lua \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Write a starter config:

```bash
asgi-lua mcp config init
```

Run the proxy:

```bash
asgi-lua mcp proxy --config asgi-lua.toml
```

Point ngrok, Cloudflare Tunnel, or another tunnel at
`http://127.0.0.1:8080`. The proxy applies the Lua policy before forwarding to
the upstream server.

`--record-out` writes replayable request records for traffic that passes through
the proxy. `--audit-out` writes redacted audit events. Rejected/challenged
requests are recorded too, not only requests forwarded upstream.

Print live policy decisions while the proxy is running:

```bash
asgi-lua mcp proxy --config asgi-lua.toml --decision-console
asgi-lua mcp proxy --config asgi-lua.toml --decision-console --decision-console-format json
```

The text console is optimized for watching local tunnel traffic. The JSON format
emits redacted audit-shaped events that can be piped into local tools. Audit
events include MCP-aware fields such as JSON-RPC id, MCP method, operation,
target tool/resource/prompt, params key names, argument key names, initialize
client metadata, and policy decision `reason` / `reason_code`.

Replay captured traffic against the same policy or a candidate policy:

```bash
asgi-lua mcp replay traces/session.jsonl
asgi-lua mcp replay traces/session.jsonl --script candidate.lua
```

Inspect a session after the proxy stops:

```bash
asgi-lua mcp inspect traces/session.jsonl
asgi-lua mcp inspect traces/audit.jsonl --kind audit
```

Live replay records are redacted by default. Use `--no-redact-records` only when
you need exact auth-sensitive replay artifacts.

CLI flags override config values:

```bash
asgi-lua mcp proxy --config asgi-lua.toml --port 8181 --no-trace
```

Example config:

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
decision_console = false
decision_console_format = "text"
max_body_bytes = 65536
timeout = 30.0
```

## State

Proxy mode uses in-memory policy state by default, which supports presets that
use `rate_limit`.

Use SQLite-backed local state:

```bash
asgi-lua mcp proxy --config asgi-lua.toml --state sqlite:policy-state.sqlite3
```

Disable state:

```bash
asgi-lua mcp proxy \
  --upstream http://127.0.0.1:9000 \
  --policy policy.asgi-lua/policy.lua \
  --state none
```

Policies using `rate_limit` require state.

## Python API

Create the ASGI proxy app directly:

```python
from asgi_lua import create_proxy_application

application = create_proxy_application(
    "http://127.0.0.1:9000",
    "policy.asgi-lua/policy.lua",
)
```

You can run that ASGI app with Uvicorn, Hypercorn, Daphne, or another ASGI
server.

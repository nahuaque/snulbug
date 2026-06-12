# MCP reverse proxy

Reverse proxy mode lets `snulbug` protect a local MCP HTTP server even when the
server is not a Python ASGI app.

Install the proxy runner:

```bash
pip install "snulbug[proxy]"
```

Copy a starter policy. For public tunnel use, `tunnel-safe` is the recommended
default:

```bash
snulbug mcp init tunnel-safe --output policy.snulbug
```

Or generate one with project-specific values:

```bash
snulbug mcp init tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Write a starter config:

```bash
snulbug mcp config init
```

Run the proxy:

```bash
snulbug mcp proxy --config snulbug.toml
```

For concrete MCP client configuration patterns, see
[MCP client setup recipes](mcp-client-recipes.md).

For a runnable upstream-plus-proxy walkthrough, see the
[end-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md).

Point ngrok, Cloudflare Tunnel, or another tunnel at
`http://127.0.0.1:8080`. The proxy applies the Lua policy before forwarding to
the upstream server. Use `tunnel-safe` unless you have a stronger external
access-control layer in front of the tunnel.

`--record-out` writes replayable request records for traffic that passes through
the proxy. `--audit-out` writes redacted audit events. Rejected/challenged
requests are recorded too, not only requests forwarded upstream.

Print live policy decisions while the proxy is running:

```bash
snulbug mcp proxy --config snulbug.toml --decision-console
snulbug mcp proxy --config snulbug.toml --decision-console --decision-console-format json
```

The text console is optimized for watching local tunnel traffic. The JSON format
emits redacted audit-shaped events that can be piped into local tools. Audit
events include MCP-aware fields such as JSON-RPC id, MCP method, operation,
target tool/resource/prompt, params key names, argument key names, initialize
client metadata, and policy decision `reason` / `reason_code`.

Replay captured traffic against the same policy or a candidate policy:

```bash
snulbug mcp replay traces/session.jsonl
snulbug mcp replay traces/session.jsonl --script candidate.lua
```

Inspect a session after the proxy stops:

```bash
snulbug mcp inspect traces/session.jsonl
snulbug mcp inspect traces/audit.jsonl --kind audit
snulbug mcp inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Live replay records are redacted by default. Use `--no-redact-records` only when
you need exact auth-sensitive replay artifacts.

CLI flags override config values:

```bash
snulbug mcp proxy --config snulbug.toml --port 8181 --no-trace
```

Example config:

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
decision_console = false
decision_console_format = "text"
max_body_bytes = 65536
timeout = 30.0
```

## MCP Facade Mode

Facade mode lets one `snulbug` proxy present several local MCP HTTP servers as a
single client-facing endpoint. It is intentionally small: `tools/list` is fanned
out to every upstream and returned as one list with tool names prefixed by
upstream name; `tools/call` is routed by that prefix and the prefix is stripped
before the call reaches the upstream server. Other JSON-RPC methods are sent to
the default upstream.

Example config:

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
decision_console = true

[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
default = true

[[mcp.proxy.upstreams]]
name = "git"
url = "http://127.0.0.1:9002/mcp"
```

The client sees tools such as `files.read_file` and `git.status`. A call to
`git.status` is forwarded to the `git` upstream as `status`.

You can also start facade mode directly from the CLI:

```bash
snulbug mcp proxy \
  --policy policy.snulbug/policy.lua \
  --facade-upstream files=http://127.0.0.1:9001/mcp \
  --facade-upstream git=http://127.0.0.1:9002/mcp
```

Use `tool_prefix` when you want a different namespace:

```toml
[[mcp.proxy.upstreams]]
name = "repo"
url = "http://127.0.0.1:9002/mcp"
tool_prefix = "git."
```

Replay records and audit logs include facade metadata such as selected upstream,
original tool name, and upstream tool name for routed calls.

## State

Proxy mode uses in-memory policy state by default, which supports presets that
use `rate_limit`.

Use SQLite-backed local state:

```bash
snulbug mcp proxy --config snulbug.toml --state sqlite:policy-state.sqlite3
```

Disable state:

```bash
snulbug mcp proxy \
  --upstream http://127.0.0.1:9000 \
  --policy policy.snulbug/policy.lua \
  --state none
```

Policies using `rate_limit` require state.

## Python API

Create the ASGI proxy app directly:

```python
from snulbug import create_proxy_application

application = create_proxy_application(
    "http://127.0.0.1:9000",
    "policy.snulbug/policy.lua",
)
```

You can run that ASGI app with Uvicorn, Hypercorn, Daphne, or another ASGI
server.

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

Run the proxy:

```bash
asgi-lua mcp proxy \
  --upstream http://127.0.0.1:9000 \
  --policy policy.asgi-lua/policy.lua \
  --record-out traces/session.jsonl \
  --audit-out traces/audit.jsonl \
  --host 127.0.0.1 \
  --port 8080
```

Point ngrok, Cloudflare Tunnel, or another tunnel at
`http://127.0.0.1:8080`. The proxy applies the Lua policy before forwarding to
the upstream server.

`--record-out` writes replayable request records for traffic that passes through
the proxy. `--audit-out` writes redacted audit events. Rejected/challenged
requests are recorded too, not only requests forwarded upstream.

Replay captured traffic against the same policy or a candidate policy:

```bash
asgi-lua mcp replay traces/session.jsonl
asgi-lua mcp replay traces/session.jsonl --script candidate.lua
```

Live replay records are exact by default. Use `--redact-records` when the replay
record itself must avoid storing secrets.

## State

Proxy mode uses in-memory policy state by default, which supports presets that
use `rate_limit`.

Use SQLite-backed local state:

```bash
asgi-lua mcp proxy \
  --upstream http://127.0.0.1:9000 \
  --policy policy.asgi-lua/policy.lua \
  --record-out traces/session.jsonl \
  --state sqlite:policy-state.sqlite3
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

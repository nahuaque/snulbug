# uvicorn-lua

`uvicorn-lua` is an ASGI middleware that runs a small Lua policy script before
your Python app. It is intended for programmable request behavior near the edge:
header checks, tenant-specific rewrites, normalization, and simple policy
decisions.

It is deliberately not a Uvicorn fork. Uvicorn still serves ASGI; this package is
just an ASGI middleware you can wrap around FastAPI, Starlette, or any ASGI app.

## Install

```bash
uv sync
```

## Minimal app

```python
from uvicorn_lua import LuaMiddleware


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


lua_script = """
return function(request, context)
  if request.headers.authorization ~= "Bearer secret" then
    return { action = "reject", status = 401, body = "unauthorized" }
  end

  return {
    action = "continue",
    context = { tenant = request.headers["x-tenant"] }
  }
end
"""

application = LuaMiddleware(app, lua_script)
```

Run it with:

```bash
uv run uvicorn hello:application
```

## Lua contract

Scripts must return a function:

```lua
return function(request, context)
  return { action = "continue" }
end
```

The `request` table contains:

- `method`
- `path`
- `raw_path`
- `query_string`
- `headers`, with lowercase header names
- `client`
- `scheme`
- `body` and `body_bytes_latin1` when `LuaConfig(read_body=True)` is enabled

Supported actions:

- `continue`: call the downstream ASGI app.
- `set_context`: merge `context` into `scope["lua"]`, then continue.
- `rewrite`: update `path`, `query`, `query_string`, and/or request `headers`, then continue.
- `respond`: send a response directly.
- `reject`: send an error response directly. Defaults to HTTP 403.

## Safety model

Lua scripts run with a small standard-library allowlist. They do not receive raw
Python objects, filesystem APIs, network APIs, `os`, `io`, `package`, or direct
database clients.

`LuaConfig` also provides:

- `instruction_limit`, enforced with a Lua debug hook for runaway scripts.
- `memory_limit_bytes`, passed to Lupa when supported.
- `read_body` and `max_body_bytes`, so body access is explicit and bounded.

This is still an in-process extension mechanism. Use a separate process or a
stronger isolation boundary for hostile third-party code.

## Policy simulation

Use the simulator to replay a JSON request fixture against a policy without
running an ASGI server:

```bash
uv run uvicorn-lua simulate policy.lua request.json
```

Example request fixture:

```json
{
  "method": "POST",
  "path": "/webhooks/vendor",
  "headers": {
    "x-tenant": "acme",
    "authorization": "Bearer secret"
  },
  "body": "{\"event\":\"created\"}"
}
```

The simulator emits the decision and execution trace:

```json
{
  "action": "rewrite",
  "body_read": true,
  "decision": {
    "action": "rewrite",
    "path": "/normalized"
  },
  "trace": {
    "duration_ms": 0.12,
    "instruction_count": 0,
    "source_name": "policy.lua"
  }
}
```

In middleware mode, traces can be attached to the ASGI scope:

```python
application = LuaMiddleware(app, lua_script, config=LuaConfig(trace=True))
```

The downstream app can read `scope["lua_trace"]`.

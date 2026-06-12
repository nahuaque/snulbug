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
- `rewrite`: update `path`, `query`, `query_string`, request `headers`, and/or the bounded request `body`, then continue.
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

Request body rewrites require `LuaConfig(read_body=True)`. The middleware
updates `content-length` when a policy replaces the body.

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

## Policy promotion

Compare an active policy and a draft policy against replay fixtures:

```bash
uv run uvicorn-lua diff active.lua draft.lua fixtures/
```

The command emits changed decisions and regressions. It exits non-zero when a
candidate policy introduces a regression, unless `--no-fail` is provided.

You can also shadow a candidate policy in live middleware:

```python
application = LuaMiddleware(
    app,
    active_policy,
    shadow_script=draft_policy,
    config=LuaConfig(trace=True),
)
```

The active policy still controls the request. The candidate decision and
comparison are attached to `scope["lua_shadow_trace"]`.

## Bounded policy state

Policies can use small state capabilities when the middleware is configured with
a state store. Lua does not receive SQL, Redis clients, filesystem access, or raw
Python objects. It receives only:

```lua
state.get(key)
state.put(key, value, { ttl = 3600 })
state.delete(key)
state.incr(key, amount, { ttl = 3600 })
state.cas(key, expected, value, { ttl = 3600 })
```

Example webhook idempotency policy:

```lua
return function(request, context, state)
  local key = "delivery:" .. request.headers["x-github-delivery"]

  if state.get(key) ~= nil then
    return { action = "reject", status = 409, body = "duplicate webhook" }
  end

  state.put(key, "seen", { ttl = 86400 })
  return { action = "continue" }
end
```

Configure SQLite-backed state:

```python
from uvicorn_lua import LuaMiddleware, SQLiteStateStore, StateLimits

application = LuaMiddleware(
    app,
    policy,
    state_store=SQLiteStateStore("policy_state.sqlite3"),
    state_limits=StateLimits(max_operations=8, max_key_bytes=128, max_value_bytes=1024),
)
```

Configure Redis-backed state:

```bash
uv sync --extra redis
```

```python
from uvicorn_lua import RedisStateStore

state_store = RedisStateStore("redis://localhost:6379/0", key_prefix="uvicorn-lua:")
```

State operations are included in `lua_trace.state_operations`. Shadow policies
use a dry-run state view: reads see the configured store, but candidate writes
are traced without mutating live state.

SQLite is appropriate for local, single-node, and small bounded policy state.
Use WAL mode, short operations, and low write contention. For multi-node
deployments, use a shared store such as Redis.

# ASGI middleware getting started

`snulbug` is primarily a local-dev MCP policy proxy, but the same Lua policy
engine can wrap FastAPI, Starlette, or any ASGI app. It can be served by
Uvicorn, Hypercorn, Daphne, or another ASGI server.

Install from this repository with `uv`:

```bash
uv sync
uv run python -c "import snulbug; print(snulbug.__version__)"
```

Or add the current GitHub source to another `uv` project:

```bash
uv add "snulbug @ git+https://github.com/lbruhacs/snulbug"
```

Minimal policy:

```python
from snulbug import LuaMiddleware


async def app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


policy = """
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

application = LuaMiddleware(app, policy)
```

Run the included basic example:

```bash
uv run uvicorn examples.basic.app:application --host 127.0.0.1 --port 8000
```

## Lua Contract

Scripts return a function:

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

Supported actions include `continue`, `set_context`, `rewrite`, `respond`,
`reject`, `challenge`, `redirect`, `rate_limit`, and `confirm`. See
[Action reference](actions.md) for examples and fields.

MCP-specific policy patterns are documented in the
[Lua policy DSL guide](lua-policy-dsl.md). Exact helper names and arguments are
listed in the [Lua policy reference](lua-request-api.md).

## Safety Model

Lua scripts run with a small standard-library allowlist. They do not receive raw
Python objects, filesystem APIs, network APIs, `os`, `io`, `package`, or direct
database clients.

`LuaConfig` provides:

- `instruction_limit`, enforced with a Lua debug hook for runaway scripts
- `memory_limit_bytes`, passed to Lupa when supported
- `read_body` and `max_body_bytes`, so body access is explicit and bounded

Request body rewrites require `LuaConfig(read_body=True)`. The middleware
updates `content-length` when a policy replaces the body.

This is still an in-process extension mechanism. Use a separate process or a
stronger isolation boundary for hostile third-party code. See the
[security model](security-model.md) for threat-boundary details.

## Policy Simulation

Use the simulator to replay a JSON request fixture against a policy without
running an ASGI server:

```bash
uv run snulbug simulate policy.lua request.json
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
from snulbug import LuaConfig, LuaMiddleware

application = LuaMiddleware(app, policy, config=LuaConfig(trace=True))
```

The downstream app can read `scope["lua_trace"]`.

Stateful policies can be replayed with an explicit state snapshot:

```bash
uv run snulbug simulate policy.lua request.json --state state.json
```

Snapshot input:

```json
{
  "initial_state": {
    "delivery:2f1c2a3b-demo": "seen"
  }
}
```

Simulator output includes `state_snapshot`, with initial state, operations, and
final state.

## Policy Promotion

Compare an active policy and a draft policy against replay fixtures:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/
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

For stateful promotion gates, pass a snapshot file or a directory of snapshots:

```bash
uv run snulbug mcp evidence diff active.lua draft.lua fixtures/ --state-snapshots snapshots/
```

When `--state-snapshots` points to a directory, the diff command looks for a
snapshot matching each fixture name, such as `snapshots/github-push.json`.

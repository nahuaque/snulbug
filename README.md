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
- amend blocked requests into reviewable candidate policy bundles

The standalone ASGI Lua middleware is still available, but it is an
implementation surface. The main use case is protecting local MCP traffic.

## One-command lab

Run the full MCP policy lifecycle without wiring up a real server:

```bash
uv run snulbug mcp lab
```

The lab creates two fake MCP upstreams behind one facade, records traffic,
learns a least-privilege policy, amends a blocked request into a candidate
policy, and writes replay/audit/report artifacts under `.snulbug-lab/`.

## Quickstart

For a tunnel-exposed local MCP server, `tunnel-safe` is the recommended default:

```bash
uv run snulbug mcp quickstart \
  --preset tunnel-safe \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
uv run snulbug mcp proxy --config snulbug.toml
```

Point the MCP client at `http://127.0.0.1:8080/mcp` with:

```text
Authorization: Bearer local-dev-secret
```

Expose the proxy, not the upstream server:

```bash
ngrok http 8080
```

See the [local MCP policy gateway quickstart](docs/quickstart.md) for client
setup, facade mode, recording, replay, and offline inspection.
For positioning against raw proxies, client allowlists, and general policy
engines, see [docs/comparison.md](docs/comparison.md).

## What It Enforces

Request-side policy:

- bearer challenges and auth checks
- MCP method and tool allowlists
- JSON-RPC batch rejection
- project path constraints for tool arguments
- schema-aware validation of `tools/call` arguments from MCP `inputSchema`
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
- learned least-privilege bundles from observed traffic
- candidate amendments for blocked legitimate requests
- a decision console for live local tunnel traffic

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

## Standalone ASGI Middleware

The same Lua policy engine can wrap FastAPI, Starlette, or any ASGI app and can
be served by Uvicorn, Hypercorn, Daphne, or another ASGI server.

```python
from snulbug import LuaMiddleware


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
uv run uvicorn examples.basic.app:application --host 127.0.0.1 --port 8000
```

Additional reference docs live in [docs/](docs/README.md). The generic ASGI
path starts at [docs/getting-started.md](docs/getting-started.md).

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
- `challenge`: send an authentication challenge with `WWW-Authenticate`.
- `redirect`: send a typed HTTP redirect with `Location`.
- `rate_limit`: enforce a fixed-window limit using the configured state store.
- `confirm`: ask an approval broker before continuing. Proxy mode fails closed
  unless confirmation is explicitly enabled.

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
application = LuaMiddleware(app, lua_script, config=LuaConfig(trace=True))
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

Simulator output includes `state_snapshot`:

```json
{
  "initial_state": {
    "delivery:2f1c2a3b-demo": "seen"
  },
  "operations": [
    {
      "op": "get",
      "key": "delivery:2f1c2a3b-demo",
      "value": "seen",
      "hit": true
    }
  ],
  "final_state": {
    "delivery:2f1c2a3b-demo": "seen"
  }
}
```

## Typed response actions

Use `challenge` for standards-shaped auth failures:

```lua
return {
  action = "challenge",
  scheme = "Bearer",
  realm = "tenant:acme",
  error = "invalid_token",
  body = "token required"
}
```

Use `redirect` for canonical endpoint moves:

```lua
return {
  action = "redirect",
  status = 307,
  location = "https://api.example.com/v2/webhooks/acme"
}
```

## Policy promotion

Compare an active policy and a draft policy against replay fixtures:

```bash
uv run snulbug diff active.lua draft.lua fixtures/
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
uv run snulbug diff active.lua draft.lua fixtures/ --state-snapshots snapshots/
```

When `--state-snapshots` points to a directory, the diff command looks for a
snapshot matching each fixture name, such as `snapshots/github-push.json`.
Both policies replay from the same initial state; each result includes its own
final state snapshot.

## Policy bundles

A policy bundle is a portable directory with a manifest, Lua entrypoint,
fixtures, optional state snapshots, and documentation:

```text
policy.snulbug/
  manifest.json
  policy.lua
  fixtures/
  snapshots/
  README.md
```

Example manifest:

```json
{
  "name": "webhook-idempotency",
  "version": "0.1.0",
  "entrypoint": "policy.lua",
  "description": "Reject duplicate webhook delivery IDs",
  "required_capabilities": ["state"],
  "limits": {
    "max_state_operations": 2
  },
  "fixtures": [
    {
      "name": "duplicate delivery is rejected",
      "request": "fixtures/duplicate-delivery.json",
      "state": "snapshots/duplicate.json",
      "expect": {
        "action": "reject",
        "status": 409,
        "body": "duplicate webhook"
      }
    }
  ]
}
```

Validate, test, and pack bundles:

```bash
uv run snulbug bundle validate examples/bundles/idempotency.snulbug
uv run snulbug bundle test examples/bundles/idempotency.snulbug
uv run snulbug bundle pack examples/bundles/idempotency.snulbug dist/idempotency.snulbug.tar.gz
```

Bundle expectations can reference common decision fields directly, such as
`action`, `status`, `path`, `body`, `headers`, and `context`. Nested fields can
use dotted paths like `decision.context.tenant` or
`state_snapshot.final_state.delivery:evt-1`.

## MCP gateway example

`snulbug` can protect a local MCP-style JSON-RPC endpoint before it is exposed
through an ngrok tunnel. The demo app is at:

```text
examples/mcp_gateway/
```

Run it locally:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

Expose it with ngrok:

```bash
ngrok http 8000
```

Then point clients at the ngrok URL plus `/mcp`.

For public tunnel use, `tunnel-safe` is the recommended preset. It requires
bearer auth, rejects JSON-RPC batches, keeps the safe-tool allowlist, and
rate-limits traffic.

See [docs/mcp-client-recipes.md](docs/mcp-client-recipes.md) for concrete
local, tunneled, header-authenticated, and managed stdio upstream setup
patterns.

The gateway policy lives as a portable bundle:

```text
examples/bundles/mcp-gateway.snulbug/
```

It demonstrates bearer challenges, tool allowlists, middleware-owned rate
limits, state-backed traces, and replayable fixtures:

```bash
uv run snulbug bundle validate examples/bundles/mcp-gateway.snulbug
uv run snulbug bundle test examples/bundles/mcp-gateway.snulbug
```

MCP policies can use the built-in helper table:

```lua
local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
if blocked ~= nil then
  return blocked
end
```

Bundled MCP presets can be copied into a project:

```bash
uv run snulbug mcp presets
uv run snulbug mcp quickstart --preset tunnel-safe
uv run snulbug mcp init tunnel-safe --output policy.snulbug
uv run snulbug bundle test policy.snulbug
```

Generate a tailored preset:

```bash
uv run snulbug mcp init tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --rate-limit 60 \
  --rate-window 60
```

Included presets:

- `local-dev-safe`: bearer auth, MCP tool allowlist, and middleware-owned rate limit.
- `auth-required`: bearer auth only.
- `tool-allowlist`: MCP `tools/call` allowlist only.
- `read-only-local-dev`: bearer auth, read-oriented MCP methods, safe tools, and rate limiting.
- `no-shell-tools`: bearer auth plus a shell/process tool-name denylist.
- `project-path-allowlist`: bearer auth, safe tools, and project path constraints for tool arguments.
- `tunnel-safe`: recommended default for public tunnels; bearer auth, no JSON-RPC batches, safe tools, and rate limiting.

Record and replay MCP request decisions as JSONL:

```bash
uv run snulbug mcp record policy.snulbug/policy.lua request.json --out traces/session.jsonl
uv run snulbug mcp replay traces/session.jsonl
uv run snulbug mcp replay traces/session.jsonl --script candidate.lua
```

Inspect replay or audit logs offline:

```bash
uv run snulbug mcp inspect traces/session.jsonl
uv run snulbug mcp inspect traces/audit.jsonl --kind audit
uv run snulbug mcp inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Write a redacted audit log while recording:

```bash
uv run snulbug mcp record policy.snulbug/policy.lua request.json \
  --out traces/session.jsonl \
  --audit-out traces/audit.jsonl
```

Replay records are redacted by default so captured artifacts are safer to keep
around. Pass `--no-redact` only when you need exact auth-sensitive replay.

Compile a captured session into a least-privilege policy bundle:

```bash
uv run snulbug mcp learn traces/session.jsonl --out learned-policy.snulbug
uv run snulbug bundle validate learned-policy.snulbug
```

The learned bundle contains `policy.lua`, `manifest.json`, and `LEARNED.md`.
It allows only observed MCP methods, tools, resource/prompt targets, and tool
argument keys.

When a learned policy blocks a legitimate request, generate a candidate
amendment instead of mutating the active bundle:

```bash
uv run snulbug mcp amend \
  learned-policy.snulbug \
  traces/audit.jsonl \
  --out candidate-policy.snulbug
```

The candidate bundle includes `AMEND.md` with added, rejected, and ignored
changes. Risky shell/exec-style tools are rejected by default.

Run a local-dev reverse proxy in front of an MCP server:

```bash
uv run snulbug mcp config init
uv run snulbug mcp proxy \
  --config snulbug.toml
```

Then expose `http://127.0.0.1:8080/mcp` with ngrok or another tunnel. Use the
`tunnel-safe` preset for this flow unless a stronger external control sits in
front of the tunnel.

The reverse proxy can also act as a thin facade for multiple local MCP servers,
including managed stdio servers. In facade mode, `tools/list` is aggregated
across upstreams and `tools/call` is routed by a namespaced tool prefix:

```bash
uv run snulbug mcp proxy \
  --policy policy.snulbug/policy.lua \
  --facade-upstream files=http://127.0.0.1:9001/mcp \
  --facade-upstream git=http://127.0.0.1:9002/mcp
```

The client sees tools like `files.read_file` and `git.status` through the single
`snulbug` endpoint.

Stdio upstreams can be managed directly from config:

```toml
[[mcp.proxy.upstreams]]
name = "files"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
```

Run the full end-to-end proxy demo:

```bash
uv run python examples/mcp_proxy_demo/run_demo.py
```

See [examples/mcp_proxy_demo](examples/mcp_proxy_demo/README.md) for the
one-command runner and two-terminal HTTP walkthrough.

Watch live policy decisions while proxying:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Redacted audit events include MCP-aware fields such as JSON-RPC id, MCP method,
operation, target tool/resource/prompt, params/argument key names, and policy
decision `reason` / `reason_code`.

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
from snulbug import LuaMiddleware, SQLiteStateStore, StateLimits

application = LuaMiddleware(
    app,
    policy,
    state_store=SQLiteStateStore("policy_state.sqlite3"),
    state_limits=StateLimits(max_operations=8, max_key_bytes=128, max_value_bytes=1024),
)
```

Configure Redis-backed state:

```bash
pip install "snulbug[redis]"
```

```python
from snulbug import RedisStateStore

state_store = RedisStateStore("redis://localhost:6379/0", key_prefix="snulbug:")
```

State operations are included in `lua_trace.state_operations`. Shadow policies
use a dry-run state view: reads see the configured store, but candidate writes
are traced without mutating live state.

Policies can also delegate fixed-window rate limiting to middleware:

```lua
return {
  action = "rate_limit",
  key = "tenant:" .. request.headers["x-tenant"],
  limit = 100,
  window = 60,
  body = "rate limit exceeded"
}
```

`rate_limit` requires `state_store=`. When the quota is exceeded, middleware
returns HTTP 429 with `Retry-After`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `X-RateLimit-Reset`.

SQLite is appropriate for local, single-node, and small bounded policy state.
Use WAL mode, short operations, and low write contention. For multi-node
deployments, use a shared store such as Redis.

## Packaging

Build local distributions:

```bash
uv build
```

Verify before publishing:

```bash
uv run pytest
uv run snulbug --help
uv run python -m snulbug --help
```

Publish when ready:

```bash
uv publish
```

`snulbug` is currently alpha software. Until 1.0, action schemas and trace
fields may evolve.

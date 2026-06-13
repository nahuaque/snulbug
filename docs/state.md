# State adapters

Stateful policies receive a bounded capability API:

```lua
state.get(key)
state.put(key, value, { ttl = 3600 })
state.delete(key)
state.incr(key, amount, { ttl = 3600 })
state.cas(key, expected, value, { ttl = 3600 })
```

Supported stores:

- `MemoryStateStore` for tests and single-process demos
- `SQLiteStateStore` for local, single-node, low-contention state
- `RedisStateStore` for shared multi-process or multi-node state
- `SnapshotStateStore` for deterministic replay

Configure limits:

```python
from snulbug import LuaMiddleware, SQLiteStateStore, StateLimits

application = LuaMiddleware(
    app,
    policy,
    state_store=SQLiteStateStore("policy_state.sqlite3"),
    state_limits=StateLimits(max_operations=8, max_key_bytes=128, max_value_bytes=1024),
)
```

Use Redis for distributed rate limits or global policy state.

Fabric runtime state uses the same adapter vocabulary, but stores the managed
gateway's latest data-plane status instead of Lua policy keys:

```bash
snulbug mcp fabric run --runtime-state sqlite:.snulbug/fabric-runtime.sqlite3
snulbug mcp fabric runtime status --runtime-state sqlite:.snulbug/fabric-runtime.sqlite3
```

Use `redis://...` plus `--runtime-state-key` when several containers or hosts
need one shared MCP fabric runtime view. Runtime state also maintains a lease
key next to the status key so only one active owner can publish heartbeats for a
given fabric key at a time.

Operational control actions use the same store and key prefix, but live under a
separate controls key. That lets an operator pause sharing, drain/quarantine an
upstream, request a force reload, or record a rollback intent without racing the
runtime heartbeat writer:

```bash
snulbug mcp fabric control pause-sharing \
  --runtime-state redis://127.0.0.1:6379/0 \
  --runtime-state-key snulbug:fabric:devbox-a

snulbug mcp fabric control list --compact
snulbug mcp fabric control clear --id ctrl_...
```

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
from asgi_lua import LuaMiddleware, SQLiteStateStore, StateLimits

application = LuaMiddleware(
    app,
    policy,
    state_store=SQLiteStateStore("policy_state.sqlite3"),
    state_limits=StateLimits(max_operations=8, max_key_bytes=128, max_value_bytes=1024),
)
```

Use Redis for distributed rate limits or global policy state.

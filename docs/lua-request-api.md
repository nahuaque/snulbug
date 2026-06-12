# Lua request API

Lua policies return a function:

```lua
return function(request, context, state)
  return { action = "continue" }
end
```

The `request` table contains:

- `method`
- `path`
- `raw_path`
- `query_string`
- `headers`, keyed by lowercase header name
- `client`
- `scheme`
- `body`, when body reading is enabled
- `body_bytes_latin1`, when body reading is enabled

The `context` table is copied from `scope["lua"]` when present. Actions can merge new context into the downstream ASGI scope.

The `state` table is available only when a state store is configured. It exposes `get`, `put`, `delete`, `incr`, and `cas`.

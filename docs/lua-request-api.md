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

## MCP helpers

The sandbox includes an `mcp` helper table for local-dev MCP gateway policies. Helpers parse the JSON-RPC request body without exposing a general Python JSON API.

```lua
local method = mcp.method(request)
local params = mcp.params(request)
local tool = mcp.tool_name(request)

if mcp.is_tool_call(request) then
  local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
  if blocked ~= nil then
    return blocked
  end
end
```

Available helpers:

- `mcp.body(request)`: parsed JSON-RPC body table, or `nil` for missing/malformed JSON.
- `mcp.method(request)`: JSON-RPC method string, or `nil`.
- `mcp.params(request)`: JSON-RPC params table, or an empty table.
- `mcp.is_method(request, method)`: true when the request method matches.
- `mcp.is_tool_call(request)`: true for `tools/call`.
- `mcp.tool_name(request)`: `params.name` for `tools/call`, or `nil`.
- `mcp.tool_allowed(request, allowed)`: true when the request is not a tool call or the tool is allowed.
- `mcp.allow_tools(request, allowed, options)`: returns `nil` when allowed, otherwise a `reject` decision.
- `mcp.reject_tool(request_or_name, status, body, options)`: builds a standard tool rejection decision.

`allowed` can be an array, such as `{ "read_file" }`, or a map, such as `{ read_file = true }`.
`options.reason` and `options.reason_code` can override the default
`mcp.tool_not_allowed` reason metadata.

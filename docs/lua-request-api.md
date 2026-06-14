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
local call = mcp.call(request)

if mcp.is_tool_call(request) then
  local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
  if blocked ~= nil then
    return blocked
  end
end
```

Available helpers:

- `mcp.body(request)`: parsed JSON-RPC body table, or `nil` for missing/malformed JSON.
- `mcp.call(request)`: normalized JSON-RPC call table with `method`, `params`, `args`, `tool`, `id`, `batch`, `invalid`, `error`, `is_tool_call`, `is_read`, and `is_write` fields.
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

## Decision helpers

The sandbox includes a `decision` table for building supported middleware
actions without repeating raw table shapes:

```lua
return function(request, context)
  local call = mcp.call(request)
  return decision.reject(403, "tool blocked", {
    reason_code = "mcp.tool_not_allowed",
    context = { tool = call.tool }
  })
end
```

Available builders:

- `decision.continue(options)`: continue to the upstream app.
- `decision.allow(reason_code, context)`: continue with optional decision metadata.
- `decision.set_context(context, options)`: merge context into the downstream ASGI scope.
- `decision.respond(status, body, options)`: return a response directly.
- `decision.reject(status, body, options)`: reject before reaching the upstream.
- `decision.challenge(options)`: build an auth challenge.
- `decision.redirect(location, options)`: build a redirect.
- `decision.rate_limit(key, limit, window, options)`: invoke configured bounded policy state.
- `decision.confirm(prompt, options)`: ask the live decision console for approval.

`options` can include `reason`, `reason_code`, `context`, and `headers` where
the underlying action supports them.

## Capability guards

The `cap` table provides small guard helpers that return `nil` when allowed or
a standard rejection decision when blocked. This makes policies read as a
short-circuit chain:

```lua
return function(request, context)
  local call = mcp.call(request)
  return cap.method(request, { "tools/call" })
    or cap.tool(request, { "safe_read_file" })
    or cap.path(call.args.path, { "README.md", "docs" })
    or decision.allow("mcp.allowed", { tool = call.tool })
end
```

Available guards:

- `cap.allowed(value, allowed)`: boolean membership check for array or map allowlists.
- `cap.method(request_or_method, allowed, options)`: allow listed JSON-RPC methods.
- `cap.tool(request_or_name, allowed, options)`: allow listed MCP tools; non-tool calls pass through.
- `cap.path(path, allowed_paths, options)`: allow non-absolute, non-traversing relative paths under listed roots.
- `cap.host(url_or_host, allowed_hosts, options)`: allow listed hosts, including `*.example.com` suffix entries.
- `cap.command(command, allowed_commands, options)`: allow shell-like command strings by first token.

# MCP gateway example

The MCP gateway demo protects a local JSON-RPC endpoint before it is exposed through ngrok.

Run the app:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

Expose it:

```bash
ngrok http 8000
```

Point MCP clients at the ngrok URL plus `/mcp`.

The policy bundle is in `examples/bundles/mcp-gateway.asgi-lua`. It demonstrates:

- bearer auth challenges
- `mcp.allow_tools` for JSON-RPC `tools/call` allowlists
- middleware-owned rate limits
- trace context for downstream ASGI code
- replayable request fixtures

Test the bundle:

```bash
uv run asgi-lua bundle test examples/bundles/mcp-gateway.asgi-lua
```

The core policy shape is:

```lua
local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
if blocked ~= nil then
  return blocked
end
```

# MCP gateway example

The MCP gateway demo protects a local JSON-RPC endpoint before it is exposed through ngrok.

For real public tunnel use, prefer the reverse proxy flow with the `tunnel-safe`
preset. This demo shows the lower-level ASGI middleware pattern.

Run the app:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

Expose it:

```bash
ngrok http 8000
```

Point MCP clients at the ngrok URL plus `/mcp`.

For local, tunneled, header-authenticated, and managed stdio upstream patterns, see
[MCP client setup recipes](mcp-client-recipes.md).

The policy bundle is in `examples/bundles/mcp-gateway.snulbug`. It demonstrates:

- bearer auth challenges
- `mcp.allow_tools` for JSON-RPC `tools/call` allowlists
- middleware-owned rate limits
- trace context for downstream ASGI code
- replayable request fixtures

Test the bundle:

```bash
uv run snulbug bundle test examples/bundles/mcp-gateway.snulbug
```

The core policy shape is:

```lua
local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
if blocked ~= nil then
  return blocked
end
```

For a packaged starter policy, use the bundled presets:

```bash
uv run snulbug mcp presets
uv run snulbug mcp init tunnel-safe --output policy.snulbug
```

Record request decisions and replay them later:

```bash
uv run snulbug mcp record policy.snulbug/policy.lua request.json --out traces/session.jsonl
uv run snulbug mcp replay traces/session.jsonl
```

Run the policy as a reverse proxy for a non-ASGI MCP server:

```bash
uv run snulbug mcp config init
uv run snulbug mcp proxy \
  --config snulbug.toml
```

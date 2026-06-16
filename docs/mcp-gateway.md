# MCP gateway example

The MCP gateway demo protects a local JSON-RPC endpoint before it is exposed through ngrok.

For real public tunnel use, prefer the reverse proxy flow with the `tunnel-safe`
preset. This demo shows the lower-level ASGI middleware pattern.

Run the app:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

For ngrok exposure, use the share workflow so snulbug generates the public Cloud
Endpoint Traffic Policy and private internal Agent Endpoint config:

```bash
snulbug mcp share create \
  --provider ngrok \
  --upstream http://127.0.0.1:8000 \
  --allow-tool safe_read_file
```

Then run `snulbug mcp share run ...` and follow the generated
`tunnel/README.md`.

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
snulbug bundle test examples/bundles/mcp-gateway.snulbug
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
snulbug mcp policy preset
snulbug mcp policy preset tunnel-safe --output policy.snulbug
```

For a more complete policy-writing guide, see the
[Lua policy DSL guide](lua-policy-dsl.md).

Record request decisions and replay them later:

```bash
snulbug mcp evidence record policy.snulbug/policy.lua request.json --out traces/session.jsonl
snulbug mcp evidence replay traces/session.jsonl
```

Run the policy as a reverse proxy for a non-ASGI MCP server:

```bash
snulbug mcp share config init
snulbug mcp share run \
  --config snulbug.toml
```

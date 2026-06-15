# Local MCP Gateway Demo

This demo wraps a small MCP-style JSON-RPC ASGI app with `snulbug`.

For public tunnel use, prefer the reverse proxy quickstart with
`--preset tunnel-safe`. This demo shows the direct ASGI middleware integration.

The Lua policy is stored as a portable bundle at:

```text
examples/bundles/mcp-gateway.snulbug/
```

Run locally:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

For ngrok exposure, use the share workflow so snulbug generates the public
Cloud Endpoint Traffic Policy and private internal Agent Endpoint config:

```bash
uv run snulbug mcp share create \
  --provider ngrok \
  --upstream http://127.0.0.1:8000 \
  --allow-tool safe_read_file
```

Then run `uv run snulbug mcp share run ...` and follow the generated
`tunnel/README.md`.

The policy does not implement MCP. It protects ingress before the request reaches
the local MCP server:

- unauthenticated requests receive a bearer challenge
- unsafe tool names are rejected
- allowed tool calls continue to the ASGI app
- over-quota calls return rate-limit intent
- all policy behavior is replayable through bundle fixtures

Validate the policy bundle:

```bash
uv run snulbug bundle test examples/bundles/mcp-gateway.snulbug
```

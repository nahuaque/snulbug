# Local MCP Gateway Demo

This demo wraps a small MCP-style JSON-RPC ASGI app with `asgi-lua`.

The Lua policy is stored as a portable bundle at:

```text
examples/bundles/mcp-gateway.asgi-lua/
```

Run locally:

```bash
uv run uvicorn examples.mcp_gateway.app:application --host 127.0.0.1 --port 8000
```

Expose through ngrok:

```bash
ngrok http 8000
```

Then point MCP clients at the ngrok URL plus `/mcp`.

The policy does not implement MCP. It protects ingress before the request reaches
the local MCP server:

- unauthenticated requests receive a bearer challenge
- unsafe tool names are rejected
- allowed tool calls continue to the ASGI app
- over-quota calls return rate-limit intent
- all policy behavior is replayable through bundle fixtures

Validate the policy bundle:

```bash
uv run asgi-lua bundle test examples/bundles/mcp-gateway.asgi-lua
```

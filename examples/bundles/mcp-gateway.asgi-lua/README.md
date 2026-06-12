# Local MCP Gateway Policy Bundle

This bundle protects a local MCP-style JSON-RPC endpoint exposed through an
ngrok tunnel.

It demonstrates:

- bearer challenge for unauthenticated callers
- allowlisting `tools/call` names
- state-backed request counting
- rate-limit intent when over quota
- replay fixtures for CI

Validate and test:

```bash
uv run asgi-lua bundle validate examples/bundles/mcp-gateway.asgi-lua
uv run asgi-lua bundle test examples/bundles/mcp-gateway.asgi-lua
```

Pack for distribution:

```bash
uv run asgi-lua bundle pack examples/bundles/mcp-gateway.asgi-lua dist/mcp-gateway.asgi-lua.tar.gz
```

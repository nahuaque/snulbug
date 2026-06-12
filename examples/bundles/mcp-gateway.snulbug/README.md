# Local MCP Gateway Policy Bundle

This bundle demonstrates protecting a local MCP-style JSON-RPC endpoint. For
real public tunnel use, prefer the bundled `tunnel-safe` preset.

It demonstrates:

- bearer challenge for unauthenticated callers
- `mcp.allow_tools` for JSON-RPC `tools/call` allowlists
- state-backed request counting
- rate-limit intent when over quota
- replay fixtures for CI

Validate and test:

```bash
uv run snulbug bundle validate examples/bundles/mcp-gateway.snulbug
uv run snulbug bundle test examples/bundles/mcp-gateway.snulbug
```

Pack for distribution:

```bash
uv run snulbug bundle pack examples/bundles/mcp-gateway.snulbug dist/mcp-gateway.snulbug.tar.gz
```

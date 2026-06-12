# MCP Project Path Allowlist

Risk profile for local filesystem-like MCP tools.

It requires `Authorization: Bearer local-dev-secret`, allows only configured
safe tools, and rejects `params.arguments.path` or `params.arguments.paths`
values that are absolute, home-relative, traversal-based, or outside the project
path allowlist.

Default allowed paths:

- `README.md`
- `docs/`
- `examples/`
- `asgi_lua/`
- `tests/`

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
or path allowlist.

# MCP Workspace Firewall

Risk profile for running coding agents against local filesystem-like MCP tools.

It requires `Authorization: Bearer local-dev-secret`, allows only configured
tools, and inspects common path-like tool arguments such as `path`, `paths`,
`file`, `cwd`, `source`, and `destination`.

The policy rejects:

- absolute, home-relative, Windows-drive, or traversal paths
- paths outside the configured workspace allowlist
- secret-looking paths such as `.env`, `.ssh/`, `secrets/`, `*.pem`, and
  `*.key`
- write-like tools targeting generated/cache paths such as `.git/`,
  `node_modules/`, `.venv/`, `__pycache__/`, `dist/`, or `build/`

Allowed decisions include `context.workspace.path_class` so audit logs can show
whether the inspected path was `allowed`, `generated`, or absent.

Default allowed paths:

- `README.md`
- `docs/`
- `examples/`
- `snulbug/`
- `tests/`

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
workspace paths, secret patterns, generated path patterns, or write-tool
heuristics.

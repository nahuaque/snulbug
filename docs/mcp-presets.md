# MCP presets

`asgi-lua` ships MCP policy bundles that can be copied into a project and edited.

List presets:

```bash
uv run asgi-lua mcp presets
```

Copy the default local-dev policy:

```bash
uv run asgi-lua mcp init --output policy.asgi-lua
```

Create the full local proxy starter instead:

```bash
uv run asgi-lua mcp quickstart
```

Copy a specific preset:

```bash
uv run asgi-lua mcp init tool-allowlist --output policy.asgi-lua
```

Generate a tailored preset:

```bash
uv run asgi-lua mcp init local-dev-safe \
  --output policy.asgi-lua \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --allow-path docs/ \
  --rate-limit 60 \
  --rate-window 60
```

Options:

- `--token`: bearer token rendered into `policy.lua`.
- `--token-env`: context key used by the generated policy for an environment-derived token, with `--token` as fallback.
- `--allow-tool`: MCP tool name to allow. Repeat for multiple tools.
- `--allow-path`: project path or prefix to allow in path-scoped profiles. Repeat for multiple paths.
- `--rate-limit`: fixed-window limit for stateful profiles.
- `--rate-window`: fixed-window duration in seconds.

Validate and test the copied bundle:

```bash
uv run asgi-lua bundle validate policy.asgi-lua
uv run asgi-lua bundle test policy.asgi-lua
```

Record and replay decisions while tuning the copied policy:

```bash
uv run asgi-lua mcp record policy.asgi-lua/policy.lua request.json --out traces/session.jsonl
uv run asgi-lua mcp replay traces/session.jsonl
```

Run the copied policy as a local reverse proxy:

```bash
uv run asgi-lua mcp config init
uv run asgi-lua mcp proxy \
  --config asgi-lua.toml
```

## Included presets

`local-dev-safe` is the default. It requires bearer auth, allows only
`safe_read_file` and `list_project_files`, and delegates fixed-window rate
limiting to middleware state.

`auth-required` only requires `Authorization: Bearer local-dev-secret` for
`/mcp`.

`tool-allowlist` only rejects unlisted `tools/call` names and passes non-tool
JSON-RPC methods through.

## Risk profiles

`read-only-local-dev` requires bearer auth, allows read-oriented MCP methods,
allows only configured safe tools, and rate-limits traffic. Use it when a client
should inspect local context without making write-like MCP calls.

```bash
uv run asgi-lua mcp init read-only-local-dev --output policy.asgi-lua
```

`no-shell-tools` requires bearer auth and blocks tool names that look like shell
or process execution, such as `shell_exec`, `run_command`, `terminal`, `bash`,
`powershell`, `spawn`, or `system`.

```bash
uv run asgi-lua mcp init no-shell-tools --output policy.asgi-lua
```

`project-path-allowlist` requires bearer auth, applies a tool allowlist, and
rejects `params.arguments.path` / `params.arguments.paths` outside configured
project paths.

```bash
uv run asgi-lua mcp init project-path-allowlist \
  --output policy.asgi-lua \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --allow-path docs/
```

`tunnel-safe` is the recommended default for ngrok, Cloudflare Tunnel, or
similar public tunnel exposure. It requires bearer auth, rejects JSON-RPC batch
requests, allows only configured safe tools, and rate-limits traffic.

```bash
uv run asgi-lua mcp quickstart \
  --preset tunnel-safe \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret
```

All copied presets are ordinary policy bundles with `manifest.json`,
`policy.lua`, fixtures, and local README files.

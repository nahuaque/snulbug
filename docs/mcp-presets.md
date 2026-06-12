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

Copy a specific preset:

```bash
uv run asgi-lua mcp init tool-allowlist --output policy.asgi-lua
```

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

## Included presets

`local-dev-safe` is the default. It requires bearer auth, allows only
`safe_read_file` and `list_project_files`, and delegates fixed-window rate
limiting to middleware state.

`auth-required` only requires `Authorization: Bearer local-dev-secret` for
`/mcp`.

`tool-allowlist` only rejects unlisted `tools/call` names and passes non-tool
JSON-RPC methods through.

All copied presets are ordinary policy bundles with `manifest.json`,
`policy.lua`, fixtures, and local README files.

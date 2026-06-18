# MCP presets

This is the detailed reference for `snulbug mcp policy preset`. Start with the
[MCP policy workflow](mcp-policy.md) for the group-level overview.

`snulbug` ships MCP policy bundles that can be copied into a project and edited.

List presets:

```bash
snulbug mcp policy preset
```

Copy the default local-dev policy:

```bash
snulbug mcp policy preset --output policy.snulbug
```

Create the full local proxy starter instead:

```bash
snulbug mcp share quickstart
```

Copy a specific preset:

```bash
snulbug mcp policy preset tool-allowlist --output policy.snulbug
```

Generate a tailored preset:

```bash
snulbug mcp policy preset local-dev-safe \
  --output policy.snulbug \
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
snulbug bundle validate policy.snulbug
snulbug bundle test policy.snulbug
```

Record and replay decisions while tuning the copied policy:

```bash
snulbug mcp evidence record policy.snulbug/policy.lua request.json --out traces/session.jsonl
snulbug mcp evidence replay traces/session.jsonl
```

Run the copied policy as a local reverse proxy:

```bash
snulbug mcp share config init
snulbug mcp share run \
  --config snulbug.toml
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
snulbug mcp policy preset read-only-local-dev --output policy.snulbug
```

`no-shell-tools` requires bearer auth and blocks tool names that look like shell
or process execution, such as `shell_exec`, `run_command`, `terminal`, `bash`,
`powershell`, `spawn`, or `system`.

```bash
snulbug mcp policy preset no-shell-tools --output policy.snulbug
```

`project-path-allowlist` requires bearer auth, applies a tool allowlist, and
rejects `params.arguments.path` / `params.arguments.paths` outside configured
project paths.

```bash
snulbug mcp policy preset project-path-allowlist \
  --output policy.snulbug \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --allow-path docs/
```

`workspace-firewall` is designed for coding agents using local filesystem-like
MCP tools. It requires bearer auth, applies a tool allowlist, inspects common
path-like arguments, blocks absolute/traversal/outside paths, blocks
secret-looking paths such as `.env`, `.ssh/`, `secrets/`, `*.pem`, and `*.key`,
and blocks write-like tools from targeting generated/cache paths such as
`.git/`, `node_modules/`, `.venv/`, `__pycache__/`, `dist/`, or `build/`.
Allowed decisions include `context.workspace.path_class` for audit/reporting.
The preset is built from the reusable Lua `workspace.*` helpers documented in
the [Lua policy reference](lua-request-api.md#workspace-firewall-helpers).

```bash
snulbug mcp policy preset workspace-firewall \
  --output policy.snulbug \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --allow-path README.md \
  --allow-path docs/
```

`tunnel-safe` is the recommended default for ngrok, Cloudflare Tunnel,
Tailscale Funnel, Pinggy, Holepunch peer bridges, or similar tunnel
exposure. It requires bearer auth, rejects JSON-RPC batch requests, requires
task leases for tool calls when a lease store is configured, and rate-limits
traffic. For share invites, it declares policy-enforced temporary capability
labels:

- `project_readonly`: default; allow configured read-only project tools.
- `project_search`: allow low-risk read/search tools against non-secret project paths.
- `docs_review`: allow read/search tools scoped to README, docs, and examples.
- `git_inspection`: allow git status/diff/log-style inspection while blocking git mutation.
- `low_risk_tools`: allow low-risk non-writing, non-network, non-secret tools classified by schema or name.

```bash
snulbug mcp share quickstart \
  --preset tunnel-safe \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret
```

All copied presets are ordinary policy bundles with `manifest.json`,
`policy.lua`, fixtures, and local README files.

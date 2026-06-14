# MCP learn mode

This is the detailed reference for `snulbug mcp policy learn` and
`snulbug mcp policy amend`. Start with the
[MCP policy workflow](mcp-policy.md) for the group-level overview.

`snulbug mcp policy learn` compiles captured MCP replay or audit logs into a
least-privilege policy bundle. It is designed for the local-dev loop:

1. Run a permissive or preset policy while developing.
2. Capture real MCP traffic through the recorder or proxy.
3. Generate a learned `.snulbug` bundle from the session.
4. Review the generated policy and report.
5. Switch the proxy to the learned policy before exposing it through a tunnel.

Capture a session:

```bash
uv run snulbug mcp share run --config snulbug.toml
```

Generate a policy bundle:

```bash
uv run snulbug mcp policy learn traces/session.jsonl --out learned-policy.snulbug
```

The output bundle contains:

- `policy.lua`: generated enforcement policy.
- `manifest.json`: normal policy bundle manifest with learned metadata.
- `LEARNED.md`: human-readable report of learned methods, tools, targets, and
  argument keys.

Validate and test the bundle:

```bash
uv run snulbug bundle validate learned-policy.snulbug
uv run snulbug bundle test learned-policy.snulbug
```

Preview the policy impact against the captured session before enabling it:

```bash
uv run snulbug mcp evidence impact \
  traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua \
  --report-out traces/impact-report.md
```

Run the proxy with the learned policy:

```bash
uv run snulbug mcp share run \
  --config snulbug.toml \
  --policy learned-policy.snulbug/policy.lua
```

## What Gets Learned

Learn mode includes only requests that were allowed in the captured session. It
learns:

- observed HTTP request paths
- observed MCP JSON-RPC methods
- observed `tools/call` tool names
- observed tool argument key names per tool
- observed resource targets for `resources/read`, `resources/subscribe`, and
  `resources/unsubscribe`
- observed prompt targets for `prompts/get`

Blocked decisions are excluded from the generated allowlist but summarized in
`LEARNED.md`.

For facade mode, learned tool names already include the facade namespace, such
as `files.read_file` or `git.status`, because that is what the client called.

## Default Enforcement

The generated policy rejects:

- paths not seen during learning
- invalid JSON-RPC bodies
- batch requests
- MCP methods not seen during learning
- tool calls for tools not seen during learning
- tool argument keys not seen for that tool
- resource or prompt targets not seen during learning

Each rejection uses a `mcp.learn.*` reason code so live console, replay, audit,
and inspection workflows can explain why enforcement changed.

## Review Before Tunnels

Learned policies are intentionally mechanical. Review `LEARNED.md` and
`policy.lua` before using the result with ngrok, Cloudflare Tunnel, Tailscale
Funnel, LocalXpose, Pinggy, Holepunch, or another tunnel/peer bridge. If the
session missed a legitimate workflow, run that workflow through the proxy and
regenerate the bundle.

## Amend a Learned Policy

When a learned policy blocks a legitimate request, capture the blocked decision
and generate a candidate amendment instead of editing the active policy in
place:

```bash
uv run snulbug mcp policy amend \
  learned-policy.snulbug \
  traces/audit.jsonl \
  --out candidate-policy.snulbug
```

Amend mode reads blocked `mcp.learn.*` decisions and proposes the smallest
matching expansion:

- `mcp.learn.path_not_observed` adds the observed path.
- `mcp.learn.method_not_observed` adds the observed MCP method.
- `mcp.learn.tool_not_observed` adds the observed tool and its observed
  argument keys.
- `mcp.learn.argument_not_observed` adds observed argument keys for an already
  learned tool.
- `mcp.learn.target_not_observed` adds observed resource or prompt targets.

The output is a new bundle with `policy.lua`, `manifest.json`, and `AMEND.md`.
The source bundle is not modified.

By default, amend mode rejects risky shell/exec-style tool names such as
`shell_exec` into the report instead of adding them to the candidate policy. Use
`--allow-risky` only when you want those names included in the candidate bundle.

Validate and review the candidate:

```bash
uv run snulbug bundle validate candidate-policy.snulbug
uv run snulbug bundle test candidate-policy.snulbug
uv run snulbug mcp evidence impact traces/session.jsonl --policy candidate-policy.snulbug/policy.lua
```

If the source learned bundle points at a replayable `generated_from` record log,
amend mode also checks that previously allowed records still pass against the
candidate policy.

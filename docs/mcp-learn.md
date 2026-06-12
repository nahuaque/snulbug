# MCP learn mode

`snulbug mcp learn` compiles captured MCP replay or audit logs into a
least-privilege policy bundle. It is designed for the local-dev loop:

1. Run a permissive or preset policy while developing.
2. Capture real MCP traffic through the recorder or proxy.
3. Generate a learned `.snulbug` bundle from the session.
4. Review the generated policy and report.
5. Switch the proxy to the learned policy before exposing it through a tunnel.

Capture a session:

```bash
uv run snulbug mcp proxy --config snulbug.toml
```

Generate a policy bundle:

```bash
uv run snulbug mcp learn traces/session.jsonl --out learned-policy.snulbug
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

Run the proxy with the learned policy:

```bash
uv run snulbug mcp proxy \
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
`policy.lua` before using the result with ngrok, Cloudflare Tunnel, or another
public tunnel. If the session missed a legitimate workflow, run that workflow
through the proxy and regenerate the bundle.

# Security model

`snulbug` is designed for local-dev MCP request and response policy, not
arbitrary untrusted compute.

Lua policies run in-process. They receive plain request data, context, and optional bounded state operations. They do not receive raw Python objects, filesystem APIs, network APIs, `os`, `io`, `package`, or database clients.

Use these controls:

- `instruction_limit` for runaway script protection
- `memory_limit_bytes` where supported by Lupa
- `read_body=True` only when required
- `max_body_bytes` for bounded body access
- `state_limits` for bounded state operations
- Redis or another shared store for multi-node state
- redacted audit logs for local-dev MCP gateway visibility
- task-scoped leases for temporary tool/path grants
- MCP `tools/call` argument validation against cached `inputSchema`
- response caps and response secret redaction for MCP tool/resource/prompt
  results
- `tools/list` description/schema pinning for silent upstream tool changes
- optional OAuth protected-resource mode with JWT/JWKS validation, bearer
  challenges, sanitized `context.auth`, and upstream authorization-header
  stripping
- OAuth scope-to-MCP selector mapping so scopes can authorize exact methods and
  tools such as `tools/list` or `tools/call:git.status`

For hostile third-party scripts, add an external isolation boundary. A separate process, container, VM, or WebAssembly runtime is a stronger boundary than the in-process Lua runtime.

CLI-created request replay logs and proxy replay logs are redacted by default.
Use `snulbug mcp evidence record --no-redact ...` or
set `redact_records = false` in `snulbug.toml` only when exact auth-sensitive
replay artifacts are required.

## Attacker boundaries

`snulbug` is most useful against a malicious MCP client or tunnel visitor. It
can require auth, reject unknown tools, enforce expiring task leases, cap
request and response sizes, rate limit traffic, validate tool arguments against
observed schemas, and leave replayable audit evidence.

When OAuth protected-resource mode is enabled, snulbug validates bearer JWT
signature, issuer, audience, and required scopes before Lua policy runs. It is
not an authorization server and does not mint tokens. When
`[mcp.auth.scope_map]` is configured, snulbug also rejects MCP methods/tools
whose selector is not covered by the token's scopes.

It can also reduce risk from a compromised or surprising upstream MCP server by
redacting likely secrets from results, detecting suspicious instruction-like
content, and pinning `tools/list` descriptions and schemas. These controls are
pattern and hash based; they are useful tripwires, not a complete semantic
understanding of every tool result.

It is not designed to safely execute hostile Lua bundles in-process. Treat
policy bundles as code unless you add an external sandbox.

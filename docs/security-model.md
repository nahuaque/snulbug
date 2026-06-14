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
- token anti-passthrough: caller OAuth bearer tokens terminate at snulbug, and
  separate upstream credentials can be brokered from snulbug config

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

When OAuth protected-resource mode is enabled, snulbug validates bearer tokens
before Lua policy runs. It can verify JWT signature, issuer, audience, and
required scopes, or call an OAuth token introspection endpoint for opaque or
revocation-sensitive tokens. It is not an authorization server and does not mint
tokens. When
`[mcp.auth.scope_map]` is configured, snulbug also rejects MCP methods/tools
whose selector is not covered by the token's scopes.

OAuth can be composed with snulbug task leases. OAuth answers who the caller is
and which MCP scopes they hold; leases answer which temporary task capability is
currently active. For public shares, the recommended high-assurance path is:
valid OAuth subject, required MCP scopes, active task lease, and Lua policy
approval. Audit events expose this as `metadata.access` without logging raw
tokens.

Lua policies can now express identity fences directly with helpers such as
`auth.require_subject`, `auth.require_tenant`, and `auth.require_group`. Use
those for share-specific trust boundaries like "only this tenant's developers
may use this remote container's write-capable tools."

Do not reuse caller OAuth tokens as upstream credentials. The default OAuth
proxy behavior strips the caller `Authorization` header before forwarding.
Use `mcp.proxy.upstream_credential` or per-facade-upstream `auth` references to
inject credentials intended for each upstream resource.

JWT signature validation supports pinned local JWKS files, remote JWKS URLs,
and issuer metadata discovery through `.well-known/oauth-authorization-server`
or `.well-known/openid-configuration`. Remote JWKS responses are cached for a
configured TTL and refreshed once when a token references a key id not present
in cache, so issuer key rotation does not require restarting the gateway. Token
introspection responses are cached by token digest for a short TTL. Use HTTPS
remote auth URLs except for localhost development.

Resource indicators are treated as exact public MCP URLs. The safest shape is
`mcp.auth.resource == mcp.auth.audience == <public MCP URL>`. For intentional
multi-URL shares, configure `mcp.auth.resource_aliases` and `mcp.auth.audiences`
explicitly. Otherwise, `share auth doctor` flags drift between the share model,
client config, tunnel URL, proxy config, resource, and audience settings.

Run `snulbug mcp share auth doctor` for OAuth shares. It checks discovery
metadata, issuer/JWKS/introspection reachability, public URL and audience
alignment, resource indicator drift, raw-token logging safeguards, Cloudflare
Access conflicts, and whether scope maps refer to actual discovered MCP tools.

Run `uv run snulbug mcp share auth lab` to inspect the composed auth path in a
self-contained demo. It proves one allowed call and two denied calls across
OAuth scopes, task leases, Lua policy, and redacted audit evidence.

It can also reduce risk from a compromised or surprising upstream MCP server by
redacting likely secrets from results, detecting suspicious instruction-like
content, and pinning `tools/list` descriptions and schemas. These controls are
pattern and hash based; they are useful tripwires, not a complete semantic
understanding of every tool result.

It is not designed to safely execute hostile Lua bundles in-process. Treat
policy bundles as code unless you add an external sandbox.

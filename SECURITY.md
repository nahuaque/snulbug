# Security Policy

`snulbug` is a local-dev MCP policy proxy. Its main security job is to put a
reviewable policy layer between an MCP client and local MCP servers, especially
before traffic is exposed through a public tunnel.

Lua policies run in-process with the ASGI app. The runtime exposes a narrow
request, context, and state API, and it does not expose raw Python objects,
filesystem access, network access, `os`, `io`, `package`, or database clients
to Lua scripts.

This is not a complete isolation boundary for hostile third-party code. Treat
Lua policies as trusted or semi-trusted configuration unless you add a stronger
external sandbox such as a separate process, container, VM, or another isolation
layer.

## Supported versions

Security fixes are provided for the latest released `0.x` version while the project is in alpha.

## Reporting a vulnerability

Please report suspected vulnerabilities privately by opening a GitHub security advisory on the repository. If advisories are not available yet, contact the repository owner directly before opening a public issue.

Include:

- affected version or commit
- policy script and request fixture, when safe to share
- impact and exploitability notes
- any mitigation you have already tested

## Threat Model

### Malicious MCP client or tunnel visitor

This is the primary attacker `snulbug` is designed for. A remote party can send
JSON-RPC requests to a local MCP server through a tunnel or local client
connection.

Expected controls:

- bearer authentication and challenges
- method and tool allowlists
- JSON-RPC batch rejection
- project path constraints for tool arguments
- rate limits backed by bounded state
- replay/audit logs with MCP-aware fields
- response size caps and secret redaction
- human confirmation prompts for risky calls that should not be always allowed

Limits:

- `snulbug` cannot make an unsafe upstream tool safe. If a permitted tool can
  execute arbitrary shell commands, the proxy can only block or constrain calls
  it understands.
- Argument validation is policy-driven today. Prefer narrow tool allowlists and
  explicit path checks for tunnel use.

### Malicious or compromised MCP server

A local upstream server can return unexpected tool descriptions, large outputs,
secrets, or prompt-injection text in tool results.

Expected controls:

- `tools/list` description and schema pinning
- MCP result size caps
- secret redaction on tool/resource/prompt results
- optional blocking of instruction-like return content
- facade namespacing so multiple upstreams are visible as distinct tool
  prefixes

Limits:

- The proxy does not yet perform full MCP schema validation for every result.
- Suspicious-content detection is pattern-based and may miss attacks or produce
  false positives.

### Malicious policy bundle

This is not a hard isolation boundary. Lua runs in-process through Lupa with a
small standard-library allowlist and runtime limits, but a hostile policy bundle
should still be treated as code.

Expected controls:

- no raw Python objects exposed to Lua
- no filesystem, network, `os`, `io`, or `package` APIs exposed to Lua
- instruction limits for runaway scripts
- memory limits where supported by Lupa
- bounded request body access
- bounded state operation counts, key sizes, value sizes, and TTLs

Limits:

- Do not run untrusted third-party policy bundles without an external sandbox.
- In-process Lua limits are defense-in-depth, not a tenant isolation guarantee.

### Malicious local user

A local user who can edit policy files, config, state databases, or upstream
server commands can change the proxy's behavior.

Expected controls:

- policy bundles, generated amendments, and replay diffs are meant to be
  reviewed like code
- SQLite state can persist pins and counters across restarts
- audit logs can show what traffic was allowed or blocked

Limits:

- `snulbug` does not protect against a local user with filesystem write access
  to policy/config/state files.

## Security Expectations

- Enable `instruction_limit` for policies that can be edited outside the deploy process.
- Keep `read_body=True` bounded with `max_body_bytes`.
- Use `state_limits` for stateful policies.
- Do not expose secrets, filesystem paths, network clients, or database clients to Lua.
- Use Redis or another shared state backend for multi-process or multi-node limits.
- Use an external sandbox for untrusted customer-authored code.
- For public tunnels, use the `tunnel-safe` preset unless an external
  access-control layer sits in front of the tunnel.
- Use confirmation mode for risky tools that are occasionally necessary but
  should not run unattended.
- Keep replay records and audit logs redacted unless exact auth-sensitive replay
  artifacts are required for a short-lived local debugging session.
- Prefer SQLite state when you want tool-description pins and rate-limit
  counters to survive proxy restarts.

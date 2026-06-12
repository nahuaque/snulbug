# Security model

`snulbug` is designed for narrow request policy, not arbitrary untrusted compute.

Lua policies run in-process. They receive plain request data, context, and optional bounded state operations. They do not receive raw Python objects, filesystem APIs, network APIs, `os`, `io`, `package`, or database clients.

Use these controls:

- `instruction_limit` for runaway script protection
- `memory_limit_bytes` where supported by Lupa
- `read_body=True` only when required
- `max_body_bytes` for bounded body access
- `state_limits` for bounded state operations
- Redis or another shared store for multi-node state
- redacted audit logs for local-dev MCP gateway visibility

For hostile third-party scripts, add an external isolation boundary. A separate process, container, VM, or WebAssembly runtime is a stronger boundary than the in-process Lua runtime.

CLI-created request replay logs and proxy replay logs are redacted by default.
Use `snulbug mcp record --no-redact ...` or
`snulbug mcp proxy --no-redact-records ...` only when exact auth-sensitive
replay artifacts are required.

# Security Policy

`snulbug` runs Lua policies in-process with the ASGI app. The runtime exposes a narrow request, context, and state API, and it does not expose raw Python objects, filesystem access, network access, `os`, `io`, `package`, or database clients to Lua scripts.

This is not a complete isolation boundary for hostile third-party code. Treat Lua policies as trusted or semi-trusted configuration unless you add a stronger external sandbox such as a separate process, container, VM, or another isolation layer.

## Supported versions

Security fixes are provided for the latest released `0.x` version while the project is in alpha.

## Reporting a vulnerability

Please report suspected vulnerabilities privately by opening a GitHub security advisory on the repository. If advisories are not available yet, contact the repository owner directly before opening a public issue.

Include:

- affected version or commit
- policy script and request fixture, when safe to share
- impact and exploitability notes
- any mitigation you have already tested

## Security expectations

- Enable `instruction_limit` for policies that can be edited outside the deploy process.
- Keep `read_body=True` bounded with `max_body_bytes`.
- Use `state_limits` for stateful policies.
- Do not expose secrets, filesystem paths, network clients, or database clients to Lua.
- Use Redis or another shared state backend for multi-process or multi-node limits.
- Use an external sandbox for untrusted customer-authored code.

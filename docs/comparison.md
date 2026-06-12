# Positioning

`snulbug` is for local-dev MCP traffic where the developer wants a reviewable
policy layer without modifying the MCP client or upstream server.

## Raw MCP Proxy

A raw MCP proxy is good plumbing. It forwards traffic.

`snulbug` adds policy workflow:

- request allow/block decisions with stable reasons
- response-side caps, redaction, instruction tripwires, and tool pinning
- redacted replay and audit logs
- learned least-privilege policy bundles from observed traffic
- amendment bundles for legitimate blocked requests
- a facade for several local MCP servers behind one endpoint

Use a raw proxy when you only need transport bridging. Use `snulbug` when you
need a policy review loop.

## Client Allowlists

Client allowlists are useful, but they are client-specific and often hard to
replay, audit, or share across tools.

`snulbug` sits between clients and servers, so the same policy can protect
Claude Desktop, Claude Code, Cursor, MCP Inspector, or any HTTP MCP client that
can point at the proxy endpoint. Captured sessions can be replayed in CI or
used to generate a narrower policy bundle.

Use client allowlists when one client owns the entire workflow. Use `snulbug`
when several clients or upstream servers need one local policy boundary.

## OPA, Rego, Cedar, or Envoy-style Policy

General policy engines are stronger choices for centralized production
authorization, fleet governance, and organization-wide policy languages.

`snulbug` is intentionally smaller and local-dev shaped:

- Lua policies can parse and transform small MCP request details directly.
- Bounded state supports local rate limits, idempotency, and tool pins.
- Replay fixtures are first-class, so policy changes can be tested like code.
- The proxy can learn from real local traffic and generate an editable bundle.

Use OPA/Cedar/Envoy when you need central governance or a production gateway.
Use `snulbug` when you need an ergonomic local policy layer for MCP tools.

## Why Lua

Lua is not magic, and it is not a hard sandbox here. The reason to use it is
practical:

- small embeddable policies
- imperative request normalization when YAML gets awkward
- simple stateful checks without exposing a database client
- easy replay against captured request fixtures
- hot-swappable policy bundles that remain readable in code review

For hostile third-party policy bundles, add an external isolation boundary.

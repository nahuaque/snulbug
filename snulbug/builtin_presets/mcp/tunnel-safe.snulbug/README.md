# MCP Tunnel Safe

Risk profile for exposing a local MCP HTTP server through ngrok, Cloudflare
Tunnel, Tailscale Funnel, Pinggy, Holepunch peer bridges, or
another tunnel.

It requires `Authorization: Bearer local-dev-secret`, rejects JSON-RPC batch
requests, requires task leases for tool calls when a lease store is configured,
and delegates fixed-window rate limiting to middleware state.

Share invites use Lua-declared temporary capability labels:

- `project_readonly`: default; allow configured read-only project tools.
- `project_search`: allow low-risk read/search tools against non-secret project paths.
- `docs_review`: allow read/search tools scoped to README, docs, and examples.
- `git_inspection`: allow git status/diff/log-style inspection while blocking git mutation.
- `low_risk_tools`: allow low-risk non-writing, non-network, non-secret tools classified by schema or name.

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
capability labels, batch policy, or rate limit.

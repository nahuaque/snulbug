# MCP Tunnel Safe

Risk profile for exposing a local MCP HTTP server through ngrok, Cloudflare
Tunnel, or another public-ish tunnel.

It requires `Authorization: Bearer local-dev-secret`, rejects JSON-RPC batch
requests, allows only `safe_read_file` and `list_project_files`, and delegates
fixed-window rate limiting to middleware state.

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
batch policy, or rate limit.

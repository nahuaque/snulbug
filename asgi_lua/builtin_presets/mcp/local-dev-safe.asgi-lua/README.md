# MCP Local Dev Safe

Default local-dev MCP gateway policy.

It requires `Authorization: Bearer local-dev-secret`, allows only
`safe_read_file` and `list_project_files`, and delegates fixed-window rate
limiting to the middleware state store.

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
or rate limit.

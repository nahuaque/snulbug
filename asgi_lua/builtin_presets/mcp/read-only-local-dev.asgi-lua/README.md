# MCP Read-Only Local Dev

Risk profile for local MCP clients that should inspect project context but not
perform write-like operations.

It requires `Authorization: Bearer local-dev-secret`, allows read-oriented MCP
methods, allows only `safe_read_file` and `list_project_files` tool calls, and
delegates fixed-window rate limiting to middleware state.

Edit `policy.lua` after copying the preset to change the token, tool allowlist,
read method list, or rate limit.

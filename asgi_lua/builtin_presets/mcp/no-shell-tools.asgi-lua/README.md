# MCP No Shell Tools

Risk profile that blocks shell-like or process-execution MCP tool names before
they reach a local MCP server.

It requires `Authorization: Bearer local-dev-secret` on `/mcp` and rejects
`tools/call` names containing terms such as `shell`, `exec`, `command`,
`terminal`, `subprocess`, `bash`, `powershell`, `spawn`, or `system`.

Edit `policy.lua` after copying the preset to change the token or denylist.

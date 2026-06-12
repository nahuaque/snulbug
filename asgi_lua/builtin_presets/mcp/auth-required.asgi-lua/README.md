# MCP Auth Required

Minimal MCP gateway policy that requires `Authorization: Bearer local-dev-secret`
on `/mcp` requests and otherwise passes the request downstream.

Edit `policy.lua` after copying the preset to change the token.

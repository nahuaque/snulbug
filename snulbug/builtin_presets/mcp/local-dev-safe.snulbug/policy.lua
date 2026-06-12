local allowed_tools = {
  "safe_read_file",
  "list_project_files",
}

local token = "local-dev-secret"

return function(request, context, state)
  if request.path ~= "/mcp" then
    return {
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "mcp.endpoint_not_found"
    }
  end

  if request.headers.authorization ~= "Bearer " .. token then
    return {
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.auth_required"
    }
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "rate_limit",
    key = "mcp:token:" .. token,
    limit = 60,
    window = 60,
    body = "too many MCP calls",
    reason = "MCP request is subject to the local fixed-window rate limit",
    reason_code = "mcp.rate_limit",
    context = {
      policy = "mcp-local-dev-safe",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }
  }
end

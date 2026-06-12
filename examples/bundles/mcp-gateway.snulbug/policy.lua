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

  if request.headers.authorization ~= "Bearer local-dev-secret" then
    return {
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP gateway token required",
      reason = "Missing or invalid MCP gateway token",
      reason_code = "mcp.auth_required"
    }
  end

  local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "rate_limit",
    key = "mcp:token:local-dev-secret",
    limit = 5,
    window = 60,
    body = "too many MCP calls",
    reason = "MCP gateway request is subject to the local fixed-window rate limit",
    reason_code = "mcp.rate_limit",
    context = {
      gateway = "mcp",
      auth = "bearer",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }
  }
end

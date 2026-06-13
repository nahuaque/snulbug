local allowed_tools = {
  ["local.safe_read_file"] = true,
  ["local.list_project_files"] = true,
  ["remote.safe_read_file"] = true,
  ["remote.list_project_files"] = true
}

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
    action = "continue",
    reason = "Container facade request allowed",
    reason_code = "mcp.container_facade_allowed"
  }
end

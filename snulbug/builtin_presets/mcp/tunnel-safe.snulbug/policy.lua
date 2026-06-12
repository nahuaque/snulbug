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

  local body = mcp.body(request)
  if type(body) ~= "table" then
    return {
      action = "reject",
      status = 400,
      body = "invalid MCP JSON-RPC request",
      reason = "MCP request body is not a JSON-RPC object",
      reason_code = "mcp.invalid_json"
    }
  end
  if type(body[1]) == "table" then
    return {
      action = "reject",
      status = 400,
      body = "MCP batch requests are disabled for tunnel-safe profile",
      reason = "Batch JSON-RPC requests are disabled for tunneled local-dev exposure",
      reason_code = "mcp.batch_rejected"
    }
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "rate_limit",
    key = "mcp:tunnel:" .. token,
    limit = 60,
    window = 60,
    body = "too many MCP calls",
    reason = "MCP request is allowed by the tunnel-safe profile",
    reason_code = "mcp.tunnel_safe_rate_limit",
    context = {
      policy = "mcp-tunnel-safe",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }
  }
end

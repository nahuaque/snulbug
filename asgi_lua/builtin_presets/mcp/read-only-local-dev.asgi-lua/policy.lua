local allowed_tools = {
  "safe_read_file",
  "list_project_files",
}

local read_methods = {
  ["initialize"] = true,
  ["notifications/initialized"] = true,
  ["tools/list"] = true,
  ["tools/call"] = true,
  ["resources/list"] = true,
  ["resources/read"] = true,
  ["prompts/list"] = true,
  ["prompts/get"] = true,
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

  local method = mcp.method(request)
  if method == nil then
    return {
      action = "reject",
      status = 400,
      body = "invalid MCP JSON-RPC request",
      reason = "MCP request body is not a JSON-RPC object with a method",
      reason_code = "mcp.invalid_json"
    }
  end

  if read_methods[method] ~= true then
    return {
      action = "reject",
      status = 403,
      body = "MCP method is not allowed by read-only profile: " .. method,
      reason = "MCP method is outside the read-only local-dev profile",
      reason_code = "mcp.method_not_read_only"
    }
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "rate_limit",
    key = "mcp:read-only:" .. token,
    limit = 60,
    window = 60,
    body = "too many MCP calls",
    reason = "MCP request is allowed by the read-only local-dev profile",
    reason_code = "mcp.read_only_allowed",
    context = {
      policy = "mcp-read-only-local-dev",
      method = method,
      tool = mcp.tool_name(request) or ""
    }
  }
end

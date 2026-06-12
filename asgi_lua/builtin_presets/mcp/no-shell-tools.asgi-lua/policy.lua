local dangerous_terms = {
  "shell",
  "exec",
  "command",
  "terminal",
  "subprocess",
  "bash",
  "zsh",
  "powershell",
  "cmd",
  "spawn",
  "system",
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

  local tool = mcp.tool_name(request)
  if tool ~= nil then
    local lower_tool = string.lower(tool)
    for _, term in ipairs(dangerous_terms) do
      if string.find(lower_tool, term, 1, true) ~= nil then
        return {
          action = "reject",
          status = 403,
          body = "MCP shell-like tool blocked: " .. tool,
          reason = "MCP tool name matches a shell or process execution denylist",
          reason_code = "mcp.shell_tool_blocked"
        }
      end
    end
  end

  return {
    action = "continue",
    reason = "MCP request passed the no-shell-tools profile",
    reason_code = "mcp.no_shell_allowed",
    context = {
      policy = "mcp-no-shell-tools",
      method = mcp.method(request) or "",
      tool = tool or ""
    }
  }
end

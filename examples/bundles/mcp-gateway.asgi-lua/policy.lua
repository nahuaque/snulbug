local function body_has(request, pattern)
  return string.find(request.body or "", pattern) ~= nil
end

local function tool_name(request)
  return string.match(request.body or "", '"name"%s*:%s*"([^"]+)"')
end

return function(request, context, state)
  if request.path ~= "/mcp" then
    return { action = "reject", status = 404, body = "unknown MCP endpoint" }
  end

  if request.headers.authorization ~= "Bearer local-dev-secret" then
    return {
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP gateway token required"
    }
  end

  if body_has(request, '"method"%s*:%s*"tools/call"') then
    local name = tool_name(request)
    if name ~= "safe_read_file" and name ~= "list_project_files" then
      return {
        action = "reject",
        status = 403,
        body = "MCP tool not allowed: " .. tostring(name)
      }
    end
  end

  return {
    action = "rate_limit",
    key = "mcp:token:local-dev-secret",
    limit = 5,
    window = 60,
    body = "too many MCP calls",
    context = {
      gateway = "mcp",
      auth = "bearer",
      tool = tool_name(request) or ""
    }
  }
end

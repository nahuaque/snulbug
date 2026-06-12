local token = "local-dev-secret"

return function(request, context, state)
  if request.path ~= "/mcp" then
    return { action = "reject", status = 404, body = "unknown MCP endpoint" }
  end

  if request.headers.authorization ~= "Bearer " .. token then
    return {
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required"
    }
  end

  return {
    action = "continue",
    context = {
      policy = "mcp-auth-required"
    }
  }
end

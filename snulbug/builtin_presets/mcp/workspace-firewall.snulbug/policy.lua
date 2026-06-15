local allowed_tools = {
  "safe_read_file",
  "list_project_files",
}

local allowed_paths = {
  "README.md",
  "docs/",
  "examples/",
  "snulbug/",
  "tests/",
}

local token = "local-dev-secret"

local workspace_context = {
  policy = "mcp-workspace-firewall",
}

local function workspace_options(extra)
  local options = {
    allowed_paths = allowed_paths,
    context = workspace_context,
  }
  if type(extra) == "table" then
    for key, value in pairs(extra) do
      options[key] = value
    end
  end
  return options
end

local function allow_context(request)
  local summary = workspace.path_summary(nil, { allowed_paths = allowed_paths })
  return {
    policy = "mcp-workspace-firewall",
    method = mcp.method(request) or "",
    tool = mcp.tool_name(request) or "",
    workspace = {
      argument = summary.argument or "",
      path = summary.path or "",
      path_class = summary.path_class or "none",
      write_intent = workspace.write_intent(),
    },
  }
end

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
      body = "MCP batch requests are disabled for workspace firewall profile",
      reason = "Batch JSON-RPC requests are disabled by the workspace firewall",
      reason_code = "mcp.batch_rejected"
    }
  end

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  blocked = workspace.block_secret_paths(nil, workspace_options())
  if blocked ~= nil then
    return blocked
  end

  blocked = workspace.require_under_project(nil, workspace_options())
  if blocked ~= nil then
    return blocked
  end

  blocked = workspace.block_generated_paths(nil, workspace_options({
    write_only = true,
    reason = "MCP write-like tool targets generated or cache output",
    reason_code = "mcp.workspace_generated_write_blocked",
  }))
  if blocked ~= nil then
    return blocked
  end

  return {
    action = "continue",
    reason = "MCP request is within the workspace firewall",
    reason_code = "mcp.workspace_allowed",
    context = allow_context(request),
  }
end

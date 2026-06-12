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

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function path_is_allowed(path)
  if type(path) ~= "string" or path == "" then
    return false
  end
  if string.sub(path, 1, 1) == "/" or string.sub(path, 1, 1) == "~" then
    return false
  end
  if string.match(path, "^%a:") ~= nil then
    return false
  end
  if path == ".." or starts_with(path, "../") then
    return false
  end
  if string.find(path, "/../", 1, true) ~= nil or string.sub(path, -3) == "/.." then
    return false
  end
  for _, allowed in ipairs(allowed_paths) do
    if path == allowed or starts_with(path, allowed) then
      return true
    end
  end
  return false
end

local function reject_path(path)
  return {
    action = "reject",
    status = 403,
    body = "MCP path not allowed: " .. tostring(path),
    reason = "MCP tool argument path is outside the project path allowlist",
    reason_code = "mcp.path_not_allowed"
  }
end

local function check_path_value(value)
  if type(value) == "string" then
    if not path_is_allowed(value) then
      return reject_path(value)
    end
  elseif type(value) == "table" then
    for _, item in ipairs(value) do
      if type(item) == "string" and not path_is_allowed(item) then
        return reject_path(item)
      end
    end
  end
  return nil
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

  local blocked = mcp.allow_tools(request, allowed_tools)
  if blocked ~= nil then
    return blocked
  end

  local params = mcp.params(request)
  local arguments = params.arguments
  if type(arguments) == "table" then
    local path_block = check_path_value(arguments.path)
    if path_block ~= nil then
      return path_block
    end
    path_block = check_path_value(arguments.paths)
    if path_block ~= nil then
      return path_block
    end
  end

  return {
    action = "continue",
    reason = "MCP request paths are within the project allowlist",
    reason_code = "mcp.path_allowed",
    context = {
      policy = "mcp-project-path-allowlist",
      method = mcp.method(request) or "",
      tool = mcp.tool_name(request) or ""
    }
  }
end

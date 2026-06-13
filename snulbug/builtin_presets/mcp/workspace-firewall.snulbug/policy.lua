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

local path_keys = {
  path = true,
  paths = true,
  filepath = true,
  file = true,
  files = true,
  filename = true,
  directory = true,
  dir = true,
  root = true,
  cwd = true,
  source = true,
  src = true,
  destination = true,
  dest = true,
  target = true,
  targetpath = true,
  oldpath = true,
  newpath = true,
  from = true,
  to = true,
}

local write_terms = {
  "write",
  "edit",
  "create",
  "delete",
  "remove",
  "rename",
  "move",
  "patch",
  "replace",
  "append",
  "mkdir",
  "rm",
  "touch",
  "save",
}

local secret_suffixes = {
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".crt",
  ".cert",
}

local generated_segments = {
  ".git",
  ".snulbug",
  ".venv",
  "venv",
  "node_modules",
  "__pycache__",
  ".ruff_cache",
  ".pytest_cache",
  ".mypy_cache",
  "dist",
  "build",
  "coverage",
}

local token = "local-dev-secret"

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function ends_with(value, suffix)
  return suffix == "" or string.sub(value, -#suffix) == suffix
end

local function normalize_arg_key(key)
  local lower = string.lower(tostring(key or ""))
  return string.gsub(lower, "[_%.%-]", "")
end

local function path_like_key(key)
  return path_keys[normalize_arg_key(key)] == true
end

local function normalize_path(path)
  local value = path
  while starts_with(value, "./") do
    value = string.sub(value, 3)
  end
  return value
end

local function basename(path)
  return string.match(path, "([^/]+)$") or path
end

local function has_segment(path, segment)
  return string.find("/" .. path .. "/", "/" .. segment .. "/", 1, true) ~= nil
end

local function path_is_allowed(path)
  for _, allowed in ipairs(allowed_paths) do
    local normalized_allowed = normalize_path(allowed)
    if ends_with(normalized_allowed, "/") then
      if starts_with(path, normalized_allowed) then
        return true
      end
    elseif path == normalized_allowed then
      return true
    end
  end
  return false
end

local function path_is_secret(path)
  local lower = string.lower(path)
  local base = basename(lower)
  if base == ".env" or starts_with(base, ".env.") then
    return true
  end
  if has_segment(lower, ".ssh") or has_segment(lower, ".gnupg") or has_segment(lower, "secrets") then
    return true
  end
  if lower == ".kube/config" or ends_with(lower, "/.kube/config") then
    return true
  end
  for _, suffix in ipairs(secret_suffixes) do
    if ends_with(lower, suffix) then
      return true
    end
  end
  return false
end

local function path_is_generated(path)
  local lower = string.lower(path)
  for _, segment in ipairs(generated_segments) do
    if has_segment(lower, segment) then
      return true
    end
  end
  return false
end

local function tool_is_write_like(tool)
  local lower = string.lower(tool or "")
  for _, term in ipairs(write_terms) do
    if string.find(lower, term, 1, true) ~= nil then
      return true
    end
  end
  return false
end

local function classify_path(path, argument)
  if type(path) ~= "string" or path == "" then
    return { argument = argument, path = tostring(path), path_class = "invalid" }
  end

  local normalized = normalize_path(path)
  if string.sub(normalized, 1, 1) == "/" or string.sub(normalized, 1, 1) == "~" then
    return { argument = argument, path = normalized, path_class = "outside" }
  end
  if string.match(normalized, "^%a:") ~= nil then
    return { argument = argument, path = normalized, path_class = "outside" }
  end
  if normalized == ".." or starts_with(normalized, "../") then
    return { argument = argument, path = normalized, path_class = "outside" }
  end
  if string.find(normalized, "/../", 1, true) ~= nil or ends_with(normalized, "/..") then
    return { argument = argument, path = normalized, path_class = "outside" }
  end
  if path_is_secret(normalized) then
    return { argument = argument, path = normalized, path_class = "secret" }
  end
  if not path_is_allowed(normalized) then
    return { argument = argument, path = normalized, path_class = "outside" }
  end
  if path_is_generated(normalized) then
    return { argument = argument, path = normalized, path_class = "generated" }
  end
  return { argument = argument, path = normalized, path_class = "allowed" }
end

local function collect_path_values(value, key, output, depth)
  if depth > 5 then
    return
  end

  if path_like_key(key) then
    if type(value) == "string" then
      table.insert(output, classify_path(value, tostring(key)))
    elseif type(value) == "table" then
      for _, item in ipairs(value) do
        if type(item) == "string" then
          table.insert(output, classify_path(item, tostring(key)))
        end
      end
    end
  end

  if type(value) == "table" then
    for child_key, child_value in pairs(value) do
      if type(child_key) == "string" then
        collect_path_values(child_value, child_key, output, depth + 1)
      end
    end
  end
end

local function workspace_context(method, tool, info, write_intent)
  return {
    policy = "mcp-workspace-firewall",
    method = method or "",
    tool = tool or "",
    workspace = {
      argument = info.argument or "",
      path = info.path or "",
      path_class = info.path_class or "none",
      write_intent = write_intent,
    },
  }
end

local function reject_workspace(method, tool, info, write_intent)
  local reason_code = "mcp.workspace_path_blocked"
  local reason = "MCP tool path is blocked by the workspace firewall"
  if info.path_class == "invalid" then
    reason_code = "mcp.workspace_path_invalid"
    reason = "MCP tool path argument is missing or invalid"
  elseif info.path_class == "outside" then
    reason_code = "mcp.workspace_path_outside"
    reason = "MCP tool path is outside the allowed workspace paths"
  elseif info.path_class == "secret" then
    reason_code = "mcp.workspace_secret_blocked"
    reason = "MCP tool path looks like a secret-bearing file or directory"
  elseif info.path_class == "generated" then
    reason_code = "mcp.workspace_generated_write_blocked"
    reason = "MCP write-like tool targets generated or cache output"
  end

  return {
    action = "reject",
    status = 403,
    body = "MCP workspace path blocked (" .. info.path_class .. "): " .. tostring(info.path),
    reason = reason,
    reason_code = reason_code,
    context = workspace_context(method, tool, info, write_intent),
  }
end

local function summarize_path_infos(path_infos)
  if #path_infos == 0 then
    return { argument = "", path = "", path_class = "none" }
  end
  for _, info in ipairs(path_infos) do
    if info.path_class == "generated" then
      return info
    end
  end
  return path_infos[1]
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

  local method = mcp.method(request)
  local tool = mcp.tool_name(request) or ""
  local write_intent = tool_is_write_like(tool)
  local path_infos = {}
  local params = mcp.params(request)
  if type(params.arguments) == "table" then
    collect_path_values(params.arguments, "", path_infos, 0)
  end

  for _, info in ipairs(path_infos) do
    if info.path_class == "invalid" or info.path_class == "outside" or info.path_class == "secret" then
      return reject_workspace(method, tool, info, write_intent)
    end
    if write_intent and info.path_class == "generated" then
      return reject_workspace(method, tool, info, write_intent)
    end
  end

  local summary = summarize_path_infos(path_infos)
  return {
    action = "continue",
    reason = "MCP request is within the workspace firewall",
    reason_code = "mcp.workspace_allowed",
    context = workspace_context(method, tool, summary, write_intent),
  }
end

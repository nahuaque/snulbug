local allowed_tools = {
  "safe_read_file",
  "list_project_files",
}

local docs_paths = {
  "README.md",
  "docs/",
  "examples/",
}

local fallback_token = "local-dev-secret"

local function policy_token(context)
  return fallback_token
end

capabilities.declare({
  {
    id = "project_readonly",
    label = "Project readonly",
    description = "Allow read-only project inspection through the tunnel-safe tool set.",
    default = true,
  },
  {
    id = "project_search",
    label = "Project search",
    description = "Allow low-risk read/search tools against non-secret project paths.",
  },
  {
    id = "docs_review",
    label = "Docs review",
    description = "Allow read/search tools scoped to README, docs, and examples.",
  },
  {
    id = "git_inspection",
    label = "Git inspection",
    description = "Allow read-only git inspection such as status, diff, log, and branch listing.",
  },
  {
    id = "low_risk_tools",
    label = "Low-risk tools",
    description = "Allow low-risk non-writing, non-network, non-secret tools classified by schema or name.",
  }
})

local function tool_is_listed(name, tools)
  if name == nil then
    return true
  end
  for _, tool in ipairs(tools) do
    if tool == name then
      return true
    end
  end
  return false
end

local function decision_context(call)
  return {
    policy = "mcp-tunnel-safe",
    method = call.method or "",
    tool = call.tool or "",
    lease_id = lease.id() or "",
    capabilities = lease.capabilities(),
    intent = intent.categories(),
    risk = intent.risk() or "",
  }
end

local function reject_capability(call)
  return access.lease_required({
    body = "MCP tool requires a matching invite capability",
    reason = "Active lease does not include a capability that allows this MCP tool",
    reason_code = "lease.capability_missing",
    context = decision_context(call),
  })
end

local function reject_tool(call, reason_code, body)
  return decision.reject(403, body, {
    reason = body,
    reason_code = reason_code,
    context = decision_context(call),
  })
end

local function workspace_guards(request, call, paths)
  local options = {
    allowed_paths = paths or { "." },
    context = {
      policy = "mcp-tunnel-safe",
      method = call.method or "",
      tool = call.tool or "",
    },
  }
  local blocked = workspace.require_under_project(nil, options)
  if blocked ~= nil then
    return blocked
  end
  blocked = workspace.block_secret_paths(nil, options)
  if blocked ~= nil then
    return blocked
  end
  return workspace.block_generated_paths(nil, options)
end

local function blocks_dangerous_intent(call)
  local blocked = intent.block_if({ "shell.exec", "network.egress", "secrets.access", "filesystem.write", "git.write", "write" }, {
    reason = "Tunnel-safe capability does not allow shell, network, secret, or write tools",
    reason_code = "mcp.tunnel_safe_intent_blocked",
    context = decision_context(call),
  })
  if blocked ~= nil then
    return blocked
  end
  return intent.require_max_risk("medium", {
    reason = "Tunnel-safe capability allows only low or medium risk tools",
    reason_code = "mcp.tunnel_safe_risk_denied",
    context = decision_context(call),
  })
end

local function low_risk_blocks(call)
  local blocked = intent.block_if({ "shell.exec", "network.egress", "secrets.access", "filesystem.write", "git.write", "write" }, {
    reason = "Low-risk tunnel-safe capability does not allow shell, network, secret, or write tools",
    reason_code = "mcp.tunnel_safe_intent_blocked",
    context = decision_context(call),
  })
  if blocked ~= nil then
    return blocked
  end
  return intent.require_max_risk("low", {
    reason = "Low-risk tunnel-safe capability allows only low-risk tools",
    reason_code = "mcp.tunnel_safe_risk_denied",
    context = decision_context(call),
  })
end

local function git_inspection_block(call)
  local tool = string.lower(tostring(call.tool or ""))
  if string.find(tool, "push", 1, true)
    or string.find(tool, "pull", 1, true)
    or string.find(tool, "commit", 1, true)
    or string.find(tool, "checkout", 1, true)
    or string.find(tool, "merge", 1, true)
    or string.find(tool, "rebase", 1, true)
    or string.find(tool, "reset", 1, true) then
    return reject_tool(call, "mcp.tunnel_safe_git_write_blocked", "Git mutation tools are not allowed by tunnel-safe git inspection")
  end
  if not intent.has_category("git.read") then
    return reject_capability(call)
  end
  return blocks_dangerous_intent(call)
end

local function allow_tool_call(request, call)
  if not lease.enabled() then
    return mcp.allow_tools(request, allowed_tools)
  end

  local blocked = lease.require({
    reason_code = "lease.active_task_lease_required",
    body = "active MCP task lease required",
  })
  if blocked ~= nil then
    return blocked
  end

  if lease.has_capability("project_readonly") and tool_is_listed(call.tool, allowed_tools) then
    return workspace_guards(request, call, { "." })
  end

  if lease.has_capability("docs_review") then
    blocked = workspace_guards(request, call, docs_paths)
    if blocked ~= nil then
      return blocked
    end
    if intent.has_category({ "read", "filesystem.read" }) then
      return blocks_dangerous_intent(call)
    end
  end

  if lease.has_capability("project_search") then
    blocked = workspace_guards(request, call, { "." })
    if blocked ~= nil then
      return blocked
    end
    if intent.has_category({ "read", "filesystem.read" }) then
      return blocks_dangerous_intent(call)
    end
  end

  if lease.has_capability("git_inspection") then
    blocked = git_inspection_block(call)
    if blocked == nil then
      return nil
    end
    if blocked.reason_code ~= "lease.capability_missing" then
      return blocked
    end
  end

  if lease.has_capability("low_risk_tools") then
    blocked = workspace_guards(request, call, { "." })
    if blocked ~= nil then
      return blocked
    end
    return low_risk_blocks(call)
  end

  return reject_capability(call)
end

local function allow_with_rate_limit(token, call)
  return {
    action = "rate_limit",
    key = "mcp:tunnel:" .. token,
    limit = 60,
    window = 60,
    body = "too many MCP calls",
    reason = "MCP request is allowed by the tunnel-safe profile",
    reason_code = "mcp.tunnel_safe_rate_limit",
    context = decision_context(call)
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

  local token = policy_token(context)
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

  local call = mcp.call(request)
  if call.is_tool_call then
    local blocked = allow_tool_call(request, call)
    if blocked ~= nil then
      return blocked
    end
  end

  return allow_with_rate_limit(token, call)
end

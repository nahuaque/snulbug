local required_tenant_id = "00000000-0000-0000-0000-000000000000"
local read_role = "Mcp.Tools.Read"
local write_role = "Mcp.Tools.Write"

local read_tools = {
  ["filesystem.read_file"] = true,
  ["git.status"] = true,
}

local write_tools = {
  ["filesystem.write_file"] = true,
  ["git.push"] = true,
}

return function(request, context, state)
  local method = mcp.method(request)
  if method ~= "tools/call" then
    return decision.allow("auth.entra.protocol_allowed", {
      provider = "entra",
      method = method or ""
    })
  end

  local tenant_id = auth.entra_tenant_id()
  local tool = mcp.tool_name(request) or ""

  if tenant_id ~= required_tenant_id then
    return decision.reject(403, "Entra tenant not allowed", {
      reason_code = "oauth.entra_tenant_denied",
      context = {
        provider = "entra",
        tenant_id = tenant_id or "",
        required_tenant = required_tenant_id,
        tool = tool
      }
    })
  end

  if read_tools[tool] then
    if auth.entra_has_app_role({ read_role, write_role }) then
      return decision.allow("auth.entra.read_allowed", {
        provider = "entra",
        tenant_id = tenant_id,
        tool = tool
      })
    end
    return access.wrong_group("entra:appRole:" .. read_role, {
      reason_code = "oauth.entra_read_app_role_required",
      context = {
        provider = "entra",
        tool = tool,
        app_role = read_role
      }
    })
  end

  if write_tools[tool] then
    if auth.entra_has_app_role(write_role) then
      return decision.allow("auth.entra.write_allowed", {
        provider = "entra",
        tenant_id = tenant_id,
        tool = tool
      })
    end
    return access.wrong_group("entra:appRole:" .. write_role, {
      reason_code = "oauth.entra_write_app_role_required",
      context = {
        provider = "entra",
        tool = tool,
        app_role = write_role
      }
    })
  end

  return mcp.reject_tool(tool, 403, "tool not allowed by Entra app-role policy", {
    reason_code = "mcp.entra_tool_not_allowed",
    context = {
      provider = "entra",
      tenant_id = tenant_id or "",
      tool = tool
    }
  })
end

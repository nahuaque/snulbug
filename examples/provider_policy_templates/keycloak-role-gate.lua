local keycloak_client_id = "snulbug-mcp"

local read_tools = {
  ["filesystem.read_file"] = true,
  ["git.status"] = true,
  ["git.diff"] = true,
}

local admin_tools = {
  ["filesystem.write_file"] = true,
  ["git.push"] = true,
}

return function(request, context, state)
  local method = mcp.method(request)
  if method ~= "tools/call" then
    return decision.allow("auth.keycloak.protocol_allowed", {
      provider = "keycloak",
      method = method or ""
    })
  end

  local tool = mcp.tool_name(request) or ""

  if read_tools[tool] then
    if auth.keycloak_has_role("mcp-reader", keycloak_client_id)
        or auth.keycloak_has_role("mcp-admin") then
      return decision.allow("auth.keycloak.reader_allowed", {
        provider = "keycloak",
        tool = tool,
        client_id = keycloak_client_id
      })
    end
    return access.wrong_group("keycloak:" .. keycloak_client_id .. ":mcp-reader", {
      reason_code = "oauth.keycloak_reader_role_required",
      context = {
        provider = "keycloak",
        tool = tool,
        client_id = keycloak_client_id
      }
    })
  end

  if admin_tools[tool] then
    if auth.keycloak_has_role("mcp-admin") then
      return decision.allow("auth.keycloak.admin_allowed", {
        provider = "keycloak",
        tool = tool,
        role = "mcp-admin"
      })
    end
    return access.wrong_group("keycloak:realm:mcp-admin", {
      reason_code = "oauth.keycloak_admin_role_required",
      context = {
        provider = "keycloak",
        tool = tool,
        role = "mcp-admin"
      }
    })
  end

  return mcp.reject_tool(tool, 403, "tool not allowed by Keycloak role policy", {
    reason_code = "mcp.keycloak_tool_not_allowed",
    context = {
      provider = "keycloak",
      tool = tool
    }
  })
end

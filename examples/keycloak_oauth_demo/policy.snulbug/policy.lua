return function(request, context, state)
  if request.path ~= "/mcp" then
    return decision.reject(404, "unknown MCP endpoint", {
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "keycloak_demo.endpoint_not_found"
    })
  end

  local method = mcp.method(request)
  if method == "tools/list" then
    local missing_scope = auth.require("tools/list")
    if missing_scope then
      return missing_scope
    end
    return decision.continue({
      reason = "Keycloak token can list demo tools",
      reason_code = "keycloak_demo.tools_list_allowed",
      context = {
        auth_subject = auth.subject() or "",
        tenant = auth.tenant() or ""
      }
    })
  end

  local tool = mcp.tool_name(request)
  if method == "tools/call" and (
    tool == "keycloak_demo.safe_read_file" or tool == "keycloak_demo.list_project_files"
  ) then
    local missing_scope = auth.require("tools/call:" .. tool)
    if missing_scope then
      return missing_scope
    end
    local wrong_tenant = auth.require_tenant("demo")
    if wrong_tenant then
      return wrong_tenant
    end
    return decision.continue({
      reason = "Keycloak token can call the scoped read-only demo file tool",
      reason_code = "keycloak_demo.file_tool_allowed",
      context = {
        auth_subject = auth.subject() or "",
        tenant = auth.tenant() or "",
        tool = tool
      }
    })
  end

  return decision.reject(403, "tool not allowed", {
    reason = "The Keycloak demo policy only allows read-only demo file tools",
    reason_code = "keycloak_demo.tool_not_allowed"
  })
end

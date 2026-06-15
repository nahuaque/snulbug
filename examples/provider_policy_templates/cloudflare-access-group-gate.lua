local required_group = "platform-dev"

local allowed_tools = {
  ["filesystem.read_file"] = true,
  ["git.status"] = true,
}

return function(request, context, state)
  local method = mcp.method(request)
  if method ~= "tools/call" then
    return decision.allow("auth.cloudflare_access.protocol_allowed", {
      provider = "cloudflare_access",
      method = method or ""
    })
  end

  local tool = mcp.tool_name(request) or ""

  if not auth.cloudflare_jwt_validated() then
    return decision.reject(403, "validated Cloudflare Access assertion required", {
      reason_code = "cloudflare_access.jwt_validation_required",
      context = {
        provider = "cloudflare_access",
        email = auth.cloudflare_email() or "",
        subject = auth.cloudflare_subject() or "",
        tool = tool
      }
    })
  end

  if not auth.cloudflare_has_group(required_group) then
    return access.wrong_group("cloudflare:" .. required_group, {
      reason_code = "oauth.cloudflare_access_group_required",
      context = {
        provider = "cloudflare_access",
        email = auth.cloudflare_email() or "",
        subject = auth.cloudflare_subject() or "",
        tool = tool
      }
    })
  end

  local blocked = mcp.allow_tools(request, allowed_tools, {
    reason_code = "mcp.cloudflare_access_tool_not_allowed",
    context = {
      provider = "cloudflare_access",
      email = auth.cloudflare_email() or "",
      subject = auth.cloudflare_subject() or "",
      tool = tool
    }
  })
  if blocked then
    return blocked
  end

  return decision.allow("auth.cloudflare_access.group_allowed", {
    provider = "cloudflare_access",
    email = auth.cloudflare_email() or "",
    subject = auth.cloudflare_subject() or "",
    group = required_group,
    tool = tool
  })
end

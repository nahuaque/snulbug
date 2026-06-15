local required_workload = {
  repository = "acme/widget-service",
  workflow = "snulbug-demo",
  ref = "refs/heads/main",
  event_name = "workflow_dispatch",
  job_workflow_ref = "acme/widget-service/.github/workflows/snulbug-demo.yml@refs/heads/main",
}

local allowed_tools = {
  ["github.get_file_contents"] = true,
  ["github.list_pull_requests"] = true,
}

return function(request, context, state)
  local method = mcp.method(request)
  if method ~= "tools/call" then
    return decision.allow("auth.github_actions.protocol_allowed", {
      provider = "github_actions",
      method = method or ""
    })
  end

  local tool = mcp.tool_name(request) or ""

  if not auth.github_matches(required_workload) then
    return access.wrong_subject("github-actions:" .. required_workload.repository .. ":main", {
      reason_code = "oauth.github_workload_denied",
      context = {
        provider = "github_actions",
        repository = auth.github_repository() or "",
        workflow = auth.github_workflow() or "",
        ref = auth.github_ref() or "",
        event_name = auth.github_event_name() or "",
        required_repository = required_workload.repository,
        required_ref = required_workload.ref,
        tool = tool
      }
    })
  end

  local missing_lease = lease.require({
    reason_code = "lease.github_workload_required",
    context = {
      provider = "github_actions",
      repository = auth.github_repository() or "",
      ref = auth.github_ref() or "",
      tool = tool
    }
  })
  if missing_lease then
    return missing_lease
  end

  local blocked = mcp.allow_tools(request, allowed_tools, {
    reason_code = "mcp.github_workload_tool_not_allowed",
    context = {
      provider = "github_actions",
      repository = auth.github_repository() or "",
      ref = auth.github_ref() or "",
      tool = tool
    }
  })
  if blocked then
    return blocked
  end

  return decision.allow("auth.github_actions.workload_allowed", {
    provider = "github_actions",
    repository = auth.github_repository() or "",
    workflow = auth.github_workflow() or "",
    ref = auth.github_ref() or "",
    lease_id = lease.id() or "",
    tool = tool
  })
end

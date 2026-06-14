return function(request, context, state)
  if request.path ~= "/mcp" then
    return decision.reject(404, "unknown MCP endpoint", {
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "claim_patterns.endpoint_not_found"
    })
  end

  return decision.continue({
    reason = "OAuth claim policy accepted the request",
    reason_code = "claim_patterns.claim_policy_allowed",
    context = {
      auth_subject = auth.subject() or "",
      auth_tenant = auth.tenant() or "",
      auth_client_id = auth.client_id() or ""
    }
  })
end


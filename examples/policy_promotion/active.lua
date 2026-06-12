return function(request, context)
  if request.headers["x-acme-signature"] ~= "signed-demo" then
    return {
      action = "reject",
      status = 401,
      headers = { ["content-type"] = "application/json" },
      body = "{\"error\":\"missing or invalid Acme signature\"}"
    }
  end

  return {
    action = "rewrite",
    path = "/tenants/acme/events",
    context = { policy_version = "active", tenant = "acme" }
  }
end

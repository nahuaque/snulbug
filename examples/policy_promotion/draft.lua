return function(request, context)
  if request.headers["x-acme-signature"] ~= "signed-demo-v2" then
    return {
      action = "reject",
      status = 401,
      headers = { ["content-type"] = "application/json" },
      body = "{\"error\":\"missing or invalid Acme v2 signature\"}"
    }
  end

  return {
    action = "rewrite",
    path = "/tenants/acme/events",
    context = { policy_version = "draft", tenant = "acme" }
  }
end

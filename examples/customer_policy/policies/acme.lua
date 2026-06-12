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
    query = { source = "acme-policy" },
    headers = {
      ["x-policy-owner"] = "acme",
      ["x-normalized-webhook"] = "true"
    },
    context = {
      tenant = "acme",
      policy = "customer-owned",
      required_signature = "x-acme-signature"
    }
  }
end

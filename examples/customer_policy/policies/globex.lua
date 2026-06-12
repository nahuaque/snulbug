return function(request, context)
  if request.method ~= "POST" then
    return {
      action = "reject",
      status = 405,
      headers = { allow = "POST" },
      body = "Globex only accepts POST callbacks"
    }
  end

  if request.headers["x-globex-env"] == "sandbox" then
    return {
      action = "respond",
      status = 202,
      headers = { ["content-type"] = "application/json" },
      body = "{\"accepted\":true,\"mode\":\"sandbox\"}"
    }
  end

  return {
    action = "set_context",
    context = {
      tenant = "globex",
      policy = "customer-owned",
      mode = "production"
    }
  }
end

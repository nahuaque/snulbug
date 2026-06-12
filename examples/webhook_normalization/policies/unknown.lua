return function(request, context)
  return {
    action = "reject",
    status = 404,
    headers = { ["content-type"] = "application/json" },
    body = "{\"error\":\"no webhook normalizer installed for this path\"}"
  }
end

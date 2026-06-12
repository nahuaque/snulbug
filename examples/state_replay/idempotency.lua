return function(request, context, state)
  local key = "delivery:" .. request.headers["x-delivery"]

  if state.get(key) ~= nil then
    return { action = "reject", status = 409, body = "duplicate webhook" }
  end

  state.put(key, "seen", { ttl = 86400 })
  return { action = "continue" }
end

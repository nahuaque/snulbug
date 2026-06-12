local function capture(body, pattern)
  return string.match(body, pattern)
end

local function json_escape(value)
  value = tostring(value or "")
  value = string.gsub(value, "\\", "\\\\")
  value = string.gsub(value, "\"", "\\\"")
  return value
end

return function(request, context)
  if request.method ~= "POST" then
    return {
      action = "reject",
      status = 405,
      headers = { allow = "POST" },
      body = "Stripe webhooks must use POST"
    }
  end

  local event_id = capture(request.body, "\"id\"%s*:%s*\"([^\"]+)\"")
  local event_type = capture(request.body, "\"type\"%s*:%s*\"([^\"]+)\"")
  local customer = capture(request.body, "\"customer\"%s*:%s*\"([^\"]+)\"") or ""

  if event_id == nil or event_type == nil then
    return {
      action = "reject",
      status = 422,
      headers = { ["content-type"] = "application/json" },
      body = "{\"error\":\"Stripe payload missing id or type\"}"
    }
  end

  local normalized = string.format(
    "{\"vendor\":\"stripe\",\"event_id\":\"%s\",\"event_type\":\"%s\",\"subject\":\"%s\",\"source_path\":\"%s\"}",
    json_escape(event_id),
    json_escape(event_type),
    json_escape(customer),
    json_escape(request.path)
  )

  return {
    action = "rewrite",
    path = "/webhooks/normalized",
    headers = {
      ["content-type"] = "application/json",
      ["x-webhook-vendor"] = "stripe",
      ["x-normalized-webhook"] = "true"
    },
    body = normalized,
    context = {
      vendor = "stripe",
      event_id = event_id,
      event_type = event_type
    }
  }
end

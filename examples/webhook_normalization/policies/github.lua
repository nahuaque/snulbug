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
      body = "GitHub webhooks must use POST"
    }
  end

  local event_type = request.headers["x-github-event"]
  local delivery = request.headers["x-github-delivery"]
  local repository = capture(request.body, "\"full_name\"%s*:%s*\"([^\"]+)\"") or ""

  if event_type == nil or delivery == nil then
    return {
      action = "reject",
      status = 422,
      headers = { ["content-type"] = "application/json" },
      body = "{\"error\":\"GitHub payload missing event headers\"}"
    }
  end

  local normalized = string.format(
    "{\"vendor\":\"github\",\"event_id\":\"%s\",\"event_type\":\"%s\",\"subject\":\"%s\",\"source_path\":\"%s\"}",
    json_escape(delivery),
    json_escape(event_type),
    json_escape(repository),
    json_escape(request.path)
  )

  return {
    action = "rewrite",
    path = "/webhooks/normalized",
    headers = {
      ["content-type"] = "application/json",
      ["x-webhook-vendor"] = "github",
      ["x-normalized-webhook"] = "true"
    },
    body = normalized,
    context = {
      vendor = "github",
      event_id = delivery,
      event_type = event_type
    }
  }
end

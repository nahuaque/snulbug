# Action reference

Policies return a decision table with an `action` field.

## continue

Call the downstream app.

```lua
return { action = "continue" }
```

## set_context

Merge context into `scope["lua"]`, then continue.

```lua
return { action = "set_context", context = { tenant = "acme" } }
```

## rewrite

Rewrite path, query, headers, or the bounded request body, then continue.

```lua
return {
  action = "rewrite",
  path = "/internal/webhook",
  headers = { ["x-normalized"] = "true" }
}
```

## respond

Send a direct response.

```lua
return { action = "respond", status = 200, body = "ok" }
```

## reject

Send an error response. Defaults to HTTP 403.

```lua
return { action = "reject", status = 403, body = "forbidden" }
```

## challenge

Send a `WWW-Authenticate` challenge.

```lua
return {
  action = "challenge",
  scheme = "Bearer",
  realm = "tenant:acme",
  error = "invalid_token",
  body = "token required"
}
```

## redirect

Send an HTTP redirect.

```lua
return { action = "redirect", status = 307, location = "https://example.com/new" }
```

## rate_limit

Delegate fixed-window rate limiting to middleware state.

```lua
return {
  action = "rate_limit",
  key = "tenant:acme",
  limit = 100,
  window = 60,
  body = "rate limit exceeded"
}
```

# Action reference

Policies return a decision table with an `action` field.

Any decision can also include:

- `reason`: short human-readable explanation for audit logs and live consoles.
- `reason_code`: stable machine-readable code for filtering and tests.

```lua
return {
  action = "reject",
  status = 403,
  body = "forbidden",
  reason = "Tool is outside this session's allowlist",
  reason_code = "session.tool_blocked"
}
```

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

## confirm

Ask an approval broker before continuing. In proxy mode, set `confirm = true`
under `[mcp.proxy]` in `snulbug.toml`. Without an enabled broker, confirmation
fails closed and the request is rejected.

```lua
return {
  action = "confirm",
  prompt = "Allow shell_exec for this session?",
  remember_key = "tool:shell_exec",
  timeout_seconds = 30,
  status = 403,
  body = "confirmation denied",
  reason = "Shell-like tool requires approval",
  reason_code = "mcp.confirm.risky_tool"
}
```

The interactive broker supports allow once, allow for the current proxy session,
or deny. Session approval requires `remember_key`.

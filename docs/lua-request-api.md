# Lua request API

Lua policies return a function:

```lua
return function(request, context, state)
  return { action = "continue" }
end
```

The `request` table contains:

- `method`
- `path`
- `raw_path`
- `query_string`
- `headers`, keyed by lowercase header name
- `client`
- `scheme`
- `body`, when body reading is enabled
- `body_bytes_latin1`, when body reading is enabled

The `context` table is copied from `scope["lua"]` when present. Actions can merge new context into the downstream ASGI scope.

The `state` table is available only when a state store is configured. It exposes `get`, `put`, `delete`, `incr`, and `cas`.

## MCP helpers

The sandbox includes an `mcp` helper table for local-dev MCP gateway policies. Helpers parse the JSON-RPC request body without exposing a general Python JSON API.

```lua
local method = mcp.method(request)
local params = mcp.params(request)
local tool = mcp.tool_name(request)
local call = mcp.call(request)
local path = mcp.arg(call, "path")

if mcp.is_tool_call(request) then
  local blocked = mcp.allow_tools(request, { "safe_read_file", "list_project_files" })
  if blocked ~= nil then
    return blocked
  end
end
```

Available helpers:

- `mcp.body(request)`: parsed JSON-RPC body table, or `nil` for missing/malformed JSON.
- `mcp.call(request)`: normalized JSON-RPC call table with `method`, `params`, `args`, `tool`, `id`, `batch`, `invalid`, `error`, `is_tool_call`, `is_read`, and `is_write` fields.
- `mcp.arg(request_or_call, key)`: read one tool/prompt argument from a request or normalized call.
- `mcp.arg_keys(request_or_call)`: sorted list of observed tool/prompt argument keys.
- `mcp.method(request)`: JSON-RPC method string, or `nil`.
- `mcp.params(request)`: JSON-RPC params table, or an empty table.
- `mcp.is_method(request, method)`: true when the request method matches.
- `mcp.is_tool_call(request)`: true for `tools/call`.
- `mcp.tool_name(request)`: `params.name` for `tools/call`, or `nil`.
- `mcp.tool_allowed(request, allowed)`: true when the request is not a tool call or the tool is allowed.
- `mcp.allow_tools(request, allowed, options)`: returns `nil` when allowed, otherwise a `reject` decision.
- `mcp.reject_tool(request_or_name, status, body, options)`: builds a standard tool rejection decision.

`allowed` can be an array, such as `{ "read_file" }`, or a map, such as `{ read_file = true }`.
`options.reason` and `options.reason_code` can override the default
`mcp.tool_not_allowed` reason metadata.

## Decision helpers

The sandbox includes a `decision` table for building supported middleware
actions without repeating raw table shapes:

```lua
return function(request, context)
  local call = mcp.call(request)
  return decision.reject(403, "tool blocked", {
    reason_code = "mcp.tool_not_allowed",
    context = { tool = call.tool }
  })
end
```

Available builders:

- `decision.continue(options)`: continue to the upstream app.
- `decision.allow(reason_code, context)`: continue with optional decision metadata.
- `decision.set_context(context, options)`: merge context into the downstream ASGI scope.
- `decision.respond(status, body, options)`: return a response directly.
- `decision.reject(status, body, options)`: reject before reaching the upstream.
  Set `options.confirm = true` to route the rejection through the same approval
  broker used by `decision.confirm`.
- `decision.challenge(options)`: build an auth challenge.
- `decision.redirect(location, options)`: build a redirect.
- `decision.rate_limit(key, limit, window, options)`: invoke configured bounded policy state.
- `decision.confirm(prompt, options)`: ask the live decision console for approval.

`options` can include `reason`, `reason_code`, `context`, and `headers` where
the underlying action supports them. Confirmation options such as `prompt`,
`remember_key`, and `timeout_seconds` are also available for `decision.confirm`
and confirmable `decision.reject` results.

## Capability guards

The `cap` table provides small guard helpers that return `nil` when allowed or
a standard rejection decision when blocked. This makes policies read as a
short-circuit chain:

```lua
return function(request, context)
  local call = mcp.call(request)
  return cap.method(request, { "tools/call" })
    or cap.tool(request, { "safe_read_file" })
    or cap.arg_path(call, "path", { "README.md", "docs" })
    or decision.allow("mcp.allowed", { tool = call.tool })
end
```

Available guards:

- `cap.allowed(value, allowed)`: boolean membership check for array or map allowlists.
- `cap.method(request_or_method, allowed, options)`: allow listed JSON-RPC methods.
- `cap.tool(request_or_name, allowed, options)`: allow listed MCP tools; non-tool calls pass through.
- `cap.arg_string(request_or_call, key, options)`: require a non-empty string argument.
- `cap.arg_path(request_or_call, key, allowed_paths, options)`: require a relative path argument under listed roots.
- `cap.arg_host(request_or_call, key, allowed_hosts, options)`: require a URL/host argument matching listed hosts.
- `cap.arg_command(request_or_call, key, allowed_commands, options)`: require a shell-like command argument whose first token is allowed.
- `cap.path(path, allowed_paths, options)`: allow non-absolute, non-traversing relative paths under listed roots.
- `cap.host(url_or_host, allowed_hosts, options)`: allow listed hosts, including `*.example.com` suffix entries.
- `cap.command(command, allowed_commands, options)`: allow shell-like command strings by first token.

Every `cap.*` rejection and `mcp.allow_tools` supports confirmation options:

```lua
return cap.tool(request, { "files.read_file" }, {
  confirm = true,
  prompt = "Allow unlisted tool once?",
  remember_key = "tool:" .. tostring(mcp.tool_name(request)),
  timeout_seconds = 30,
  reason_code = "mcp.policy.tool_rejected"
})
```

## OAuth Auth Helpers

When `[mcp.auth]` runs in OAuth protected-resource mode, Lua policies also get
a request-scoped `auth` helper table. The helper reads the sanitized auth
context produced by the proxy; it never exposes the raw bearer token.

```lua
return function(request, context)
  local wrong_tenant = auth.require_tenant("tenant-a", {
    reason_code = "oauth.tenant_required"
  })
  if wrong_tenant then
    return wrong_tenant
  end

  local missing_group = auth.require_group({ "platform-dev", "mcp-admins" }, {
    reason_code = "oauth.platform_group_required"
  })
  if missing_group then
    return missing_group
  end

  local denied = auth.require("tools/call:git.status", {
    reason_code = "oauth.git_status_scope_required"
  })
  if denied then
    return denied
  end

  return decision.allow("mcp.allowed", {
    subject = auth.subject(),
    tenant = auth.tenant(),
    groups = auth.groups(),
    client_id = auth.client_id(),
  })
end
```

Available helpers:

- `auth.claims()`: return the sanitized `context.auth` table.
- `auth.subject()`: return the JWT subject claim.
- `auth.client_id()`: return `azp` or `client_id` when present.
- `auth.email()`: return the token email claim when present.
- `auth.tenant()`: return `tid` or `tenant` when present.
- `auth.groups()`: return token groups as an array.
- `auth.is_subject(subject_or_subjects)`: true when the token subject matches
  a string or one entry in an array.
- `auth.in_tenant(tenant_or_tenants)`: true when the token tenant matches a
  string or one entry in an array.
- `auth.has_group(group_or_groups)`: true when any required group is present.
- `auth.scopes()`: return the token scopes as an array.
- `auth.has_scope(scope)`: true when the token includes `scope`.
- `auth.can(selector)`: true when the token has a scope mapped to an MCP
  selector such as `tools/list` or `tools/call:git.status`.
- `auth.require_subject(subject_or_subjects, options)`: return `nil` when the
  subject matches, otherwise a 403 reject.
- `auth.require_tenant(tenant_or_tenants, options)`: return `nil` when the
  tenant matches, otherwise a 403 reject.
- `auth.require_group(group_or_groups, options)`: return `nil` when any group
  matches, otherwise a 403 reject.
- `auth.require_scope(scope, options)`: return `nil` when present, otherwise a
  `decision.challenge` with `error = "insufficient_scope"`.
- `auth.require(selector, options)`: return `nil` when `auth.can(selector)` is
  true, otherwise a `decision.challenge`.

`auth.can` uses the same `[mcp.auth.scope_map]` selectors enforced by the
proxy, so Lua policy and pre-Lua OAuth enforcement stay aligned.
Use `[mcp.auth.claim_policy]` when tenant, subject, group, client ID, or custom
JWT claims can be mapped to allowed tool names declaratively; Lua still receives
`context.auth.claim_policy` for audit/context-aware follow-up decisions.
When `[[mcp.auth.issuers]]` profiles are configured, Lua receives the selected
profile as `context.auth.profile_id`.
Use the subject, tenant, and group helpers for identity fences inside a share:
for example, "only members of `platform-dev` in `tenant-a` may call this
write-capable tool." These helpers read sanitized claims only; raw bearer
tokens are never exposed to Lua.

## Task Lease Helpers

When `mcp.proxy.lease_file` is configured, Lua policies also get a non-consuming
lease preview in `context.lease` and a `lease` helper table. The preview checks
the presented `x-snulbug-lease` token before Lua runs, but the lease is consumed
only later if the request reaches the upstream.

```lua
return function(request, context)
  local denied = lease.require({
    reason_code = "lease.active_task_lease_required"
  })
  if denied then
    return denied
  end

  return decision.allow("mcp.allowed", {
    lease_id = lease.id(),
    lease_task = lease.task(),
  })
end
```

Available helpers:

- `lease.info()`: return the sanitized `context.lease` table.
- `lease.enabled()`: true when a lease file is configured.
- `lease.required()`: true when `lease_required = true`.
- `lease.checked()`: true when a presented lease token was checked.
- `lease.allowed()` / `lease.active()`: true when the presented lease covers
  the current `tools/call`.
- `lease.id()`: return the matched lease id.
- `lease.task()`: return the matched lease task label.
- `lease.reason_code()`: return the lease denial reason, such as
  `lease.missing`, `lease.path_not_allowed`, or
  `lease.subject_not_allowed`.
- `lease.require(options)`: return `nil` when no lease is needed or the active
  lease covers the request, otherwise a `decision.reject`.

For auth-bound leases, `lease.info()` / `context.lease` also includes:

- `auth_bound`: true when the matched lease has OAuth identity constraints.
- `auth`: sanitized OAuth fields used for the binding check, such as
  `subject`, `issuer`, `tenant`, `client_id`, `groups`, and `profile_id`.

Auth-bound lease denials use reason codes such as `lease.auth_missing`,
`lease.subject_not_allowed`, `lease.issuer_not_allowed`,
`lease.tenant_not_allowed`, `lease.client_id_not_allowed`,
`lease.group_not_allowed`, and `lease.auth_profile_not_allowed`.

For public shares, the intended composition is: valid OAuth subject, required
MCP scopes, active snulbug task lease, and Lua policy approval.

# Lua Policy Reference

This is the exhaustive reference for the Lua helpers available inside Snulbug
policies. If you are writing a policy from scratch, start with the
[Lua Policy DSL guide](lua-policy-dsl.md), then return here for exact helper
names, arguments, and decision fields.

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

## Intent Helpers

The `intent` table exposes schema-aware MCP tool capability and risk metadata.
When the reverse proxy has seen a `tools/list` response, snulbug classifies the
called tool using its cached `inputSchema`. Without cached schema metadata,
helpers fall back to deterministic tool-name inference.

```lua
return function(request)
  return intent.require_max_risk("medium")
    or intent.confirm_if({ "filesystem.write", "network.egress" })
    or decision.allow("mcp.intent_allowed", {
      tool = intent.name(),
      risk = intent.risk(),
      categories = intent.categories()
    })
end
```

Available helpers:

- `intent.info()`: return the current intent metadata table. Fields can include
  `name`, `level`, `score`, `categories`, `signals`, `schema`, `source`, and
  `confidence`.
- `intent.name()`: current MCP tool name, or `nil` for non-tool calls.
- `intent.category()`: first normalized category, or `nil`.
- `intent.categories()`: normalized category list. This includes classifier
  categories such as `command`, `mutation`, `network`, `filesystem`, `secrets`,
  `read`, `open-schema`, and `schema-drift`, plus policy-friendly aliases such
  as `shell.exec`, `network.egress`, `filesystem.read`,
  `filesystem.write`, `git.read`, `git.write`, `secrets.access`, `read`, and
  `write`.
- `intent.risk()`: risk level, usually `low`, `medium`, or `high`.
- `intent.risk_score()`: numeric risk score.
- `intent.has_category(category_or_categories)`: true when any current
  category matches. Wildcards such as `filesystem.*` are supported.
- `intent.require_category(category_or_categories, options)`: return `nil`
  when matched, otherwise reject with `reason_code =
  "mcp.intent_category_denied"`.
- `intent.require_max_risk(level, options)`: return `nil` when the current risk
  is at or below `level`, otherwise reject with `reason_code =
  "mcp.intent_risk_denied"`.
- `intent.block_if(category_or_categories, options)`: reject when the current
  intent matches one of the supplied categories. Default `reason_code` is
  `mcp.intent_blocked`.
- `intent.confirm_if(category_or_categories, options)`: return a confirmation
  decision when the current intent matches one of the supplied categories.
  Default `reason_code` is `mcp.intent_confirmation_required`.

Intent decisions include sanitized context such as tool, risk, risk score,
categories, source, confidence, and any required or blocked category. The raw
schema document is not added to decision context unless the policy explicitly
copies fields from `intent.info().schema`.

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
  If `options.capability_request` is present and confirmation is denied or
  unavailable, snulbug returns an MCP JSON-RPC error with structured
  `error.data.capability_request`.

`options` can include `reason`, `reason_code`, `context`, and `headers` where
the underlying action supports them. Confirmation options such as `prompt`,
`remember_key`, and `timeout_seconds` are also available for `decision.confirm`
and confirmable `decision.reject` results.

## Access Reason Builders

The `access` table builds standardized auth and lease denials for Lua policies.
Use these when a policy is enforcing identity, scope, lease, or route checks and
you want audit logs, replay diffs, and reports to use consistent reason codes:

```lua
local denied = auth.require("tools/call:git.status")
  or auth.require_tenant("tenant-a")
  or auth.require_group("platform-dev")
  or lease.require()
if denied then
  return denied
end
```

Available builders:

- `access.missing_scope(scope, options)`: `decision.challenge` with
  `reason_code = "oauth.missing_scope"` and `error = "insufficient_scope"`.
- `access.scope_denied(selector, options)`: `decision.challenge` with
  `reason_code = "oauth.scope_map_denied"`.
- `access.wrong_subject(subject_or_subjects, options)`: `decision.reject` with
  `reason_code = "oauth.subject_denied"`.
- `access.wrong_tenant(tenant_or_tenants, options)`: `decision.reject` with
  `reason_code = "oauth.tenant_denied"`.
- `access.wrong_group(group_or_groups, options)`: `decision.reject` with
  `reason_code = "oauth.group_denied"`.
- `access.lease_required(options)`: `decision.reject` with the current lease
  reason code, or `lease.required` when no more specific lease reason exists.
- `access.expired_lease(options)`: `decision.reject` with
  `reason_code = "lease.expired"`.
- `access.contract_required(options)`: `decision.reject` with
  `reason_code = "share.contract_required"` when a policy requires a bound
  share contract.
- `access.contract_mismatch(details, options)`: `decision.reject` with
  `reason_code = "share.contract_mismatch"` when a policy requires a specific
  contract digest or signer key id.
- `access.route_mismatch(details, options)`: `decision.reject` with
  `reason_code = "access.route_mismatch"` for tenant/upstream/facade route
  fences.

`auth.require_scope`, `auth.require`, `auth.require_subject`,
`auth.require_tenant`, `auth.require_group`, and `lease.require` use these
builders by default. `options.context` is merged into the standard context, and
`options.body`, `options.reason`, and `options.reason_code` can still override
the emitted decision when a policy needs a local code.

## Share Contract Helpers

When `snulbug mcp share run` starts with `--require-contract`, the proxy binds
the approved share contract, exposes it at the snulbug well-known endpoints,
and passes safe contract metadata into Lua as `context.share`. The sandbox also
includes a `share` helper table for policies that want to enforce that runtime
binding:

```lua
return function(request, context)
  return share.require_contract_bound()
    or share.require_contract_key_id("local-review")
    or decision.allow("share.contract_bound", {
      contract_digest = share.contract_digest()
    })
end
```

Available helpers:

- `share.info()`: return the sanitized `context.share` table.
- `share.bound()`: true when a runtime contract is bound and has a digest.
- `share.required()`: true when the share was started with a required contract.
- `share.signed()`: true when the bound contract includes a snulbug signature.
- `share.verified()`: true when snulbug verified the runtime contract before
  binding it.
- `share.runtime_status()`: runtime binding status, such as `bound`.
- `share.contract_digest()`: stable binding digest used in audit metadata.
- `share.binding_digest()`: binding digest, falling back to
  `share.contract_digest()`.
- `share.document_digest()`: document digest for the approved contract JSON.
- `share.key_id()`: signer key id from the approved contract.
- `share.require_contract_bound(options)`: return `nil` when bound, otherwise
  `access.contract_required`.
- `share.require_contract_digest(digest_or_digests, options)`: return `nil`
  when the runtime digest matches, otherwise `access.contract_mismatch`.
- `share.require_contract_key_id(key_or_keys, options)`: return `nil` when the
  signer key id matches, otherwise `access.contract_mismatch`.

These helpers do not expose the raw contract document, bearer tokens, lease
tokens, or upstream credentials. They are intended for policies that need to
fail closed unless a human-reviewed contract is the exact one currently
running.

## Upstream Route Helpers

In facade/fabric mode, Lua policies receive a pre-routing preview as
`context.upstream` plus an `upstream` helper table. This lets a policy bind
OAuth identity to a specific upstream route or fabric member before the request
is forwarded:

```lua
local wrong_route = upstream.require_for_tenant({
  ["tenant-a"] = { "files" },
  ["tenant-b"] = { "git" }
})
if wrong_route then
  return wrong_route
end
```

Available helpers:

- `upstream.info()`: return the sanitized `context.upstream` table.
- `upstream.matched()`: true when the facade route matched the request.
- `upstream.name()`: selected upstream/fabric member name for a routed call.
- `upstream.transport()`: selected upstream transport, such as `http`,
  `stdio`, or `holepunch`.
- `upstream.tool_prefix()`: client-facing facade tool prefix.
- `upstream.tool()`: client-facing tool name, such as `git.status`.
- `upstream.upstream_tool()`: upstream-local tool name after prefix removal.
- `upstream.manifest_identity()`: signed upstream manifest identity when
  configured.
- `upstream.is(upstream_or_upstreams)`: true when the selected upstream matches
  a string or one entry in an array.
- `upstream.require(upstream_or_upstreams, options)`: return `nil` when the
  selected upstream is allowed, otherwise `access.route_mismatch`.
- `upstream.require_for_tenant(map, options)`: use `auth.tenant()` as a key in
  `map`, then require the selected upstream to match that value.
- `upstream.require_for_issuer(map, options)`: use `auth.issuer()` as a key.
- `upstream.require_for_auth_profile(map, options)`: use `auth.profile_id()` as
  a key.

Identity maps can use strings or arrays as values:

```lua
upstream.require_for_issuer({
  ["https://tenant-a-idp.example.com"] = { "tenant-a-files", "tenant-a-git" },
  ["https://tenant-b-idp.example.com"] = "tenant-b-files",
  ["*"] = "public-readonly"
})
```

These helpers expose route metadata needed for policy: upstream name,
transport, tool prefix, selected tool, manifest identity/metadata, bridge peer
metadata, and route revision/fingerprint. They do not expose upstream
credentials.

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
- `cap.request(request, options)`: build a confirmation-backed, MCP-native
  just-in-time capability request. It suggests a normal snulbug task lease
  using `allow_tools`, `allow_paths`, `allow_hosts`, `allow_commands`, `ttl`,
  `max_calls`, and `task`.

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

Use `cap.request` when the right next step is a lease review rather than a
hard deny:

```lua
return cap.request(request, {
  task = "Read project docs",
  ttl = "10m",
  max_calls = 2,
  allow_paths = { "README.md", "docs" },
  remember_key = "cap:" .. tostring(mcp.tool_name(request)),
  reason_code = "mcp.docs_capability_requested"
})
```

## Workspace Firewall Helpers

The `workspace` table provides higher-level local-dev filesystem guards for
MCP tools that accept project path arguments. The helpers inspect the current
MCP request, so policies can stay terse:

```lua
return function(request, context)
  return workspace.require_under_project("path")
    or workspace.block_secret_paths("path")
    or workspace.block_generated_paths("path")
    or workspace.readonly_only()
    or decision.allow("mcp.workspace_allowed")
end
```

Available guards:

- `workspace.require_under_project(arg_key_or_keys, options)`: require matching
  path arguments to be relative project paths with no absolute paths, home-dir
  paths, drive-letter paths, or parent traversal. By default this allows any
  relative project path; pass `options.allowed_paths`, `options.roots`, or
  `options.project_paths` to constrain paths to selected roots.
- `workspace.block_secret_paths(arg_key_or_keys, options)`: block
  secret-looking paths such as `.env`, `.env.*`, `.ssh/`, `.gnupg/`,
  `secrets/`, `.kube/config`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.crt`,
  and `*.cert`.
- `workspace.block_generated_paths(arg_key_or_keys, options)`: block generated
  or cache paths such as `.git/`, `.snulbug/`, `.venv/`, `venv/`,
  `node_modules/`, `__pycache__/`, `.ruff_cache/`, `.pytest_cache/`,
  `.mypy_cache/`, `dist/`, `build/`, and `coverage/`. Set
  `options.write_only = true` to apply this only to write-like tool names.
- `workspace.readonly_only(options)`: allow read-oriented MCP methods and
  reject write-like tool calls such as names containing `write`, `edit`,
  `create`, `delete`, `rename`, `patch`, `append`, `mkdir`, `rm`, `touch`, or
  `save`.

`arg_key_or_keys` can be a string, an array, a map, or `nil`. When it is `nil`,
the helpers inspect common path-like argument names such as `path`, `paths`,
`file`, `directory`, `cwd`, `source`, `destination`, `target`, `oldpath`, and
`newpath`.

Supporting helpers:

- `workspace.write_intent()`: true when the current tool name looks write-like.
- `workspace.path_values(arg_key_or_keys)`: return matching raw argument values.
- `workspace.path_summary(arg_key_or_keys, options)`: return one sanitized
  summary table with `argument`, `path`, `path_class`, and `write_intent`.

Workspace guard rejections use stable reason codes such as
`mcp.workspace_path_invalid`, `mcp.workspace_path_outside`,
`mcp.workspace_secret_blocked`, `mcp.workspace_generated_path_blocked`, and
`mcp.workspace_readonly_required`. `options.context`, `options.reason`,
`options.reason_code`, and confirmation fields can override or extend the
standard decision.

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
- `auth.issuer()`: return the JWT issuer claim.
- `auth.profile_id()`: return the matched `[[mcp.auth.issuers]]` profile id.
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
- `auth.require_scope(scope, options)`: return `nil` when present, otherwise
  `access.missing_scope(scope, options)`.
- `auth.require(selector, options)`: return `nil` when `auth.can(selector)` is
  true, otherwise `access.scope_denied(selector, options)`.

Provider-aware helpers read normalized claim shapes from `context.auth.provider`
so policies do not need to know each provider's raw JWT/header layout:

- Keycloak:
  - `auth.keycloak_realm_roles()`: return realm roles from
    `realm_access.roles`.
  - `auth.keycloak_client_roles(client_id)`: return roles from
    `resource_access[client_id].roles`.
  - `auth.keycloak_has_role(role, client_id)`: true when the role is present;
    omit `client_id` to check realm roles and all client role sets.
- Cloudflare Access:
  - `auth.cloudflare_email()`: return the normalized Access email. When
    assertion validation is enabled, this comes from the signed JWT claim;
    otherwise it comes from the Access email header.
  - `auth.cloudflare_jwt_validated()`: true when the Access assertion was
    cryptographically validated by the proxy.
  - `auth.cloudflare_subject()`: return the validated Access JWT subject when
    available.
  - `auth.cloudflare_groups()`: return normalized Access groups.
  - `auth.cloudflare_has_group(group_or_groups)`: true when any group matches.
- GitHub Actions OIDC:
  - `auth.github_repository()`, `auth.github_workflow()`,
    `auth.github_workflow_ref()`, `auth.github_job_workflow_ref()`,
    `auth.github_ref()`, and `auth.github_event_name()`: return normalized
    GitHub Actions claims.
  - `auth.github_matches(options)`: true when all supplied fields match. It
    accepts `repository`, `repository_owner`, `workflow`, `workflow_ref`,
    `job_workflow_ref`, `ref`, `event_name`, `actor`, and `environment`.
- Entra:
  - `auth.entra_groups()`: return Entra group IDs from `groups`.
  - `auth.entra_has_group(group_or_groups)`: true when any group matches.
  - `auth.entra_app_roles()`: return app roles from `roles`.
  - `auth.entra_has_app_role(role_or_roles)`: true when any app role matches.
  - `auth.entra_tenant_id()` and `auth.entra_app_id()`: return `tid` and
    `appid`/`azp`/`client_id`.

```lua
local denied = nil
if not auth.keycloak_has_role("mcp-admin") then
  denied = access.wrong_group("mcp-admin", {
    reason_code = "oauth.keycloak_role_required"
  })
end
if denied then
  return denied
end

if not auth.github_matches({
  repository = "acme/widget",
  ref = "refs/heads/main",
  event_name = "workflow_dispatch"
}) then
  return access.wrong_subject("github-actions-main", {
    reason_code = "oauth.github_actions_ref_denied"
  })
end
```

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
    lease_capabilities = lease.capabilities(),
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
- `lease.capabilities()`: return temporary capability labels attached to the
  lease, such as `project_readonly` or `docs_review`.
- `lease.has_capability(name)`: true when the active lease includes that label.
- `lease.reason_code()`: return the lease denial reason, such as
  `lease.missing`, `lease.path_not_allowed`, or
  `lease.subject_not_allowed`.
- `lease.require(options)`: return `nil` when no lease is needed or the active
  lease covers the request, otherwise a standardized `access.lease_required`
  or `access.expired_lease` rejection.

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

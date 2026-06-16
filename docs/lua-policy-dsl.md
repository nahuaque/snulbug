# Lua Policy DSL

Snulbug policies are small Lua programs that sit between an MCP client and one
or more upstream MCP servers. A good policy reads like a chain of gates:

```lua
return function(request, context, state)
  local call = mcp.call(request)

  return auth.require("tools/call:" .. tostring(call.tool))
    or lease.require()
    or workspace.require_under_project({ "path", "cwd" })
    or workspace.block_secret_paths({ "path", "cwd" })
    or decision.allow("mcp.allowed", {
      tool = call.tool,
      subject = auth.subject(),
      lease_id = lease.id()
    })
end
```

Each guard returns `nil` when the request is allowed to keep moving. The first
non-`nil` decision stops the chain and becomes the proxy decision.

## Contents

- [When To Use Lua](#when-to-use-lua)
- [Policy Shape](#policy-shape)
- [Helper Families](#helper-families)
- [Core Patterns](#core-patterns)
- [Decision Style](#decision-style)
- [Policy Style Guide](#policy-style-guide)
- [Test Loop](#test-loop)
- [More Examples](#more-examples)

## When To Use Lua

Use Lua for request-specific policy that needs a little logic:

- allow this tool only for this tenant, group, lease, upstream, or project path
- block secret-looking file paths and generated directories
- ask for one-time confirmation before a risky tool call
- bind OAuth claims to MCP tool names and facade routes
- add stable reason codes and audit context that explain the decision

Prefer config when the rule is declarative:

- OAuth issuer, audience, JWKS, and scope validation
- claim-to-tool allowlists with `[mcp.auth.claim_policy]`
- upstream credentials and anti-passthrough behavior
- event sinks, recording, schema validation, and tool pinning
- policy bundle lifecycle and share session wiring

## Policy Shape

Every policy returns a function:

```lua
return function(request, context, state)
  return decision.continue()
end
```

The function receives:

| Argument | Purpose |
| --- | --- |
| `request` | HTTP request data plus bounded body fields when body reading is enabled. |
| `context` | Sanitized proxy metadata such as auth, lease, share, tunnel, upstream, and fabric context. |
| `state` | Optional bounded state adapter with `get`, `put`, `delete`, `incr`, and `cas`. |

For MCP proxy work, prefer the helper tables over raw request parsing.

## Helper Families

| Helper | Use It For |
| --- | --- |
| `mcp.*` | Parse JSON-RPC/MCP method, tool name, params, arguments, and read/write hints. |
| `decision.*` | Build supported actions with consistent metadata. |
| `cap.*` | Compact allowlists for methods, tools, path args, hosts, and command args. |
| `workspace.*` | Local-dev filesystem safety rules for project paths, secrets, generated files, and read-only shares. |
| `auth.*` | OAuth subject, issuer, tenant, group, scope, provider, and scope-map checks. |
| `lease.*` | Task-scoped capability leases and auth-bound lease checks. |
| `upstream.*` | Facade/fabric route checks for selected upstreams and fabric members. |
| `share.*` | Runtime share contract binding checks. |
| `access.*` | Standardized denial/challenge reason builders. |

See the [Lua policy reference](lua-request-api.md) for every function and field.

## Core Patterns

### Tool Allowlist

```lua
return function(request)
  return mcp.allow_tools(request, {
    "safe_read_file",
    "list_project_files"
  }) or decision.allow("mcp.tool_allowed", {
    tool = mcp.tool_name(request)
  })
end
```

Use this for simple MCP shares or as the first gate in a larger policy.

### Workspace Firewall

```lua
return function(request)
  return cap.tool(request, { "filesystem.read_file", "filesystem.list" })
    or workspace.require_under_project({ "path", "directory", "cwd" })
    or workspace.block_secret_paths({ "path", "directory", "cwd" })
    or workspace.block_generated_paths({ "path", "directory", "cwd" })
    or workspace.readonly_only()
    or decision.allow("mcp.workspace_allowed", {
      path = workspace.path_summary({ "path", "directory", "cwd" })
    })
end
```

This is the default shape for an agent workspace firewall. It blocks absolute
paths, parent traversal, home-directory paths, secret material, generated
directories, and write-like tools.

### OAuth Plus Lease

```lua
return function(request)
  local call = mcp.call(request)

  return auth.require("tools/call:" .. tostring(call.tool))
    or auth.require_tenant("tenant-a")
    or auth.require_group({ "platform-dev", "mcp-admins" })
    or lease.require({
      reason_code = "lease.active_task_lease_required"
    })
    or decision.allow("mcp.identity_and_lease_allowed", {
      tool = call.tool,
      subject = auth.subject(),
      tenant = auth.tenant(),
      lease_id = lease.id()
    })
end
```

This is the public-share model: valid OAuth token, matching MCP scope, active
task lease, and Lua policy approval.

### Upstream-Aware Facade

```lua
return function(request)
  return upstream.require_for_tenant({
    ["tenant-a"] = { "tenant-a-files", "tenant-a-git" },
    ["tenant-b"] = "tenant-b-files",
    ["*"] = "public-readonly"
  }) or decision.allow("mcp.route_allowed", {
    upstream = upstream.name(),
    tool = upstream.tool(),
    tenant = auth.tenant()
  })
end
```

Use this when one Snulbug facade composes several MCP servers and identity must
stay bound to the right upstream route.

### Human Confirmation

```lua
return function(request)
  if mcp.tool_name(request) == "git.push" then
    return decision.confirm("Allow git.push for this session?", {
      remember_key = "tool:git.push:" .. tostring(auth.subject()),
      timeout_seconds = 30,
      reason_code = "mcp.confirm.git_push"
    })
  end

  return decision.allow("mcp.allowed")
end
```

Confirmation is useful for risky-but-legitimate tool calls during an agent
session. Prefer stable `remember_key` values so repeated approvals are clear.

### Bounded State

This pattern requires a configured state adapter.

```lua
return function(request, context, state)
  if state == nil then
    return decision.reject(500, "policy state is not configured", {
      reason_code = "mcp.state_required"
    })
  end

  local subject = auth.subject() or "anonymous"
  local key = "calls:" .. subject .. ":" .. tostring(mcp.tool_name(request))
  local count = state.incr(key, 1, { ttl = 60 })

  if count > 30 then
    return decision.reject(429, "tool call rate limit exceeded", {
      reason_code = "mcp.rate_limited",
      context = { subject = subject, window_seconds = 60 }
    })
  end

  return decision.allow("mcp.rate_limit_ok")
end
```

Keep state small, bounded, and advisory. For shared runtime state, configure a
backing store instead of relying on per-process memory.

## Decision Style

Use a stable reason code for every meaningful outcome:

```lua
return decision.reject(403, "tenant denied", {
  reason_code = "oauth.tenant_denied",
  context = {
    expected_tenant = "tenant-a",
    actual_tenant = auth.tenant()
  }
})
```

Reason codes are the connective tissue between live console output, audit JSONL,
replay logs, policy diffs, share reports, and CI gates. Good codes are:

- stable: `mcp.workspace_secret_blocked`, not `blocked_thing_2`
- specific: `oauth.github_actions_ref_denied`, not `auth_failed`
- product-shaped: `share.contract_mismatch`, `lease.subject_not_allowed`
- safe: never include raw tokens, secrets, or full sensitive paths in the code

## Policy Style Guide

1. Put coarse gates first: method, tool, auth, lease, route.
2. Put data-sensitive gates next: path, host, command, workspace helpers.
3. End with `decision.allow(...)`; do not rely on implicit fallthrough.
4. Prefer `auth.require`, `lease.require`, `upstream.require`, and
   `workspace.*` over hand-rolled parsing.
5. Keep raw headers and raw bodies out of policy logic unless the policy is
   specifically about HTTP adaptation.
6. Emit sanitized context that helps the next human understand the decision.
7. Use confirmation for exceptional risk, not as a substitute for policy.
8. Keep state bounded and avoid long-running computation.

## Test Loop

Start from a preset, record evidence, and replay before sharing:

```bash
uv run snulbug mcp policy preset tunnel-safe --output policy.snulbug
uv run snulbug mcp evidence record policy.snulbug/policy.lua request.json --out traces/session.jsonl
uv run snulbug mcp evidence replay traces/session.jsonl
uv run snulbug mcp evidence impact traces/session.jsonl --policy policy.snulbug/policy.lua
```

For share sessions, use the share workflow:

```bash
uv run snulbug mcp share create --provider ngrok --upstream http://127.0.0.1:9000
uv run snulbug mcp share run .snulbug/shares/share-...
uv run snulbug mcp share status .snulbug/shares/share-...
uv run snulbug mcp share report .snulbug/shares/share-...
```

## More Examples

- [Lua policy reference](lua-request-api.md)
- [MCP presets](mcp-presets.md)
- [Policy workflow](mcp-policy.md)
- [Evidence workflow](mcp-evidence.md)
- [Provider-aware policy templates](../examples/provider_policy_templates/README.md)
- [OAuth claim-policy examples](../examples/auth_claim_patterns/README.md)
- [Workspace firewall preset](../snulbug/builtin_presets/mcp/workspace-firewall.snulbug/README.md)

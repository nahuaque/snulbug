# Policy Deny Backoff

Policy deny backoff protects a shared local-dev MCP gateway from repeated
equivalent blocked calls. When a Lua policy rejects or challenges the same
subject/tool/route shape repeatedly, snulbug can return a short cooldown
response before Lua runs and before the upstream is reached.

This is intentionally not a sleep or queue inside the proxy. The first deny is
recorded in the configured policy state store. Later matching requests during
the cooldown are rejected immediately with `429` and `Retry-After`.

## Configuration

Enable it in `snulbug.toml`:

```toml
[mcp.proxy]
state = "sqlite:policy-state.sqlite3"

[mcp.policy_backoff]
enabled = true
base_seconds = 2
factor = 2.0
max_seconds = 60
window_seconds = 300
jitter = true
status = 429
reason_codes = ["mcp.*", "oauth.scope_map_denied", "lease.tool_not_allowed"]
exclude_reason_codes = ["oauth.invalid_token", "cloudflare_access.*"]
key_fields = [
  "auth.subject",
  "auth.client_id",
  "auth.tenant",
  "lease.id",
  "mcp.method",
  "mcp.tool",
  "mcp.target",
  "upstream.name",
  "decision.reason_code",
]
```

Use SQLite when you want cooldowns to survive a proxy restart. Use Redis when
multiple proxy workers or hosts should share the same cooldown state. In-memory
state is fine for a single local demo process.

## What Counts As Equivalent

The backoff key is built from `key_fields`. By default it distinguishes:

- the authenticated subject, client ID, and tenant when present
- the active task lease when present
- the MCP method, tool name, or resource target
- the selected upstream/fabric member
- the policy denial reason code

If no auth identity is available, snulbug falls back to the client IP so
anonymous repeated denies do not all collapse into a single global cooldown.

## Selected Denies

Only Lua `reject` and `challenge` decisions are eligible. Defaults include MCP
policy denies, scope-map denies, and lease tool-denies. Defaults exclude invalid
OAuth tokens and Cloudflare Access failures because those are usually better
handled by the identity provider or tunnel edge.

Lua policies should emit stable `reason_code` values for this feature to be
useful:

```lua
if mcp.tool_name(request) == "shell.exec" then
  return decision.reject(403, "shell execution is not allowed", {
    reason_code = "mcp.tool_not_allowed"
  })
end
```

## Runtime Behavior

The first selected deny returns the Lua policy response with advisory headers:

```text
x-snulbug-backoff-count: 1
x-snulbug-backoff-retry-after: 2
x-snulbug-backoff-reason: mcp.tool_not_allowed
```

During the cooldown, matching requests return without running Lua or touching
the upstream:

```text
HTTP/1.1 429 Too Many Requests
retry-after: 2
x-snulbug-backoff-count: 1
x-snulbug-backoff-reason: mcp.tool_not_allowed
```

Audit and replay records include `metadata.policy_backoff`, so session reports
and external event sinks can distinguish original policy denies from cooldown
short-circuits.

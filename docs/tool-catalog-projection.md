# Policy-aware tool catalog projection

Tool catalog projection filters `tools/list` responses before they reach the MCP
client. With projection enabled, snulbug still asks upstreams for their full tool
catalog, but the client only sees tools it can plausibly invoke under the active
gateway controls.

Enable it with:

```toml
[mcp.catalog]
projection = "policy-aware"
```

The first projection slice applies declarative gates that are already enforced on
tool calls:

- OAuth scope maps from `[mcp.auth.scope_map]`
- declarative claim-policy rules from `[mcp.auth.claim_policy]`
- active task leases from `mcp.proxy.lease_file`

For example:

```toml
[mcp.catalog]
projection = "policy-aware"

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
"mcp:tool.files.read" = ["tools/call:files.read_file"]
"mcp:tool.git.status" = ["tools/call:git.status"]
```

A caller with `mcp:tools.read mcp:tool.files.read` can list the catalog, but only
`files.read_file` remains visible. `git.status` is hidden because the caller
does not have a scope that matches `tools/call:git.status`.

When `lease_required = true`, `tools/list` is not rejected just because the lease
is missing. Instead, projection returns an empty visible catalog. With a valid
lease, only tools listed in the lease `allow_tools` grant remain visible.

Audit and replay records include `metadata.catalog_projection`:

```json
{
  "enabled": true,
  "projection": "policy-aware",
  "original_tool_count": 2,
  "visible_tool_count": 1,
  "hidden_tool_count": 1,
  "hidden_reason_counts": {
    "oauth.scope_map_denied": 1
  },
  "hidden_tools": [
    {"name": "git.status", "reason_code": "oauth.scope_map_denied"}
  ]
}
```

Projection happens after tool description pinning, so snulbug can still detect
upstream catalog drift even for tools hidden from the client.

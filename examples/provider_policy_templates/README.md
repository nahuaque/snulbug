# Provider-aware Lua policy templates

These templates show idiomatic Lua policy patterns for provider-specific auth
claims normalized into `context.auth.provider`.

Use them when declarative `[mcp.auth.claim_policy]` is too coarse and the share
needs contextual logic, task leases, or provider-specific helper checks.

## Templates

- `keycloak-role-gate.lua`: realm and client-role gates for read and admin MCP
  tools.
- `entra-app-role-gate.lua`: Entra tenant plus app-role gates for read/write
  tool families.
- `github-actions-workload-gate.lua`: GitHub Actions OIDC repository/workflow
  claim gates composed with a snulbug task lease.
- `cloudflare-access-group-gate.lua`: Cloudflare Access assertion validation
  plus Access group gates.

## Use

Copy one template into a share policy bundle and edit the constants at the top:

```bash
cp examples/provider_policy_templates/keycloak-role-gate.lua policy.snulbug/policy.lua
uv run snulbug bundle validate policy.snulbug
```

These are intentionally narrow examples. In a real share, keep response
redaction, schema validation, leases, and evidence recording enabled in
`snulbug.toml`.

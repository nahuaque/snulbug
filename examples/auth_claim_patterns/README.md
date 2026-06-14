# OAuth claim-policy patterns

These examples show how to use `[mcp.auth.claim_policy]` when identity claims
map cleanly to MCP tool access. Claim policy runs before Lua and before
upstream calls, so common identity fences can stay declarative and auditable.

Use Lua helpers such as `auth.require_tenant(...)`, `auth.require_group(...)`,
or `auth.require_subject(...)` when a share needs task-specific logic that is
too contextual for a static mapping.

## Patterns

- `tenant-isolation.toml`: a tenant claim fences tenant-prefixed tools.
- `group-gated-tools.toml`: group membership grants read, git, or admin tool
  families.
- `ci-workload-identity.toml`: GitHub Actions OIDC-style workload claims grant
  a CI job a small tool set without MCP OAuth scopes.

Validate the config shape without reaching an issuer:

```bash
uv run snulbug mcp share auth doctor \
  --config examples/auth_claim_patterns/tenant-isolation.toml \
  --url https://tenant-a-share.example.com/mcp \
  --no-live-checks
```

The examples use issuer discovery and placeholder HTTPS issuer URLs. Replace
the issuer/audience/resource values with the exact provider and public share
URLs before running a real gateway.

## Tenant Isolation

Use this when one gateway fronts tenant-scoped tools and a token's tenant claim
is the trust boundary. The example requires `tenant-a` globally, then allows
only `tenant_a.*` and selected shared read-only tools.

```toml
[mcp.auth]
required_claims = { tenant = ["tenant-a"] }

[mcp.auth.claim_policy]
enabled = true
default_action = "deny"

[[mcp.auth.claim_policy.rules]]
claim = "tenant"
values = ["tenant-a"]
allow_tool_prefixes = ["tenant_a.", "shared.read_"]
```

## Group-Gated Tools

Use this when identity provider groups map to operational roles. Multiple rules
can match the same token. A platform developer can get git read tools while an
MCP admin gets a broader tool prefix.

```toml
[[mcp.auth.claim_policy.rules]]
claim = "groups"
values = ["platform-dev"]
allow_selectors = ["tools/call:git.status", "tools/call:git.diff"]
```

## CI / Workload Identity

Use this when the caller is a workload identity token rather than a user OAuth
access token. GitHub Actions OIDC does not issue MCP scopes, so the example
uses exact workload claims plus a task lease.

```toml
[mcp.auth]
issuer = "https://token.actions.githubusercontent.com"
required_scopes = []
required_claims = {
  repository = ["acme/widget-service"],
  ref = ["refs/heads/main"],
  event_name = ["workflow_dispatch"],
}
```

In a real share, keep `lease_required = true` so a valid CI identity still needs
a temporary snulbug task lease for the specific job.


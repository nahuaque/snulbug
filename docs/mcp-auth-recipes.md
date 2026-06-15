# MCP auth interop recipes

snulbug does not implement dynamic client registration or act as an
authorization server. Instead, it can generate provider setup flows for the
identity systems you already use:

```bash
uv run snulbug mcp share auth init \
  --provider keycloak \
  --url https://mcp.example.com/mcp \
  --issuer https://idp.example.com/realms/dev
```

`init` writes a generated setup directory with provider instructions, an auth
TOML overlay, a client token request shape, and next commands:

```bash
uv run snulbug mcp share auth init \
  --provider auth0 \
  --url https://mcp.example.com/mcp \
  --domain tenant.example.com \
  --client-id mcp-agent \
  --output-dir .snulbug/auth/auth0
```

Use `--compact` for JSON output an agent can inspect. Use `recipe` when you only
want the Markdown guidance and do not want files:

```bash
uv run snulbug mcp share auth recipe \
  --provider auth0 \
  --url https://mcp.example.com/mcp \
  --domain tenant.example.com \
  --output .snulbug/auth/auth0.md
```

Supported providers:

- `keycloak`
- `auth0`
- `okta`
- `entra`
- `cloudflare-access`
- `github-oidc`

## Demo Status

The checked-in real-provider demo coverage is intentionally narrow until each
provider can be validated against a live dev account:

- Keycloak: runnable Docker Compose demo in
  [`examples/keycloak_oauth_demo`](../examples/keycloak_oauth_demo/README.md).
- Auth0: generated setup recipe is available; live provider demo forthcoming.
- Okta: generated setup recipe is available; live provider demo forthcoming.
- Microsoft Entra: generated setup recipe is available; live provider demo
  forthcoming.
- Cloudflare Access: generated origin-side adapter recipe is available; live
  provider demo forthcoming.
- GitHub OIDC: generated workload-identity recipe is available; live provider
  demo forthcoming.

## What Init Generates

The setup directory contains:

- `README.md`: provider setup plus snulbug next steps
- `snulbug.auth.toml`: auth-focused TOML to merge into a share config
- `client-token-request.json`: issuer/audience/client/scopes the MCP client should request
- `commands.json`: run and doctor commands
- `auth-init.json`: machine-readable metadata for agentic harnesses

## What a Recipe Contains

Each recipe includes:

- provider-side setup steps
- a `snulbug.toml` auth snippet
- the token request shape the client should use
- a `share auth doctor` command to verify resource/audience and issuer setup
- provider documentation links

The OAuth provider recipes configure snulbug as an OAuth protected resource:

```toml
[mcp.auth]
mode = "oauth-resource"
resource = "https://mcp.example.com/mcp"
issuer = "https://issuer.example.com"
audience = "https://mcp.example.com/mcp"
issuer_discovery = true
token_validation = "jwt"
strip_authorization_upstream = true
```

The Cloudflare Access recipe is different: it configures Cloudflare Access as
the outer access gate and snulbug as the origin-side MCP policy gateway:

```toml
[mcp.proxy]
cloudflare_access = "enforce"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = true
cloudflare_access_require_cf_ray = true
cloudflare_access_validate_jwt = true
cloudflare_access_team_domain = "YOUR-TEAM.cloudflareaccess.com"
cloudflare_access_audience = "YOUR-CLOUDFLARE-ACCESS-AUD-TAG"

[mcp.auth]
mode = "off"
```

`cloudflare_access_audience` is the Cloudflare Access application AUD tag. With
JWT validation enabled, snulbug verifies the Access assertion signature and uses
the signed email claim for allowlists.

The GitHub OIDC recipe is also different. GitHub Actions OIDC tokens do not
carry MCP scopes, so the recipe validates issuer/audience and expects leases and
Lua identity policy to constrain the workflow.

## Provider Notes

Keycloak often needs an explicit audience mapper so access tokens contain the
MCP public URL in `aud`.

Auth0 should model the MCP endpoint as an API whose Identifier is the public MCP
URL, then issue access tokens for that audience.

Okta should use a custom authorization server with the MCP public URL as the
authorization server audience.

Microsoft Entra works best with a stable verified domain for the Application ID
URI. Temporary tunnel domains may require an `api://...` Application ID URI; in
that case, keep the configuration intentional and validate it with
`share auth doctor`.

Cloudflare Access can be used without OAuth protected-resource mode. Enable
`cloudflare_access_validate_jwt` so snulbug validates the Access assertion at
the origin, then keep snulbug leases and Lua policy enabled for task-specific
bounds after Access succeeds.

GitHub OIDC should be treated as workload identity, not user OAuth. Require
`lease_required = true`, bind the task lease to the exact workflow subject or
repository claims where possible, and keep Lua checks for any workflow-specific
rules that do not fit the lease fields.

## Keycloak Compose Demo

For a runnable Keycloak setup, see
[`examples/keycloak_oauth_demo`](../examples/keycloak_oauth_demo/README.md).
The demo checks in the output of `snulbug mcp share auth init --provider
keycloak`, imports a matching Keycloak realm with client scopes and an audience
mapper, then runs snulbug as an OAuth protected MCP resource in Docker Compose.

## Claim-Policy Examples

For explicit identity-to-tool patterns, see
[`examples/auth_claim_patterns`](../examples/auth_claim_patterns/README.md).
It includes tenant isolation, group-gated tools, and GitHub Actions
OIDC/workload identity configs that are parsed and exercised by the test suite.

For provider-specific Lua helper patterns, see
[`examples/provider_policy_templates`](../examples/provider_policy_templates/README.md).
It includes copyable Keycloak role gates, Entra app-role gates, GitHub Actions
workload gates, and Cloudflare Access group gates.

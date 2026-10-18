# MCP auth interop recipes

snulbug does not implement dynamic client registration or act as an
authorization server. Instead, it can generate provider setup flows for the
identity systems you already use:

```bash
snulbug mcp share auth init \
  --provider keycloak \
  --url https://mcp.example.com/mcp \
  --issuer https://idp.example.com/realms/dev
```

`init` writes a generated setup directory with provider instructions, an auth
TOML overlay, a client token request shape, and next commands:

```bash
snulbug mcp share auth init \
  --provider auth0 \
  --url https://mcp.example.com/mcp \
  --domain tenant.example.com \
  --client-id mcp-agent \
  --output-dir .snulbug/auth/auth0
```

Use `--compact` for JSON output an agent can inspect. Use `recipe` when you only
want the Markdown guidance and do not want files:

```bash
snulbug mcp share auth recipe \
  --provider auth0 \
  --url https://mcp.example.com/mcp \
  --domain tenant.example.com \
  --output .snulbug/auth/auth0.md
```

Supported providers:

- `keycloak`
- `pocket-id`
- `auth0`
- `okta`
- `okta-xaa`
- `entra`
- `cloudflare-access`
- `github-oidc`

## Demo Status

The checked-in real-provider demo coverage is intentionally narrow until each
provider can be validated against a live dev account:

- Keycloak: runnable Docker Compose demo in
  [`examples/keycloak_oauth_demo`](../examples/keycloak_oauth_demo/README.md).
- Pocket ID: generated setup and synthetic RS256 token/discovery fixtures are
  covered; a live passkey login or real-client demo has not been validated.
- Auth0: generated setup recipe is available; live provider demo forthcoming.
- Okta: generated setup recipe is available; live provider demo forthcoming.
- Okta XAA / MCP Enterprise-Managed Authorization: generated setup recipe is
  available; live provider demo forthcoming.
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

The Okta XAA recipe uses MCP Enterprise-Managed Authorization. The enterprise
IdP/client owns the authorization flow, while snulbug validates the final access
token and adds MCP-specific controls:

```toml
[mcp.auth]
mode = "enterprise-managed"
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

### Keycloak

Keycloak often needs an explicit audience mapper so access tokens contain the
MCP public URL in `aud`.

### Pocket ID

Use Pocket ID as the external issuer, with snulbug as its protected API:

```bash
snulbug mcp share auth init \
  --provider pocket-id \
  --url https://share.example.com/mcp \
  --issuer https://id.example.com \
  --client-id "$POCKET_ID_CLIENT_ID"
```

Use the actual client ID from Pocket ID, not the client's display name. Omit
`--client-id` to generate instructions before registering a client.

This writes `.snulbug/auth/pocket-id/` with the normal five setup files. Review
the generated README and merge `snulbug.auth.toml` into your existing share
config; the overlay is not a standalone upstream/policy configuration. From a
source checkout, prefix these commands with `uv run`.

In Pocket ID, create an **API** with resource `https://share.example.com/mcp`,
then add the permission keys listed in the generated setup. Grant those
permissions to the MCP client under **User-delegated access**. Public clients
use authorization code with PKCE S256 and their exact callback URLs. The client
requests `resource=https://share.example.com/mcp` and `openid` plus the API
permissions. It sends the resulting **access token**, not its ID token, to
snulbug. See [Pocket ID APIs and permissions](https://pocket-id.org/docs/guides/apis).

`--scope` can narrow the generated permission set. `mcp:connect` is always
required. Default tool selectors are examples (`filesystem.read_file` and
`git.status`); change them to match discovered tool names. Custom permissions
start with empty selector lists, which grant no MCP actions until mapped. A
connect-only configuration does not implicitly grant all tools. Identity scopes
such as `openid` are not API permission keys; the client request adds `openid`
automatically.

For CIMD clients, Pocket ID requires an explicit metadata-document URL allowlist
and a separate API permission grant. Prefer exact metadata URLs. The API-wide
metadata-client grant applies to future allowed clients too; it is not a grant
to just one client. Manual registration remains supported, so disabled CIMD is
not a doctor failure. See [Pocket ID client metadata](https://pocket-id.org/docs/guides/client-id-metadata-documents).

Keep `lease_required = true` and give the consumer its `x-snulbug-lease` header.
Automation uses a separate confidential client with **Client access (M2M)**,
resource-bound API permissions, and an identity-bound renewable invite. Pocket
ID token acquisition/refresh and snulbug lease renewal remain separate consumer
operations. No client secret or refresh token belongs in the gateway config.

Do not assume Pocket ID groups or custom tenant claims are present in API access
tokens: profile/custom claims are documented for ID tokens/userinfo. This recipe
uses subject/client identity, scopes, and leases, without a new claim mapper or
userinfo fetch. Inspect actual API tokens before adding claim-dependent Lua.
See [Pocket ID scopes and claims](https://pocket-id.org/docs/guides/scopes-and-claims).

After starting the share, verify it with the existing doctor:

```bash
snulbug mcp share auth doctor \
  --config .snulbug/shares/my-share/snulbug.toml \
  --url https://share.example.com/mcp \
  --token "$ACCESS_TOKEN" \
  --header "x-snulbug-lease: $SNULBUG_LEASE"
```

Doctor checks public resource/audience alignment, metadata issuer identity,
PKCE S256 when authorization code is advertised, reachable JWKS, and scope-map
tool targets. It reports CIMD advertisement but cannot inspect Pocket ID's
private API grants or allowlist. Global issuer `scopes_supported` is not proof
that a particular API permission was granted. Prove sample tokens, discovered
schemas, and recorded evidence with the existing [auth conformance pack](#auth-conformance-pack).
Token checks cover authentication on initialization; tool-scope behavior also
needs recorded/replayed calls. DPoP stays optional pending issuer/client testing.

Use stable HTTPS issuer and public resource URLs. If a tunnel URL changes,
register a replacement Pocket ID API resource, grant it to the client, and align
the snulbug configuration rather than accepting client-ID audiences. Pocket ID
API resources cannot be edited after creation. Console authentication is
unchanged; this recipe does not add Pocket ID console login.

### Other Providers

Auth0 should model the MCP endpoint as an API whose Identifier is the public MCP
URL, then issue access tokens for that audience.

Okta should use a custom authorization server with the MCP public URL as the
authorization server audience.

Okta XAA should register the snulbug MCP endpoint as the protected resource and
enable the MCP enterprise-managed authorization extension for the client/resource
pair. Keep `lease_required = true`; enterprise identity is necessary but not
sufficient for tool use.

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

## Auth Conformance Pack

After recording authenticated MCP calls and discovering schemas, use the existing
auth conformance workflow for any OAuth provider. Set `ACCESS_TOKEN` to a valid
API access token and `WRONG_AUDIENCE_TOKEN` to a token for a different resource
or a client-bound ID token. Keep both in the environment, not checked-in files:

```bash
snulbug mcp share auth conformance generate \
  --config .snulbug/shares/my-share/snulbug.toml \
  --url https://share.example.com/mcp \
  --schema-catalog schemas.json \
  --log audit.jsonl --kind audit \
  --token-env valid=ACCESS_TOKEN \
  --denied-token-env wrong-audience=WRONG_AUDIENCE_TOKEN \
  --output-dir .snulbug/auth-conformance

snulbug mcp share auth conformance run .snulbug/auth-conformance \
  --header "x-snulbug-lease: $SNULBUG_LEASE"
```

Use your actual schema/audit paths. The pack stores token environment references,
config/schema fingerprints, and evidence summaries, not raw sample tokens. Run
with `--no-live-checks` for offline validation; this does not prove live login,
private issuer grants, or client interoperability.

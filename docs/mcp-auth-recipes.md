# MCP auth interop recipes

snulbug does not implement dynamic client registration or act as an
authorization server. Instead, it can generate provider setup recipes for the
identity systems you already use:

```bash
uv run snulbug mcp share auth recipe \
  --provider keycloak \
  --url https://mcp.example.com/mcp \
  --issuer https://idp.example.com/realms/dev
```

Use `--compact` for JSON output an agent can inspect, or `--output` to write the
Markdown recipe:

```bash
uv run snulbug mcp share auth recipe \
  --provider auth0 \
  --url https://mcp.example.com/mcp \
  --domain tenant.example.com \
  --client-id mcp-agent \
  --output .snulbug/auth/auth0.md
```

Supported providers:

- `keycloak`
- `auth0`
- `okta`
- `entra`
- `cloudflare-access`
- `github-oidc`

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

[mcp.auth]
mode = "off"
```

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

Cloudflare Access can be used without OAuth protected-resource mode. Keep
snulbug leases and Lua policy enabled for task-specific bounds after Access
succeeds.

GitHub OIDC should be treated as workload identity, not user OAuth. Require
`lease_required = true` and add Lua checks for the exact workflow subject when
the share is sensitive.

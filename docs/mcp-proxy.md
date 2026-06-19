# MCP reverse proxy

Reverse proxy mode lets `snulbug` protect a local MCP HTTP server even when the
server is not a Python ASGI app.

Install the proxy runner with `uv`:

```bash
uv tool install "snulbug[discovery]"
snulbug --help
```

Or add it to another `uv` project:

```bash
uv add "snulbug[discovery]"
```

If you are working from the source checkout, run `uv sync --all-extras --dev`
and prefix CLI commands with `uv run`.

Copy a starter policy. For public tunnel use, `tunnel-safe` is the recommended
default:

```bash
snulbug mcp policy preset tunnel-safe --output policy.snulbug
```

Or generate one with project-specific values:

```bash
snulbug mcp policy preset tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Write a starter config:

```bash
snulbug mcp share config init
```

Run the proxy:

```bash
snulbug mcp share run --config snulbug.toml
```

For concrete MCP client configuration patterns, see
[MCP client setup recipes](mcp-client-recipes.md).

For a generated temporary bearer/lease share directory, see
[MCP share sessions](mcp-share.md).

For a runnable upstream-plus-proxy walkthrough, see the
[end-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md).

Point ngrok, Cloudflare Tunnel, Tailscale Funnel, Pinggy, or a
private Holepunch peer bridge at `http://127.0.0.1:8080`. The proxy applies the
Lua policy before forwarding to the upstream server. Use `tunnel-safe` unless
you have a stronger external access-control layer in front of the tunnel or
peer bridge.

For public tunnel use, prefer a generated share session. It writes the policy,
config, lease, client config, provider setup files, and doctor command together:

```bash
snulbug mcp share create \
  --provider ngrok \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
export SNULBUG_SHARE_TOKEN=...
snulbug mcp share run .snulbug/shares/share-...
ngrok start --config .snulbug/shares/share-.../tunnel/ngrok-agent.yml --all
```

For ngrok, the generated provider directory contains `ngrok-agent.yml` for the
private `.internal` Agent Endpoint and `ngrok-traffic-policy.yml` for the
public Cloud Endpoint. Attach the Traffic Policy to the public Cloud Endpoint;
it performs coarse MCP checks and forwards allowed traffic to the internal
Agent Endpoint. See [End-to-end ngrok MCP gateway](ngrok-end-to-end.md) for a
complete public Cloud Endpoint walkthrough.

```bash
export NGROK_URL=https://YOUR-NGROK-CLOUD-ENDPOINT
```

Use curl as a minimal MCP client to check the local proxy before exposing it:

```bash
curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Then check the public tunnel:

```bash
curl -sS "${NGROK_URL}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Before sharing the public URL, verify that the tunnel reaches snulbug and that
unauthenticated MCP traffic is blocked:

```bash
snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${NGROK_URL}/mcp"
```

See [MCP share sessions](mcp-share.md) for Cloudflare Access, Tailscale Funnel,
Pinggy, and Holepunch peer bridge variants.

`record_out` writes replayable request records for traffic that passes through
the proxy. `[[mcp.events.sinks]]` writes operational outputs such as redacted
audit events, live console decisions, webhook alerts, and fabric event logs.
Rejected/challenged requests are recorded too, not only requests forwarded
upstream.

Add a console sink to print live policy decisions while the proxy is running:

```toml
[[mcp.events.sinks]]
type = "console"
format = "text" # or "json"
```

Then run:

```bash
snulbug mcp share run --config snulbug.toml
```

The text console is optimized for watching local tunnel traffic. The JSON format
emits redacted audit-shaped events that can be piped into local tools. Audit
events include MCP-aware fields such as JSON-RPC id, MCP method, operation,
target tool/resource/prompt, params key names, argument key names, initialize
client metadata, tunnel provider metadata, and policy decision `reason` /
`reason_code`.

Replay captured traffic against the same policy or a candidate policy:

```bash
snulbug mcp evidence replay traces/session.jsonl
snulbug mcp evidence replay traces/session.jsonl --script candidate.lua
```

Inspect a session after the proxy stops:

```bash
snulbug mcp evidence inspect traces/session.jsonl
snulbug mcp evidence inspect traces/audit.jsonl --kind audit
snulbug mcp evidence inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Live replay records are redacted by default. Set `redact_records = false` in
`snulbug.toml` only when you need exact auth-sensitive replay artifacts.

The proxy CLI accepts a small bootstrap override surface for host, port,
upstream, facade upstreams, policy, and replay record output:

```bash
snulbug mcp share run --config snulbug.toml --port 8181
```

For facade mode, the proxy can hot-reload upstream routes from the declarative
fabric config while it is running:

```bash
snulbug mcp share run \
  --config snulbug.toml \
  --reload-fabric \
  --fabric-reload-interval 2
```

On each reload check, snulbug re-reads `[mcp.fabric]`, discovery providers, and
`[[mcp.proxy.upstreams]]`. If the route table changed, new requests use the new
upstreams without restarting uvicorn. In-flight requests keep the route snapshot
they started with. If the config is temporarily invalid while you are editing
it, the proxy keeps serving the previous route table and records the reload
error in live replay/audit metadata.

Example config:

```toml
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
redact_records = true
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = true
lease_header = "x-snulbug-lease"
tunnel_provider = "auto"
tunnel_public_url = ""
tailscale_profile = ""
cloudflare_access = "off"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = false
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_emails = []
cloudflare_access_allowed_domains = []
cloudflare_access_validate_jwt = false
cloudflare_access_team_domain = ""
cloudflare_access_audience = ""
cloudflare_access_certs_url = ""
cloudflare_access_jwks_cache_seconds = 300.0
cloudflare_access_jwks_fetch_timeout = 5.0
cloudflare_access_leeway_seconds = 60.0
timeout = 30.0

[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[[mcp.events.sinks]]
type = "console"
format = "text"
```

`tunnel_provider` can be `auto`, `generic`, `ngrok`, `cloudflare`, `tailscale`,
`pinggy`, `ssh`, or `holepunch`. With `auto`, snulbug infers the provider
from request headers and the public host when possible. Set `tunnel_public_url`
when you want audit logs to record the externally shared MCP URL or client-side
peer bridge URL even if the request reaches snulbug through a local reverse
proxy.

Use `tunnel_provider = "ssh"` for a plain reverse SSH tunnel to a host you
control. The generated share defaults to `http://127.0.0.1:18080/mcp`, which is
loopback on the SSH host after running the reverse tunnel command, not loopback
on the laptop running snulbug.

## Tailscale Funnel / Serve Profiles

For generated share sessions, `--provider tailscale` defaults to the
`funnel-public` profile. That profile treats the `.ts.net` URL as publicly
reachable through Funnel and expects both snulbug bearer auth and an active task
lease before `share doctor` passes:

```bash
snulbug mcp share create \
  --provider tailscale \
  --url https://dev.tailnet.ts.net/mcp \
  --allow-tool safe_read_file \
  --ttl 30m
```

The equivalent proxy config shape is:

```toml
[mcp.proxy]
tunnel_provider = "tailscale"
tunnel_public_url = "https://dev.tailnet.ts.net/mcp"
tailscale_profile = "funnel-public"
lease_required = true
lease_header = "x-snulbug-lease"
```

Use `tailscale_profile = "serve-tailnet"` for tailnet-only Tailscale Serve
shares. It still expects snulbug bearer auth, but lease checks are warnings
rather than hard public-Funnel failures. Use `tailscale_profile = "oauth-resource"`
when the MCP client supports MCP OAuth and snulbug should
terminate OAuth before forwarding to upstream MCP servers.

## Event Sinks

Use `[[mcp.events.sinks]]` for operational event outputs. Replay records still
use `record_out`; event sinks cover audit JSONL, live console output, webhook
alerts, and fabric control-plane JSONL.

```toml
[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[[mcp.events.sinks]]
type = "console"
format = "text"

[[mcp.events.sinks]]
type = "webhook"
name = "security-alerts"
url_env = "SNULBUG_SECURITY_WEBHOOK_URL"
events = [
  "mcp.decision.blocked",
  "mcp.response.redacted",
  "mcp.tool.changed",
  "snulbug.fabric.upstream.unhealthy",
]
body_mode = "metadata_only"
redaction = "strict"
timeout_ms = 750
retry_attempts = 3
signing_secret_env = "SNULBUG_WEBHOOK_SECRET"
```

Event names can match the raw event `type`, derived MCP names such as
`mcp.decision.blocked` or `mcp.response.redacted`, Lua `reason_code` values, or
fabric control-plane event types. Webhook delivery is fail-open and
asynchronous, so webhook errors do not block MCP requests. `body_mode =
"metadata_only"` drops request headers from audit payloads before delivery.
Keep `redaction = "strict"` for normal local development.

For webhook sinks, when `signing_secret_env` resolves to a secret, snulbug adds:

- `x-snulbug-signature-timestamp`
- `x-snulbug-signature: sha256=<hmac>`
- `x-snulbug-webhook-sink`

## OAuth Protected Resource Mode

When exposing a public MCP endpoint to clients that understand MCP
authorization, snulbug can act as an OAuth protected resource server. The
authorization server remains external; snulbug validates incoming bearer
tokens before Lua policy or upstream forwarding.

```toml
[mcp.auth]
mode = "oauth-resource"
resource = "https://mcp.example.com/mcp"
# resource_aliases = ["https://preview.example.com/mcp"]
issuer = "https://issuer.example.com"
authorization_servers = ["https://issuer.example.com"]
audience = "https://mcp.example.com/mcp"
# audiences = ["https://preview.example.com/mcp"]
required_scopes = ["mcp:connect"]
scopes_supported = ["mcp:connect", "mcp:tools.read", "mcp:tool.git.status"]
jwks_path = "auth/jwks.json"
# Or use issuer-managed rotation / discovery:
# jwks_url = "https://issuer.example.com/.well-known/jwks.json"
# issuer_discovery = true
# issuer_metadata_url = "https://issuer.example.com/.well-known/oauth-authorization-server"
# jwks_cache_seconds = 300
# jwks_fetch_timeout = 5
# token_validation = "jwt" # jwt, introspection, jwt_or_introspection, jwt_and_introspection
# introspection_endpoint = "https://issuer.example.com/oauth/introspect"
# introspection_client_id = "snulbug-share"
# introspection_client_secret_env = "SNULBUG_INTROSPECTION_CLIENT_SECRET"
# introspection_cache_seconds = 30
# introspection_fetch_timeout = 5
strip_authorization_upstream = true

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list", "resources/list"]
"mcp:tool.files.read" = ["tools/call:filesystem.read_file"]
"mcp:tool.git.status" = ["tools/call:git.status"]

[mcp.auth.claim_policy]
enabled = true
default_action = "deny"

[[mcp.auth.claim_policy.rules]]
id = "tenant-a-tools"
claim = "tenant"
values = ["tenant-a"]
allow_tool_prefixes = ["tenant_a.", "shared."]
allow_tools = ["filesystem.read_file"]

[[mcp.auth.issuers]]
id = "tenant-a"
issuer = "https://tenant-a-idp.example.com"
audience = "https://mcp.example.com/mcp"
jwks_url = "https://tenant-a-idp.example.com/.well-known/jwks.json"
required_scopes = ["mcp:connect"]
required_claims = { tenant = ["tenant-a"] }

[mcp.auth.issuers.scope_map]
"mcp:tenant-a.files" = ["tools/call:tenant_a.*"]
```

With this enabled, snulbug:

- serves `GET /.well-known/oauth-protected-resource`
- challenges missing or invalid tokens with `WWW-Authenticate: Bearer ...`
- rejects insufficient scopes before Lua and upstream calls
- validates JWT signatures from `jwks_path`, a cached remote `jwks_url`, or a
  discovered issuer `jwks_uri`
- optionally validates opaque or revocation-sensitive tokens with OAuth token
  introspection
- maps OAuth scopes to MCP methods/tools using `[mcp.auth.scope_map]`
- maps OAuth claims such as tenant, subject, client ID, group, or nested custom
  claims to allowed MCP tools using `[mcp.auth.claim_policy]`
- accepts multiple issuer/tenant profiles with `[[mcp.auth.issuers]]`, each
  with its own issuer, audience, JWKS, required claims, scope map, and claim
  policy
- can explicitly allow multi-URL shares with `resource_aliases` and
  `audiences` instead of silently accepting tunnel URL drift
- exposes sanitized claims to Lua as `context.auth`
- exposes Lua helpers such as `auth.has_scope("mcp:tool.git.status")` and
  `auth.can("tools/call:git.status")`
- exposes identity policy helpers such as `auth.require_subject(...)`,
  `auth.require_tenant(...)`, and `auth.require_group(...)`
- exposes provider-aware Lua helpers for Keycloak roles, Cloudflare Access
  email/groups, GitHub Actions OIDC repository/workflow/ref claims, and Entra
  groups/app roles
- composes with task-scoped leases, so a tool call can require both an OAuth
  subject/scope and an active snulbug lease
- records redacted `auth` audit metadata
- strips the caller `Authorization` header before forwarding upstream by
  default
- can inject a separate upstream credential from snulbug credential config

Scope-map selectors match exact MCP methods such as `tools/list` or
tool-specific selectors such as `tools/call:git.status`. A selector ending in
`*` matches by prefix, for example `tools/call:filesystem.*`. MCP handshake
messages such as `initialize`, `ping`, and `notifications/*` are allowed once
`required_scopes` has passed, so you do not need to map protocol setup traffic.

Claim policies are a declarative pre-Lua guard for common identity-to-tool
rules. Each rule matches a claim value and allows exact tool names, tool-name
prefixes, or selector patterns:

```toml
[mcp.auth.claim_policy]
enabled = true
default_action = "deny"

[[mcp.auth.claim_policy.rules]]
id = "platform-git"
claim = "groups"
values = ["platform-dev"]
allow_selectors = ["tools/call:git.*"]

[[mcp.auth.claim_policy.rules]]
id = "tenant-a"
claim = "tenant"
values = ["tenant-a"]
allow_tool_prefixes = ["tenant_a.", "shared."]
```

Supported claim aliases include `tenant` (`tenant` or `tid`), `subject` (`sub`),
`client_id` (`client_id` or `azp`), and `scope`. Other claim names can be
literal custom claim keys such as `https://example.com/tenant.slug`, or nested
paths such as `tenant.slug`. Requests still pass through Lua after the
declarative check, so use this for broad identity fences and Lua for
task-specific or stateful decisions.

For copy-pasteable tenant, group, and CI/workload identity patterns, see
[`examples/auth_claim_patterns`](../examples/auth_claim_patterns/README.md).

For a facade or fabric gateway, use `[[mcp.auth.issuers]]` when different
tenants, upstream route families, or dev environments trust different identity
providers or need different MCP mappings. The gateway still advertises one
protected resource, but validates each token against the configured profiles
until one fully passes issuer/audience validation, required scopes, required
claims, scope-map checks, and claim policy:

```toml
[mcp.auth]
mode = "oauth-resource"
resource = "https://mcp.example.com/mcp"

[[mcp.auth.issuers]]
id = "tenant-a"
issuer = "https://tenant-a-idp.example.com"
audience = "https://mcp.example.com/mcp"
jwks_url = "https://tenant-a-idp.example.com/.well-known/jwks.json"
required_scopes = ["mcp:connect"]
required_claims = { tenant = ["tenant-a"] }

[mcp.auth.issuers.scope_map]
"mcp:tenant-a.files" = ["tools/call:tenant_a.*"]

[[mcp.auth.issuers]]
id = "tenant-b"
issuer = "https://tenant-b-idp.example.com"
audience = "https://mcp.example.com/mcp"
jwks_url = "https://tenant-b-idp.example.com/.well-known/jwks.json"
required_scopes = ["mcp:connect"]
required_claims = { tenant = ["tenant-b"] }

[mcp.auth.issuers.scope_map]
"mcp:tenant-b.files" = ["tools/call:tenant_b.*"]
```

Unset profile fields inherit from `[mcp.auth]`, so shared resource, audience,
timeouts, and token-validation mode can live globally while tenant-specific
issuer/JWKS/scope-map details stay in each profile. Audit metadata includes
`auth.profile_id` and `access.auth.profile_id`.

Use Lua identity helpers when authorization depends on who is using a share,
not just what scope the token carries:

```lua
local denied = auth.require_tenant("tenant-a", {
  reason_code = "oauth.tenant_required"
}) or auth.require_group({ "platform-dev", "mcp-admins" }, {
  reason_code = "oauth.group_required"
})
if denied then
  return denied
end
```

The JWT verifier uses `PyJWT[crypto]`. snulbug is not an authorization server:
it does not mint tokens, host login, run authorization-code flows, or perform
dynamic client registration. Use your identity provider or tunnel/access layer
for those pieces.

Use `jwks_path` when you want a pinned local key file. Use `jwks_url` when the
issuer owns key rotation. If neither is set, `issuer_discovery = true` lets
snulbug read `.well-known/oauth-authorization-server` or
`.well-known/openid-configuration` from `issuer` and use the advertised
`jwks_uri`. Runtime remote JWKS fetches are cached for `jwks_cache_seconds`; if
a token arrives with a `kid` missing from the cached set, snulbug refreshes the
JWKS once and retries validation. Remote auth URLs must use HTTPS except for
localhost development.

Set `token_validation = "introspection"` for opaque tokens or when you need
revocation-sensitive checks. snulbug POSTs to `introspection_endpoint`, or to a
discovered issuer `introspection_endpoint`, caches active responses by token
digest for `introspection_cache_seconds`, verifies issuer/audience/time claims
when present, and never forwards or logs raw caller tokens. `jwt_or_introspection`
tries JWT first and falls back to introspection; `jwt_and_introspection` requires
both a valid JWT and an active introspection response.

OAuth audit metadata includes an `auth.runtime` summary with safe per-process
counters for JWKS, issuer-metadata, and introspection caches. The same runtime
summary tracks allowed/denied auth decisions, reason-code counts, JWKS refreshes
after key rotation, issuer/JWKS/introspection fetch failures, and scope-denial
counts by MCP selector such as `tools/call:git.status`. These counters never
include bearer tokens or introspected token bodies.

For public MCP shares, treat `mcp.auth.resource` and `mcp.auth.audience` as exact
resource indicators: they should match the public MCP URL a client uses, such as
`https://mcp.example.com/mcp`. If the same gateway is intentionally reachable
through more than one public URL, add the secondary URLs to both
`resource_aliases` and `audiences`. The auth doctor fails accidental drift
between `--url`, share session URLs, `mcp.proxy.tunnel_public_url`, and the auth
resource/audience settings.

Before sharing an OAuth-protected public MCP URL, run:

```bash
snulbug mcp share auth doctor \
  --config snulbug.toml \
  --url https://mcp.example.com/mcp \
  --token "${ACCESS_TOKEN}"
```

The auth doctor verifies protected-resource metadata, issuer metadata, JWKS or
introspection reachability, resource/audience alignment, HTTPS requirements,
raw-token logging safeguards, scope-map selectors against live `tools/list`, and
claim-policy tool entries against live `tools/list`, and Cloudflare Access
conflicts.

For task-oriented shares, OAuth and leases answer different questions:

- OAuth: who is this caller, and which MCP methods/tools did the token scope
  allow?
- snulbug leases: what temporary task capability is active for this request?
- Lua policy: what local rule should still apply before forwarding?

The strongest public-share path is all of them together: valid OAuth subject,
required MCP scopes, active task lease, and Lua approval. Audit records include
`metadata.auth`, `metadata.lease`, and `metadata.access` so this composition is
reviewable after the session.

You can exercise that model locally with:

```bash
snulbug mcp share demo auth
```

The lab writes `.snulbug-auth-lab/AUTH_LAB.md` plus the generated config,
policy, JWKS, demo tokens, lease file, request fixtures, and redacted logs.

### Token Anti-Passthrough

OAuth tokens are terminated at snulbug. By default,
`strip_authorization_upstream = true` removes the caller `Authorization` header
before proxying so a token minted for the public snulbug resource is not reused
against a different MCP upstream.

For single-upstream proxy mode, inject a separate upstream credential by
referencing `[mcp.fabric.credentials]`:

```toml
[mcp.fabric.credentials.local_api]
type = "env"
env = "LOCAL_MCP_TOKEN"
scheme = "bearer"
header = "Authorization"

[mcp.proxy]
upstream = "http://127.0.0.1:9001/mcp"
upstream_credential = "local_api"
```

For facade mode, keep using per-upstream `auth = "credential_id"` entries.
In both modes, snulbug records safe audit metadata such as `auth.subject`,
`auth.issuer`, `auth.scope_match`, `auth.anti_passthrough`, and
`metadata.upstream_auth` or `facade.upstream_metadata.auth`. It does not record
raw caller bearer tokens or upstream credential values.

## Cloudflare Access Adapter

When snulbug is the origin behind Cloudflare Access, it can audit or enforce the
Access headers that Cloudflare forwards after an Access policy succeeds.

```toml
[mcp.proxy]
tunnel_provider = "cloudflare"
tunnel_public_url = "https://mcp.example.com/mcp"
cloudflare_access_profile = "access-gate"
cloudflare_access = "enforce"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = true
cloudflare_access_allowed_domains = ["example.com"]
cloudflare_access_validate_jwt = true
cloudflare_access_team_domain = "YOUR-TEAM.cloudflareaccess.com"
cloudflare_access_audience = "YOUR-CLOUDFLARE-ACCESS-AUD-TAG"
```

`cloudflare_access` can be:

- `off`: ignore Access headers.
- `audit`: record what would have been blocked but allow the request.
- `enforce`: reject requests before Lua policy and upstream forwarding when
  required Access headers or allowlist checks are missing.

`cloudflare_access_profile` is generation/doctor metadata used by
`snulbug mcp share create --provider cloudflare`:

- `access-gate`: default Cloudflare Tunnel profile; enforce Access, validate
  the signed Access JWT, and keep snulbug bearer/lease/policy checks inside.
- `service-token`: same origin-side Access enforcement, plus generated MCP
  client headers for `CF-Access-Client-Id` and `CF-Access-Client-Secret` using
  environment-variable placeholders.
- `oauth-resource`: Cloudflare Tunnel as transport while snulbug acts as the
  MCP OAuth protected resource; Cloudflare Access stays in `audit` mode so it
  does not block OAuth protected-resource discovery.
- `audit`: observe Cloudflare Access headers before enforcing.

Set `cloudflare_access_team_domain` to the Cloudflare Access issuer domain for
your Zero Trust team, such as `my-team.cloudflareaccess.com`. snulbug derives
the certs URL as `<team-domain>/cdn-cgi/access/certs` unless
`cloudflare_access_certs_url` is set explicitly. Set
`cloudflare_access_audience` to the Access application AUD tag, not the MCP URL.

With `cloudflare_access_validate_jwt = true`, snulbug validates
`CF-Access-Jwt-Assertion` with RS256, issuer, audience, expiry, and the cached
Cloudflare Access JWKS before Lua or upstream forwarding. Email/domain
allowlists then use the signed JWT `email` claim instead of trusting
`CF-Access-Authenticated-User-Email`. In `audit` mode, failed validation is
recorded as `would_block` but traffic is still allowed.

The adapter records redacted `cloudflare_access` audit fields including mode,
email, email source, email domain, JWT validation status, `CF-Ray`, country,
decision, and `reason_code`. It never stores the raw
`CF-Access-Jwt-Assertion`, and it strips Access credential headers before
forwarding to the local upstream.

This is an origin-side defense that complements, rather than replaces,
Cloudflare Access policy configuration.

## Task-Scoped Leases

Leases give a client temporary MCP capabilities for one named task. A lease can
allow exact tools, path prefixes, URL hosts, command names, and a maximum number
of `tools/call` uses. In OAuth protected-resource mode, a lease can also be
bound to sanitized identity claims such as subject, issuer, tenant, client ID,
group, or snulbug auth profile. The lease file stores token hashes only; the
plaintext token is shown once when the lease is created.

Create a lease:

```bash
snulbug mcp share lease create \
  --file leases.json \
  --task "Read README before editing docs" \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --allow-subject user-1 \
  --allow-tenant tenant-a \
  --allow-group platform-dev \
  --ttl 30m \
  --max-calls 5
```

Send the returned `x-snulbug-lease` header with MCP requests. The proxy hot-loads
the JSON file on each call, so new leases and revocations do not require a proxy
restart.

Create an invite when you want snulbug to package the share URL, bearer header,
lease header, and downstream client snippets together:

```bash
snulbug mcp share invite create .snulbug/share \
  --recipient "agent demo" \
  --task "Read README before editing docs" \
  --capability docs_review \
  --ttl 30m \
  --max-calls 5
```

The create response includes MCP client JSON, a curl smoke test, Claude Code
setup, Codex `config.toml`, and environment exports. Stored invite records are
redacted, and the web console requires its local console secret before it
reveals invite tokens.

Auth binding flags are optional. When any are present, the current OAuth context
must match every configured dimension before the lease covers the request. Use:

- `--allow-subject` for JWT `sub`
- `--allow-issuer` for JWT `iss`
- `--allow-tenant` for `tenant` or `tid`
- `--allow-client-id` for `client_id` or `azp`
- `--allow-group` for one required group membership
- `--allow-auth-profile` for a matched `[[mcp.auth.issuers]]` profile id

Require leases for every MCP tool call:

```toml
[mcp.proxy]
lease_file = "leases.json"
lease_required = true
lease_header = "x-snulbug-lease"
```

When a lease file is configured, Lua receives a non-consuming preview as
`context.lease` and can use helpers such as `lease.require()`, `lease.id()`, and
`lease.task()`. Share invites can attach temporary capability labels, exposed as
`lease.capabilities()` and `lease.has_capability("project_readonly")`, so policy
can interpret a human-readable grant without duplicating path or tool rules in
the invite itself. Declare the labels with `capabilities.declare(...)` before
returning the Lua handler; the share console uses that declaration as the invite
menu and rejects undeclared labels. The proxy still performs the final lease
check and only consumes a lease use when the request reaches the upstream. For auth-bound leases,
`context.lease.auth_bound` is true and `context.lease.auth` contains the matched
sanitized OAuth identity fields.

Useful operations:

```bash
snulbug mcp share lease list --file leases.json
snulbug mcp share lease revoke lease_abc123 --file leases.json
```

Preview whether a lease covers captured traffic before requiring it:

```bash
snulbug mcp evidence impact traces/session.jsonl --lease leases.json --report-out traces/impact-report.md
```

In facade mode, leases use the client-facing tool name, such as
`files.read_file` or `git.status`.

## Argument Schema Firewall

When `schema_validation = true`, snulbug learns each MCP tool's `inputSchema`
from successful `tools/list` responses and validates later `tools/call`
`params.arguments` before forwarding the call upstream. This blocks malformed or
unexpected arguments at the proxy boundary, including missing required fields,
wrong primitive types, disallowed enum values, invalid string lengths/patterns,
oversized arrays, and extra properties when the schema sets
`additionalProperties = false`.

Calls pass through until a schema has been observed, so clients that call a tool
before listing tools are not broken. In facade mode, schemas are stored under the
client-facing prefixed tool names such as `files.read_file`.

```toml
[mcp.proxy]
schema_validation = true
schema_validation_action = "block"
```

Use warn mode while introducing the proxy to an existing workflow by setting
`schema_validation_action = "warn"` in `snulbug.toml`.

Schema snapshots live in the configured state adapter. Use SQLite if you want
learned schemas to survive proxy restarts.

## Policy Deny Backoff

Enable policy deny backoff when repeated equivalent denies should cool down
quickly instead of rerunning Lua and hitting the full proxy path every time:

```toml
[mcp.proxy]
state = "sqlite:policy-state.sqlite3"

[mcp.policy_backoff]
enabled = true
base_seconds = 2
factor = 2.0
max_seconds = 60
window_seconds = 300
reason_codes = ["mcp.*", "oauth.scope_map_denied", "lease.tool_not_allowed"]
exclude_reason_codes = ["oauth.invalid_token", "cloudflare_access.*"]
```

The first selected Lua `reject` or `challenge` records a cooldown in policy
state. Matching requests during the cooldown return `429` with `Retry-After`
before Lua runs and before any upstream is reached. See
[Policy deny backoff](policy-deny-backoff.md) for key fields, headers, and audit
metadata.

## Response Controls

Request policy runs before upstream calls. The proxy also applies MCP-aware
return-path controls to successful JSON-RPC responses:

- `response_max_bytes` blocks oversized `tools/call`, `resources/read`, and
  `prompts/get` responses with a JSON-RPC error.
- `response_redact_secrets` redacts high-confidence bearer tokens, API keys,
  GitHub tokens, AWS access keys, and secret-shaped JSON fields from MCP
  results before they reach the client.
- `response_block_instructions` blocks tool/resource/prompt results that contain
  instruction-like phrases such as "ignore previous instructions". It is off by
  default because local files may legitimately contain security examples or
  prompt text.
- `tool_pinning` hashes `tools/list` names, descriptions, and input schemas on
  first sight. With `tool_pinning_action = "block"`, a later silent description
  or schema change is rejected until the proxy state is reset or reviewed.

Tool pins live in the configured state adapter. The default in-memory state pins
for the current proxy process. SQLite-backed state keeps pins across restarts:

```toml
[mcp.proxy]
state = "sqlite:policy-state.sqlite3"
tool_pinning = true
tool_pinning_action = "block"
```

Configure response controls in `snulbug.toml`; the proxy CLI intentionally keeps
advanced runtime policy out of flags.

For reviewable snapshots and CI checks outside the live proxy, use
`snulbug mcp policy schemas discover --method tools` and `snulbug mcp policy schemas diff`.
See [MCP schema discovery](mcp-schemas.md).

## Human Confirmation

Policies can return `action = "confirm"` for risky calls that should not be
always allowed or always blocked. The proxy fails closed unless confirmation is
explicitly enabled:

```bash
snulbug mcp share run --config snulbug.toml
```

with:

```toml
[mcp.proxy]
confirm = true
```

Example policy fragment:

```lua
if mcp.tool_name(request) == "shell_exec" then
  return {
    action = "confirm",
    prompt = "Allow shell_exec for this session?",
    remember_key = "tool:shell_exec",
    timeout_seconds = 30,
    status = 403,
    body = "confirmation denied",
    reason = "Shell-like tool requires approval",
    reason_code = "mcp.confirm.risky_tool"
  }
end
```

The interactive prompt supports:

- `o`: allow once
- `a`: allow for this proxy session when `remember_key` is set
- `d`: deny

If a policy branch is conceptually a denial but should have a human override
path, return `action = "reject"` with `confirm = true`. snulbug routes that
through the same confirmation broker instead of a separate approval mechanism:

```lua
return decision.reject(403, "blocked by policy", {
  confirm = true,
  prompt = "Allow this blocked tool once?",
  remember_key = "tool:" .. mcp.tool_name(request),
  reason_code = "mcp.policy.tool_rejected"
})
```

For just-in-time lease workflows, use `cap.request(...)`. It is still a
confirmation decision, so approval goes through the same live broker. When
confirmation is unavailable or denied, snulbug returns an MCP JSON-RPC error
with `error.data.capability_request` and a suggested task lease instead of a
plain HTTP rejection:

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

Timeouts, non-interactive stdin, and disabled confirmation all reject the
request. Replay and audit records include the confirmation result.

## MCP Facade Mode

Facade mode lets one `snulbug` proxy present several local MCP HTTP, stdio, or
Holepunch-bridged MCP servers as a single client-facing HTTP endpoint. It is
intentionally small:
`tools/list` is fanned out to every upstream and returned as one list with tool
names prefixed by upstream name; `tools/call` is routed by that prefix and the
prefix is stripped before the call reaches the upstream server. Other JSON-RPC
methods are sent to the default upstream.

Example config:

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"

[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
default = true

[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[[mcp.events.sinks]]
type = "console"
format = "text"

[[mcp.proxy.upstreams]]
name = "git"
url = "http://127.0.0.1:9002/mcp"
```

The client sees tools such as `files.read_file` and `git.status`. A call to
`git.status` is forwarded to the `git` upstream as `status`.

Enable health-driven routing when one facade fronts optional or remote
upstreams and a failing member should not break the whole tool surface:

```toml
[mcp.proxy]
facade_health_routing = true
facade_health_failure_threshold = 2
facade_health_cooldown_seconds = 30.0
facade_health_exclude_unhealthy = true
```

With health routing enabled, facade mode tracks upstream failures from
`tools/list`, `tools/call`, default routed methods, connection errors, invalid
tool-list responses, and HTTP 5xx responses. An upstream moves from `healthy` to
`degraded`, then to `unhealthy` after the configured consecutive failure
threshold. Unhealthy upstreams are skipped for fanout and tool routing until the
cooldown expires, at which point the next request probes the upstream and marks
it recovered on success. Replay and audit metadata include `upstream_health`
with the skipped upstreams, failures, current status, and control-plane event
types.

You can also start facade mode directly from the CLI:

```bash
snulbug mcp share run \
  --policy policy.snulbug/policy.lua \
  --facade-upstream files=http://127.0.0.1:9001/mcp \
  --facade-upstream git=http://127.0.0.1:9002/mcp \
  --facade-health-routing
```

Use `tool_prefix` when you want a different namespace:

```toml
[[mcp.proxy.upstreams]]
name = "repo"
url = "http://127.0.0.1:9002/mcp"
tool_prefix = "git."
```

Replay records include facade metadata such as selected upstream, upstream
transport, original tool name, and upstream tool name for routed calls. Audit
events promote the same upstream identity into a top-level `facade` field so a
session report can show which local, stdio, or peer-bridged server handled each
decision.

### Signed upstream manifests

Signed upstream manifests let facade mode fail closed when an upstream identity
or advertised capability document changes unexpectedly. This is useful when one
gateway fronts multiple local, containerized, or peer-bridged MCP servers and you
want audit records to carry a verified upstream identity instead of only a local
config name.

Create an unsigned JSON manifest:

```json
{
  "schema": "snulbug.upstream-manifest.v1",
  "identity": "files@local",
  "transport": "http",
  "tool_prefix": "files.",
  "labels": {
    "owner": "local-dev"
  },
  "tools": [
    {
      "name": "read_file",
      "description": "Read a project file"
    }
  ]
}
```

Sign and verify it with a shared secret kept outside the file:

```bash
export SNULBUG_MANIFEST_SECRET="replace-with-a-local-secret"
snulbug mcp fabric manifest sign manifests/files.json \
  --out manifests/files.signed.json \
  --key-id dev
snulbug mcp fabric manifest verify manifests/files.signed.json \
  --expect-identity files@local
```

Then require that manifest for the facade upstream:

```toml
[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
tool_prefix = "files."
manifest = "manifests/files.signed.json"
manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
manifest_identity = "files@local"
```

On startup, snulbug verifies the manifest HMAC-SHA256 signature, digest, key id,
and optional expected identity. Replay records and audit events include only
safe manifest metadata: identity, digest, key id, schema, transport, tool prefix,
tool count, labels, path, and whether the manifest was required. The signing
secret is never written into record or audit metadata.

### Managed stdio upstreams

Use `transport = "stdio"` when an MCP server is normally launched as a local
stdio process. `snulbug` starts the process on first use, sends newline-delimited
JSON-RPC over stdin/stdout, serializes requests per process, and exposes the
server through the same HTTP facade endpoint.

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080

[[mcp.proxy.upstreams]]
name = "files"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
default = true

[[mcp.proxy.upstreams]]
name = "git"
transport = "stdio"
command = "uvx"
args = ["mcp-server-git"]
```

The client still connects to `http://127.0.0.1:8080/mcp` and sees namespaced
tools such as `files.read_file` and `git.status`.

Optional stdio fields:

```toml
cwd = "/path/to/project"
env = { MCP_LOG_LEVEL = "error" }
tool_prefix = "repo."
```

Only configure commands you trust. The process runs locally with the configured
command, arguments, working directory, and environment.

### Holepunch upstreams

Use `transport = "holepunch"` when an upstream MCP server is reachable through a
Holepunch/Hypertele peer bridge. `snulbug` supervises the local bridge process,
waits for the local bridge URL to answer HTTP, then routes facade traffic through
that URL like any other HTTP upstream.

When the ASGI runner sends lifespan events, facade startup starts all configured
Holepunch bridges and waits for their local URLs before reporting startup
complete. If a runner does not use lifespan, snulbug performs the same readiness
check before the first request routed to that upstream.

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080

[[mcp.proxy.upstreams]]
name = "remote-devbox"
transport = "holepunch"
peer = "SERVER_PEER_KEY"
local_port = 19100
tool_prefix = "devbox."
```

This expands to a local upstream URL of `http://127.0.0.1:19100/mcp` and starts
Hypertele with:

```bash
hypertele -p 19100 -s SERVER_PEER_KEY --private
```

You can use a generated Hypertele config instead of a peer argument:

```toml
[[mcp.proxy.upstreams]]
name = "remote-files"
transport = "holepunch"
local_port = 19101
bridge_config = "hypertele-client.json"
tool_prefix = "remote_files."
```

Advanced bridge fields:

```toml
bridge_command = "hypertele"
bridge_args = ["-p", "19101", "-c", "hypertele-client.json", "--private"]
bridge_cwd = "/path/to/bridge/config"
bridge_env = { HYPERDHT_BOOTSTRAP = "..." }
bridge_private = true
bridge_ready_timeout = 10.0
url = "http://127.0.0.1:19101/mcp"
```

Replay records and audit logs include the selected upstream transport and
Holepunch bridge metadata, including upstream name, tool prefix, local URL,
peer key when configured, local bridge port, and bridge readiness settings.

## State

Proxy mode uses in-memory policy state by default, which supports presets that
use `rate_limit`.

Use SQLite-backed local state:

```bash
snulbug mcp share run --config snulbug.toml
```

with:

```toml
[mcp.proxy]
state = "sqlite:policy-state.sqlite3"
```

Disable state:

```bash
snulbug mcp share run --config snulbug.toml
```

with:

```toml
[mcp.proxy]
state = "none"
```

Policies using `rate_limit` require state.

## Python API

Create the ASGI proxy app directly:

```python
from snulbug import create_proxy_application

application = create_proxy_application(
    "http://127.0.0.1:9000",
    "policy.snulbug/policy.lua",
)
```

You can run that ASGI app with Uvicorn, Hypercorn, Daphne, or another ASGI
server.

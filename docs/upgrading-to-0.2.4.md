# Upgrading to 0.2.4

This release strengthens always-on operation without changing the default MCP
protocol or adding an authorization server. Back up the complete share directory
before upgrading: policies, configuration, lease/invite stores, session model,
tunnel files, and evidence. Treat that backup as secret-bearing material.
Do not regenerate an existing share with `share create --force` as an upgrade.

## Tunnel ownership changes

`snulbug mcp share run DIRECTORY` now owns and supervises ngrok/SSH tunnels by
default, even with `--no-console`. Stop a separately running agent before letting
snulbug take ownership. Otherwise duplicate agents/endpoints may fail to start.

To keep an external supervisor in charge of the tunnel:

```bash
snulbug mcp share run /var/lib/snulbug/share --no-console --no-tunnel
```

Alternatively merge `tunnel_autostart = false` into `[mcp.runtime]`. Intentional
console stops remain stopped; unexpected exits use bounded restart backoff.
Retries never replay MCP calls. Follow the [always-on runtime recipes](always-on-runtime.md)
for service-account credentials, persistent storage, and shutdown deadlines.

## HTTP mounts require declared auth ownership for readiness

For every existing `[[mcp.proxy.http_routes]]`, declare who owns authentication:

```toml
[[mcp.proxy.http_routes]]
prefix = "/app"
upstream = "http://127.0.0.1:3000"
auth = "upstream"
methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
forward_authorization = true
forward_cookies = true
health_path = "/healthz"
health_status = 200
```

Merge settings into the existing mount, not a duplicate table for the same
prefix. Use a real, safe health path or omit the health fields and review the
resulting warning. A health response does not prove application authentication.

- `auth = "upstream"` means the application still enforces login and permissions.
  Its Authorization and Cookie/Set-Cookie headers pass through by default.
- `auth = "public"` means intentional unauthenticated exposure at snulbug. By
  default it strips request Authorization/Cookie and response Set-Cookie; review
  explicit forwarding overrides. It does not strip every possible custom secret
  header or secrets embedded in bodies/URLs.
- Existing mounts without `auth` still forward, but doctor/readiness now fail
  until ownership is declared. The short `--http-route PREFIX=URL` flag does not
  guess this setting: edit generated TOML before sharing.
- Permitted methods default to GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS.
  TRACE, CONNECT, and custom methods are no longer forwarded.

Restart the gateway after editing mount settings. If prefixes change, also update
the ngrok Cloud Endpoint policy. MCP OAuth, bearer auth, leases, and revocation
do **not** protect or revoke mounted application access. Pocket ID/OIDC login,
CSRF defenses, and application authorization remain the app's responsibility.
See [mount contracts](mcp-proxy.md#mount-contracts-and-readiness).

## Review contracts after upgrading

HTTP mount declarations now participate in share-contract bindings and readiness
review digests. A previous review may need acknowledging again; a required signed
contract that omits or differs from current mounts can prevent startup. Inspect
the differences, review the intended exposure, then regenerate/sign the contract
using the existing `snulbug mcp share contract` workflow. Do not discard the old
contract or bypass its requirement merely to suppress a drift failure.

## Upstream credential restrictions

File references must resolve to regular UTF-8 files, no larger than 16 KiB.
Symlinks to regular files work; FIFOs/devices do not. Broker results must be
nonempty single HTTP header values without control characters, within the same
size bound. Update old multiline/oversized values rather than disabling checks.
Plugin resolver errors now produce fixed reason codes rather than raw backend
exception text.

For rotation, atomically replace a protected credential file; new requests pick
it up without restarting. Update environment-backed credentials in the service
supervisor and restart the gateway: exporting a variable in another shell does
not update its environment. Missing or invalid sources fail closed with no
last-known-good/client-token fallback. Existing streams are not reauthenticated
mid-flight. See [credential operations](credential-brokers.md#always-on-upstream-credentials).

## Verification

```bash
snulbug mcp share doctor /var/lib/snulbug/share
snulbug mcp share status /var/lib/snulbug/share
snulbug mcp share report /var/lib/snulbug/share
```

Run doctor in the gateway's service environment, or through its protected local
console. Status/report and console refreshes reuse saved diagnostics rather than
resolving secrets or repeatedly probing endpoints. Doctor's optional ngrok cloud
drift check needs a separate API key, not an agent authtoken, and never applies
cloud changes. Without cloud access it reports that inspection as unverified.

Perform a safe MCP tool call and an application request through the intended
client URL, then verify that a revoked MCP lease is rejected. Failure explanations
now distinguish policy admission from upstream/result failures: an allowed Lua
decision alone is not proof that the request succeeded or had no side effects.

Existing leases/invites remain in their stores; the upgrade does not intentionally
rotate their tokens. Installed-package share creation now also works outside a
source checkout, including preparing a container gateway source snapshot from
installed code and distribution metadata. That snapshot is not a published Docker
image or a Docker-build interoperability certification.

# Upgrading to 0.2.5

Snulbug 0.2.5 preserves the configured public origin across internal tunnel hops
and downstream MCP/HTTP forwarding. Back up the complete share directory before
upgrading and treat it as secret-bearing material. Do not recreate an existing
share with `share create --force` to update its tunnel policy.

For upgrades from before 0.2.4, also review the
[always-on runtime and HTTP mount upgrade notes](upgrading-to-0.2.4.md).

## Check the canonical public URL

The existing `mcp.proxy.tunnel_public_url` now determines downstream
`X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`. The MCP path is
excluded from the origin; HTTP mounts independently provide their public prefix.
Local requests through the gateway intentionally advertise the same configured
public origin, not the local/internal hostname.

Use the exact intended HTTP(S) share URL without credentials, query strings, or
fragments. Malformed authorities and control characters now fail configuration
validation. Without a public URL, HTTP mounts retain local-request forwarding
and doctor warns that the external origin is unknown. Aliases and wildcard hosts
are not automatically trusted.

## Decide whether the app needs the public Host

By default, the literal Host remains the backend authority. The canonical
forwarding headers are sufficient for apps that support trusted proxy headers.
For an app that needs the public Host for virtual hosting or URL generation,
merge this option into its existing mount:

```toml
[mcp.proxy]
tunnel_public_url = "https://share.example.com/mcp"

[[mcp.proxy.http_routes]]
prefix = "/app"
upstream = "http://127.0.0.1:3000"
auth = "upstream"
preserve_host = true
```

Do not add duplicate tables for an existing prefix. `preserve_host = true`
requires an explicit public URL. The connection target, HTTPS SNI, and
certificate verification remain tied to the upstream URL. MCP upstreams retain
their own backend Host while receiving canonical forwarding metadata.

Configure the app to trust snulbug's immediate backend connection, accept its
public hostname, and generate URLs for `/app`. Prefix stripping does not set an
application's root path automatically. Snulbug does not rewrite HTML, Location
headers, cookie paths, Origin, or Referer. Application login, permissions, and
CSRF protection remain the app's responsibility; MCP leases do not guard it.

## Review and reattach the ngrok policy

Newly generated ngrok Cloud Endpoint policies capture the public host/scheme
before internal forwarding, reject unexpected origins with HTTP 421, and replace
caller-supplied forwarding/capture/audit headers. Snulbug rejects malformed,
duplicate, incomplete, or mismatched captured pairs with HTTP 400. These headers
are consistency checks, not authentication of the tunnel agent.

Existing policy files and live Cloud Endpoints are not changed automatically:

1. Confirm the intended public URL in the existing share configuration.
2. Run `snulbug mcp share doctor DIRECTORY` and review the desired ngrok baseline
   and drift result. Add `--compact` for JSON, which includes `ngrok.desired_policy` when
   inspection is available; the discovery extra supplies YAML inspection.
3. Review and update `tunnel/ngrok-traffic-policy.yml`, retaining any deliberately
   customized rules, and reattach the reviewed policy to the public Cloud Endpoint.
4. Restart the gateway after config changes and rerun doctor. A running agent or
   valid local YAML does not prove that the public endpoint has the new policy.

Direct requests without captured headers remain supported. Older policies do not
gain capture checks by upgrading Python alone, and doctor can flag them as drifted.
Passive console refreshes do not apply cloud changes or probe upstreams repeatedly.

## Renew reviews and contracts deliberately

Effective public origins and Host modes now participate in HTTP mount bindings.
Existing mount health results and readiness reviews can become stale, and a
required signed contract created before these fields existed can prevent startup.
Inspect the intended exposure, run health/doctor checks, then renew the review
and regenerate/sign the contract through the existing `share contract` workflow.
Do not bypass a required contract just to suppress drift.

## Verify before handoff

```bash
snulbug mcp share doctor /path/to/share
snulbug mcp share status /path/to/share
snulbug mcp share report /path/to/share
```

Check a safe MCP operation and an app link/redirect through the public URL.
The default MCP protocol and experimental profile limitations are unchanged.
Local release QA and ngrok config validation do not certify live provider/client
interoperability. See [public-origin forwarding](mcp-proxy.md#public-origin-and-host-preservation).

# Tunnel init

`snulbug tunnel init` generates provider-specific setup commands and optional
config snippets for exposing the snulbug MCP proxy through a public tunnel.

It does not run ngrok, cloudflared, or Tailscale for you. It gives you the
commands, client URL/header values, and doctor command to run before sharing the
endpoint.

## Ngrok

```bash
snulbug tunnel init \
  --provider ngrok \
  --hostname YOUR-TUNNEL.ngrok.app \
  --config snulbug.toml \
  --output-dir tunnel.ngrok
```

Generated output includes:

- an `ngrok http` command pointed at the snulbug proxy origin
- an `ngrok-traffic-policy.yml` guard that rejects non-MCP paths, missing or
  malformed bearer auth, unexpected methods, and non-JSON POSTs before they
  reach snulbug
- the `snulbug tunnel doctor --provider ngrok ...` command to run before sharing

Run the generated ngrok command from the output directory, or pass an absolute
path to `--traffic-policy-file`:

```bash
ngrok http 8080 \
  --url https://YOUR-TUNNEL.ngrok.app \
  --traffic-policy-file ngrok-traffic-policy.yml
```

## Cloudflare Tunnel

```bash
snulbug tunnel init \
  --provider cloudflare \
  --hostname mcp.example.com \
  --config snulbug.toml \
  --output-dir tunnel.cloudflare
```

Generated output includes:

- `cloudflared tunnel create` and `cloudflared tunnel route dns` commands
- `cloudflared.yml` ingress config that routes the public hostname to snulbug
- a doctor command that can include Cloudflare Access headers

For Access-protected apps, run doctor with service-token headers:

```bash
snulbug tunnel doctor \
  --provider cloudflare \
  --url https://mcp.example.com/mcp \
  --config snulbug.toml \
  --header "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
  --header "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}" \
  --token "${SNULBUG_TOKEN}"
```

To have snulbug enforce that real origin traffic arrived through Cloudflare
Access, turn on the origin-side adapter:

```toml
[mcp.proxy]
tunnel_provider = "cloudflare"
cloudflare_access = "enforce"
cloudflare_access_require_email = true
cloudflare_access_allowed_domains = ["example.com"]
```

## Tailscale Funnel

```bash
snulbug tunnel init \
  --provider tailscale \
  --hostname HOST.TAILNET.ts.net \
  --config snulbug.toml \
  --output-dir tunnel.tailscale
```

Generated output includes:

- a `tailscale funnel` command pointed at the snulbug proxy port
- the public MCP URL for client setup
- an explicit bearer-header and lease recipe for public Funnel clients
- a doctor command that verifies snulbug still blocks unauthenticated public
  traffic

Tailscale Funnel exposes a local service over public HTTPS. Keep snulbug's
`tunnel-safe` preset in front of the MCP server and require the bearer header:

```text
Authorization: Bearer ${SNULBUG_TOKEN}
```

The generated quickstart config leaves leases optional by default:

```toml
[mcp.proxy]
tunnel_provider = "tailscale"
tunnel_public_url = "https://HOST.TAILNET.ts.net/mcp"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
```

Create a short-lived lease when an agent needs one bounded task:

```bash
snulbug mcp lease create \
  --file leases.json \
  --task "Tailscale Funnel MCP session" \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Then send the returned lease token with tool-call requests:

```text
x-snulbug-lease: <lease token>
```

Set `lease_required = true` when every `tools/call` through the Funnel should
carry an active lease.

## Compact JSON

Agentic harnesses can consume the plan directly:

```bash
snulbug tunnel init --provider ngrok --hostname YOUR-TUNNEL.ngrok.app --compact
```

The compact output includes `commands`, `client`, `doctor`, generated `files`,
and `next_steps`.

For explicit audit labels while proxying, copy the generated public URL into
`snulbug.toml`:

```toml
[mcp.proxy]
tunnel_provider = "ngrok"
tunnel_public_url = "https://YOUR-TUNNEL.ngrok.app/mcp"
```

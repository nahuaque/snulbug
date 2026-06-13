# Tunnel init

`snulbug tunnel init` writes provider-specific setup files under
`.snulbug/configs` by default and prints copy-pasteable commands for exposing
the snulbug MCP proxy through a public tunnel or private peer bridge. Pass
`--output-dir` when you want those files somewhere else.

It does not run ngrok, cloudflared, Tailscale, LocalXpose, or Hypertele for
you. It gives you the commands, client URL/header values, and doctor command to
run before sharing the endpoint.

If no `snulbug.toml` is present, init also creates a safe starter under
`.snulbug/configs/`: `snulbug.toml`, `policy.snulbug/`, and `traces/`. The
starter points at `http://127.0.0.1:9000`; edit the generated `upstream` value
if your local MCP server uses another URL.

Use [Expose](expose.md) when you want the proxy, provider, doctor, client, and
session-report commands printed as one ordered plan.

## Ngrok

```bash
snulbug tunnel init \
  --provider ngrok
export SNULBUG_TOKEN=local-dev-secret
snulbug mcp proxy --config .snulbug/configs/snulbug.toml --decision-console
```

Generated output includes:

- `.snulbug/configs/snulbug.toml` and a starter `policy.snulbug/` when no
  config exists
- an `ngrok http` command pointed at the snulbug proxy origin
- an `ngrok-traffic-policy.yml` guard that rejects non-MCP paths, missing or
  malformed bearer auth, unexpected methods, and non-JSON POSTs before they
  reach snulbug
- the `snulbug tunnel doctor --provider ngrok ...` command to run before sharing

Run the generated ngrok command from the output directory, or pass an absolute
path to `--traffic-policy-file`:

```bash
ngrok http 8080 \
  --traffic-policy-file .snulbug/configs/ngrok-traffic-policy.yml
```

Copy the exact `Forwarding` HTTPS URL printed by ngrok. Random free ngrok URLs
commonly use domains such as `ngrok-free.dev` or `ngrok-free.app`; do not
rewrite them into an `ngrok.app` hostname.

Then test the tunnel with a JSON-RPC MCP `tools/list` request:

```bash
NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
curl -sS "${NGROK_URL}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

## Cloudflare Tunnel

```bash
snulbug tunnel init \
  --provider cloudflare \
  --config snulbug.toml \
  --output-dir tunnel.cloudflare
```

Generated output includes:

- `cloudflared tunnel create` and `cloudflared tunnel route dns` commands
- `cloudflared.yml` ingress config that routes the public hostname to snulbug
- a doctor command that can include Cloudflare Access headers

If you already know the named tunnel hostname, pass it with
`--hostname mcp.example.com`. Otherwise replace the generated placeholder in
`cloudflared.yml` and set the exact public origin before running doctor:

```bash
export CLOUDFLARE_TUNNEL_URL=https://mcp.example.com
```

For Access-protected apps, run doctor with service-token headers:

```bash
snulbug tunnel doctor \
  --provider cloudflare \
  --url "${CLOUDFLARE_TUNNEL_URL}/mcp" \
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

```bash
export TAILSCALE_FUNNEL_URL=https://HOST.TAILNET.ts.net
```

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

## LocalXpose

```bash
snulbug tunnel init \
  --provider localxpose \
  --config snulbug.toml \
  --output-dir tunnel.localxpose
```

Generated output includes:

- a `loclx tunnel http` command pointed at the snulbug proxy port
- the public MCP URL for client setup
- a doctor command that verifies snulbug still blocks unauthenticated public
  traffic

LocalXpose's basic HTTP tunnel command forwards to `localhost:8080`, which
matches snulbug's default proxy port. After starting the tunnel, set the exact
HTTPS URL printed by `loclx`:

```bash
loclx tunnel http
export LOCALXPOSE_URL=https://YOUR-LOCALXPOSE-FORWARDING-DOMAIN
```

Then run doctor before sharing the URL:

```bash
snulbug tunnel doctor \
  --provider localxpose \
  --url "${LOCALXPOSE_URL}/mcp" \
  --config snulbug.toml \
  --token "${SNULBUG_TOKEN}"
```

If you have a reserved LocalXpose domain, pass it to init:

```bash
snulbug tunnel init \
  --provider localxpose \
  --hostname mcp-dev.loclx.io
```

## Holepunch peer bridge

```bash
snulbug tunnel init \
  --provider holepunch \
  --config snulbug.toml \
  --output-dir tunnel.holepunch
```

Generated output includes:

- a Hypertele server command for the snulbug machine
- a Hypertele client command for the MCP client machine
- `hypertele-server.json` and `hypertele-client.json` placeholder configs
- a local client-side MCP URL, defaulting to `http://127.0.0.1:18080/mcp`
- explicit snulbug bearer and lease defaults

Holepunch support is a private peer bridge, not a public HTTPS tunnel. The MCP
client connects to a local port on the client machine; Hypertele carries that
traffic over the peer bridge to the snulbug proxy.

On the snulbug machine:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
hypertele-server -l 8080 --address 127.0.0.1 -c hypertele-server.json --private
```

On the MCP client machine:

```bash
hypertele -p 18080 -c hypertele-client.json --private
```

Point the MCP client at:

```text
http://127.0.0.1:18080/mcp
Authorization: Bearer ${SNULBUG_TOKEN}
```

Recommended config labels for audit events:

```toml
[mcp.proxy]
tunnel_provider = "holepunch"
tunnel_public_url = "http://127.0.0.1:18080/mcp"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
```

Set `lease_required = true` when every peer-bridged `tools/call` should carry an
active task lease.

## Compact JSON

Agentic harnesses can consume the plan directly:

```bash
snulbug tunnel init --provider ngrok --compact
```

The compact output includes `commands`, `client`, `doctor`, generated `files`,
provider-specific `bridge` metadata when present, and `next_steps`.

For explicit audit labels while proxying, copy the exact ngrok `Forwarding`
origin into `snulbug.toml` and append `/mcp`:

```toml
[mcp.proxy]
tunnel_provider = "ngrok"
tunnel_public_url = "https://YOUR-NGROK-FORWARDING-DOMAIN/mcp"
```

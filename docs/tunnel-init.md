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
- an optional `ngrok-traffic-policy.yml` guard that rejects requests missing an
  `Authorization` header before they reach snulbug
- the `snulbug tunnel doctor --provider ngrok ...` command to run before sharing

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
- a doctor command that verifies snulbug still blocks unauthenticated public
  traffic

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

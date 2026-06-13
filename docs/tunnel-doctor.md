# Tunnel doctor

`snulbug tunnel doctor` checks whether a local MCP policy proxy is safe to put
behind a public tunnel.

Use [Tunnel init](tunnel-init.md) first when you want provider-specific setup
commands or config files.

Run it against the local proxy before sharing a tunnel URL:

```bash
snulbug tunnel doctor \
  --config snulbug.toml \
  --token local-dev-secret
```

Run it against a public tunnel URL:

```bash
export NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
snulbug tunnel doctor \
  --provider ngrok \
  --url "${NGROK_URL}/mcp" \
  --config snulbug.toml \
  --token local-dev-secret
```

Use the exact `Forwarding` HTTPS origin printed by ngrok. Do not assume the
domain is `ngrok.app`; free URLs commonly use domains such as `ngrok-free.dev`
or `ngrok-free.app`.

For Cloudflare Access service-token protected apps, pass the Access headers:

```bash
export CLOUDFLARE_TUNNEL_URL=https://mcp.example.com
snulbug tunnel doctor \
  --provider cloudflare \
  --url "${CLOUDFLARE_TUNNEL_URL}/mcp" \
  --config snulbug.toml \
  --header "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
  --header "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}" \
  --token local-dev-secret
```

If `cloudflare_access = "enforce"` is set in `snulbug.toml`, live proxy
records and audit events include a `cloudflare_access` object with the Access
mode, authenticated email when Cloudflare provides it, decision, and
`reason_code`.

For Tailscale Funnel, snulbug should still enforce bearer auth or leases:

```bash
export TAILSCALE_FUNNEL_URL=https://HOST.TAILNET.ts.net
snulbug tunnel doctor \
  --provider tailscale \
  --url "${TAILSCALE_FUNNEL_URL}/mcp" \
  --config snulbug.toml \
  --token local-dev-secret
```

For a Holepunch/Hypertele peer bridge, run doctor from a machine where the
client-side bridge is listening:

```bash
snulbug tunnel doctor \
  --provider holepunch \
  --url http://127.0.0.1:18080/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

Holepunch bridges do not expose a stable public hostname or edge header, so the
provider-hint check is informational. Use `tunnel_provider = "holepunch"` and
`tunnel_public_url = "http://127.0.0.1:18080/mcp"` in `snulbug.toml` when you
want audit events to carry explicit peer-bridge labels.

## What it checks

- the local URL, inferred from `snulbug.toml` when possible, accepts HTTP
  connections
- unauthenticated MCP requests are blocked with `401` or `403`
- authenticated `tools/list` round trips return MCP-shaped JSON
- public tunnel URLs also block unauthenticated traffic
- `snulbug.toml` keeps tunnel-safe defaults such as redacted records, response
  secret redaction, tool pinning, and schema validation
- `record_out` and `audit_out` grow after probes when configured
- provider hints are present when the selected provider exposes recognizable
  hostnames or response headers

Machine-readable output:

```bash
export TUNNEL_URL=https://YOUR-TUNNEL-FORWARDING-DOMAIN
snulbug tunnel doctor --url "${TUNNEL_URL}/mcp" --token local-dev-secret --compact
```

The compact JSON output contains `checks`, `summary`, `recommendations`, and the
raw HTTP `probes` used to make the decision. A failed check means the tunnel
should not be shared until the recommendation is addressed.

When the proxy handles real traffic, snulbug records provider-aware `tunnel`
fields in replay metadata, audit JSONL, and JSON decision-console output.

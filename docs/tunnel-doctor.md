# Tunnel doctor

`snulbug tunnel doctor` checks whether a local MCP policy proxy is safe to put
behind a public tunnel.

Run it against the local proxy before sharing a tunnel URL:

```bash
snulbug tunnel doctor \
  --config snulbug.toml \
  --token local-dev-secret
```

Run it against a public tunnel URL:

```bash
snulbug tunnel doctor \
  --provider ngrok \
  --url https://YOUR-TUNNEL.ngrok.app/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

For Cloudflare Access service-token protected apps, pass the Access headers:

```bash
snulbug tunnel doctor \
  --provider cloudflare \
  --url https://mcp.example.com/mcp \
  --config snulbug.toml \
  --header "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
  --header "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}" \
  --token local-dev-secret
```

For Tailscale Funnel, snulbug should still enforce bearer auth or leases:

```bash
snulbug tunnel doctor \
  --provider tailscale \
  --url https://HOST.TAILNET.ts.net/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

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
snulbug tunnel doctor --url https://YOUR-TUNNEL.example/mcp --token local-dev-secret --compact
```

The compact JSON output contains `checks`, `summary`, `recommendations`, and the
raw HTTP `probes` used to make the decision. A failed check means the tunnel
should not be shared until the recommendation is addressed.

# Expose

`snulbug expose` is the one-command planner for a tunnel-safe MCP exposure
session. It does not supervise long-running processes yet; it generates the
ordered commands and files needed to expose the snulbug proxy, verify the public
boundary, configure an MCP client, and write a session report.

Use it when you want the whole flow in one place:

```bash
uv run snulbug expose \
  --provider localxpose \
  --dry-run
```

The dry run prints the planned config path, proxy command, provider command,
doctor command, MCP client URL/header, and audit inspection command without
writing files.

To write the starter config and provider setup files:

```bash
uv run snulbug expose \
  --provider ngrok \
  --force
```

If no config exists, normal mode creates the same tunnel-safe starter files as
`snulbug tunnel init` under `.snulbug/configs`:

- `snulbug.toml`
- `policy.snulbug/`
- `traces/`
- provider setup files such as `ngrok-traffic-policy.yml`

## Public URL

For providers with generated public URLs, copy the exact HTTPS origin printed by
the provider and export the matching variable before running doctor:

```bash
export NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
export LOCALXPOSE_URL=https://YOUR-LOCALXPOSE-FORWARDING-DOMAIN
export PINGGY_URL=https://YOUR-PINGGY-FORWARDING-DOMAIN
export TAILSCALE_FUNNEL_URL=https://HOST.TAILNET.ts.net
export CLOUDFLARE_TUNNEL_URL=https://mcp.example.com
```

The generated doctor command appends `/mcp` itself.

## Compact Output

Agentic harnesses can consume the plan as JSON:

```bash
uv run snulbug expose \
  --provider localxpose \
  --dry-run \
  --compact
```

The compact output includes `commands`, `steps`, `client`, `files`, and the
nested provider `tunnel` plan.

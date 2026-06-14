# MCP share sessions

`snulbug mcp share` creates a bounded, ready-to-run local MCP share session.
It composes the existing quickstart, lease, tunnel-init, client-config, and
reporting pieces into one generated directory.

Use it when you want to give an agent or collaborator temporary access to a
local MCP server without hand-wiring every control.

```bash
uv run snulbug mcp share \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

By default, the command writes under `.snulbug/shares/share-*` and creates:

```text
policy.snulbug/
snulbug.toml
leases.json
mcp-client.json
SHARE.md
tunnel/
containers/
traces/
```

The generated policy uses a random bearer token unless `--token` is supplied.
The generated config sets `lease_required = true`, so every MCP `tools/call`
must carry the generated `x-snulbug-lease` token. The lease expires after the
configured `--ttl`.

## Generated workflow

Open the generated `SHARE.md`. It contains the exact commands for the session:

```bash
export SNULBUG_SHARE_TOKEN=...
uv run snulbug mcp proxy --config .snulbug/shares/share-*/snulbug.toml --decision-console
```

Run the generated provider command in another shell. For the default Holepunch
peer bridge, that is a Hypertele command from the generated `tunnel/` directory.

Before sharing `mcp-client.json`, run the generated doctor command:

```bash
uv run snulbug tunnel doctor \
  --provider holepunch \
  --url http://127.0.0.1:18080/mcp \
  --config .snulbug/shares/share-*/snulbug.toml \
  --token ${SNULBUG_SHARE_TOKEN}
```

## Client config

`mcp-client.json` contains the URL and headers for the client:

```json
{
  "mcpServers": {
    "snulbug-share": {
      "url": "http://127.0.0.1:18080/mcp",
      "headers": {
        "Authorization": "Bearer ...",
        "x-snulbug-lease": "..."
      }
    }
  }
}
```

Treat this file as secret-bearing material. It contains both the bearer token
and the lease token.

## Remote container as upstream

Every share also writes an optional `containers/` recipe for the containerized
facade case:

```text
containers/
  docker-compose.yml
  Dockerfile.gateway
  Dockerfile.remote-peer
  snulbug.local.toml
  snulbug.facade.toml
  policy.snulbug/
  leases.json
  mcp-client.facade.json
  mock_mcp_server.py
  mock_mcp_server.js
  snulbug-src/
  hypertele-server.json
  hypertele-client.json
```

The recipe models three services: a snulbug gateway, a local MCP container, and
a remote-by-peer MCP container reached through a managed Hypertele bridge. It
uses facade tool names such as `local.safe_read_file` and
`remote.safe_read_file`.

The normal share config remains at `snulbug.toml`. The container recipe has its
own facade config, policy, lease file, and MCP client config so experimenting
with container upstreams does not change the default share session.
The generated `Dockerfile.gateway` installs from `snulbug-src/`, a source
snapshot copied from the checkout that created the share, so it does not require
a published PyPI release.

Start from the generated local-only recipe first. This path does not install
Node, npm, or Hypertele in the snulbug gateway image:

```bash
cd .snulbug/shares/share-*/containers
docker compose up --build
```

Replace the placeholder peer material in `hypertele-server.json` and
`hypertele-client.json` before using the peer bridge outside local testing. For
the remote peer path, make Hypertele available to the gateway or run it as a
sidecar, then switch the gateway command from `snulbug.local.toml` to
`snulbug.facade.toml`.
Point clients at `mcp-client.facade.json` for this facade recipe.

## Public tunnel providers

The share command also works with existing tunnel providers:

```bash
uv run snulbug mcp share \
  --provider ngrok \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --ttl 30m
```

For public tunnel providers, expose the snulbug proxy, not the upstream MCP
server, and run the generated doctor command before sharing the client config.
Pass `--hostname` only when you have a reserved tunnel hostname; otherwise copy
the exact forwarding URL printed by the tunnel provider.

## Close out

When the task is complete:

```bash
uv run snulbug mcp evidence inspect .snulbug/shares/share-*/traces/audit.jsonl \
  --kind audit \
  --report-out .snulbug/shares/share-*/session-report.md

uv run snulbug mcp lease revoke LEASE_ID \
  --file .snulbug/shares/share-*/leases.json
```

Then stop the proxy and provider process. Delete the share directory when you no
longer need the local audit artifacts.

# MCP client setup recipes

These recipes show how to put `snulbug` between an MCP client and a local MCP
HTTP server or managed stdio server.

`snulbug` exposes one policy-controlled HTTP MCP endpoint to the client. Behind
that endpoint it can proxy to HTTP MCP servers or launch managed stdio MCP
servers through facade mode:

```text
MCP client
  -> snulbug reverse proxy
      -> local MCP HTTP server
      -> managed stdio MCP server
```

## 1. Ephemeral share session

Use this when you want one bounded session with generated bearer auth, a
task-scoped lease, provider setup, client config, and close-out commands:

```bash
uv run snulbug mcp share \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Open the generated `SHARE.md`, run the proxy/provider/doctor commands, then
copy the generated `mcp-client.json` into the MCP client. It contains both:

```text
Authorization: Bearer <generated token>
x-snulbug-lease: <generated lease token>
```

Treat `mcp-client.json` as secret-bearing material.

## 2. Local HTTP MCP client

Use this when the MCP client runs on the same machine as the local MCP server.

Create a policy and config:

```bash
uv run snulbug mcp init local-dev-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files

uv run snulbug mcp config init
```

Edit `snulbug.toml` so `upstream` points at the local MCP server:

```toml
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
redact_records = true
confirm = false
response_max_bytes = 262144
response_redact_secrets = true
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
```

Run the proxy:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Point the client at:

```text
http://127.0.0.1:8080/mcp
```

Set this HTTP header in the client:

```text
Authorization: Bearer local-dev-secret
```

If your client uses JSON config, the shape is usually equivalent to:

```json
{
  "mcpServers": {
    "local-policy-gateway": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {
        "Authorization": "Bearer local-dev-secret"
      }
    }
  }
}
```

Client config field names vary. The important parts are the URL and bearer
header.

## 3. Remote client through a tunnel

Use this when the MCP client cannot reach your laptop directly.

For public tunnel use, start from the `tunnel-safe` preset. It requires bearer
auth, rejects JSON-RPC batch requests, allows only configured safe tools, and
rate-limits traffic.

```bash
uv run snulbug mcp quickstart \
  --preset tunnel-safe \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --force
```

Run the proxy locally:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Expose the proxy, not the upstream MCP server:

```bash
uv run snulbug tunnel init \
  --provider ngrok
export SNULBUG_TOKEN=local-dev-secret
uv run snulbug mcp proxy --config .snulbug/configs/snulbug.toml --decision-console
ngrok http 8080 --traffic-policy-file .snulbug/configs/ngrok-traffic-policy.yml
```

Copy the exact `Forwarding` HTTPS URL printed by ngrok. Random free ngrok URLs
commonly use `ngrok-free.app`; do not rewrite them as `ngrok-free.ngrok.app`.

Test with curl before configuring a full MCP client:

```bash
NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
curl -sS "${NGROK_URL}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Verify the public tunnel before sharing it:

```bash
uv run snulbug tunnel doctor \
  --provider ngrok \
  --url "${NGROK_URL}/mcp" \
  --config .snulbug/configs/snulbug.toml \
  --token "${SNULBUG_TOKEN}"
```

Point the client at:

```text
https://YOUR-TUNNEL.example/mcp
```

Keep the same bearer header:

```text
Authorization: Bearer local-dev-secret
```

### Tailscale Funnel with bearer and leases

For Tailscale Funnel, keep the same snulbug defaults. Funnel exposes the local
snulbug proxy over public HTTPS; snulbug still enforces the MCP bearer token,
policy, audit log, and optional leases.

```bash
uv run snulbug mcp quickstart \
  --preset tunnel-safe \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --force

uv run snulbug mcp proxy --config snulbug.toml --decision-console

uv run snulbug tunnel init \
  --provider tailscale \
  --hostname HOST.TAILNET.ts.net \
  --config snulbug.toml \
  --output-dir tunnel.tailscale

sudo tailscale funnel 8080
```

The MCP client should use the Funnel URL and bearer header:

```text
https://HOST.TAILNET.ts.net/mcp
Authorization: Bearer local-dev-secret
```

The generated quickstart config keeps leases optional by default:

```toml
[mcp.proxy]
tunnel_provider = "tailscale"
tunnel_public_url = "https://HOST.TAILNET.ts.net/mcp"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
```

Mint a short-lived lease when an agent needs one bounded task:

```bash
uv run snulbug mcp lease create \
  --file leases.json \
  --task "Tailscale Funnel MCP session" \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Send the returned lease token as:

```text
x-snulbug-lease: <lease token>
```

Set `lease_required = true` when every `tools/call` through the Funnel should
carry an active lease. Before sharing the Funnel URL, run:

```bash
uv run snulbug tunnel doctor \
  --provider tailscale \
  --url https://HOST.TAILNET.ts.net/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

### Holepunch peer bridge with Hypertele

Use this when both sides can run a local sidecar and you want a private peer
bridge instead of a public tunnel URL. The MCP client talks to a local port on
the client machine; Hypertele carries traffic to snulbug on the developer
machine.

On the snulbug machine:

```bash
uv run snulbug mcp quickstart \
  --preset tunnel-safe \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --force

uv run snulbug tunnel init \
  --provider holepunch \
  --config snulbug.toml \
  --output-dir tunnel.holepunch

uv run snulbug mcp proxy --config snulbug.toml --decision-console
hypertele-server -l 8080 --address 127.0.0.1 -c tunnel.holepunch/hypertele-server.json --private
```

Replace the placeholder seed and peer keys in the generated Hypertele configs,
then run the client bridge on the MCP client machine:

```bash
hypertele -p 18080 -c hypertele-client.json --private
```

Point the MCP client at the local bridge:

```text
http://127.0.0.1:18080/mcp
Authorization: Bearer local-dev-secret
```

Use explicit audit labels in `snulbug.toml`:

```toml
[mcp.proxy]
tunnel_provider = "holepunch"
tunnel_public_url = "http://127.0.0.1:18080/mcp"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
```

Mint a lease the same way as the public tunnel recipes:

```bash
uv run snulbug mcp lease create \
  --file leases.json \
  --task "Holepunch MCP peer session" \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Run doctor from a machine where the client-side bridge is listening:

```bash
uv run snulbug tunnel doctor \
  --provider holepunch \
  --url http://127.0.0.1:18080/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

For public tunnels, treat `tunnel-safe` as the recommended default. Do not expose
the `tool-allowlist` preset by itself unless another tunnel or network layer
already authenticates callers and rejects abusive traffic.

## 4. Observe a client session

Run the proxy with the decision console:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

The console prints one redacted decision per request, including the MCP method,
tool or target, JSON-RPC id, action, and reason code.

After the session, inspect the captured logs:

```bash
uv run snulbug mcp inspect traces/session.jsonl
uv run snulbug mcp inspect traces/audit.jsonl --kind audit
```

Replay records are redacted by default. If you need exact replay for a local
debug session, opt in explicitly:

```bash
uv run snulbug mcp proxy --config snulbug.toml --no-redact-records
```

Exact replay records can contain bearer tokens, cookies, API keys, and tool
arguments.

## 5. Tighten tool access for one client

Start with the tools the client should actually call:

```bash
uv run snulbug mcp init local-dev-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool read_repo \
  --allow-tool search_docs \
  --rate-limit 30 \
  --rate-window 60 \
  --force
```

Validate before proxying:

```bash
uv run snulbug bundle validate policy.snulbug
uv run snulbug bundle test policy.snulbug
```

Denied tool calls return `reason_code = "mcp.tool_not_allowed"` and appear in
audit logs and offline inspection findings.

## 6. Client cannot set HTTP headers

Prefer a client or adapter that can send an `Authorization` header. If that is
not possible, keep the proxy bound to `127.0.0.1` and avoid public tunnels.

For a loopback-only workflow, you can use `tool-allowlist`:

```bash
uv run snulbug mcp init tool-allowlist \
  --output policy.snulbug \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

This does not authenticate callers. It should be paired with local-only network
binding or another trusted access-control layer.

## 7. Upstream server only supports stdio

Use this when the MCP server you want to protect is normally launched as a stdio
process, or when it is reachable through a supervised Holepunch peer bridge.
Configure it as a managed facade upstream:

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
confirm = false
response_max_bytes = 262144
response_redact_secrets = true
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"

[[mcp.proxy.upstreams]]
name = "files"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "."]

[[mcp.proxy.upstreams]]
name = "git"
transport = "stdio"
command = "uvx"
args = ["mcp-server-git"]

[[mcp.proxy.upstreams]]
name = "remote-devbox"
transport = "holepunch"
peer = "SERVER_PEER_KEY"
local_port = 19100
tool_prefix = "devbox."
```

Run the proxy:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Point the client at the single facade endpoint:

```text
http://127.0.0.1:8080/mcp
```

The client sees namespaced tools such as `files.read_file`, `git.status`, and
`devbox.read_file`. `tools/list` is aggregated across the configured upstreams
and `tools/call` is routed back to the matching local process or peer bridge.

## 8. Container facade with a remote peer upstream

Use this when the snulbug gateway and MCP upstreams run as containers, and one
upstream is on another machine or container host reachable through a Holepunch
peer bridge.

The share command writes a ready-to-edit compose recipe under
`.snulbug/shares/share-*/containers/`:

```bash
uv run snulbug mcp share \
  --provider holepunch \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m

cd .snulbug/shares/share-*/containers
docker compose up --build
```

The default command starts one `snulbug-gateway` service and one `local-mcp`
service without installing Node, npm, or Hypertele in the gateway image. The
recipe also includes a `remote-by-peer-mcp` service and `snulbug.facade.toml` for
the peer-bridge variant. That facade config exposes prefixed tools such as
`local.safe_read_file` and `remote.safe_read_file`, and the generated
`mcp-client.facade.json` contains the bearer and lease headers for that session.

For a checked-in version of the same shape, see
[`examples/mcp_container_facade`](../examples/mcp_container_facade/README.md).

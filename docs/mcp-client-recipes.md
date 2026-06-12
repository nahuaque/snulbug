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

## 1. Local HTTP MCP client

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

## 2. Remote client through a tunnel

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
  --provider ngrok \
  --hostname YOUR-TUNNEL.ngrok.app \
  --config snulbug.toml
ngrok http 8080 --url https://YOUR-TUNNEL.ngrok.app --traffic-policy-file ngrok-traffic-policy.yml
```

Verify the public tunnel before sharing it:

```bash
uv run snulbug tunnel doctor \
  --provider ngrok \
  --url https://YOUR-TUNNEL.ngrok.app/mcp \
  --config snulbug.toml \
  --token local-dev-secret
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

For public tunnels, treat `tunnel-safe` as the recommended default. Do not expose
the `tool-allowlist` preset by itself unless another tunnel or network layer
already authenticates callers and rejects abusive traffic.

## 3. Observe a client session

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

## 4. Tighten tool access for one client

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

## 5. Client cannot set HTTP headers

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

## 6. Upstream server only supports stdio

Use this when the MCP server you want to protect is normally launched as a stdio
process. Configure it as a managed facade upstream:

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
```

Run the proxy:

```bash
uv run snulbug mcp proxy --config snulbug.toml --decision-console
```

Point the client at the single facade endpoint:

```text
http://127.0.0.1:8080/mcp
```

The client sees namespaced tools such as `files.read_file` and `git.status`.
`tools/list` is aggregated across the configured upstreams and `tools/call` is
routed back to the matching stdio process.

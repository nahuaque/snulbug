# MCP client setup recipes

These recipes show how to put `snulbug` between an MCP client and a local MCP
HTTP server.

`snulbug` does not implement MCP and does not translate stdio to HTTP. It is a
policy gateway for HTTP JSON-RPC traffic:

```text
MCP client
  -> snulbug reverse proxy
      -> local MCP HTTP server
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
ngrok http 8080
```

Point the client at:

```text
https://YOUR-TUNNEL.example/mcp
```

Keep the same bearer header:

```text
Authorization: Bearer local-dev-secret
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

## 6. Client only supports stdio MCP servers

Some MCP clients only launch stdio servers. `snulbug` does not bridge stdio to
HTTP. Use one of these patterns instead:

- Run an HTTP-capable MCP server upstream and configure the client to use its
  HTTP transport through `snulbug`.
- Use a separate stdio-to-HTTP bridge, then put `snulbug` between the bridge and
  the HTTP MCP server.
- Keep stdio-only tools outside `snulbug` and use `snulbug` only for HTTP MCP
  endpoints that need local policy, audit, replay, and inspection.

# End-to-end ngrok MCP gateway

This walkthrough exercises the full public tunnel path:

```text
curl or MCP client
  -> ngrok public Cloud Endpoint
  -> ngrok Traffic Policy
  -> forward-internal to snulbug-mcp.internal
  -> local snulbug gateway on 127.0.0.1:8080
  -> demo MCP upstream on 127.0.0.1:9000
```

It uses the checked-in demo MCP upstream and a generated `tunnel-safe` share
session with bearer auth, a task lease, replay logs, audit logs, and an ngrok
Cloud Endpoint Traffic Policy.

## Prerequisites

- ngrok v3 is installed and authenticated.
- You have a public ngrok Cloud Endpoint, such as
  `https://example.ngrok-free.dev`.
- You are running from the snulbug source repo with `uv sync` completed.

Set the public origin first. Use `export`; an inline assignment such as
`NGROK_PUBLIC_ORIGIN=... curl "${NGROK_PUBLIC_ORIGIN}/mcp"` will expand the URL
before the variable exists in the shell.

```bash
export NGROK_PUBLIC_ORIGIN="https://YOUR-NGROK-CLOUD-ENDPOINT"
```

## 1. Start the demo MCP upstream

Terminal 1:

```bash
uv run python examples/mcp_proxy_demo/upstream.py --host 127.0.0.1 --port 9000
```

Expected output:

```text
demo MCP upstream listening on http://127.0.0.1:9000/mcp
```

## 2. Create the ngrok share

Terminal 2:

```bash
uv run snulbug mcp share create \
  --directory .snulbug/shares/ngrok-demo \
  --provider ngrok \
  --url "${NGROK_PUBLIC_ORIGIN}/mcp" \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 2h \
  --force
```

The share writes the important files here:

```text
.snulbug/shares/ngrok-demo/snulbug.toml
.snulbug/shares/ngrok-demo/mcp-client.json
.snulbug/shares/ngrok-demo/tunnel/ngrok-agent.yml
.snulbug/shares/ngrok-demo/tunnel/ngrok-traffic-policy.yml
```

`mcp-client.json` contains the bearer token and lease token for the generated
session. Treat it as secret-bearing material.

## 3. Export the generated client headers

The generated share requires both bearer auth and an `x-snulbug-lease` header
for `tools/call`.

```bash
export SNULBUG_TOKEN="$(uv run python -c 'import json; h=json.load(open(".snulbug/shares/ngrok-demo/mcp-client.json"))["mcpServers"]["snulbug-share"]["headers"]; print(h["Authorization"].split(" ", 1)[1])')"

export SNULBUG_LEASE="$(uv run python -c 'import json; h=json.load(open(".snulbug/shares/ngrok-demo/mcp-client.json"))["mcpServers"]["snulbug-share"]["headers"]; print(h["x-snulbug-lease"])')"

printf 'token length: %s\nlease length: %s\n' "${#SNULBUG_TOKEN}" "${#SNULBUG_LEASE}"
```

If the token length is `0`, ngrok's Traffic Policy will return a bare `401`
before the request reaches snulbug.

## 4. Start snulbug

Terminal 2:

```bash
uv run snulbug mcp share run .snulbug/shares/ngrok-demo
```

Leave this process running. Successful requests print decision lines such as
`snulbug decision=...`.

## 5. Start the ngrok internal Agent Endpoint

Terminal 3:

```bash
ngrok start --config .snulbug/shares/ngrok-demo/tunnel/ngrok-agent.yml --all
```

The local ngrok status should show the private internal endpoint, not the public
origin:

```text
Forwarding  https://snulbug-mcp.internal -> http://127.0.0.1:8080
```

That is expected. The public URL is the Cloud Endpoint managed in the ngrok
dashboard. The local agent only connects the private `.internal` endpoint to
the local snulbug gateway.

## 6. Attach the Traffic Policy

In the ngrok dashboard, open the public Cloud Endpoint matching
`NGROK_PUBLIC_ORIGIN` and attach:

```text
.snulbug/shares/ngrok-demo/tunnel/ngrok-traffic-policy.yml
```

The generated Traffic Policy performs coarse MCP checks, then forwards allowed
traffic to the private internal endpoint:

```yaml
type: forward-internal
config:
  url: "https://snulbug-mcp.internal"
```

## 7. Verify local snulbug first

Before debugging ngrok, verify the local gateway:

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "x-snulbug-lease: ${SNULBUG_LEASE}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"local-safe","method":"tools/call","params":{"name":"safe_read_file","arguments":{"path":"README.md"}}}'
```

Expected result: `HTTP/1.1 200 OK` with demo file content.

## 8. Verify the public Cloud Endpoint

Allowed request:

```bash
curl -i "${NGROK_PUBLIC_ORIGIN}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "x-snulbug-lease: ${SNULBUG_LEASE}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"safe","method":"tools/call","params":{"name":"safe_read_file","arguments":{"path":"README.md"}}}'
```

Expected result: `HTTP/2 200` with a JSON-RPC result from `safe_read_file`.

Blocked request:

```bash
curl -i "${NGROK_PUBLIC_ORIGIN}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "x-snulbug-lease: ${SNULBUG_LEASE}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"blocked","method":"tools/call","params":{"name":"shell_exec","arguments":{"cmd":"whoami"}}}'
```

Expected result: snulbug rejects the request before it reaches the upstream.
The snulbug terminal should print a blocked decision with the MCP tool name.

## 9. Inspect the session

```bash
uv run snulbug mcp share status .snulbug/shares/ngrok-demo

uv run snulbug mcp share doctor .snulbug/shares/ngrok-demo \
  --url "${NGROK_PUBLIC_ORIGIN}/mcp"

uv run snulbug mcp share report .snulbug/shares/ngrok-demo \
  --output .snulbug/shares/ngrok-demo/report.md \
  --force
```

The report summarizes what was exposed, which requests were allowed or blocked,
the active lease, upstream health, and next commands.

## Troubleshooting

Bare `HTTP/2 401` with `content-length: 0` usually means ngrok's Traffic Policy
blocked the request before snulbug saw it. Check that `Authorization` is present
and that `SNULBUG_TOKEN` is not empty.

`curl: (3) URL rejected: No host part` usually means the public origin variable
was assigned inline with the curl command. Use `export NGROK_PUBLIC_ORIGIN=...`
before running curl.

If the ngrok status only shows `https://snulbug-mcp.internal`, that is normal
for the Cloud Endpoint plus internal Agent Endpoint pattern. Attach the
generated Traffic Policy to the public Cloud Endpoint in the ngrok dashboard.

If local curl works but public curl fails, the problem is the ngrok Cloud
Endpoint, Traffic Policy attachment, or internal endpoint forwarding. If local
curl fails, fix the upstream, snulbug process, bearer token, or lease first.

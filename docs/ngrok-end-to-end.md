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
snulbug mcp share create \
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

Before running the share, replace `YOUR_NGROK_AUTHTOKEN` in
`tunnel/ngrok-agent.yml` with the agent credential for your account, or complete
the generated config's instructions for using your existing ngrok v3 config.
Authenticating a different ngrok config does not fill in this placeholder.
Protect the generated share directory and agent config; they contain secrets.

### Optional: Share a Webapp on the Same Tunnel

To expose an app on port 3000, add this flag to the `share create` command in
step 2 before creating the share:

```bash
--http-route /app=http://127.0.0.1:3000
```

The generated gateway config and ngrok Traffic Policy now allow `/app` and
`/app/...` alongside `/mcp`. After starting the app, gateway, and ngrok and
attaching the generated policy, test both hops without MCP credentials:

```bash
curl -i http://127.0.0.1:8080/app/
curl -i "${NGROK_PUBLIC_ORIGIN}/app/"
```

The route strips `/app` before forwarding, so the app receives `/`. Configure
its public base path as `/app/` for asset links and redirects. App traffic
bypasses all MCP authentication/policy/recording; the app owns its authentication.
Declare each mount's `auth` owner in generated TOML before doctor/readiness;
MCP authentication and leases do not protect these routes. See
[shared HTTP routes](mcp-proxy.md#shared-http-routes) for multiple backends
and preserving prefixes. Existing shares need both a TOML route and an updated
Cloud Endpoint Traffic Policy; changing TOML alone leaves ngrok's old deny rule
in effect.

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
snulbug mcp share run .snulbug/shares/ngrok-demo
```

This starts the gateway, the managed ngrok internal Agent Endpoint, and the
local share console at `http://127.0.0.1:8765`. ngrok uses the existing generated
`tunnel/ngrok-agent.yml`; no second agent command is needed. Leave this process
running. Successful requests print decision lines such as
`snulbug decision=...`.

For headless operation, append `--no-console`. This disables only the UI;
ngrok still starts and receives bounded crash supervision. The console's
**Start tunnel** and **Stop tunnel** controls operate on the same managed
process. Stopping it intentionally keeps it stopped until an explicit start.
See [Always-on share runtime](always-on-runtime.md)
for retry settings, shutdown ordering, and OS supervisor recipes. Neither the
share console nor ngrok's local inspection UI should be exposed publicly.

## 5. Inspect the ngrok internal Agent Endpoint

Use the share console's tunnel-provider panel and the local ngrok inspection
UI at `http://127.0.0.1:4040`. The local ngrok status should show the private
internal endpoint, not the public origin:

```text
Forwarding  https://snulbug-mcp.internal -> http://127.0.0.1:8080
```

That is expected. The public URL is the Cloud Endpoint managed in the ngrok
dashboard. The local agent only connects the private `.internal` endpoint to
the local snulbug gateway. A running agent is not proof of public reachability
or a correctly attached Traffic Policy; complete the doctor and public checks
below.

### Optional: Start ngrok manually

If you prefer to manage the agent separately, replace the command in step 4
with:

```bash
snulbug mcp share run .snulbug/shares/ngrok-demo --no-tunnel
```

`--no-tunnel` disables automatic startup, not the console. Its **Start tunnel**
button can still start a managed agent explicitly, so do not use it while your
external agent owns the endpoint.

Terminal 3:

```bash
ngrok start --config .snulbug/shares/ngrok-demo/tunnel/ngrok-agent.yml --all
```

Do not run this command alongside the automatically managed agent. Stop the
external agent separately when finished; snulbug does not supervise it.

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
snulbug mcp share status .snulbug/shares/ngrok-demo

snulbug mcp share doctor .snulbug/shares/ngrok-demo \
  --url "${NGROK_PUBLIC_ORIGIN}/mcp"

snulbug mcp share report .snulbug/shares/ngrok-demo \
  --output .snulbug/shares/ngrok-demo/report.md \
  --force
```

The report summarizes what was exposed, which requests were allowed or blocked,
the active lease, upstream health, and next commands.

### Check for configuration drift

The existing `share doctor` also compares the current snulbug configuration,
generated `tunnel/ngrok-traffic-policy.yml`, and deployed Cloud Endpoint policy.
Install the YAML parser with `uv tool install 'snulbug[discovery]'` (or
`uv sync --extra discovery` in the source checkout).

For cloud inspection, supply `NGROK_API_KEY` to the doctor process or to the
`share run` service that hosts the console. This is an ngrok **API key**, not
the agent authtoken. Keep it in your service's secret environment, not source
control, command arguments, or generated client snippets. No key is needed
for the local policy comparison.

Optionally select a Cloud Endpoint by ID and/or use the existing credential
broker configuration in the share's `snulbug.toml`:

```toml
[mcp.ngrok]
endpoint_id = "ep_REPLACE_WITH_YOUR_ENDPOINT_ID"

[mcp.ngrok.api_credential]
type = "env"
env = "NGROK_API_KEY"
```

Omit `endpoint_id` to find a unique active endpoint matching the public origin.
For a file credential instead, use `type = "file"` and `path = "ngrok-api-key"`;
relative paths resolve beside `snulbug.toml`. Protect that file with mode `0600`.
Existing credential broker plugins can also supply the reference.

Run the doctor command above, or **Run doctor** in the console. The Tunnel
Provider panel shows the saved ngrok drift result, changed field paths, and a
desired policy baseline for manual review. The session report includes the
same check results. Changing local inputs invalidates the saved inspection.
Console refresh and ordinary health checks never poll the ngrok cloud API.

Inspection checks the endpoint's public origin, Cloud Endpoint type, public
binding, internal forwarding target, MCP path, HTTP mounts, and coarse edge
guards. OAuth baselines allow protected-resource metadata and leave token
challenges to snulbug, including DPoP. Rules and expression order matter;
rule names, whitespace, comments, and mapping key order do not. This is a
structural baseline comparison, not a proof that custom CEL expressions are
semantically equivalent. Intentional custom policy differences still need review.

Missing credentials, unavailable YAML support, and disabled cloud checks are
reported as unchecked, never as a deployed-policy match. `--no-live-checks`
disables this cloud inspection and does not resolve the API credential.
An inaccessible API or ambiguous endpoint selection cannot produce a pass.
Cloud results are point-in-time evidence: rerun doctor after dashboard changes.

The integration only makes bounded HTTPS GET requests to the
[ngrok Endpoints API](https://ngrok.com/docs/api-reference/endpoints/get).
It does not create, update, or delete endpoints. Reports contain digests and
safe field paths, never deployed policy values or API keys. Review your custom
rules before copying the desired baseline to the generated file and attaching
it to the Cloud Endpoint in ngrok; snulbug never applies it automatically.

Send SIGTERM or press Ctrl-C in the `share run` terminal to stop the gateway.
Uvicorn drains requests and streams up to the configured deadline, cancels
remaining work, then the runtime stops managed ngrok. If you chose the manual
path, stop that ngrok process separately. See [MCP share sessions](mcp-share.md)
for lease revocation and closeout reporting.

## Troubleshooting

If managed ngrok does not start, check the service account's `PATH`, the agent
config's authtoken placeholder, and whether another ngrok process already owns
the endpoint. After the bounded crash retry budget is exhausted, fix the cause
and use **Start tunnel** in the console or restart `share run`. The runtime
never retries MCP tool calls during restart or shutdown.

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

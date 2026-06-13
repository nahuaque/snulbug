# MCP reverse proxy

Reverse proxy mode lets `snulbug` protect a local MCP HTTP server even when the
server is not a Python ASGI app.

Install the proxy runner from this repository with `uv`:

```bash
uv sync
uv run snulbug --help
```

Or add the current GitHub source to another `uv` project:

```bash
uv add "snulbug[discovery] @ git+https://github.com/lbruhacs/snulbug"
```

Copy a starter policy. For public tunnel use, `tunnel-safe` is the recommended
default:

```bash
uv run snulbug mcp init tunnel-safe --output policy.snulbug
```

Or generate one with project-specific values:

```bash
uv run snulbug mcp init tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Write a starter config:

```bash
uv run snulbug mcp config init
```

Run the proxy:

```bash
uv run snulbug mcp proxy --config snulbug.toml
```

For concrete MCP client configuration patterns, see
[MCP client setup recipes](mcp-client-recipes.md).

For a generated temporary bearer/lease share directory, see
[MCP share sessions](mcp-share.md).

For a runnable upstream-plus-proxy walkthrough, see the
[end-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md).

Point ngrok, Cloudflare Tunnel, Tailscale Funnel, LocalXpose, or a private
Holepunch peer bridge at `http://127.0.0.1:8080`. The proxy applies the Lua
policy before forwarding to the upstream server. Use `tunnel-safe` unless you
have a stronger external access-control layer in front of the tunnel or peer
bridge.

Generate provider-specific tunnel setup files first. If no config exists,
snulbug writes a starter config, policy bundle, traces directory, and provider
files under `.snulbug/configs`:

```bash
uv run snulbug tunnel init \
  --provider ngrok
export SNULBUG_TOKEN=local-dev-secret
uv run snulbug mcp proxy --config .snulbug/configs/snulbug.toml --decision-console
ngrok http 8080 --traffic-policy-file .snulbug/configs/ngrok-traffic-policy.yml
```

Copy the exact `Forwarding` HTTPS URL printed by ngrok. Random free ngrok URLs
commonly use domains such as `ngrok-free.dev` or `ngrok-free.app`; do not
rewrite them into an `ngrok.app` hostname.

```bash
NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN
```

Use curl as a minimal MCP client to check the local proxy before exposing it:

```bash
curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Then check the public tunnel:

```bash
curl -sS "${NGROK_URL}/mcp" \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":"tools-list","method":"tools/list","params":{}}'
```

Before sharing the public URL, verify that the tunnel reaches snulbug and that
unauthenticated MCP traffic is blocked:

```bash
snulbug tunnel doctor \
  --provider ngrok \
  --url "${NGROK_URL}/mcp" \
  --config .snulbug/configs/snulbug.toml \
  --token "${SNULBUG_TOKEN}"
```

See [Tunnel init](tunnel-init.md) and [Tunnel doctor](tunnel-doctor.md) for
Cloudflare Access, Tailscale Funnel, LocalXpose, and Holepunch peer bridge
variants.

`--record-out` writes replayable request records for traffic that passes through
the proxy. `--audit-out` writes redacted audit events. Rejected/challenged
requests are recorded too, not only requests forwarded upstream.

Print live policy decisions while the proxy is running:

```bash
snulbug mcp proxy --config snulbug.toml --decision-console
snulbug mcp proxy --config snulbug.toml --decision-console --decision-console-format json
```

The text console is optimized for watching local tunnel traffic. The JSON format
emits redacted audit-shaped events that can be piped into local tools. Audit
events include MCP-aware fields such as JSON-RPC id, MCP method, operation,
target tool/resource/prompt, params key names, argument key names, initialize
client metadata, tunnel provider metadata, and policy decision `reason` /
`reason_code`.

Replay captured traffic against the same policy or a candidate policy:

```bash
snulbug mcp replay traces/session.jsonl
snulbug mcp replay traces/session.jsonl --script candidate.lua
```

Inspect a session after the proxy stops:

```bash
snulbug mcp inspect traces/session.jsonl
snulbug mcp inspect traces/audit.jsonl --kind audit
snulbug mcp inspect traces/audit.jsonl --kind audit --report-out traces/session-report.md
```

Live replay records are redacted by default. Use `--no-redact-records` only when
you need exact auth-sensitive replay artifacts.

CLI flags override config values:

```bash
snulbug mcp proxy --config snulbug.toml --port 8181 --no-trace
```

For facade mode, the proxy can hot-reload upstream routes from the declarative
fabric config while it is running:

```bash
snulbug mcp proxy \
  --config snulbug.toml \
  --reload-fabric \
  --fabric-reload-interval 2
```

On each reload check, snulbug re-reads `[mcp.fabric]`, discovery providers, and
`[[mcp.proxy.upstreams]]`. If the route table changed, new requests use the new
upstreams without restarting uvicorn. In-flight requests keep the route snapshot
they started with. If the config is temporarily invalid while you are editing
it, the proxy keeps serving the previous route table and records the reload
error in live replay/audit metadata.

Example config:

```toml
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
redact_records = true
decision_console = false
decision_console_format = "text"
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
tunnel_provider = "auto"
tunnel_public_url = ""
cloudflare_access = "off"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = false
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_emails = []
cloudflare_access_allowed_domains = []
timeout = 30.0
```

`tunnel_provider` can be `auto`, `generic`, `ngrok`, `cloudflare`, `tailscale`,
`localxpose`, or `holepunch`. With `auto`, snulbug infers the provider from
request headers and the public host when possible. Set `tunnel_public_url` when
you want audit logs to record the externally shared MCP URL or client-side peer
bridge URL even if the request reaches snulbug through a local reverse proxy.

## Cloudflare Access Adapter

When snulbug is the origin behind Cloudflare Access, it can audit or enforce the
Access headers that Cloudflare forwards after an Access policy succeeds.

```toml
[mcp.proxy]
tunnel_provider = "cloudflare"
tunnel_public_url = "https://mcp.example.com/mcp"
cloudflare_access = "enforce"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = true
cloudflare_access_allowed_domains = ["example.com"]
```

`cloudflare_access` can be:

- `off`: ignore Access headers.
- `audit`: record what would have been blocked but allow the request.
- `enforce`: reject requests before Lua policy and upstream forwarding when
  required Access headers or allowlist checks are missing.

The adapter records redacted `cloudflare_access` audit fields including mode,
email, email domain, `CF-Ray`, country, decision, and `reason_code`. It never
stores the raw `CF-Access-Jwt-Assertion`, and it strips Access credential
headers before forwarding to the local upstream.

This is an origin-side defense, not a replacement for Cloudflare Access policy
configuration. snulbug checks that expected Access headers are present and
match local allowlists; it does not cryptographically validate the Access JWT in
this first adapter.

## Task-Scoped Leases

Leases give a client temporary MCP capabilities for one named task. A lease can
allow exact tools, path prefixes, URL hosts, command names, and a maximum number
of `tools/call` uses. The lease file stores token hashes only; the plaintext
token is shown once when the lease is created.

Create a lease:

```bash
snulbug mcp lease create \
  --file leases.json \
  --task "Read README before editing docs" \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --ttl 30m \
  --max-calls 5
```

Send the returned `x-snulbug-lease` header with MCP requests. The proxy hot-loads
the JSON file on each call, so new leases and revocations do not require a proxy
restart.

Require leases for every MCP tool call:

```toml
[mcp.proxy]
lease_file = "leases.json"
lease_required = true
lease_header = "x-snulbug-lease"
```

Useful operations:

```bash
snulbug mcp lease list --file leases.json
snulbug mcp lease revoke lease_abc123 --file leases.json
```

Preview whether a lease covers captured traffic before requiring it:

```bash
snulbug mcp impact traces/session.jsonl --lease leases.json --report-out traces/impact-report.md
```

In facade mode, leases use the client-facing tool name, such as
`files.read_file` or `git.status`.

## Argument Schema Firewall

When `schema_validation = true`, snulbug learns each MCP tool's `inputSchema`
from successful `tools/list` responses and validates later `tools/call`
`params.arguments` before forwarding the call upstream. This blocks malformed or
unexpected arguments at the proxy boundary, including missing required fields,
wrong primitive types, disallowed enum values, invalid string lengths/patterns,
oversized arrays, and extra properties when the schema sets
`additionalProperties = false`.

Calls pass through until a schema has been observed, so clients that call a tool
before listing tools are not broken. In facade mode, schemas are stored under the
client-facing prefixed tool names such as `files.read_file`.

```toml
[mcp.proxy]
schema_validation = true
schema_validation_action = "block"
```

Use warn mode while introducing the proxy to an existing workflow:

```bash
snulbug mcp proxy --config snulbug.toml --schema-validation-action warn
```

Schema snapshots live in the configured state adapter. Use SQLite if you want
learned schemas to survive proxy restarts.

## Response Controls

Request policy runs before upstream calls. The proxy also applies MCP-aware
return-path controls to successful JSON-RPC responses:

- `response_max_bytes` blocks oversized `tools/call`, `resources/read`, and
  `prompts/get` responses with a JSON-RPC error.
- `response_redact_secrets` redacts high-confidence bearer tokens, API keys,
  GitHub tokens, AWS access keys, and secret-shaped JSON fields from MCP
  results before they reach the client.
- `response_block_instructions` blocks tool/resource/prompt results that contain
  instruction-like phrases such as "ignore previous instructions". It is off by
  default because local files may legitimately contain security examples or
  prompt text.
- `tool_pinning` hashes `tools/list` names, descriptions, and input schemas on
  first sight. With `tool_pinning_action = "block"`, a later silent description
  or schema change is rejected until the proxy state is reset or reviewed.

Tool pins live in the configured state adapter. The default in-memory state pins
for the current proxy process. SQLite-backed state keeps pins across restarts:

```toml
[mcp.proxy]
state = "sqlite:policy-state.sqlite3"
tool_pinning = true
tool_pinning_action = "block"
```

CLI overrides:

```bash
snulbug mcp proxy --config snulbug.toml --response-max-bytes 131072
snulbug mcp proxy --config snulbug.toml --response-block-instructions
snulbug mcp proxy --config snulbug.toml --tool-pinning-action warn
```

## Human Confirmation

Policies can return `action = "confirm"` for risky calls that should not be
always allowed or always blocked. The proxy fails closed unless confirmation is
explicitly enabled:

```bash
snulbug mcp proxy --config snulbug.toml --confirm
```

Example policy fragment:

```lua
if mcp.tool_name(request) == "shell_exec" then
  return {
    action = "confirm",
    prompt = "Allow shell_exec for this session?",
    remember_key = "tool:shell_exec",
    timeout_seconds = 30,
    status = 403,
    body = "confirmation denied",
    reason = "Shell-like tool requires approval",
    reason_code = "mcp.confirm.risky_tool"
  }
end
```

The interactive prompt supports:

- `o`: allow once
- `a`: allow for this proxy session when `remember_key` is set
- `d`: deny

Timeouts, non-interactive stdin, and disabled confirmation all reject the
request. Replay and audit records include the confirmation result.

## MCP Facade Mode

Facade mode lets one `snulbug` proxy present several local MCP HTTP, stdio, or
Holepunch-bridged MCP servers as a single client-facing HTTP endpoint. It is
intentionally small:
`tools/list` is fanned out to every upstream and returned as one list with tool
names prefixed by upstream name; `tools/call` is routed by that prefix and the
prefix is stripped before the call reaches the upstream server. Other JSON-RPC
methods are sent to the default upstream.

Example config:

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"
decision_console = true

[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
default = true

[[mcp.proxy.upstreams]]
name = "git"
url = "http://127.0.0.1:9002/mcp"
```

The client sees tools such as `files.read_file` and `git.status`. A call to
`git.status` is forwarded to the `git` upstream as `status`.

Enable health-driven routing when one facade fronts optional or remote
upstreams and a failing member should not break the whole tool surface:

```toml
[mcp.proxy]
facade_health_routing = true
facade_health_failure_threshold = 2
facade_health_cooldown_seconds = 30.0
facade_health_exclude_unhealthy = true
```

With health routing enabled, facade mode tracks upstream failures from
`tools/list`, `tools/call`, default routed methods, connection errors, invalid
tool-list responses, and HTTP 5xx responses. An upstream moves from `healthy` to
`degraded`, then to `unhealthy` after the configured consecutive failure
threshold. Unhealthy upstreams are skipped for fanout and tool routing until the
cooldown expires, at which point the next request probes the upstream and marks
it recovered on success. Replay and audit metadata include `upstream_health`
with the skipped upstreams, failures, current status, and control-plane event
types.

You can also start facade mode directly from the CLI:

```bash
snulbug mcp proxy \
  --policy policy.snulbug/policy.lua \
  --facade-upstream files=http://127.0.0.1:9001/mcp \
  --facade-upstream git=http://127.0.0.1:9002/mcp \
  --facade-health-routing
```

Use `tool_prefix` when you want a different namespace:

```toml
[[mcp.proxy.upstreams]]
name = "repo"
url = "http://127.0.0.1:9002/mcp"
tool_prefix = "git."
```

Replay records include facade metadata such as selected upstream, upstream
transport, original tool name, and upstream tool name for routed calls. Audit
events promote the same upstream identity into a top-level `facade` field so a
session report can show which local, stdio, or peer-bridged server handled each
decision.

### Signed upstream manifests

Signed upstream manifests let facade mode fail closed when an upstream identity
or advertised capability document changes unexpectedly. This is useful when one
gateway fronts multiple local, containerized, or peer-bridged MCP servers and you
want audit records to carry a verified upstream identity instead of only a local
config name.

Create an unsigned JSON manifest:

```json
{
  "schema": "snulbug.upstream-manifest.v1",
  "identity": "files@local",
  "transport": "http",
  "tool_prefix": "files.",
  "labels": {
    "owner": "local-dev"
  },
  "tools": [
    {
      "name": "read_file",
      "description": "Read a project file"
    }
  ]
}
```

Sign and verify it with a shared secret kept outside the file:

```bash
export SNULBUG_MANIFEST_SECRET="replace-with-a-local-secret"
snulbug mcp manifest sign manifests/files.json \
  --out manifests/files.signed.json \
  --key-id dev
snulbug mcp manifest verify manifests/files.signed.json \
  --expect-identity files@local
```

Then require that manifest for the facade upstream:

```toml
[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
tool_prefix = "files."
manifest = "manifests/files.signed.json"
manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
manifest_identity = "files@local"
```

On startup, snulbug verifies the manifest HMAC-SHA256 signature, digest, key id,
and optional expected identity. Replay records and audit events include only
safe manifest metadata: identity, digest, key id, schema, transport, tool prefix,
tool count, labels, path, and whether the manifest was required. The signing
secret is never written into record or audit metadata.

### Managed stdio upstreams

Use `transport = "stdio"` when an MCP server is normally launched as a local
stdio process. `snulbug` starts the process on first use, sends newline-delimited
JSON-RPC over stdin/stdout, serializes requests per process, and exposes the
server through the same HTTP facade endpoint.

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080

[[mcp.proxy.upstreams]]
name = "files"
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
default = true

[[mcp.proxy.upstreams]]
name = "git"
transport = "stdio"
command = "uvx"
args = ["mcp-server-git"]
```

The client still connects to `http://127.0.0.1:8080/mcp` and sees namespaced
tools such as `files.read_file` and `git.status`.

Optional stdio fields:

```toml
cwd = "/path/to/project"
env = { MCP_LOG_LEVEL = "error" }
tool_prefix = "repo."
```

Only configure commands you trust. The process runs locally with the configured
command, arguments, working directory, and environment.

### Holepunch upstreams

Use `transport = "holepunch"` when an upstream MCP server is reachable through a
Holepunch/Hypertele peer bridge. `snulbug` supervises the local bridge process,
waits for the local bridge URL to answer HTTP, then routes facade traffic through
that URL like any other HTTP upstream.

When the ASGI runner sends lifespan events, facade startup starts all configured
Holepunch bridges and waits for their local URLs before reporting startup
complete. If a runner does not use lifespan, snulbug performs the same readiness
check before the first request routed to that upstream.

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080

[[mcp.proxy.upstreams]]
name = "remote-devbox"
transport = "holepunch"
peer = "SERVER_PEER_KEY"
local_port = 19100
tool_prefix = "devbox."
```

This expands to a local upstream URL of `http://127.0.0.1:19100/mcp` and starts
Hypertele with:

```bash
hypertele -p 19100 -s SERVER_PEER_KEY --private
```

You can use a generated Hypertele config instead of a peer argument:

```toml
[[mcp.proxy.upstreams]]
name = "remote-files"
transport = "holepunch"
local_port = 19101
bridge_config = "hypertele-client.json"
tool_prefix = "remote_files."
```

Advanced bridge fields:

```toml
bridge_command = "hypertele"
bridge_args = ["-p", "19101", "-c", "hypertele-client.json", "--private"]
bridge_cwd = "/path/to/bridge/config"
bridge_env = { HYPERDHT_BOOTSTRAP = "..." }
bridge_private = true
bridge_ready_timeout = 10.0
url = "http://127.0.0.1:19101/mcp"
```

Replay records and audit logs include the selected upstream transport and
Holepunch bridge metadata, including upstream name, tool prefix, local URL,
peer key when configured, local bridge port, and bridge readiness settings.

## State

Proxy mode uses in-memory policy state by default, which supports presets that
use `rate_limit`.

Use SQLite-backed local state:

```bash
snulbug mcp proxy --config snulbug.toml --state sqlite:policy-state.sqlite3
```

Disable state:

```bash
snulbug mcp proxy \
  --upstream http://127.0.0.1:9000 \
  --policy policy.snulbug/policy.lua \
  --state none
```

Policies using `rate_limit` require state.

## Python API

Create the ASGI proxy app directly:

```python
from snulbug import create_proxy_application

application = create_proxy_application(
    "http://127.0.0.1:9000",
    "policy.snulbug/policy.lua",
)
```

You can run that ASGI app with Uvicorn, Hypercorn, Daphne, or another ASGI
server.

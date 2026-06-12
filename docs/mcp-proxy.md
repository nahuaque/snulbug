# MCP reverse proxy

Reverse proxy mode lets `snulbug` protect a local MCP HTTP server even when the
server is not a Python ASGI app.

Install the proxy runner:

```bash
pip install "snulbug[proxy]"
```

Copy a starter policy. For public tunnel use, `tunnel-safe` is the recommended
default:

```bash
snulbug mcp init tunnel-safe --output policy.snulbug
```

Or generate one with project-specific values:

```bash
snulbug mcp init tunnel-safe \
  --output policy.snulbug \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files
```

Write a starter config:

```bash
snulbug mcp config init
```

Run the proxy:

```bash
snulbug mcp proxy --config snulbug.toml
```

For concrete MCP client configuration patterns, see
[MCP client setup recipes](mcp-client-recipes.md).

For a runnable upstream-plus-proxy walkthrough, see the
[end-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md).

Point ngrok, Cloudflare Tunnel, or another tunnel at
`http://127.0.0.1:8080`. The proxy applies the Lua policy before forwarding to
the upstream server. Use `tunnel-safe` unless you have a stronger external
access-control layer in front of the tunnel.

Generate provider-specific tunnel setup snippets first:

```bash
snulbug tunnel init \
  --provider ngrok \
  --hostname YOUR-TUNNEL.ngrok.app \
  --config snulbug.toml \
  --output-dir tunnel.ngrok
```

Before sharing the public URL, verify that the tunnel reaches snulbug and that
unauthenticated MCP traffic is blocked:

```bash
snulbug tunnel doctor \
  --provider ngrok \
  --url https://YOUR-TUNNEL.ngrok.app/mcp \
  --config snulbug.toml \
  --token local-dev-secret
```

See [Tunnel init](tunnel-init.md) and [Tunnel doctor](tunnel-doctor.md) for
Cloudflare Access and Tailscale Funnel variants.

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

`tunnel_provider` can be `auto`, `generic`, `ngrok`, `cloudflare`, or
`tailscale`. With `auto`, snulbug infers the provider from request headers and
the public host when possible. Set `tunnel_public_url` when you want audit logs
to record the externally shared MCP URL even if the request reaches snulbug
through a local reverse proxy.

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

Facade mode lets one `snulbug` proxy present several local MCP HTTP or stdio
servers as a single client-facing HTTP endpoint. It is intentionally small:
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

You can also start facade mode directly from the CLI:

```bash
snulbug mcp proxy \
  --policy policy.snulbug/policy.lua \
  --facade-upstream files=http://127.0.0.1:9001/mcp \
  --facade-upstream git=http://127.0.0.1:9002/mcp
```

Use `tool_prefix` when you want a different namespace:

```toml
[[mcp.proxy.upstreams]]
name = "repo"
url = "http://127.0.0.1:9002/mcp"
tool_prefix = "git."
```

Replay records and audit logs include facade metadata such as selected upstream,
original tool name, and upstream tool name for routed calls.

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

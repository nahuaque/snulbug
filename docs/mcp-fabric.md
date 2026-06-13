# MCP Fabric Config

`snulbug mcp fabric` treats one snulbug facade gateway plus its declared
upstreams as a small local-dev MCP fabric. It does not replace proxy config; it
adds a fabric-level section that status and doctor commands can inspect.

```toml
[mcp.fabric]
name = "local-dev"
description = "One gateway fronting local and remote MCP servers"
gateway_url = "http://127.0.0.1:8080/mcp"
require_manifests = true
probe_gateway = true
probe_upstreams = true
timeout = 5.0

[mcp.proxy]
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
record_out = "traces/session.jsonl"
audit_out = "traces/audit.jsonl"

[[mcp.proxy.upstreams]]
name = "files"
url = "http://127.0.0.1:9001/mcp"
tool_prefix = "files."
manifest = "manifests/files.signed.json"
manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
manifest_identity = "files@local"

[[mcp.proxy.upstreams]]
name = "remote-devbox"
transport = "holepunch"
peer = "SERVER_PEER_KEY"
local_port = 19100
tool_prefix = "devbox."
manifest = "manifests/devbox.signed.json"
manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
manifest_identity = "devbox@peer"
```

When `gateway_url` is empty, snulbug infers it from `[mcp.proxy]` `host` and
`port`.

## Status

`status` is a static topology summary. It reads config and manifest files but
does not make network calls.

```bash
snulbug mcp fabric status --config snulbug.toml
snulbug mcp fabric status --config snulbug.toml --compact
```

It reports:

- gateway URL
- proxy policy, state, logs, tunnel provider, and lease mode
- upstream names, transports, prefixes, bridge details, and manifests
- manifest presence and declared signed metadata
- transport and manifest counts

## Doctor

`doctor` is the active readiness gate. It verifies configured manifests, checks
stdio commands, and probes MCP `tools/list` on the gateway and HTTP/Holepunch
upstream URLs.

```bash
export SNULBUG_MANIFEST_SECRET="replace-with-a-local-secret"
snulbug mcp fabric doctor \
  --config snulbug.toml \
  --token local-dev-secret
```

For custom auth headers:

```bash
snulbug mcp fabric doctor \
  --config snulbug.toml \
  --header "Authorization: Bearer local-dev-secret" \
  --header "x-snulbug-lease: sbl_..."
```

For static-only checks:

```bash
snulbug mcp fabric doctor \
  --config snulbug.toml \
  --no-probe-gateway \
  --no-probe-upstreams
```

Use `fabric doctor` before handing an agent a fabric endpoint or sharing a
tunnel/peer bridge. Use `tunnel doctor` for public tunnel exposure checks.

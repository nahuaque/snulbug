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

## Discovery Providers

Discovery providers let a fabric load facade upstreams from a small registry
instead of hard-coding every `[[mcp.proxy.upstreams]]` entry in `snulbug.toml`.
The discovered entries are normalized into the same upstream model as static
config, so duplicate names/tool prefixes still fail closed and signed manifest
settings keep working.

```toml
[mcp.fabric.discovery]
enabled = true

[[mcp.fabric.discovery.providers]]
name = "local-registry"
type = "file"
path = "discovery/upstreams.json"
required = true

[[mcp.fabric.discovery.providers]]
name = "container-env"
type = "env"
env = "SNULBUG_DISCOVERY_UPSTREAMS"

[[mcp.fabric.discovery.providers]]
name = "peer-directory"
type = "directory"
path = "discovery/peers"
glob = "*.json"
```

Supported provider types:

- `file`: reads one JSON or TOML registry file
- `directory`: reads every matching JSON/TOML file in a directory, sorted by
  filename
- `env`: reads JSON from an environment variable

Each provider can return one upstream object, a list of upstream objects, an
object with `upstreams`, or a TOML/JSON config-shaped object containing
`mcp.proxy.upstreams`.

```json
{
  "upstreams": [
    {
      "name": "remote-devbox",
      "transport": "holepunch",
      "peer": "SERVER_PEER_KEY",
      "local_port": 19100,
      "tool_prefix": "devbox.",
      "manifest": "manifests/devbox.signed.json",
      "manifest_secret_env": "SNULBUG_MANIFEST_SECRET",
      "manifest_identity": "devbox@peer"
    }
  ]
}
```

Inspect discovery without starting the proxy:

```bash
snulbug mcp fabric discover --config snulbug.toml
snulbug mcp fabric discover --config snulbug.toml --compact
```

Discovery does not execute commands or contact networks. It is intentionally a
registry adapter layer: external systems such as Docker Compose, a peer bridge
supervisor, or a future Hyperswarm watcher can write registry files or env JSON,
and snulbug consumes them through the same validation path as local config.

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

## Learn Mode

`learn` compiles topology-aware replay or audit logs into a reviewable fabric
profile. It is the fabric-level companion to `snulbug mcp learn`: policy learn
infers least-privilege tool rules, while fabric learn infers the gateway,
upstreams, routes, transports, bridge metadata, and manifest identities observed
while proxying.

```bash
snulbug mcp fabric learn traces/audit.jsonl \
  --kind audit \
  --out learned-fabric
```

The output directory contains:

- `fabric.json`: machine-readable learned topology, traffic counters, upstream
  identities, and conflicts
- `snulbug.fabric.toml`: starter config for `[mcp.fabric]`, `[mcp.proxy]`, and
  learned `[[mcp.proxy.upstreams]]`
- `FABRIC.md`: human review report with upstreams, observed tools, review notes,
  and conflicting topology values

Learn mode never writes observed secret values. If it sees a manifest path, the
starter config uses `manifest_secret_env = "SNULBUG_MANIFEST_SECRET"`. If the
log does not prove a required address or command, the generated TOML keeps the
file parseable with `TODO` placeholders so the missing trust decision is visible.

Typical review loop:

```bash
snulbug mcp fabric learn traces/audit.jsonl --out learned-fabric
less learned-fabric/FABRIC.md
$EDITOR learned-fabric/snulbug.fabric.toml
snulbug mcp fabric doctor --config learned-fabric/snulbug.fabric.toml
```

Use this after a live facade recording session to convert "what actually routed
where" into a declarative fabric baseline. Then run `snulbug mcp learn` on the
same session log if you also want a least-privilege Lua policy for the observed
tools.

## Topology-Aware Audit Fields

When proxy mode is started from config, snulbug derives audit-safe topology
metadata from `[mcp.fabric]` and `[mcp.proxy]` and writes it into replay records
and audit events.

Replay records include:

```json
{
  "metadata": {
    "topology": {
      "fabric": {
        "name": "local-dev",
        "gateway_url": "http://127.0.0.1:8080/mcp"
      },
      "gateway": {
        "url": "http://127.0.0.1:8080/mcp",
        "facade": true,
        "tunnel_provider": "holepunch"
      },
      "summary": {
        "upstream_count": 2,
        "transports": {
          "http": 1,
          "holepunch": 1
        }
      },
      "route": {
        "mode": "facade",
        "operation": "tools/call",
        "tool": "devbox.read_file",
        "upstream": "remote-devbox",
        "upstream_transport": "holepunch",
        "upstream_tool": "read_file",
        "upstream_identity": "devbox@peer",
        "manifest_digest": "sha256:..."
      }
    }
  }
}
```

Audit events promote the same object to top-level `topology`, so downstream
inspection tools can answer which fabric, gateway, route, transport, signed
manifest, and upstream handled a decision without reverse-engineering facade
metadata.

Secrets are not copied into topology metadata. URLs are written without query
strings or userinfo, stdio entries include the command name rather than full
environment, and manifest entries include only verification metadata such as
identity, digest, key id, and tool count.

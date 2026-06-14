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
- `static` / `static_toml`: reads inline `upstreams` or a static TOML registry
- `docker_compose`: reads Docker Compose services with `snulbug.mcp.*` labels
- `kubernetes`: reads Kubernetes Service lists/manifests with
  `snulbug.dev/mcp-*` annotations
- `tailscale`: reads Tailscale API/status JSON and filters by tags, default
  `tag:mcp`
- `mdns` / `dns_sd`: reads mDNS/DNS-SD record snapshots or inline TXT records
- `codespaces`: maps GitHub Codespaces forwarded ports into MCP upstream URLs
- `devcontainer`: reads `.devcontainer/devcontainer.json`
  `customizations.snulbug.upstreams`
- `supervisor` / `process_registry`: reads a local process supervisor registry
  and exposes ready/running MCP processes
- `members` / `member_registry` / `remote_members`: reads active remote
  data-plane member registrations from a file, SQLite state, or Redis state

YAML Compose/Kubernetes files are supported when PyYAML is installed, for
example with `snulbug[discovery]`. JSON and TOML registries work without extra
dependencies.

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

Discovery does not execute commands. It is intentionally a registry adapter
layer: external systems such as Docker Compose, a peer bridge supervisor, or a
future Hyperswarm watcher can write registry files or env JSON, and snulbug
consumes them through the same validation path as local config. Providers only
contact a network when an explicit `api_url` is configured.

## Remote Fabric Members

Remote data-plane containers can register themselves as fabric members and
publish the MCP upstreams they serve. The control plane consumes that registry
through the `members` discovery provider, applies normal upstream validation,
and carries member identity into status, topology, replay, and audit metadata.

For a simple local demo, use a file-backed registry:

```bash
snulbug mcp fabric member register remote-a \
  --registry .snulbug/fabric-members.json \
  --upstream files=http://127.0.0.1:9001/mcp \
  --ttl-seconds 60

snulbug mcp fabric member heartbeat remote-a \
  --registry .snulbug/fabric-members.json \
  --ttl-seconds 60
```

For a remote container, run a lightweight member agent. It registers once, then
heartbeats until the process exits:

```bash
snulbug mcp fabric member agent remote-a \
  --registry redis://127.0.0.1:6379/0 \
  --registry-key snulbug:fabric:dev:members \
  --upstream files=http://127.0.0.1:9001/mcp \
  --ttl-seconds 60 \
  --interval 20 \
  --unregister-on-exit
```

The gateway side discovers active data-plane members:

```toml
[[mcp.fabric.discovery.providers]]
name = "remote-members"
type = "members"
path = ".snulbug/fabric-members.json"
```

Shared state registries use the same SQLite/Redis vocabulary as runtime state:

```toml
[[mcp.fabric.discovery.providers]]
name = "remote-members"
type = "members"
state = "redis://127.0.0.1:6379/0"
state_key = "snulbug:fabric:dev:members"
```

Only `active` `data_plane` members are routed by default, and expired members
are ignored. Member upstream names and tool prefixes are prefixed by default
(`remote-a-files`, `remote-a.files.`) so independently managed containers do not
collide in a shared facade. Set `prefix_member_names = false` only when another
registry layer already guarantees global names.

## Control-Plane Events

`snulbug mcp fabric controller` writes durable controller state and a JSONL
event log. Each reconcile envelope keeps the older `changes` list and now also
includes typed `control_events` using schema `snulbug.control-plane-event.v1`.

Current event types:

- `snulbug.fabric.route.changed`
- `snulbug.fabric.manifest.changed`
- `snulbug.fabric.policy.changed`
- `snulbug.fabric.discovery.degraded`
- `snulbug.fabric.discovery.recovered`
- `snulbug.fabric.upstream.degraded`
- `snulbug.fabric.upstream.unhealthy`
- `snulbug.fabric.upstream.recovered`
- `snulbug.fabric.reload.failed`
- `snulbug.fabric.reload.recovered`

Live fabric reloads attach the same `control_events` and `event_types` fields
to replay/audit metadata under `metadata.fabric_reload`, so session logs show
route reloads, reload failures, and recovery after a bad config edit.

Facade health routing uses the same event schema in replay/audit metadata under
`metadata.upstream_health.control_events`. When enabled, the data plane emits
`upstream.degraded`, `upstream.unhealthy`, and `upstream.recovered` events as it
removes unhealthy upstreams from fanout/tool routing and probes them again after
the configured cooldown.

### Docker Compose Labels

`docker_compose` reads a Compose file and includes services labeled
`snulbug.mcp.enabled=true`.

```yaml
services:
  files-mcp:
    image: ghcr.io/example/files-mcp
    ports:
      - "9001:9000"
    labels:
      snulbug.mcp.enabled: "true"
      snulbug.mcp.name: files
      snulbug.mcp.tool_prefix: files.
```

By default, the generated upstream URL uses the Compose service name and target
port: `http://files-mcp:9000/mcp`.

### Kubernetes Services

`kubernetes` reads a Service manifest/list from `path`, `env`, or `api_url`.
Annotate services explicitly:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: git-mcp
  namespace: dev
  annotations:
    snulbug.dev/mcp-enabled: "true"
    snulbug.dev/mcp-name: git
    snulbug.dev/mcp-tool_prefix: git.
spec:
  ports:
    - port: 9002
```

The default in-cluster URL is
`http://git-mcp.dev.svc:9002/mcp`.

### Tailscale

`tailscale` consumes Tailscale API JSON or `tailscale status --json` output from
`path`, `env`, or an explicit `api_url`. It filters devices by `tag`/`tags` and
builds URLs from DNS names.

```toml
[[mcp.fabric.discovery.providers]]
name = "tailnet"
type = "tailscale"
env = "SNULBUG_TAILSCALE_DEVICES"
tag = "tag:mcp"
port = 9000
```

For live HTTP API reads, set `api_url` plus one of `authorization_env`,
`bearer_token_env`, or `basic_token_env`. Snapshot files/env are preferred for
repeatable local-dev runs.

### LAN DNS-SD

`mdns` reads DNS-SD snapshots or inline records. This intentionally avoids a
daemon dependency; a LAN watcher can write the snapshot and snulbug consumes it.

```toml
[[mcp.fabric.discovery.providers]]
name = "lan"
type = "mdns"
records = [
  { name = "files", host = "files.local", port = 9004, properties = { "snulbug.mcp.enabled" = "true" } }
]
```

### Codespaces And Devcontainers

`codespaces` converts configured forwarded ports into Codespaces URLs when
`CODESPACE_NAME` and `GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN` are present.
See [Codespaces and devcontainers](devcontainers.md) for the devcontainer
Feature and member-agent workflow.

```toml
[[mcp.fabric.discovery.providers]]
name = "codespace"
type = "codespaces"
ports = [{ name = "files", port = 9005, tool_prefix = "files." }]
```

`devcontainer` reads:

```json
{
  "customizations": {
    "snulbug": {
      "upstreams": [
        { "name": "workspace", "url": "http://127.0.0.1:9006/mcp" }
      ]
    }
  }
}
```

### Supervisor Registry

`supervisor` reads JSON/TOML written by a local process supervisor and includes
processes whose `status` is `ready` or `running`.

```json
{
  "processes": [
    { "name": "files", "port": 9007, "status": "ready" }
  ]
}
```

Custom providers can also be registered from Python with
`register_discovery_provider("my_type", resolver)`, where `resolver(provider)`
returns raw upstream tables.

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

## Controller

`controller` turns the declarative fabric into a lightweight reconciliation
loop. It repeatedly loads `snulbug.toml`, resolves discovery providers, computes
a deterministic desired-state fingerprint, writes a state snapshot, and appends
change events when the fabric changes.

Run one reconcile for CI or an agentic harness:

```bash
snulbug mcp fabric controller \
  --config snulbug.toml \
  --once \
  --compact
```

Run it as a local control-plane loop:

```bash
snulbug mcp fabric controller \
  --config snulbug.toml \
  --interval 2 \
  --state .snulbug/fabric-state.json \
  --event-log .snulbug/fabric-events.jsonl
```

The state snapshot includes the current fabric, gateway, proxy, discovery
providers, upstreams, summary counters, recommendations, fingerprint, and
detected changes. Change events are JSONL records with
`type = "snulbug.fabric.reconcile"` and are written only when the desired fabric
changes.

The controller can also expose local read-only status endpoints:

```bash
snulbug mcp fabric controller \
  --config snulbug.toml \
  --status-server \
  --status-port 8765
```

Endpoints:

- `/healthz`: last reconcile health as JSON
- `/status`: latest controller snapshot as JSON
- `/metrics`: Prometheus-style gauges for fabric health, changes, upstreams,
  discovery errors, and missing required manifests

## Policy Activation

The controller can enforce signed policy bundle lifecycle state before the data
plane starts. This turns policy activation into reconciled fabric state instead
of an out-of-band manual step.

```toml
[mcp.fabric.policy_activation]
mode = "promote_approved"
key_id = "local-review"
secret_env = "SNULBUG_BUNDLE_SECRET"
```

Modes:

- `off`: do not inspect or mutate policy bundle lifecycle state
- `require_active`: require the configured policy bundle to be signed and
  already `active`
- `promote_approved`: verify an `active` bundle, or promote a signed
  `approved` bundle to `active`

The controller only manages policies that are configured as bundle entrypoints,
for example:

```toml
[mcp.proxy]
policy = "policy.snulbug/policy.lua"
```

If activation fails because the bundle is still `observed` or `proposed`, the
controller reports unhealthy and `fabric run` refuses to start the data plane.

This is the control-plane foundation. It does not hot-swap a running proxy route
table by itself; pair it with proxy fabric reload when you want the running data
plane to consume those changes:

```bash
snulbug mcp proxy \
  --config snulbug.toml \
  --reload-fabric \
  --fabric-reload-interval 2
```

With reload enabled, the facade proxy periodically re-reads the same fabric
config/discovery sources and swaps its upstream route table for new requests.
Replay records and audit events include `fabric_reload`, `route_revision`, and
`route_fingerprint` metadata so a session can be tied back to the exact route
snapshot that served it.

## Managed Run

`fabric run` starts the controller and the live-reloading data plane together.
Use it when you want snulbug to act as one local MCP fabric process instead of
running `fabric controller` and `mcp proxy --reload-fabric` separately.

```bash
snulbug mcp fabric run \
  --config snulbug.toml \
  --status-port 8765
```

It does four things:

- reconciles fabric state into `.snulbug/fabric-state.json`
- appends controller change events to `.snulbug/fabric-events.jsonl`
- exposes `/healthz`, `/status`, and `/metrics` on the controller status port
- starts the MCP facade proxy with fabric reload enabled

Agent-friendly startup output:

```bash
snulbug mcp fabric run --config snulbug.toml --compact
```

The managed status endpoint includes runtime state alongside controller state:

- `runtime.data_plane` reports whether the managed proxy is `running`,
  `stopped`, or `blocked`, plus bind address, policy, trace outputs, reload
  interval, and upstream names.
- `runtime.conformance` reports whether a conformance pack was checked and
  whether it passed.
- `share_gate` is the agent-readable readiness decision. It is blocked when the
  controller is unhealthy, the data plane is not running, or required
  conformance is not passing. Persisted `running` state also carries a heartbeat;
  stale heartbeats block the share gate instead of advertising an abandoned
  gateway as safe.

By default, `fabric run` persists the latest runtime status in
`.snulbug/fabric-runtime.sqlite3`. Use SQLite for one local gateway and Redis
when multiple containers or hosts need to share the same runtime view:

```bash
snulbug mcp fabric run \
  --config snulbug.toml \
  --runtime-state sqlite:.snulbug/fabric-runtime.sqlite3

snulbug mcp fabric run \
  --config snulbug.toml \
  --runtime-state redis://127.0.0.1:6379/0 \
  --runtime-state-key snulbug:fabric:devbox-a
```

Shared runtime state is protected by an owner lease. Each `fabric run` instance
gets an owner id and a monotonic fencing token; a second active instance with
the same runtime-state key is refused until the first lease is released or
expires. Use an explicit owner id for stable container names:

```bash
snulbug mcp fabric run \
  --config snulbug.toml \
  --runtime-state redis://127.0.0.1:6379/0 \
  --runtime-instance-id gateway-devbox-a \
  --runtime-lease-ttl 30
```

Read or clear the persisted runtime state without contacting the live status
server:

```bash
snulbug mcp fabric runtime status --compact
snulbug mcp fabric runtime clear
```

Operational controls are stored beside the runtime status and are consumed by
managed `fabric run` instances on each controller/reload tick:

```bash
snulbug mcp fabric control pause-sharing --reason "rotating tunnel token"
snulbug mcp fabric control quarantine-upstream files --reason "unexpected tool schema"
snulbug mcp fabric control drain-upstream git --reason "maintenance"
snulbug mcp fabric control force-reload
snulbug mcp fabric control rollback-policy policy.previous.snulbug/policy.lua
snulbug mcp fabric control list --compact
snulbug mcp fabric control clear --action quarantine_upstream --target files
```

`pause-sharing` and `rollback-policy` block `share_gate`. Drained and
quarantined upstreams stay in the route table for observability, but facade
routing skips them for `tools/list` fanout and `tools/call`. `force-reload`
defaults to a short TTL and forces the next reload tick to rebuild the facade
routes even if the config fingerprint is unchanged.

To gate public sharing on a generated conformance pack:

```bash
snulbug mcp fabric run \
  --config snulbug.toml \
  --conformance-pack .snulbug/fabric-conformance \
  --require-conformance
```

`fabric run` requires facade upstreams from `[[mcp.proxy.upstreams]]` or
discovery providers. For a single upstream reverse proxy, use
`snulbug mcp proxy --config snulbug.toml`.

## Upstream Credentials

Fabric configs can declare small credential references and attach them to
individual HTTP or Holepunch upstreams. snulbug stores only the reference
metadata in config, status, audit, and replay output. The secret value is read
from the environment or a local file only when the proxy forwards a request or
`fabric doctor` probes that upstream.

```toml
[mcp.fabric.credentials.codespace]
type = "env"
env = "CODESPACE_MCP_TOKEN"
scheme = "bearer" # bearer, basic, or raw
header = "Authorization"

[mcp.fabric.credentials.local_api]
type = "file"
path = ".snulbug/secrets/local-api-token"
scheme = "raw"
header = "x-api-key"

[[mcp.proxy.upstreams]]
name = "codespace-files"
url = "https://example-codespace.github.dev/mcp"
tool_prefix = "codespace.files."
auth = "codespace"

[[mcp.proxy.upstreams]]
name = "local-api"
url = "http://127.0.0.1:9001/mcp"
tool_prefix = "local."
auth = "local_api"
```

When `auth` is configured, snulbug injects that upstream credential into the
outbound request and replaces any same-named caller header. This prevents a
gateway/client bearer token from being accidentally forwarded to the upstream.
Run `fabric doctor` to check that all referenced env vars or files are present
before starting or sharing the fabric.

## Doctor

`doctor` is the active readiness gate. It verifies configured manifests, checks
upstream credential refs, stdio commands, and probes MCP `tools/list` on the
gateway and HTTP/Holepunch upstream URLs.

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
tunnel/peer bridge. Use `mcp share doctor` for share-session exposure checks.

## Conformance Packs

`fabric conformance` generates a path-based test pack that proves the current
fabric config, signed manifests, policy bundle, and replay/audit logs still
agree. Use it as the final local or CI gate before sharing a gateway, tunnel, or
peer bridge.

Generate a pack from the config and one or more topology-aware logs:

```bash
snulbug mcp fabric conformance generate \
  --config snulbug.toml \
  --log traces/session.jsonl \
  --kind record \
  --out .snulbug/fabric-conformance
```

Run the pack:

```bash
snulbug mcp fabric conformance run .snulbug/fabric-conformance
```

The runner fails closed when:

- the config, policy, manifest, or log fingerprint changed since generation
- `fabric doctor` cannot load the config or verify required signed manifests
- the configured policy bundle fails validation or fixture tests
- replay records no longer match the current policy decision output
- topology-aware logs mention undeclared upstreams, miss configured upstreams,
  or carry route/manifest metadata that disagrees with the current config

By default, conformance runs offline and disables active gateway/upstream
network probes. Add `--probe-gateway` or `--probe-upstreams` when the gateway
and upstreams are already running and you want the pack to include live MCP
`tools/list` checks. Pass `--token` or `--header` for authenticated probes.

## Learn Mode

`learn` compiles topology-aware replay or audit logs into a reviewable fabric
profile. It is the fabric-level companion to `snulbug mcp policy learn`: policy learn
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
where" into a declarative fabric baseline. Then run `snulbug mcp policy learn` on the
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

# MCP share sessions

`snulbug mcp share` creates and manages a bounded local MCP share session. It
composes policy creation, lease creation, tunnel setup, client config, live
proxying, verification, and closeout reporting into one generated directory.

Use it when you want to give an agent or collaborator temporary access to a
local MCP server without hand-wiring every control.

## Golden path

The high-level session loop is:

```text
share create -> share run -> share status -> policy amend -> share activate -> share report
```

Create the bounded session:

```bash
uv run snulbug mcp share create \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Run it:

```bash
export SNULBUG_SHARE_TOKEN=...
uv run snulbug mcp share run .snulbug/shares/share-...
```

Check live state:

```bash
uv run snulbug mcp share status .snulbug/shares/share-...
```

If the audit log shows a legitimate blocked request, amend the reviewed policy
bundle:

```bash
uv run snulbug mcp policy amend \
  .snulbug/shares/share-.../policy.snulbug \
  .snulbug/shares/share-.../traces/audit.jsonl \
  --out .snulbug/shares/share-.../policy.snulbug \
  --force
```

Then promote and activate the policy bundle:

```bash
export SNULBUG_BUNDLE_SECRET=...
uv run snulbug mcp share promote .snulbug/shares/share-... --to proposed --key-id local-review
uv run snulbug mcp share promote .snulbug/shares/share-... --to approved --key-id local-review
uv run snulbug mcp share activate .snulbug/shares/share-... --key-id local-review
```

Generate the closeout report:

```bash
uv run snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

## Generated files

By default, the command writes under `.snulbug/shares/share-*` and creates:

```text
share.json
.snulbug/share/session.json
policy.snulbug/
snulbug.toml
leases.json
mcp-client.json
SHARE.md
tunnel/
containers/
traces/
```

The generated policy uses a random bearer token unless `--token` is supplied.
The generated config sets `lease_required = true`, so every MCP `tools/call`
must carry the generated `x-snulbug-lease` token. The lease expires after the
configured `--ttl`.

`share.json` is the generated compatibility manifest used by existing share
commands. `.snulbug/share/session.json` is the canonical control-plane session
model. It records the current share state, provider/public URL, local gateway
config, upstreams, policy bundle and active policy path, lease store, replay and
audit logs, reports, last health summary, and policy amendment/lifecycle
pointers without duplicating bearer or lease tokens.

## Session lifecycle

Run the generated share:

```bash
export SNULBUG_SHARE_TOKEN=...
uv run snulbug mcp share run .snulbug/shares/share-...
```

Or run from inside the generated share directory:

```bash
cd .snulbug/shares/share-...
uv run snulbug mcp share run
```

`share run` starts the snulbug proxy from the canonical session model when
`.snulbug/share/session.json` is present. It reconciles the active config,
policy, lease, replay log, and audit log paths before starting the gateway. The
generated `SHARE.md` still includes the lower-level provider command when the
selected tunnel or peer bridge needs a second process. For the default
Holepunch peer bridge, that provider command is a Hypertele command from the
generated `tunnel/` directory.

Before sharing `mcp-client.json`, verify the session:

```bash
uv run snulbug mcp share doctor .snulbug/shares/share-...
```

`share doctor` is the pre-share readiness gate. It loads the generated config,
validates the policy bundle or Lua entrypoint, runs static fabric checks,
optionally runs a generated fabric conformance pack, checks the current share
status, and runs the tunnel/public URL doctor. The command exits non-zero when
any required check fails.

If the provider prints a random public URL after startup, pass the exact MCP URL
to doctor. This updates `share.json` and `mcp-client.json` before probing:
It also updates `.snulbug/share/session.json`, so later `status` and report
commands see the resolved public endpoint.

```bash
uv run snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}"
```

For OAuth protected-resource shares, run the auth-specific doctor before handing
the URL to an MCP client:

```bash
uv run snulbug mcp share auth doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --token "${ACCESS_TOKEN}"
```

`share auth doctor` checks protected-resource metadata, issuer metadata, JWKS or
introspection reachability, HTTPS/public URL alignment, token redaction
settings, scope-to-tool mappings, and Cloudflare Access conflicts. Use
`--no-live-checks` while editing local config, or `--config snulbug.toml` before
a generated share directory exists.

Runtime JWT validation can use either a pinned local `jwks_path` or a remote
`jwks_url` with bounded caching and refresh-on-rotation. The auth doctor probes
the configured remote JWKS endpoint during live checks.

To exercise the full auth model locally without an external identity provider,
run the auth lab:

```bash
uv run snulbug mcp share auth lab
```

The lab starts a mock issuer and MCP upstream, mints demo JWTs, creates a task
lease, runs `share auth doctor`, drives allowed and denied tool calls, and
writes the evidence under `.snulbug-auth-lab/`.

For fabric facade sessions, pass a generated conformance pack when you want the
share gate to prove config, manifests, policies, and replay logs still agree:

```bash
uv run snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --conformance-pack .snulbug/fabric-conformance \
  --require-conformance
```

Inspect the generated client config without opening files by hand:

```bash
uv run snulbug mcp share client .snulbug/shares/share-...
```

Check state later:

```bash
uv run snulbug mcp share status .snulbug/shares/share-...
```

Status is the live "what is happening?" command. It summarizes whether the
gateway is reachable, upstream health, the last public tunnel doctor result
when one has been recorded, the active policy bundle and lifecycle state,
recent allowed/blocked/confirmed counts from the share evidence, current leases,
last recording paths, and high-risk findings.

Generate a share-session report at any point:

```bash
uv run snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

The report is human-readable Markdown built from the session model plus audit
and replay logs. It lists what was exposed, observed clients and source IPs,
tools observed, allowed/blocked/confirmed counts, redaction and risk findings,
upstream health, policy state, and exact next commands.

## Remote member attach

Use `share attach` when a Codespace, devcontainer, Holepunch peer, or another
container should become a managed upstream for an existing share session:

```bash
uv run snulbug mcp share attach .snulbug/shares/share-... \
  --member-id codespace-files \
  --kind codespaces \
  --upstream files=https://NAME-9001.app.github.dev/mcp \
  --metadata-output codespace-member.json
```

The command registers the member in the share's fabric member registry, appends
a `members` discovery provider to `snulbug.toml` when needed, and records the
attachment in both `share.json` and `.snulbug/share/session.json`. Subsequent
`share run`, `share status`, `share report`, and `share doctor` commands use
the attached member through normal fabric discovery. `--metadata-output` writes
the normalized, re-consumable member descriptor inside the share directory.

Remote environments can also emit JSON metadata and let the laptop consume it:

```json
{
  "member_id": "devcontainer-a",
  "kind": "devcontainer",
  "upstreams": [
    {"name": "files", "url": "http://127.0.0.1:9001/mcp"}
  ],
  "labels": {"runtime": "docker"}
}
```

```bash
uv run snulbug mcp share attach .snulbug/shares/share-... \
  --metadata-file devcontainer-member.json
```

By default the registry is `.snulbug/fabric-members.json` inside the share
directory. Use `--registry sqlite:/path/to/fabric-members.sqlite3` or
`--registry redis://... --registry-key snulbug:fabric:members` when remote
members need to update a shared registry directly.

## Policy lifecycle shortcuts

The share command wraps the normal policy bundle lifecycle flow and keeps the
session model in sync:

```bash
export SNULBUG_BUNDLE_SECRET=...
uv run snulbug mcp share promote .snulbug/shares/share-... --to proposed --key-id local-review
uv run snulbug mcp share promote .snulbug/shares/share-... --to approved --key-id local-review
uv run snulbug mcp share activate .snulbug/shares/share-... --key-id local-review
```

From inside a generated share directory, omit the directory:

```bash
uv run snulbug mcp share promote --to proposed --key-id local-review
uv run snulbug mcp share activate --key-id local-review
```

These commands call the same signed policy lifecycle machinery as
`snulbug mcp policy lifecycle promote`, then update
`.snulbug/share/session.json` so `share status` and `share report` show the
current lifecycle state and last share-scoped lifecycle action.

## Client config

`mcp-client.json` contains the URL and headers for the client:

```json
{
  "mcpServers": {
    "snulbug-share": {
      "url": "http://127.0.0.1:18080/mcp",
      "headers": {
        "Authorization": "Bearer ...",
        "x-snulbug-lease": "..."
      }
    }
  }
}
```

Treat this file as secret-bearing material. It contains both the bearer token
and the lease token.

## Remote container as upstream

Every share also writes an optional `containers/` recipe for the containerized
facade case:

```text
containers/
  docker-compose.yml
  Dockerfile.gateway
  Dockerfile.remote-peer
  snulbug.local.toml
  snulbug.facade.toml
  policy.snulbug/
  leases.json
  mcp-client.facade.json
  mock_mcp_server.py
  mock_mcp_server.js
  snulbug-src/
  hypertele-server.json
  hypertele-client.json
```

The recipe models three services: a snulbug gateway, a local MCP container, and
a remote-by-peer MCP container reached through a managed Hypertele bridge. It
uses facade tool names such as `local.safe_read_file` and
`remote.safe_read_file`.

The normal share config remains at `snulbug.toml`. The container recipe has its
own facade config, policy, lease file, and MCP client config so experimenting
with container upstreams does not change the default share session.
The generated `Dockerfile.gateway` installs from `snulbug-src/`, a source
snapshot copied from the checkout that created the share, so it does not require
a published PyPI release.

Start from the generated local-only recipe first. This path does not install
Node, npm, or Hypertele in the snulbug gateway image:

```bash
cd .snulbug/shares/share-*/containers
docker compose up --build
```

Replace the placeholder peer material in `hypertele-server.json` and
`hypertele-client.json` before using the peer bridge outside local testing. For
the remote peer path, make Hypertele available to the gateway or run it as a
sidecar, then switch the gateway command from `snulbug.local.toml` to
`snulbug.facade.toml`.
Point clients at `mcp-client.facade.json` for this facade recipe.

## Public tunnel providers

The share command also works with existing tunnel providers:

```bash
uv run snulbug mcp share create \
  --provider ngrok \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --ttl 30m
```

For public tunnel providers, expose the snulbug proxy, not the upstream MCP
server, and run the generated doctor command before sharing the client config.
Pass `--hostname` only when you have a reserved tunnel hostname; otherwise copy
the exact forwarding URL printed by the tunnel provider and pass it to
`snulbug mcp share doctor --url`.

## Close out

When the task is complete:

```bash
uv run snulbug mcp share close .snulbug/shares/share-... --report --revoke
```

Closeout revokes the session lease, writes `session-report.md` when possible,
and marks `share.json` closed. Add `--learn` to generate a learned policy bundle
from the share replay log during closeout:

```bash
uv run snulbug mcp share close .snulbug/shares/share-... --learn --force
```

Then stop the proxy and provider process. Delete the share directory when you no
longer need the local audit artifacts.

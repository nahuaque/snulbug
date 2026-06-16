# MCP share sessions

`snulbug mcp share` creates and manages a bounded local MCP share session. It
composes policy creation, lease creation, tunnel setup, client config, live
proxying, verification, and closeout reporting into one generated directory.

Use it when you want to give an agent or collaborator temporary access to a
local MCP server without hand-wiring every control.

## Golden path

The high-level session loop is:

```text
share create -> share run -> share status -> share policy amend -> share policy activate -> share doctor -> share contract -> share report
```

Create the bounded session:

```bash
snulbug mcp share create \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

Run it:

```bash
export SNULBUG_SHARE_TOKEN=...
snulbug mcp share run .snulbug/shares/share-...
```

Check live state:

```bash
snulbug mcp share status .snulbug/shares/share-...
```

If the audit log shows a legitimate blocked request, amend the reviewed policy
bundle:

```bash
snulbug mcp share policy amend .snulbug/shares/share-...
```

By default this uses the share audit/session log and updates the share policy
bundle in place; pass `--out` when you want a detached candidate bundle.

Then promote and activate the policy bundle:

```bash
export SNULBUG_BUNDLE_SECRET=...
snulbug mcp share policy promote .snulbug/shares/share-... --to proposed --key-id local-review
snulbug mcp share policy promote .snulbug/shares/share-... --to approved --key-id local-review
snulbug mcp share policy activate .snulbug/shares/share-... --key-id local-review
```

Generate the closeout report:

```bash
snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

`share status`, `share report`, and share contracts include a tool-risk review.
It combines observed tool calls from `traces/audit.jsonl` or
`traces/session.jsonl` with discovered MCP schema catalogs when present. Drop a
catalog at `traces/schemas.json`, `schemas.json`, `schemas/*.json`, or
`.snulbug/schemas/*.json` inside the share directory, or reference one from the
session model, and the report will classify schema-declared tools even before
traffic is observed. The table records evidence source, confidence, risk level,
categories, and signals such as command-capable arguments, network/path
arguments, destructive annotations, and open argument schemas.

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
snulbug mcp share run .snulbug/shares/share-...
```

Or run from inside the generated share directory:

```bash
cd .snulbug/shares/share-...
snulbug mcp share run
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
snulbug mcp share doctor .snulbug/shares/share-...
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
snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}"
```

Generate a share contract when you want a machine-readable handoff artifact for
a reviewer, agent harness, or CI attachment:

```bash
snulbug mcp share contract .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-contract.json
```

The contract records the public client URL, redacted header names, upstreams,
policy lifecycle state, lease bounds, auth/scope configuration, recent evidence
counts, findings, and last doctor state. It does not include bearer tokens,
lease tokens, raw request bodies, or raw response bodies. Add `--include-doctor`
to run the readiness gate while generating it, and add `--sign` to attach an
HMAC signature using `SNULBUG_SHARE_CONTRACT_SECRET`:

```bash
export SNULBUG_SHARE_CONTRACT_SECRET=...
snulbug mcp share contract .snulbug/shares/share-... \
  --include-doctor \
  --sign \
  --key-id local-review \
  --output .snulbug/shares/share-.../share-contract.signed.json \
  --force
```

Bind the live proxy to the approved contract when starting the share:

```bash
snulbug mcp share run .snulbug/shares/share-... \
  --require-contract .snulbug/shares/share-.../share-contract.signed.json
```

While running, the proxy exposes the approved JSON contract at
`GET /.well-known/snulbug/share-contract` and records the stable contract
binding digest in audit metadata as `metadata.share.contract_digest`. `share
status` and `share doctor` compare the required binding digest against the
current share shape and flag drift before you hand the URL to a client.
Lua policies can also enforce the same binding directly with helpers such as
`share.require_contract_bound()`, `share.require_contract_digest(...)`, and
`share.require_contract_key_id(...)`.

For humans and MCP clients that do not run snulbug locally, the same bound
runtime exposes a zero-install verification surface:

```text
GET /snulbug
GET /.well-known/snulbug/share
GET /.well-known/snulbug/share-contract
GET /.well-known/snulbug/share-contract.sha256
```

`/snulbug` is a browser-readable trust page with the MCP URL, binding digest,
signer key id, policy lifecycle, lease/auth requirements, upstream summary,
observed tools, and the approved contract JSON. The well-known JSON/text
endpoints give simple HTTP-only agent harnesses the same contract and digest
without requiring a snulbug binary on the client side.

For OAuth protected-resource shares, run the auth-specific doctor before handing
the URL to an MCP client:

```bash
snulbug mcp share auth doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --token "${ACCESS_TOKEN}"
```

`share auth doctor` checks protected-resource metadata, issuer metadata, JWKS or
introspection reachability, HTTPS/public URL alignment, token redaction
settings, scope-to-tool mappings, and Cloudflare Access conflicts. Use
`--no-live-checks` while editing local config, or `--config snulbug.toml` before
a generated share directory exists.

When you want a reviewable auth gate before sharing, generate an auth
conformance pack from the current config, discovered schemas, sample token
references, and replay/audit evidence:

```bash
snulbug mcp share auth conformance generate .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --schema-catalog traces/schemas.json \
  --log traces/audit.jsonl \
  --kind audit \
  --token-env valid=ACCESS_TOKEN \
  --output-dir .snulbug/auth-conformance
```

The pack records file fingerprints and token environment-variable names, not raw
token values. Run it after setting the referenced token env vars:

```bash
snulbug mcp share auth conformance run .snulbug/auth-conformance
```

The run step reloads the config, re-runs auth doctor, validates sample tokens,
checks scope/claim mappings against schema catalogs, and verifies the replay or
audit logs contain auth decision evidence.

The auth doctor also checks resource/audience drift. `mcp.auth.resource` and
`mcp.auth.audience` should exactly match the public MCP URL. If a tunnel URL
changes, rerun the doctor with `--url` and update stale share/client/config
URLs. If a share is intentionally reachable through more than one public URL,
configure both `mcp.auth.resource_aliases` and `mcp.auth.audiences`; otherwise
snulbug treats multiple public URLs as accidental drift.

To generate provider-specific setup files without implementing dynamic client
registration inside snulbug, use:

```bash
snulbug mcp share auth init \
  --provider keycloak \
  --url "${PUBLIC_MCP_URL}" \
  --issuer "${ISSUER_URL}"
```

This writes `.snulbug/auth/<provider>/README.md`, `snulbug.auth.toml`,
`client-token-request.json`, `commands.json`, and `auth-init.json`. Merge the
generated TOML into the share's `snulbug.toml`, complete provider setup, then
run the generated auth doctor command.

Runtime JWT validation can use either a pinned local `jwks_path` or a remote
`jwks_url` with bounded caching and refresh-on-rotation. If `issuer_discovery`
is enabled, snulbug can also discover the issuer `jwks_uri` from
`.well-known/oauth-authorization-server` or `.well-known/openid-configuration`.
For opaque or revocation-sensitive tokens, set
`token_validation = "introspection"` and configure or discover an
`introspection_endpoint`. The auth doctor probes remote JWKS and can POST an
active token to introspection during live checks.

To exercise the full auth model locally without an external identity provider,
run the auth lab:

```bash
snulbug mcp share demo auth
```

The lab starts a mock issuer and MCP upstream, mints demo JWTs, creates a task
lease, runs `share auth doctor`, drives allowed and denied tool calls, and
writes the evidence under `.snulbug-auth-lab/`.

For fabric facade sessions, pass a generated conformance pack when you want the
share gate to prove config, manifests, policies, and replay logs still agree:

```bash
snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --conformance-pack .snulbug/fabric-conformance \
  --require-conformance
```

Inspect the generated client config without opening files by hand:

```bash
snulbug mcp share client .snulbug/shares/share-...
```

Check state later:

```bash
snulbug mcp share status .snulbug/shares/share-...
```

Status is the live "what is happening?" command. It summarizes whether the
gateway is reachable, upstream health, the last public tunnel doctor result
when one has been recorded, the active policy bundle and lifecycle state,
recent allowed/blocked/confirmed counts from the share evidence, current leases,
last recording paths, and high-risk findings.

Generate a share-session report at any point:

```bash
snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

The report is human-readable Markdown built from the session model plus audit
and replay logs. It lists what was exposed, observed clients and source IPs,
tools observed, allowed/blocked/confirmed counts, redaction and risk findings,
upstream health, policy state, and exact next commands. It also classifies
observed MCP tools by risk signal, so shell/process tools, mutating tools,
network-capable tools, filesystem tools, and secret-like tools are visible
before you reuse or hand off the share.

## Remote member attach

Use `share member attach` when a Codespace, devcontainer, Holepunch peer, or
another container should become a managed upstream for an existing share
session:

```bash
snulbug mcp share member attach .snulbug/shares/share-... \
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
snulbug mcp share member attach .snulbug/shares/share-... \
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
snulbug mcp share policy promote .snulbug/shares/share-... --to proposed --key-id local-review
snulbug mcp share policy promote .snulbug/shares/share-... --to approved --key-id local-review
snulbug mcp share policy activate .snulbug/shares/share-... --key-id local-review
```

From inside a generated share directory, omit the directory:

```bash
snulbug mcp share policy promote --to proposed --key-id local-review
snulbug mcp share policy activate --key-id local-review
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
snulbug mcp share create \
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

For ngrok, the generated provider setup follows ngrok's MCP gateway pattern by
default: `tunnel/ngrok-agent.yml` defines a private `.internal` Agent Endpoint
that points at snulbug, and `tunnel/ngrok-traffic-policy.yml` is attached to
the public Cloud Endpoint. The Traffic Policy keeps the existing coarse MCP
edge checks, then forwards allowed traffic to the internal Agent Endpoint.
See [End-to-end ngrok MCP gateway](ngrok-end-to-end.md) for the full
upstream-to-public-Cloud-Endpoint walkthrough.

For Tailscale, `share create --provider tailscale` defaults to the
`funnel-public` profile. This assumes the client URL is reachable through
Tailscale Funnel, keeps snulbug as the MCP policy boundary, and requires the
generated bearer header plus an active task lease before `share doctor` passes:

```bash
snulbug mcp share create \
  --provider tailscale \
  --url https://dev.tailnet.ts.net/mcp \
  --allow-tool safe_read_file \
  --ttl 30m
sudo tailscale funnel 8080
snulbug mcp share doctor .snulbug/shares/share-... \
  --url https://dev.tailnet.ts.net/mcp
```

Use the `serve-tailnet` profile when the endpoint is tailnet-only through
Tailscale Serve rather than public Funnel. Bearer auth still applies, but the
doctor treats leases as a recommended task boundary instead of a public-share
hard requirement:

```bash
snulbug mcp share create \
  --provider tailscale \
  --tailscale-profile serve-tailnet \
  --url https://dev.tailnet.ts.net/mcp
```

Use the `oauth-resource` profile when the MCP client supports MCP OAuth and
snulbug should terminate OAuth for the Tailscale URL. In this profile, Tailscale
is transport, snulbug validates issuer/resource/audience/scopes, and the caller
`Authorization` header is stripped before upstream forwarding:

```bash
snulbug mcp share create \
  --provider tailscale \
  --tailscale-profile oauth-resource \
  --url https://dev.tailnet.ts.net/mcp \
  --auth-issuer https://auth.example.com
```

For Cloudflare Tunnel, `share create --provider cloudflare` defaults to the
`access-gate` profile. This makes Cloudflare Access the outer user/device gate,
requires `CF-Access-Jwt-Assertion`, requires `CF-Ray`, strips Access credential
headers before upstream forwarding, and expects signed Access JWT validation to
be configured before `share doctor` passes:

```bash
snulbug mcp share create \
  --provider cloudflare \
  --url https://mcp.example.com/mcp \
  --cloudflare-access-team-domain team.cloudflareaccess.com \
  --cloudflare-access-audience YOUR-CLOUDFLARE-ACCESS-AUD-TAG \
  --cloudflare-access-allow-domain example.com
```

Use the `service-token` profile for machine clients that cannot complete a
browser Access session. The generated MCP client config uses environment
placeholders, not raw service-token secrets:

```bash
snulbug mcp share create \
  --provider cloudflare \
  --cloudflare-profile service-token \
  --url https://mcp.example.com/mcp \
  --cloudflare-access-team-domain team.cloudflareaccess.com \
  --cloudflare-access-audience YOUR-CLOUDFLARE-ACCESS-AUD-TAG
```

Then set these where the MCP client runs:

```bash
export CLOUDFLARE_ACCESS_CLIENT_ID=...
export CLOUDFLARE_ACCESS_CLIENT_SECRET=...
```

Use the `oauth-resource` profile when the MCP client supports MCP OAuth and
snulbug should be the OAuth protected resource. In that profile Cloudflare
Tunnel is transport, Cloudflare Access stays in audit mode, and snulbug
validates OAuth issuer/resource/audience/scopes:

```bash
snulbug mcp share create \
  --provider cloudflare \
  --cloudflare-profile oauth-resource \
  --url https://mcp.example.com/mcp \
  --auth-issuer https://auth.example.com
```

Use the `audit` profile to observe Cloudflare Access headers before enforcing.

## Close out

When the task is complete:

```bash
snulbug mcp share close .snulbug/shares/share-... --report --revoke
```

Closeout revokes the session lease, writes `session-report.md` when possible,
and marks `share.json` closed. Add `--learn` to generate a learned policy bundle
from the share replay log during closeout:

```bash
snulbug mcp share close .snulbug/shares/share-... --learn --force
```

Then stop the proxy and provider process. Delete the share directory when you no
longer need the local audit artifacts.

<p align="center">
  <img src="https://raw.githubusercontent.com/nahuaque/snulbug/main/assets/snulbug.png" alt="snulbug logo" width="220">
</p>

# snulbug

`snulbug` is a local-dev MCP policy proxy. Put it between an MCP client and one
or more local MCP servers before you hand an agent a broad toolset or expose a
server through a public tunnel.

It gives you a tight loop for agent-tool safety:

- start with a conservative `tunnel-safe` policy
- watch live allow/block decisions while traffic flows
- record redacted replay and audit logs
- learn a least-privilege policy from observed traffic
- amend blocked requests into reviewable candidate bundles
- project `tools/list` into the safe tool catalog a caller can actually use
- classify observed and schema-declared MCP tools by risk before handoff
- review MCP-native capability requests and approve them into normal task leases
- use task-scoped leases for temporary tool/path grants, optionally bound to
  OAuth subject, tenant, client, group, issuer, or auth profile
- turn OAuth identity into MCP-specific tool permissions
- pin facade upstream identity with signed manifests

The standalone ASGI Lua middleware is still available, but it is an
implementation surface. The main use case is protecting local MCP traffic.

## Auth Model

snulbug can act as an MCP OAuth protected resource, including
enterprise-managed authorization flows where the enterprise IdP/client owns
login and consent. The useful part is the MCP-specific authorization layer on
top:

- validate JWTs with local or remote JWKS, issuer discovery, or token introspection
- validate DPoP-bound access tokens and reject Bearer downgrades or replayed proofs
- enforce exact resource/audience settings so tunnel URLs do not drift silently
- trust multiple issuer or tenant profiles for facade and fabric gateways
- map OAuth scopes to concrete MCP methods and tools
- map tenant, group, subject, client ID, or custom claims to tool allowlists
- strip caller OAuth tokens before upstream calls and inject separate upstream credentials
- compose OAuth identity with task-scoped leases and Lua policy before a tool call is allowed
- surface auth runtime counters for JWKS cache state, refreshes, issuer failures, and scope denials
- generate auth conformance packs from config, schemas, sample token refs, and replay/audit logs

Audit records include the selected auth profile, scope/claim-policy decisions,
lease state, auth runtime counters, and Lua decision without logging raw bearer
tokens.

## Install

Install the CLI with `uv`:

```bash
uv tool install "snulbug[discovery]"
snulbug --help
```

For one-off use without a persistent tool install:

```bash
uvx "snulbug[discovery]" --help
```

From another `uv` project:

```bash
uv add "snulbug[discovery]"
```

Add the Redis extra when you need Redis-backed policy, runtime, or member state:

```bash
uv add "snulbug[discovery,redis]"
```

From this repository, use source mode:

```bash
uv sync --all-extras --dev
uv run snulbug --help
uv run pytest
```

The examples below use the installed `snulbug` command. If you are working from
the checkout without installing the tool, prefix commands with `uv run`.

`snulbug` supports Python 3.10 through 3.13.

## Golden Path

The primary workflow is:

```text
share create -> share run -> share status -> share requests approve -> share policy amend -> share policy activate -> share doctor -> share contract -> share report
```

Ask the CLI for a copy-paste version before wiring a client or harness:

```bash
snulbug mcp guide --workflow share
snulbug mcp guide --workflow learn-amend-impact --compact
```

1. Create a temporary share session with generated bearer auth, a task lease,
   provider setup, client config, and close-out report commands:

```bash
snulbug mcp share create \
  --provider holepunch \
  --upstream http://127.0.0.1:9000 \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --ttl 30m
```

2. Run the protected gateway from the generated share directory:

```bash
export SNULBUG_SHARE_TOKEN=...
snulbug mcp share run .snulbug/shares/share-...
```

Inside a generated share directory, `snulbug mcp share run` is enough;
it reads `.snulbug/share/session.json`, reconciles the active config,
policy, lease, and log paths, and starts the local share console before
starting the gateway. Pass `--no-console` when you only want the proxy.

3. Check what is happening:

```bash
snulbug mcp share status .snulbug/shares/share-...
```

The run command also opens a local-only web control room over the same share
session model at `http://127.0.0.1:8765` by default. It shows the
capability-request inbox with a detail drawer, live decision timeline, active
lease store with revoke controls, auth visibility for OAuth subjects/scopes and
JWKS cache health, audit logs, risk summary, findings, inline share doctor,
policy amendment preview, a tool/schema change panel with discovered tools,
risk levels, pinned schema hashes, and drift alerts, a tunnel-provider panel
with public URL, local console, auth mode, generated commands, and last doctor
result, and one-click Markdown session report download using the same report
generator as the CLI. For providers with known local
inspection UIs, the provider panel includes a clickable local console row and
probes whether it is reachable; ngrok appears as
`http://127.0.0.1:4040`.

4. If a legitimate request asks for a temporary capability, review it and mint
   a normal task-scoped lease:

```bash
snulbug mcp share requests list .snulbug/shares/share-...
snulbug mcp share requests approve cap_... \
  --directory .snulbug/shares/share-... \
  --ttl 10m \
  --max-calls 2
```

5. If a legitimate request needs a permanent policy change, amend the reviewed policy bundle from
   the audit log:

```bash
snulbug mcp share policy amend .snulbug/shares/share-...
```

By default this uses the share audit/session log and updates the share policy
bundle in place; pass `--out` when you want a detached candidate bundle.

6. Promote and activate the share policy without leaving the share workflow:

```bash
export SNULBUG_BUNDLE_SECRET=...
snulbug mcp share policy promote .snulbug/shares/share-... --to proposed --key-id local-review
snulbug mcp share policy promote .snulbug/shares/share-... --to approved --key-id local-review
snulbug mcp share policy activate .snulbug/shares/share-... --key-id local-review
```

7. Generate the closeout report from the session model and audit evidence:

```bash
snulbug mcp share report .snulbug/shares/share-... \
  --output .snulbug/shares/share-.../share-report.md
```

Before sharing a public URL or client config, run the share doctor. It is the
single pre-share gate for generated config, policy bundle validity, fabric
checks, current status, public tunnel safety, and behavioral handoff acceptance
checks such as tools/list allowed, unknown tool blocked, revoked lease blocked,
and MCP Inspector setup generated:

```bash
PUBLIC_MCP_URL=https://YOUR-FORWARDING-DOMAIN/mcp
snulbug mcp share doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}"
snulbug mcp share client .snulbug/shares/share-...
export SNULBUG_SHARE_CONTRACT_SECRET=...
snulbug mcp share contract .snulbug/shares/share-... \
  --sign \
  --key-id local-review \
  --output .snulbug/shares/share-.../share-contract.json
```

Pass `--invite invite_...` when you want doctor to run the handoff acceptance
checks against a specific task invite.

To bind the live gateway to that approved contract, run with:

```bash
snulbug mcp share run .snulbug/shares/share-... \
  --require-contract .snulbug/shares/share-.../share-contract.json
```

The running gateway publishes a zero-install trust surface:

- `https://YOUR-FORWARDING-DOMAIN/snulbug` human trust page
- `https://YOUR-FORWARDING-DOMAIN/.well-known/snulbug/share` compact JSON summary
- `https://YOUR-FORWARDING-DOMAIN/.well-known/snulbug/share-contract` approved contract JSON
- `https://YOUR-FORWARDING-DOMAIN/.well-known/snulbug/share-contract.sha256` binding digest

If the share uses OAuth protected-resource or enterprise-managed auth mode, run
the auth doctor too:

```bash
snulbug mcp share auth doctor .snulbug/shares/share-... \
  --url "${PUBLIC_MCP_URL}" \
  --token "${ACCESS_TOKEN}"
```

For multi-upstream facade setups, inspect the declared fabric before handing it
to an agent:

```bash
snulbug mcp fabric status --config snulbug.toml
snulbug mcp fabric doctor --config snulbug.toml --token local-dev-secret
snulbug mcp fabric conformance generate \
  --config snulbug.toml \
  --log traces/session.jsonl \
  --out .snulbug/fabric-conformance
snulbug mcp fabric conformance run .snulbug/fabric-conformance
```

See the full [local MCP policy gateway quickstart](docs/quickstart.md) for
client setup, facade mode, fabric checks, recording, replay, inspection, and
tunnel notes.

## Demos

Run the local policy lab when you want the full lifecycle without wiring a real
server:

```bash
snulbug mcp share demo local
```

The lab creates fake MCP upstreams behind one facade, records traffic, learns a
least-privilege policy, amends a blocked request into a candidate policy, and
writes replay/audit/report artifacts under `.snulbug-lab/`.

Run the OAuth auth lab when you want to prove the stronger public-share model:
valid OAuth subject, tenant/group identity fence, mapped MCP tool scope, active
task lease, Lua approval, and redacted audit output.

```bash
snulbug mcp share demo auth
```

It writes a mock issuer, JWKS, demo tokens, lease file, proxy config, requests,
session/audit logs, and `AUTH_LAB.md` under `.snulbug-auth-lab/`.

For a real provider, the [Keycloak OAuth compose demo](examples/keycloak_oauth_demo/README.md)
runs Keycloak, snulbug, and a demo MCP upstream together. It uses generated
`share auth init --provider keycloak` setup, validates JWTs through issuer
discovery, maps Keycloak scopes to MCP tools, and proves caller OAuth tokens are
not forwarded upstream.

Other provider flows are generated setup recipes until their live demos are
validated against dev accounts. See
[MCP auth interop recipes](docs/mcp-auth-recipes.md) for the current status.

For Codespaces, start the bundled mock MCP server in the Codespace terminal:

```bash
snulbug mcp share member codespace serve-demo
```

It prints the forwarded MCP URL and the matching laptop command. On the laptop,
attach that URL to a local snulbug gateway:

```bash
snulbug mcp share member codespace attach https://YOUR-CODESPACE-9001.app.github.dev/mcp
```

`attach` generates `.snulbug/codespace-local/`, preflights the upstream with
`tools/list`, starts the gateway at `http://127.0.0.1:8080/mcp`, and writes
replay/audit logs for inspection.

## Live Use

Watch decisions while proxying. The generated config includes a console event
sink by default:

```bash
snulbug mcp share run --config snulbug.toml
```

Create a task-scoped lease when you want an MCP client or agent to do one
bounded job:

```bash
snulbug mcp share lease create \
  --file leases.json \
  --task "Read project docs only" \
  --allow-tool safe_read_file \
  --allow-path README.md \
  --allow-subject user-1 \
  --ttl 30m
```

Send the returned `x-snulbug-lease` header with MCP requests. New configs require
an active task lease for `tools/call` by default. OAuth-protected shares can
require both a valid scoped OAuth token and an active task lease before Lua
allows the tool call. If a lease includes auth binding flags, the current
sanitized OAuth context must match those bounds too; a copied lease token alone
is not enough.

When you want to hand a downstream client a ready-to-use setup packet, create a
task-scoped invite instead. It mints a backing lease and returns one-time setup
snippets for MCP client JSON, curl, Claude Code, Codex `config.toml`, and
environment variables:

```bash
snulbug mcp share invite create .snulbug/share \
  --recipient "local agent" \
  --task "Read project docs only" \
  --capability docs_review \
  --ttl 30m
```

The active Lua policy declares the supported invite capability labels. The
default `tunnel-safe` preset offers `project_readonly`, `project_search`,
`docs_review`, `git_inspection`, and `low_risk_tools`; the invite stores only
labels, while Lua enforces the actual tool, path, intent, and risk rules. The
invite list stored in the share session is redacted; bearer and lease tokens are
only shown in the create response or in the local share console after you enter
the console secret printed by `snulbug mcp share run`.

After a session, inspect the logs:

```bash
snulbug mcp evidence inspect traces/session.jsonl
snulbug mcp evidence inspect traces/audit.jsonl --kind audit
```

Learn a least-privilege bundle from observed traffic:

```bash
snulbug mcp policy learn traces/session.jsonl --out learned-policy.snulbug
snulbug bundle validate learned-policy.snulbug
snulbug bundle test learned-policy.snulbug
```

Preview the blast radius before enabling a candidate policy or lease:

```bash
snulbug mcp evidence impact traces/session.jsonl \
  --policy learned-policy.snulbug/policy.lua \
  --lease leases.json \
  --report-out traces/impact-report.md
```

When the learned policy blocks a legitimate request, generate a candidate
amendment instead of editing the active policy in place:

```bash
snulbug mcp policy amend \
  learned-policy.snulbug \
  traces/audit.jsonl \
  --out candidate-policy.snulbug
```

## What It Enforces

Request-side policy:

- bearer challenges and auth checks
- MCP method and tool allowlists
- JSON-RPC batch rejection
- project path constraints for tool arguments
- agent workspace firewalling with path classification and secret/generated path blocks
- schema-aware validation of `tools/call` arguments from MCP `inputSchema`
- schema-aware Lua intent guards for tool categories and risk levels
- task-scoped capability leases with expiring tool/path grants
- MCP-native just-in-time capability requests that suggest normal task leases
- small stateful policies such as rate limits and idempotency keys
- state-backed exponential backoff for repeated equivalent policy denies

Response-side policy:

- redaction of likely secrets from tool/resource/prompt results
- maximum MCP response body size
- optional blocking for instruction-like tool output
- `tools/list` description and schema pinning to catch silent upstream changes
- policy-aware `tools/list` projection using OAuth scopes, claim rules, and active leases
- human confirmation for risky or otherwise blocked calls, with allow-once or session approval

Workflow:

- redacted replay logs for deterministic policy testing
- audit JSONL with MCP-aware fields
- policy evidence diffs that summarize newly allowed tools, MCP path patterns, and argument shapes
- SARIF output for CI gates on policy diffs, schema drift, and share readiness failures
- share reports that classify observed MCP tools by risk signals before handoff
- provider-aware tunnel audit fields for ngrok, Cloudflare, Tailscale, Pinggy, SSH, Holepunch, and generic forwarders
- Cloudflare Tunnel profiles for Access-gated, service-token, OAuth-resource, and audit-first shares
- Tailscale Funnel/Serve profiles for public bearer+lease shares, tailnet-only shares, and OAuth-resource shares
- optional Cloudflare Access origin-side audit/enforcement with Access JWT validation
- optional OAuth protected-resource mode with JWT/JWKS, token introspection, DPoP validation, and MCP auth challenges
- OAuth scope-to-MCP method/tool mapping for least-privilege public shares
- OAuth resource/audience drift checks for tunnel-safe public shares
- generated auth setup flows for Keycloak, Auth0, Okta, Entra, Cloudflare Access, and GitHub OIDC
- composable OAuth + auth-bound task lease + Lua policy access decisions
- anti-passthrough credential brokering so caller OAuth tokens stop at snulbug
- learned least-privilege bundles from observed traffic
- candidate amendments for blocked legitimate requests
- a decision console for live local tunnel traffic

## Documentation

Start with:

- [Quickstart: local MCP policy gateway](docs/quickstart.md)
- [MCP share sessions](docs/mcp-share.md)
- [MCP CLI guide for agents and harnesses](docs/mcp-guide.md)
- [MCP policy workflow: preset, learn, amend, lifecycle](docs/mcp-policy.md)
- [MCP schema workflow: discover, diff, generate policy](docs/mcp-schemas.md)
- [Policy deny backoff](docs/policy-deny-backoff.md)
- [MCP evidence workflow: record, replay, inspect, impact, diff](docs/mcp-evidence.md)
- [CI policy gates and SARIF output](docs/ci-policy-gates.md)
- [MCP reverse proxy](docs/mcp-proxy.md)
- [MCP fabric config, discovery, and conformance](docs/mcp-fabric.md)
- [Codespaces and devcontainers](docs/devcontainers.md)
- [MCP client setup recipes](docs/mcp-client-recipes.md)
- [MCP auth interop recipes](docs/mcp-auth-recipes.md)
- [Lua policy DSL guide](docs/lua-policy-dsl.md)
- [OAuth claim-policy examples](examples/auth_claim_patterns/README.md)
- [Provider-aware Lua policy templates](examples/provider_policy_templates/README.md)
- [Security model](docs/security-model.md)
- [Positioning and comparisons](docs/comparison.md)
- [Roadmap](docs/roadmap.md)

Reference docs:

- [MCP presets](docs/mcp-presets.md)
- [MCP learn and amend mode](docs/mcp-learn.md)
- [MCP evidence record, replay, and inspect](docs/mcp-recorder.md)
- [MCP evidence impact preview](docs/mcp-impact.md)
- [ASGI middleware getting started](docs/getting-started.md)
- [Lua policy reference](docs/lua-request-api.md)
- [Action reference](docs/actions.md)
- [State adapters](docs/state.md)
- [Policy bundles](docs/bundles.md)
- [MCP gateway example](docs/mcp-gateway.md)
- [End-to-end ngrok MCP gateway](docs/ngrok-end-to-end.md)
- [End-to-end MCP policy proxy demo](examples/mcp_proxy_demo/README.md)
- [Keycloak OAuth compose demo](examples/keycloak_oauth_demo/README.md)
- [Release process](docs/release.md)

`snulbug` is currently alpha software. Until 1.0, action schemas and trace
fields may evolve.

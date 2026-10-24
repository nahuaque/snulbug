# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning after `1.0.0`. Before `1.0.0`, minor versions may include action schema or trace schema changes.

## [Unreleased]

## [0.2.6] - 2026-10-24

Trusted internal lease selection and gateway credential-boundary hardening.

- Add trusted, request-local Python/ASGI lease-ID selection for embedding gateways, reusing identity bindings, expiry/revocation checks, policy previews, and atomic call budgets. Reject conflicting selections without recovering or injecting lease credentials.
- Consume lease credential headers at the upstream boundary, including custom header names, facade transport plugins, and streamed HTTP requests. Include configured custom lease-header names in replay/audit redaction.
- Validate supplied selections on facade discovery without consuming calls, and reject lease denials on bodyless HTTP stream opens before forwarding.

Upgrade note: public clients continue to send their existing lease headers, but
upstream applications no longer receive them. Keep lease enforcement at the
gateway; embedding hosts must independently authorize any internally selected
lease reference. No change to renewal/expiry configuration or MCP protocol defaults.
See the [trusted selection integration guide](docs/mcp-proxy.md#trusted-internal-lease-selection).

## [0.2.5] - 2026-10-23

Public-origin preservation for shared MCP and HTTP gateways.
Read the [0.2.5 upgrade notes](docs/upgrading-to-0.2.5.md) before deploying an
existing ngrok share or a share with required signed HTTP mount contracts.

- Forward canonical public host, scheme, and port from the configured share URL across internal hops. HTTP mounts can opt into `preserve_host = true`; backend Host remains the default and upstream TLS verification is unchanged.
- Generate ngrok policies that capture and validate the original public authority/scheme before forwarding and replace caller-supplied origin/audit headers. Reject invalid capture pairs at the gateway and unsafe public URLs at config load; keep observed ingress headers for audit provenance, not forwarding authority.
- Include effective origin and Host mode in mount health checks, doctor, status, reports, the web console, readiness reviews, and signed mount contracts. Existing ngrok policies need manual review and reattachment; no cloud changes or share regeneration are applied automatically.
- Add regression coverage for spoofed/duplicate headers, redirects, prefixes, ports, IPv6, MCP forwarding, health/cache invalidation, and contract drift, including installed-wheel packaging checks.

No change to the default MCP protocol or preview limitations. Application auth,
proxy trust, base paths, and CSRF defenses remain the mounted app's responsibility;
this release does not rewrite HTML, redirect locations, or cookie paths.

## [0.2.4] - 2026-10-19

Operational hardening for always-on shares and shared HTTP/MCP gateways.
See the [0.2.4 upgrade notes](docs/upgrading-to-0.2.4.md) before restarting an
existing service, especially if a tunnel is already running separately.

- Moved ngrok/SSH tunnel management into the share runtime: `share run` supervises tunnels with or without the web console, bounded crash-restart backoff, explicit stop/start controls, and graceful gateway/tunnel shutdown. Added `--no-tunnel` and always-on deployment recipes.
- Added read-only ngrok policy drift checks to share doctor, readiness, reports, and the console: compare current config, generated policy, and deployed Cloud Endpoint policy without exposing deployed secrets or applying cloud changes. Includes OAuth-aware edge baselines and stale-result invalidation.
- Added evidence-based request failure explanations to existing audit logs, live decisions, and session reports: distinguish admission gates, upstream credentials/connectivity, HTTP/MCP errors, partial catalogs, and response checks while preserving Lua decisions and unknown execution outcomes. Removed raw forwarding exceptions from client errors and facade health evidence; no tool-call retries.
- Hardened upstream credential operations: bounded regular-file/header reads, secret-free broker failures, and live share doctor availability/hygiene checks surfaced in readiness, status, reports, and the Auth drawer. Documented atomic file rotation and environment restart semantics; passive refreshes reuse saved diagnostics without resolving secrets.
- Added explicit HTTP mount contracts for authentication ownership, methods, credential-header forwarding, inactivity timeouts, and optional backend health checks. Reused share doctor/readiness, reports, the provider drawer, and signed share-contract bindings; public mounts strip Authorization/cookies by default, and MCP auth/leases remain separate from application access.
- Added isolated installed-wheel operations QA for share creation, local MCP/HTTP traffic, credential rotation, persisted leases, and supervised shutdown. Fixed installed-package share creation so container recipe snapshots no longer require a source checkout.

No change to the default MCP protocol version or experimental profile limitations.
This release does not add HTTP application OIDC, overload protection, automatic
tool-call retries, or a published container image.

## [0.2.3] - 2026-10-18

Add Pocket ID setup through the existing OAuth provider and lease machinery.

- Added `share auth init --provider pocket-id` with resource-bound API permissions, deny-by-default scope maps, PKCE/CIMD registration instructions, automation guidance, and lease-aware doctor commands.
- Extended auth doctor to check exact issuer metadata identity, advertised PKCE S256, and CIMD availability without claiming access to private provider grants or allowlists.
- Added synthetic RS256 user/bot token fixtures, rejection and JWKS rotation tests, and existing auth conformance-pack coverage; documented setup and identity-claim limitations.

Pocket ID live passkey/client interoperability remains unverified. This release
does not add browser console login or authentication to HTTP mounts. No change
to the default MCP protocol version or the experimental profile's limitations.

## [0.2.2] - 2026-10-16

Support always-on MCP bots with renewable automation invites, without introducing
a separate permission or approval system.

- Added renewable automation invites using the existing backing lease, with bounded consumer renewal/restart recovery, rotating access tokens, identity bindings, persistent usage budgets, and console/CLI setup snippets.
- Serialized lease mutations across local workers so renewal, revocation, cleanup, and concurrent call consumption cannot overwrite each other's state.
- Added renewal visibility and refresh-stable invite forms in the web console, secret-safe renewal audit events, and share closeout that revokes invites as well as the session lease.

Automation renewal is opt-in. Access leases remain short-lived; the owner's
renewal authorization has a separate hard expiry. Clients must adopt refreshed
lease headers, and revocation or exhausted budgets prevent recovery. No change
to the default MCP protocol version or the experimental profile's limitations.

## [0.2.1] - 2026-10-15

Expose web applications and APIs alongside MCP through one gateway and ngrok tunnel.

- Added `[[mcp.proxy.http_routes]]` mounts with longest-prefix routing, segment-boundary matching, configurable prefix stripping, and reserved MCP/gateway paths.
- Added repeatable `--http-route PREFIX=URL` flags to share creation and quickstart, with matching ngrok Traffic Policy rules that apply MCP edge checks only to the MCP endpoint.
- Added streaming HTTP uploads, responses, and SSE with disconnect cleanup, ordinary HTTP headers/cookies/content encodings, and plain HTTP upstream errors; included local proxy/facade regression coverage and setup documentation.
- Raised the PyJWT minimum to 2.15 and updated the lockfile to exclude the versions flagged by the current JWT security advisories.

HTTP mounts bypass MCP authentication, leases, Lua, redaction, and MCP evidence
logging; each backend owns its authentication. Applications must configure their
public base path. WebSockets and rewriting HTML, redirects, or cookie paths are
outside this slice. See [shared HTTP routes](docs/mcp-proxy.md#shared-http-routes)
and the [ngrok walkthrough](docs/ngrok-end-to-end.md).

## [0.2.0] - 2026-09-06

This release expands MCP protocol support while keeping **2025-11-25 as the default**.
The **2026-07-28 profile is opt-in and remains a request-stream preview**, not a
claim of complete MCP conformance. See the [upgrade notes](docs/mcp-protocol.md#upgrading-to-020).

- Added version-aware discovery, request metadata/header validation, schema-derived parameter headers, and explicit implementation coverage in share doctor.
- Added bounded HTTP SSE and managed stdio streaming/subscriptions, with multiplexed stdio requests, cancellation, disconnect cleanup, credential-expiry limits, and existing policy/audit controls. Facade subscriptions use the default upstream only.
- Added multi-round-trip request (MRTR) relay through existing auth, lease, and server-to-client policies, plus private, immediately stale result hints and HTTP no-store handling without introducing a response cache.
- Replaced the hand-written schema subset with offline JSON Schema 2020-12 input/output validation across both protocol profiles, including bounded diagnostics and pinned conformance fixtures. Invalid declarations and unresolved external references are reported rather than silently accepted.
- Strengthened release checks for packaged protocol modules, fixture licensing, and isolated installed-wheel protocol/schema behavior; updated package and devcontainer release metadata to 0.2.0.

Real-client/provider E2E verification remains deferred. Modern Tasks, facade-wide
subscription aggregation, reconnect/resume, and continuous reauthorization of open
streams are outside this preview; doctor continues to report incomplete conformance.

## [0.1.3] - 2026-07-05

This is primarily an MCP conformance release for the 2025-11-25 protocol line.

- Added first-class MCP protocol mediation for official tasks, task capability enforcement, completion requests, progress/cancellation notifications, resource subscriptions/change notifications, and server-to-client `sampling`, `elicitation`, and `roots` requests.
- Hardened Streamable HTTP handling with configurable MCP protocol-version, accept/content-type, session, origin, GET, and DELETE checks, plus conformance diagnostics surfaced through `share doctor`.
- Expanded schema discovery, pinning, diffing, and validation to cover tool output schemas, `structuredContent`, `execution.taskSupport`, and resource/prompt metadata including icons.
- Improved OAuth conformance with scope-bearing challenges for incremental consent and MCP protected-resource checks that are easier to validate before public sharing.
- Folded share acceptance checks into doctor/report workflows so a share can prove config, policy, discovered schemas, replay evidence, and handoff connectivity before exposing a tunnel.
- Updated the devcontainer feature release line to `0.1.3`.

## [0.1.2] - 2026-06-30

- Added the local share console as the default companion UI for `snulbug mcp share run`, including setup flows, readiness review, health checks, live decisions, pending requests, policy visibility, auth visibility, lease management, tool/schema drift, tunnel status, and one-click session reports.
- Added task-scoped share invites with policy-declared capability labels, invite setup snippets, console-secret-gated sensitive views, invite cleanup, and invite metadata in lease/audit records.
- Changed generated MCP share configs to require active task leases by default for tool calls, and hardened lease authorization around inactive, revoked, and stale invite-backed leases.
- Added MCP-native just-in-time capability requests, policy deny backoff, policy-aware tool catalog projection, and richer Lua policy DSL helpers for access, auth, leases, workspace rules, upstream routing, and capability requests.
- Added OAuth DPoP validation with replay protection, Redis-backed DPoP replay caching when Redis state is enabled, enterprise-managed MCP auth support, auth runtime visibility, and stronger OAuth + lease composition.
- Added ngrok management and diagnostics in the share console, improved ngrok setup guidance, provider-local console visibility, public tunnel health checks, and SSH reverse tunnel support.
- Added MCP Inspector setup generation and share doctor acceptance checks so handoff flows can prove client connectivity and policy behavior before sharing.
- Added plugin extension points for auth providers, credential brokers, discovery providers, evidence exporters, tool risk analyzers, upstream transports, and share doctor/conformance checks.
- Added `snulbug release-qa` with version, README, formatting, linting, Bandit, pytest, build, distribution inspection, and source/built-wheel smoke-test gates, and wired it into release documentation and publishing workflow.

## [0.1.1] - 2026-06-16

- Fixed PyPI/TestPyPI project metadata and README logo URLs to point at the
  published `nahuaque/snulbug` repository.
- Added public GitHub project metadata, CI, contribution docs, security docs, issue templates, and reference documentation.
- Added the basic ASGI middleware example under `examples/basic`.
- Added bundled MCP policy presets with `snulbug mcp policy preset`.
- Added MCP request decision recording and replay with `snulbug mcp evidence record` and `snulbug mcp evidence replay`.
- Added secret redaction and redacted MCP audit JSONL logs.
- Added local-dev MCP reverse proxy mode with `snulbug mcp share run`.
- Added live proxy request recording and audit logging with `snulbug mcp share run --record-out`.
- Added MCP proxy TOML config files with `snulbug mcp share config init` and `snulbug mcp share run --config`.
- Added configurable MCP policy generation options to `snulbug mcp policy preset`.
- Added live proxy decision console output with generated console event sinks.
- Added MCP-aware audit fields for JSON-RPC id, method, operation, targets, key names, batches, and initialize metadata.
- Added policy decision `reason` and `reason_code` conventions across MCP helpers, presets, audit logs, and live console output.
- Added offline MCP log inspection with `snulbug mcp evidence inspect`.
- Changed MCP record/proxy defaults to redact replay artifacts unless exact logging is explicitly requested.
- Added MCP client setup recipes for local, tunneled, authenticated, recording, and stdio-only workflows.
- Added a local MCP policy gateway quickstart and `snulbug mcp share quickstart` generator.
- Added a runnable end-to-end MCP policy proxy demo.
- Added MCP risk-profile presets for read-only local development, shell-tool denial, project path allowlists, and tunneled servers.
- Added Markdown MCP session reports with `snulbug mcp evidence inspect --report-out`.
- Documented `tunnel-safe` as the recommended default for public tunnel use.
- Added MCP facade mode for serving multiple local MCP HTTP servers through one `snulbug mcp share run` endpoint.
- Added managed stdio MCP upstreams for facade mode, so local stdio servers can be exposed through the same policy-controlled HTTP endpoint.
- Added MCP learn mode with `snulbug mcp policy learn` to compile captured replay/audit logs into least-privilege policy bundles.
- Added MCP amend mode with `snulbug mcp policy amend` to produce candidate patches from blocked learned-policy decisions.
- Added `snulbug mcp share lab`, a one-command local MCP policy lab covering facade, recording, inspection, learn, and amend.

## [0.1.0] - 2026-06-12

- Initial alpha package for programmable Lua request policy in ASGI middleware.
- Added request actions: `continue`, `set_context`, `rewrite`, `respond`, `reject`, `challenge`, `redirect`, and `rate_limit`.
- Added bounded policy state with memory, SQLite, Redis, snapshot, and dry-run support.
- Added simulator, policy diffing, shadow policy support, bundle validation, bundle tests, and bundle packing.
- Added customer-owned request policy, webhook normalization, state replay, idempotency bundle, and MCP gateway examples.

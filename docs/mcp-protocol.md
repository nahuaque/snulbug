# MCP Protocol Versions

Snulbug defaults to **2025-11-25**. The latest published MCP revision is
**2026-07-28**; snulbug currently implements a **bounded request-stream preview** of
that revision. Recognizing a revision does not mean complete conformance.

| Revision | Gateway behavior | Discovery |
| --- | --- | --- |
| 2025-11-25 | Existing proxy/facade behavior; default | Legacy `initialize` flow |
| 2026-07-28 | Stateless JSON, request-scoped SSE, MRTR, and bounded HTTP/stdio subscriptions preview | Local `server/discover` |
| 2025-03-26 / 2025-06-18 | Recognized legacy profiles; end-to-end coverage untested | Legacy `initialize` flow |

Snulbug share sessions, invite capabilities, and task leases are application
state. They are distinct from the protocol-level sessions removed in modern MCP.

## Upgrading to 0.2.0

Existing shares keep the 2025-11-25 profile; no configuration migration is
required to retain that protocol. Do not switch production shares to the preview
solely because the package version changed. Real-client/provider E2E verification,
including modern auth interoperability, remains deferred, and doctor does not
claim complete conformance.

Schema enforcement changes apply to **both profiles** when schema validation is
enabled. The previous hand-written subset is replaced by JSON Schema 2020-12:

- Previously ignored constraints can now block a request or result. Replay your
  existing evidence against the upgraded policy before handoff.
- Invalid schemas, unsupported declared dialects, and unresolved external
  references produce validation issues. Existing block/warn settings still apply;
  repair declarations rather than disabling enforcement as a migration shortcut.
- Remote/file schema retrieval is disabled. Bundle referenced definitions into
  the supplied schema; `format` remains an annotation rather than an assertion.
- Runtime dependencies now include `httpx`, `jsonschema`, and `referencing`.
  Reinstall/upgrade the package or sync the source checkout's lockfile.

The preview supports HTTP and managed stdio subscriptions, but facade
subscriptions target only the default upstream. Open streams have bounded
lifetimes and verified credential-expiry limits, not continuous policy/lease
reauthorization. Modern Tasks, reconnect/resume, and cross-version translation
are not included. These limits are unchanged by a passing release QA run.

## Try Modern Discovery

In a separate test config, select the preview explicitly:

```toml
[mcp.proxy]
streamable_http_protocol_version = "2026-07-28"
```

Keep the rest of your existing proxy config, including its Lua policy and auth
settings. Use only upstream HTTP or managed stdio servers that implement the modern revision.
The preview does not initialize legacy servers or translate between revisions.
Keep existing production shares on the legacy default until the preview meets
their conformance requirements, including real-client and auth interoperability verification.

Start the test gateway using the normal share workflow:

```bash
uv run snulbug mcp share run --config snulbug-preview.toml
```

With `SNULBUG_TOKEN` set to the bearer credential configured for that share:

```bash
curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: server/discover' \
  -d '{"jsonrpc":"2.0","id":"discover","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

Discovery runs behind OAuth/Cloudflare authentication when configured, and
behind the active Lua policy. For Lua allowlists, include `server/discover` as
protocol setup traffic. The bundled tunnel-safe policy allows it after bearer
authentication; an active tool lease is not needed just to discover the gateway.

The response identifies **snulbug**, including when the gateway has multiple
upstreams. It carries `resultType: "complete"`, `supportedVersions`,
`ttlMs: 0`, `cacheScope: "private"`, and basic tools/resources/prompts/completions
dispatch capabilities without subscription flags. These describe the gateway's
dispatch surface, not a guarantee that an upstream implements every method. The
`_meta["io.snulbug/implementation"]` field reports the request-stream preview scope and
remaining implementation requirements. Upstream health is still checked through
the existing health/doctor checks; a discovery success does not prove reachability
of any upstream.

Every modern request validates the version and method headers against request
metadata. Header mismatches return `-32020`; unsupported revisions return
`-32022`. Obsolete MCP session requirements do not apply to this profile.

## Stateless Request Dispatch

The preview forwards `tools/list`, `tools/call`, `resources/list`,
`resources/templates/list`, `resources/read`, `prompts/list`, `prompts/get`,
and `completion/complete` through existing auth, Lua, lease, schema, response,
and routing controls. No prior discovery or initialize call is required.
Each request carries its own client capabilities and protocol version.

For a modern upstream exposing `safe_read_file`, with that tool permitted by
the active Lua policy and the lease in `SNULBUG_LEASE`:

```bash
curl -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H "x-snulbug-lease: ${SNULBUG_LEASE}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: safe_read_file' \
  -d '{"jsonrpc":"2.0","id":"read","method":"tools/call","params":{"name":"safe_read_file","arguments":{"path":"README.md"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

In facade mode, use the prefixed tool name in both `Mcp-Name` and `params.name`.

`tools/call` and `prompts/get` require `Mcp-Name` to match `params.name`;
`resources/read` requires it to match `params.uri`. Header-safe ASCII is sent
literally; other values use the specification's UTF-8 Base64 sentinel encoding.
When the facade strips a tool prefix, it rebuilds `Mcp-Name` for the upstream.
`Mcp-Session-Id` and `Last-Event-ID` are removed before forwarding and are not
returned to clients. Authentication and lease validity are checked on every call.

Final upstream responses must be JSON-RPC responses with matching IDs and a
`resultType: "complete"` result, or a JSON-RPC error. JSON responses and final SSE
results pass through the existing response, output-schema, and catalog controls.
MRTR interim results follow the controls below. Task results and legacy-shaped success results fail closed.
Rejecting a response does not undo a tool's side effects.

## Request-Scoped Streaming

Modern HTTP upstreams can return JSON or SSE. Managed stdio upstreams can emit
interleaved notifications before their final JSON-RPC response; snulbug exposes
these as SSE through the same facade, without a separate transport mode.
Use `curl -N` to display streamed events without curl's output buffering.

- `notifications/progress` and `notifications/message` are forwarded as they arrive.
  Progress tokens must match the originating request. Existing progress policy
  controls apply, including configured monotonicity and rate-limit enforcement.
- Notifications reuse response-policy redaction and instruction-content checks.
  Unsupported messages and independent server-to-client requests fail closed;
  streaming does not bypass MRTR policy checks.
- Backpressure follows downstream writes. Disconnecting the HTTP client cancels
  the forwarding operation and closes its HTTP upstream connection. For managed
  stdio, cancellation terminates/reaps the process before another request can
  reuse the client. The next call can start a fresh process. This cannot guarantee
  that remote work or already-performed side effects are undone.
- Each SSE frame and final JSON result is bounded by the smaller of
  `response_max_bytes` and 2 MiB (2 MiB if unset). HTTP SSE input has an aggregate
  byte budget of eight times that limit; at most 1,024 notifications are accepted
  per request. HTTP I/O and stdio response reads use the configured proxy timeout.
- Arbitrary upstream SSE comments and fields are not relayed. Compression,
  independent GET streams, and reconnection/resume remain unsupported.
  An EOF without a terminal response is a stream failure.
- Before streaming starts, failures return HTTP 502 with a JSON-RPC error. After
  HTTP 200/SSE has started, failures terminate the stream with a JSON-RPC error
  using the original request ID. Clients must inspect the final RPC, not just
  the HTTP status.

The existing request record receives a `metadata.stream` summary: completion or
failure/disconnect status, notification counts, received SSE bytes, and redacted
event counts. It does not create one audit record per notification or store raw
notification payloads. Legacy HTTP forwarding is unchanged by this preview.

## Multi Round-Trip Requests

`tools/call`, `resources/read`, and `prompts/get` can return `resultType:
"input_required"`. Snulbug validates and mediates this response over JSON, SSE,
and managed stdio. The client supplies a **new JSON-RPC ID** when retrying the
original operation, echoes `requestState` exactly when present, and puts its
answers in `params.inputResponses`. Snulbug does not execute the client's inputs,
retry automatically, or create a second approval queue.
MRTR answers do not grant a snulbug capability, approve a pending policy request,
or replace the task lease. MCP client capabilities describe supported protocol
features, not authorization scopes.

The existing response setting governs embedded requests:

```toml
[mcp.proxy]
streamable_http_protocol_version = "2026-07-28"
server_to_client_request_action = "block" # default; also supports "warn" and "allow"
```

Only opt into `warn` or `allow` for trusted upstreams and clients. These settings
cover embedded `elicitation/create`, `sampling/createMessage`, and `roots/list`
requests using the existing server-to-client policy and audit fields. Client
capabilities must support the requested feature, including elicitation form/URL
mode and sampling tools/context. Unsupported capabilities, unknown input methods,
and malformed envelopes fail closed even in `allow` mode. Sampling and roots
remain available for interoperability, not as a recommendation for new policies.

Example interim result:

```json
{
  "jsonrpc": "2.0",
  "id": "read-1",
  "result": {
    "resultType": "input_required",
    "requestState": "opaque-upstream-state",
    "inputRequests": {
      "confirm": {
        "method": "elicitation/create",
        "params": {
          "mode": "form",
          "message": "Confirm the project to inspect",
          "requestedSchema": {"type": "object", "properties": {"project": {"type": "string"}}}
        }
      }
    }
  }
}
```

Retry the original method/name/arguments, with the usual auth, lease, protocol
headers and per-request metadata, adding:

```json
{
  "requestState": "opaque-upstream-state",
  "inputResponses": {"confirm": {"action": "accept", "content": {"project": "demo"}}}
}
```

Every retry runs through current auth/scopes, Lua, route selection, argument
validation, and lease enforcement. Tool retries consume another lease call;
expired, revoked, or exhausted leases do not gain an exemption. Facade routing
still uses the explicit tool prefix, never data inside `requestState`.
Final results retain normal output-schema validation; interim results are not
mistaken for final `structuredContent`.

Limits are 32 inputs per map, 256-byte input keys, 256 KiB encoded input maps,
and 64 KiB opaque state, in addition to existing request/response bounds.
State-only interim results are allowed, and no background retry loop is created.
Notification/result content still receives response-policy checks. Opaque state
and input correlation keys are preserved on the wire, not rewritten by redaction.

Records include `metadata.mrtr` counts and continuation/result markers.
Default log redaction hides **all** `requestState` and `inputResponses` values;
exact, unredacted recording remains an explicit opt-in and can contain sensitive
answers. Redacted evidence is suitable for policy replay, not reconstructing a
live continuation exchange.

**Trust boundary:** this is a stateless relay, not a continuation credential
broker. Snulbug does not attest to state, bind it to a previous request/principal,
enforce single-use, pin a route across retries, or impose a cumulative round limit.
The upstream must authenticate/integrity-protect its state and enforce principal,
request, expiry, and replay constraints where relevant. In particular, shared
upstream credentials do not automatically convey the downstream OAuth subject.
Do not enable sensitive continuations for an upstream that relies on client-echoed
state as trusted authorization. Clients control whether and how often to retry.

## HTTP Change Subscriptions

The preview supports `subscriptions/listen` through HTTP and managed stdio upstreams. In a facade,
the request goes **only to the configured default upstream**, not a merged fanout
of all members. It does not translate resource URIs or synthesize facade-wide
tool-change events. Both transports use the same acknowledgment, filter, response
policy, lifetime, and evidence controls described below.

Explicitly allow `subscriptions/listen` in your Lua policy and, for OAuth scope
maps, grant that method to the appropriate scope. This slice does not broaden
bundled policy allowlists. `mcp.is_resource_subscription(request)` recognizes the
method; `mcp.call(request).resource_operation` is `"listen"` and
`mcp.call(request).resource.notifications` exposes the requested filter. It is
**not** classified as a read-only call. URI access must be authorized in policy;
being listed in a filter is not an authorization grant.

For a policy-authorized subscription to tool catalog changes:

```bash
curl -N -sS http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer ${SNULBUG_TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: subscriptions/listen' \
  -d '{"jsonrpc":"2.0","id":"watch-1","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

Filters support `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`,
and `resourceSubscriptions` (at most 128 unique, nonempty URIs, each at most
4,096 characters). Omitted flags are not requested. The first notification must
be `notifications/subscriptions/acknowledged`, accepting only a subset of the
requested filters. Every notification must carry the original request ID in
`params._meta["io.modelcontextprotocol/subscriptionId"]`. Resource updates must
match an accepted URI exactly. Missing/duplicate acknowledgments, broadened
filters, cross-stream IDs, and unrequested changes terminate the stream before
the offending event reaches the client. Progress, logging, and server requests
are not permitted on this stream.

Notifications reuse response redaction/instruction checks and resource policy
checks. Subscription identity is request-local, not taken from the legacy shared
URI subscription registry. Correlation IDs are preserved on the wire; routing
fields that would need redaction fail closed instead of silently changing URI.
An upstream graceful close must return `resultType: "complete"` with the same
subscription ID in result metadata. An early JSON-RPC error is also supported.

The existing `resource_subscription_ttl_seconds` setting bounds the entire
operation, capped at one hour. Verified OAuth or Cloudflare Access JWT expiry
can shorten that lifetime. Quiet streams do not hit the ordinary HTTP read
timeout, but connection/write timeouts, event/frame/aggregate byte limits,
backpressure, and disconnect cleanup still apply. At expiry, snulbug closes the
upstream and returns a terminal RPC error requiring reconnection. There is no
automatic reconnect or event replay.

Auth, scope, and Lua checks run when the subscription opens. Policy reloads,
lease revocations, route quarantine, or changes to an issuer's revocation state
do **not** continuously reauthorize an already-open stream in this slice; use a
short TTL where rapid reauthorization matters. Task leases are still enforced
for tool calls, not automatically required for subscriptions.

The existing final request record includes `metadata.stream.subscription` with
requested/accepted category counts, acknowledgment state, and event counts.
It does not log every notification or persist raw resource URIs in that summary.
Discovery continues to omit upstream-dependent subscription capability flags;
the actual accepted filter comes from the upstream acknowledgment.

### Managed Stdio

A managed process has one stdout reader and separate bounded queues for active
requests. Up to 31 subscriptions can remain open alongside one ordinary request;
the ordinary slot is reserved so subscriptions cannot exhaust tool-call capacity.
Ordinary requests stay serialized because log notifications may lack correlation
metadata. Each modern request receives a unique upstream wire ID, and subscription
IDs are translated back to the original client ID before policy checks or delivery.
Clients may therefore reuse identical request IDs without colliding with each other.

Disconnects, lifetime/credential expiry, and rejected notification callbacks send
`notifications/cancelled` with the upstream request ID. Cancelling one subscription
leaves other active requests alone. Cancelling an ordinary request resets the
process because late untagged notifications cannot be safely attributed. When the
last cancelled request leaves, snulbug closes stdin and reaps the process, escalating
to termination/kill if necessary. Normal completion keeps the process reusable.

The ordinary upstream timeout applies to writes, initial acknowledgment, and
notification delivery, but not to quiet periods after acknowledgment. Queues allow
32 messages / 2 MiB per request, with an 8 MiB aggregate wire-byte budget and a
2 MiB line limit. A blocked consumer does not stop routing other requests. Queue
overflow, malformed or uncorrelated messages, and unexpected server requests fail
the shared process and outstanding requests; clients must reconnect. Late messages
for cancelled subscriptions also fail the process rather than reaching another client.
No subscriptions or tool calls are automatically replayed after a restart.

This does not bridge protocol revisions: configure a modern stdio server for a
modern share. Legacy stdio requests retain their sequential behavior.

## Schema-Derived Parameter Headers

Modern tool schemas can designate primitive arguments as HTTP mirrors using
`x-mcp-header`. For example:

```json
{
  "type": "object",
  "properties": {
    "region": {"type": "string", "x-mcp-header": "Region"},
    "options": {
      "type": "object",
      "properties": {"dryRun": {"type": "boolean", "x-mcp-header": "Dry-Run"}}
    }
  }
}
```

A `tools/call` with `{"region":"us-east-1","options":{"dryRun":true}}` in
`params.arguments` must include:

```text
Mcp-Param-Region: us-east-1
Mcp-Param-Dry-Run: true
```

After observing `tools/list`, snulbug validates recognized mirrors **before Lua
evaluation**, returning HTTP 400 / `-32020` on missing, duplicate, malformed,
or mismatched headers. Comparisons use decoded values and case-insensitive header
names. Integers are compared numerically within the JavaScript safe-integer range;
strings and booleans use exact values. Null or absent arguments omit their headers.
Non-ASCII, control characters, boundary whitespace, and literal Base64 sentinels
use the same encoding as `Mcp-Name`.

Annotations must name unique HTTP tokens and occur on string/integer/boolean
properties reached solely through nested `properties`. Annotations inside arrays,
references, or composition branches are invalid. Modern gateway catalogs and
schema discovery exclude invalid tools; diagnostics identify the tool and reason.
Gateway response metadata includes `parameter_headers.rejected_count` and rejected
tool summaries. The existing schema cache retains rejected definitions so calling
an excluded tool by name cannot bypass the check. Existing pinning/drift policy
still applies.

This uses the existing tool schema store, even when general `schema_validation`
is disabled. No additional discovery request, registry, or approval flow is
created. **Before a schema has been observed, its headers are unknown** and remain
passthrough. Unknown `Mcp-Param-*` headers must not be treated as trusted policy
inputs; upstream servers remain responsible for validating their full definitions.
Call `tools/list` again when a schema changes, then retry with matching mirrors.

If Lua rewrites arguments, snulbug rebuilds recognized headers from the resulting
body using the schema snapshot checked at ingress. It preserves unknown headers.
Facade calls use the prefixed tool's cached schema, while forwarding strips the
tool prefix and rebuilds `Mcp-Name` as before. Auth, leases, input validation, and
response policy retain their normal enforcement; mirrors grant no permission.

Preview limits: 128 annotations per schema, 128 characters per header suffix,
4,096 schema nodes, and 64 nesting levels, in addition to request/response bounds.
Rejection messages and header-check summaries contain no argument/header values.
Normal request recording settings still apply to the underlying traffic.

## Policy-Safe Cache Hints

Modern gateway responses use `ttlMs: 0` and `cacheScope: "private"` for
completed discovery, catalog, and resource-read results. Upstream hints are
normalized even when missing or malformed: results can depend on the current
subject, lease, and Lua policy, so an upstream's public catalog is not necessarily
public after gateway filtering. JSON is sealed after Lua; SSE terminal events
use the existing bounded stream sender. MRTR interim results carry no hints;
completed continuation results remain private and immediately stale.

The MCP endpoint emits HTTP `Cache-Control: no-store`, including denials, and
removes upstream cache directives and validators. No response cache is created:
each request reaching snulbug still runs the existing authorization and policy
checks. This does not revoke data a client has already received or force a
noncompliant client to discard it. Legacy-profile behavior is unchanged.

Request evidence includes a bounded `cache` summary (under `stream` for SSE),
with effective hints and whether incoming hints needed adjustment, never raw
malformed hint values. Cache handling is reported in protocol coverage.

## JSON Schema Validation

Tool arguments and final `structuredContent` use the same offline JSON Schema
2020-12 validator (`jsonschema` with an explicit `referencing` registry).
This replaces the former hand-written subset in both modern and legacy profiles.
Existing `schema_validation` and `schema_validation_action = "block" | "warn"`
settings still control enforcement; no parallel schema store is introduced.

The validator handles conditional and dependent schemas, `prefixItems`,
`contains`, `unevaluatedProperties`/`unevaluatedItems`, local anchors and dynamic
references, recursive schemas over finite instances, and constraints alongside
`$ref`. Boolean schemas and JSON number/boolean distinctions are preserved.
Invalid declarations are retained and reported instead of silently becoming
unconstrained schemas. A tool whose schema has not been observed still follows
the existing unknown-schema behavior; this does not trigger automatic discovery.

Operational boundaries:

- The default and supported explicit dialect is JSON Schema 2020-12; other
  declared dialects are rejected rather than silently interpreted differently.
- References may resolve within the supplied schema, including embedded `$id`
  resources. No URL or filesystem retrieval is permitted.
- `format` is an annotation, not an assertion. Content annotations do not decode
  or execute content. Regular expressions use the library's Python regex engine.
- Schemas are limited to 256 KiB when JSON-encoded. Schema and instance trees
  each allow 10,000 nodes and 64 nesting levels. At most 20 issues are returned,
  with bounded paths and messages that omit instance values and exception text.
- The validator is in-process. These structural limits are **not** a hard CPU
  timeout or an isolation boundary for adversarial regexes/combinators.

Tests include a pinned, selected JSON-Schema-Test-Suite pack plus input/output
policy regressions. Remote-fixture cases are explicitly skipped and retrieval
denial is tested separately. This closes the tracked schema implementation gap,
not every possible conformance or sandboxing concern.

## Remaining Dispatch Gaps

Legacy initialize/notifications, Tasks methods, and unknown RPCs
return HTTP 404 / `-32601`. Requests containing task wrappers, malformed MRTR
fields, or continuations on unsupported methods return HTTP 400 / `-32602` before forwarding.
Modern auth interoperability verification remains a tracked gap. Facade-wide
subscription aggregation and continuous stream reauthorization are still outside
this preview. Doctor reports incomplete coverage.

## Doctor and Schema Discovery

`share doctor` chooses its conformance checks from the configured protocol
version. Its `mcp_spec` artifact distinguishes:

- `spec_version`: the selected profile.
- `latest_spec_version`: the latest published revision.
- `coverage`: known implemented, unsupported, and untested requirements.
- `conformance_complete`: currently false, including for the legacy checks.
- `latest_coverage`: current migration coverage even when using a legacy share.

With live checks enabled, a modern doctor run sends an authenticated
`server/discover` request and validates the JSON-RPC response, response ID,
version advertisement, and cache fields. Offline runs label that probe untested
and make no discovery request. A successful discovery check is **not** full
conformance: modern auth interoperability still requires review, and
`conformance_complete` remains false even when no individual checks fail.

The existing schema catalog command can inspect the preview too:

```bash
uv run snulbug mcp policy schemas discover \
  --url http://127.0.0.1:8080/mcp \
  --protocol-version 2026-07-28 \
  --method server/discover \
  --header "Authorization: Bearer ${SNULBUG_TOKEN}" \
  --out discovery.json
```

Modern schema discovery constructs per-request metadata and method headers;
its default method set uses `server/discover` in place of `initialize`.
Omit `--method` to inspect the configured modern upstream's catalogs too. Server identity
and supported versions live in the existing catalog, so normal catalog diffing
and offline normalization work without a separate discovery artifact format.

Request evidence uses the same version metadata for modern traffic as for
legacy initialization, while retaining secret redaction. Client information is
self-reported, not an authenticated identity.

## References

- [MCP 2026-07-28 discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)
- [Multi Round-Trip Requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)
- [Subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions)
- [Result caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching)
- [Streamable HTTP metadata and headers](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Managed stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [Versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [Revision changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)

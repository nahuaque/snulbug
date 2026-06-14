# MCP schema discovery

`snulbug mcp schemas` discovers and diffs the MCP capability surface an agent is
about to trust. It captures more than `tools/list`: server capabilities from
`initialize`, tool input/output schemas, resources, resource templates, and
prompts.

Use it before sharing a gateway, when reviewing an upstream change, or when
building a fabric profile from servers you do not directly own.

## Discover a live endpoint

```bash
uv run snulbug mcp schemas discover \
  --url http://127.0.0.1:8080/mcp \
  --token local-dev-secret \
  --label local-gateway \
  --out .snulbug/schemas/local-gateway.json \
  --report-out .snulbug/schemas/local-gateway.md
```

The live probe sends JSON-RPC requests for:

- `initialize`
- `tools/list`
- `resources/list`
- `resources/templates/list`
- `prompts/list`

By default, requests use MCP protocol version `2025-06-18` and include
`Accept: application/json, text/event-stream`, so plain JSON and Streamable
HTTP/SSE responses are both accepted.

For custom auth or tunnel provider headers:

```bash
uv run snulbug mcp schemas discover \
  --url https://YOUR-TUNNEL.example/mcp \
  --header "Authorization: Bearer ${SNULBUG_TOKEN}" \
  --header "X-Provider-Session: demo" \
  --out .snulbug/schemas/tunnel.json
```

Limit discovery when an upstream does not implement every surface:

```bash
uv run snulbug mcp schemas discover \
  --url http://127.0.0.1:8080/mcp \
  --method initialize \
  --method tools \
  --method prompts \
  --out .snulbug/schemas/tools-and-prompts.json
```

Discovery exits zero when it can build a catalog. If an optional MCP method
returns an error or no response, the catalog is marked `ok: false` with
per-method errors so the partial result is still reviewable.

## Discover from saved responses

Offline discovery is useful for CI, fixtures, and captured lab traffic:

```bash
uv run snulbug mcp schemas discover \
  --from mcp-method-responses.json \
  --label baseline \
  --out .snulbug/schemas/baseline.json
```

The input can be an existing snulbug schema catalog or a response collection:

```json
{
  "responses": {
    "initialize": {"result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "demo"}}},
    "tools/list": {"result": {"tools": []}},
    "resources/list": {"result": {"resources": []}},
    "resources/templates/list": {"result": {"resourceTemplates": []}},
    "prompts/list": {"result": {"prompts": []}}
  }
}
```

Single MCP list responses are accepted too, which is handy when testing one
surface at a time.

## Diff schema catalogs

```bash
uv run snulbug mcp schemas diff \
  .snulbug/schemas/baseline.json \
  .snulbug/schemas/current.json
```

Add review gates with `--fail-on`:

```bash
uv run snulbug mcp schemas diff \
  .snulbug/schemas/baseline.json \
  .snulbug/schemas/current.json \
  --fail-on added \
  --fail-on changed \
  --report-out .snulbug/schemas/diff.md
```

Use `--fail-on removed` for compatibility gates, or `--fail-on any` when an MCP
surface must match exactly.

## Generate a policy from a catalog

Turn a discovered schema catalog into a reviewable policy bundle:

```bash
uv run snulbug mcp policy from-schema \
  .snulbug/schemas/local-gateway.json \
  --out policy.schema.snulbug \
  --token "${SNULBUG_TOKEN}"
```

The generated bundle contains:

- `policy.lua`: deny-by-default MCP policy derived from the schema catalog
- `manifest.json`: bundle manifest with schema hash, risk summary, and lease suggestions
- `SCHEMA_POLICY.md`: review report with tool risk annotations
- `fixtures/`: bundle fixtures proving declared list calls pass and unknown tools fail

Validate it like any other policy bundle:

```bash
uv run snulbug bundle validate policy.schema.snulbug
uv run snulbug bundle test policy.schema.snulbug
```

The generated policy:

- allows only declared MCP methods and tools
- rejects unknown tools by default
- checks required tool arguments from `inputSchema`
- rejects extra arguments when `additionalProperties: false`
- validates simple scalar argument types and enum values
- constrains path-like arguments to project path prefixes
- sends high-risk tools to `confirm` by default

Customize the policy guardrails while generating:

```bash
uv run snulbug mcp policy from-schema \
  .snulbug/schemas/local-gateway.json \
  --out policy.schema.snulbug \
  --allow-path README.md \
  --allow-path src/ \
  --high-risk-action reject
```

`--high-risk-action` accepts `allow`, `confirm`, or `reject`. The default is
`confirm`, which is usually the right local-dev behavior for tools that look
like shell execution, destructive writes, network access, or secret handling.

## Catalog contents

Catalogs are sorted and hashed with stable JSON SHA-256. The normalized catalog
contains:

- server protocol version, capabilities, server info, and instructions
- tool `name`, `title`, `description`, `inputSchema`, `outputSchema`, and annotations
- resource `uri`, `name`, `title`, `description`, `mimeType`, and annotations
- resource template `uriTemplate`, metadata, and annotations
- prompt `name`, `title`, `description`, and typed arguments

This is broader than the MCP tool change watcher. Use `snulbug mcp tools` when
you only need a focused `tools/list` pinning artifact; use `snulbug mcp schemas`
when the whole MCP contract should be reviewable.

# MCP tool change watcher

`snulbug mcp tools` snapshots and diffs `tools/list` declarations. Use it when
you want reviewable evidence that an MCP server did not silently add tools,
remove tools, or change descriptions/input schemas before an agent uses it.

Runtime `tool_pinning` protects live proxy traffic. The tool watcher is the
offline and CI companion: it writes stable JSON snapshots and exits nonzero when
configured change types appear.

## Snapshot a live endpoint

```bash
uv run snulbug mcp tools snapshot \
  --url http://127.0.0.1:8080/mcp \
  --token local-dev-secret \
  --label local-gateway \
  --out .snulbug/tools/local-gateway.json
```

For custom auth or provider headers:

```bash
uv run snulbug mcp tools snapshot \
  --url https://YOUR-TUNNEL.example/mcp \
  --header "Authorization: Bearer ${SNULBUG_TOKEN}" \
  --header "Accept: application/json, text/event-stream" \
  --out .snulbug/tools/tunnel.json
```

The live snapshot command sends a JSON-RPC `tools/list` request and accepts
plain JSON or Streamable HTTP/SSE responses.

## Snapshot from a saved response

```bash
uv run snulbug mcp tools snapshot \
  --from tools-list-response.json \
  --label baseline \
  --out .snulbug/tools/baseline.json
```

`--from` accepts:

- a full JSON-RPC `tools/list` response with `result.tools`
- a raw object with `tools`
- a raw tools array
- an existing snulbug tool snapshot

## Diff snapshots

```bash
uv run snulbug mcp tools diff \
  .snulbug/tools/baseline.json \
  .snulbug/tools/current.json
```

Add CI gates with `--fail-on`:

```bash
uv run snulbug mcp tools diff \
  .snulbug/tools/baseline.json \
  .snulbug/tools/current.json \
  --fail-on added \
  --fail-on changed
```

Use `--fail-on removed` for stricter compatibility checks, or `--fail-on any`
to fail on every change type.

## Snapshot contents

Snapshots are sorted by tool name and hash the fields snulbug cares about for
MCP rug-pull detection:

- `name`
- `description`
- `inputSchema`

The hash is stable JSON SHA-256, so snapshots are suitable for code review.

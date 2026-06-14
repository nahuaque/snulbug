# Legacy tools/list shortcut

`snulbug mcp tools` is a focused shortcut for tools-only pinning. It remains
available for small CI checks, but the primary review surface is now
[`snulbug mcp schemas`](mcp-schemas.md), which captures tools, server
capabilities, resources, resource templates, prompts, output schemas, and tool
annotations.

Prefer schema discovery for new workflows:

```bash
uv run snulbug mcp schemas discover \
  --url http://127.0.0.1:8080/mcp \
  --method tools \
  --label local-gateway \
  --out .snulbug/schemas/tools-only.json
```

Diff tools-only schema catalogs with the normal schema diff command:

```bash
uv run snulbug mcp schemas diff \
  .snulbug/schemas/tools-baseline.json \
  .snulbug/schemas/tools-current.json \
  --fail-on added \
  --fail-on changed
```

The legacy shortcut still writes a compact tool snapshot:

```bash
uv run snulbug mcp tools snapshot \
  --url http://127.0.0.1:8080/mcp \
  --token local-dev-secret \
  --label local-gateway \
  --out .snulbug/tools/local-gateway.json
```

And it still diffs those snapshots:

```bash
uv run snulbug mcp tools diff \
  .snulbug/tools/baseline.json \
  .snulbug/tools/current.json \
  --fail-on added \
  --fail-on changed
```

Tool snapshots and tools-only schema catalogs now share the same normalized tool
shape and hash inputs: `name`, `title`, `description`, `inputSchema`,
`outputSchema`, and `annotations`.

# End-to-end MCP policy proxy demo

This demo shows the local-dev MCP wedge end to end:

```text
demo MCP client request
  -> snulbug reverse proxy policy
      -> standalone HTTP MCP upstream server
```

The upstream server intentionally does not enforce auth or tool policy. It lists
an unsafe `shell_exec` tool and would accept that tool if reached directly. The
`snulbug` proxy adds bearer auth, a safe tool allowlist, live decisions,
replayable records, redacted audit logs, and offline inspection.

## One-command demo

Run:

```bash
uv run python examples/mcp_proxy_demo/run_demo.py
```

The runner starts the upstream server on an ephemeral localhost port, generates a
quickstart scaffold under `examples/mcp_proxy_demo/.run/`, sends three requests
through the proxy app, and prints the results:

- missing auth -> `401`
- allowed `safe_read_file` call -> `200`
- blocked `shell_exec` call -> `403`

It leaves generated artifacts here:

```text
examples/mcp_proxy_demo/.run/snulbug.toml
examples/mcp_proxy_demo/.run/policy.snulbug/
examples/mcp_proxy_demo/.run/traces/session.jsonl
examples/mcp_proxy_demo/.run/traces/audit.jsonl
```

Inspect the captured logs:

```bash
uv run snulbug mcp inspect examples/mcp_proxy_demo/.run/traces/session.jsonl
uv run snulbug mcp inspect examples/mcp_proxy_demo/.run/traces/audit.jsonl --kind audit
uv run snulbug mcp inspect examples/mcp_proxy_demo/.run/traces/audit.jsonl \
  --kind audit \
  --report-out examples/mcp_proxy_demo/.run/traces/session-report.md
```

## Two-terminal HTTP demo

Terminal 1: start the standalone upstream MCP server:

```bash
uv run python examples/mcp_proxy_demo/upstream.py --host 127.0.0.1 --port 9000
```

Terminal 2: create policy/config and run the proxy:

```bash
uv run snulbug mcp quickstart \
  --directory examples/mcp_proxy_demo/.run \
  --upstream http://127.0.0.1:9000 \
  --token local-dev-secret \
  --allow-tool safe_read_file \
  --allow-tool list_project_files \
  --force

uv run snulbug mcp proxy --config examples/mcp_proxy_demo/.run/snulbug.toml
```

Send an allowed tool call:

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer local-dev-secret' \
  --data @examples/mcp_proxy_demo/requests/safe-tool.json
```

Send a blocked tool call:

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer local-dev-secret' \
  --data @examples/mcp_proxy_demo/requests/blocked-tool.json
```

Send an unauthenticated request:

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  --data @examples/mcp_proxy_demo/requests/tools-list.json
```

The live decision console prints the action, status, MCP method/tool, and policy
reason code for each request. Replay and audit logs are redacted by default.

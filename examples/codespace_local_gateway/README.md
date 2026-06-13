# Codespace-to-Local Gateway

This demo makes a GitHub Codespace look like a local MCP upstream while a laptop
runs the snulbug policy gateway:

```text
MCP client on laptop
  -> http://127.0.0.1:8080/mcp
      -> snulbug laptop gateway
          -> Codespace forwarded MCP server
```

## Demo A: One Codespace URL

Use this path for a live demo. It does not require Redis or a published snulbug
package. The laptop gateway reads one Codespace MCP URL from
`SNULBUG_DISCOVERY_UPSTREAMS`.

## Prerequisites

- This source repo checked out on the laptop.
- A Codespace running this repo, or any repo where you can run the mock MCP
  server from this example.
- Codespace port `9001` forwarded and reachable from the laptop. For the toy
  server, make the port public in the Codespaces Ports panel.

The direct Codespaces upstream URL is outside the laptop gateway. Use this demo
with the mock server or protect real upstreams separately.

### 1. Start the mock MCP server in Codespaces

From the Codespace terminal:

```bash
uv sync
uv run snulbug mcp codespace serve-demo --host 0.0.0.0 --port 9001
```

Make port `9001` public or otherwise reachable from the laptop. The command
prints the expected forwarded URL and a laptop attach command. In a Codespace
shell, the forwarded URL has this shape:

```bash
echo "https://${CODESPACE_NAME}-9001.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/mcp"
```

### 2. Start the laptop gateway

From this repo on the laptop:

```bash
uv sync
export CODESPACE_MCP_URL="https://YOUR-CODESPACE-9001.app.github.dev/mcp"
uv run snulbug mcp codespace attach "$CODESPACE_MCP_URL"
```

The command writes `.snulbug/codespace-local/snulbug.toml`, preflights the
remote MCP URL with `tools/list`, prints the local MCP client URL, and starts
the proxy. The proxy listens on:

```text
http://127.0.0.1:8080/mcp
```

### 3. Verify the facade

List tools through the local gateway:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'
```

Expected tool names:

```text
codespace.files.safe_read_file
codespace.files.list_project_files
```

Call a tool:

```bash
curl -s http://127.0.0.1:8080/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"codespace.files.list_project_files","arguments":{}}}'
```

Inspect the audit log after traffic flows:

```bash
uv run snulbug mcp inspect \
  .snulbug/codespace-local/traces/audit.jsonl \
  --kind audit
```

Clean generated demo artifacts:

```bash
rm -rf .snulbug/codespace-local
```

Under the hood, `codespace attach` uses the same env discovery shape as
`snulbug.env-gateway.toml`:

```bash
export SNULBUG_DISCOVERY_UPSTREAMS="[{\"name\":\"codespace-files\",\"url\":\"${CODESPACE_MCP_URL}\",\"tool_prefix\":\"codespace.files.\"}]"
```

## Demo B: Redis Member Agent

Use this path when the Codespace should register and unregister itself as a
remote fabric member. It needs a Redis URL reachable by both the laptop and the
Codespace.

```text
MCP client on laptop
  -> http://127.0.0.1:8080/mcp
      -> snulbug laptop gateway
          -> Redis member registry
          -> Codespace forwarded MCP server
```

The Codespace publishes its MCP upstream through
`snulbug mcp fabric member agent`. The laptop gateway discovers active members
from Redis and exposes them as one local MCP facade.

### Codespace side

Copy `.devcontainer/devcontainer.json` from this example into the repository you
open in Codespaces, then replace the Redis URL:

```json
"registry": "redis://YOUR_SHARED_REDIS:6379/0"
```

The devcontainer Feature starts the mock MCP server and the member agent. The
important Feature option is:

```json
"member_upstream": "codespaces:files:9001:/mcp"
```

At runtime the agent resolves it to:

```text
files=https://${CODESPACE_NAME}-9001.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/mcp
```

Manual equivalent:

```bash
snulbug mcp fabric member agent "codespace-${CODESPACE_NAME}" \
  --registry "$SNULBUG_MEMBER_REGISTRY" \
  --registry-key snulbug:fabric:codespaces:members \
  --upstream "files=https://${CODESPACE_NAME}-9001.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/mcp" \
  --ttl-seconds 60 \
  --interval 20 \
  --unregister-on-exit
```

### Laptop side

Edit `snulbug.local-gateway.toml` with the same Redis URL:

```toml
[[mcp.fabric.discovery.providers]]
name = "codespace-members"
type = "members"
state = "redis://YOUR_SHARED_REDIS:6379/0"
state_key = "snulbug:fabric:codespaces:members"
```

Verify discovery:

```bash
uv run snulbug mcp fabric discover \
  --config examples/codespace_local_gateway/snulbug.local-gateway.toml
```

Start the local gateway:

```bash
uv run snulbug mcp proxy \
  --config examples/codespace_local_gateway/snulbug.local-gateway.toml
```

Point an MCP client at:

```text
http://127.0.0.1:8080/mcp
```

The Codespace tools are exposed through the member-prefixed facade, for example:

```text
codespace-files.files.safe_read_file
codespace-files.files.list_project_files
```

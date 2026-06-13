# Codespace-to-local gateway

This demo makes a GitHub Codespace act as a remote MCP data-plane member while a
laptop runs the snulbug policy gateway:

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

## Prerequisites

- A Redis URL reachable by both the laptop and the Codespace. A managed Redis
  instance is the simplest path for the demo.
- A Codespace with port `9001` forwarded. For this toy MCP server, make the port
  public or otherwise reachable from the laptop.

The direct Codespaces upstream URL is outside the laptop gateway. Use this demo
with the mock server or protect real upstreams separately.

## Codespace side

Copy `.devcontainer/devcontainer.json` from this example into the repository you
open in Codespaces, then replace the Redis URL:

```json
"registry": "redis://YOUR_SHARED_REDIS:6379/0"
```

The devcontainer Feature starts:

```bash
python examples/codespace_local_gateway/mock_mcp_server.py \
  --host 0.0.0.0 \
  --port 9001 \
  --name codespace

snulbug-devcontainer-agent start
```

The important Feature option is:

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

## Laptop side

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

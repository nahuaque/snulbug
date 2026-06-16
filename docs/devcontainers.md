# Codespaces and Devcontainers

The snulbug devcontainer Feature installs the CLI and adds runtime helpers for
disposable MCP workspaces. A devcontainer can act as a normal CLI environment,
a snulbug gateway, or a remote fabric member that registers its local MCP
servers with a shared control plane.

## Feature usage

```json
{
  "features": {
    "ghcr.io/lbruhacs/snulbug/features/snulbug:0.1.0": {
      "version": "0.1.0",
      "mode": "member-agent",
      "policy_profile": "tunnel-safe",
      "registry": "redis://redis:6379/0",
      "registry_key": "snulbug:fabric:dev:members",
      "member_id": "codespace-files",
      "member_upstream": "codespaces:files:9001:/mcp",
      "ttl_seconds": "60",
      "heartbeat_interval": "20"
    }
  },
  "postCreateCommand": "snulbug-devcontainer-init",
  "postStartCommand": "snulbug-devcontainer-agent start"
}
```

The feature installs from PyPI by default. Set `version` to a released snulbug
version for reproducible devcontainers. Use `install_source = "github"` and
`github_ref` only when testing unreleased changes from a branch or commit.

In GitHub Codespaces, `member_upstream` can use:

```text
codespaces:NAME:PORT[:PATH]
```

The agent resolves that to the forwarded URL:

```text
NAME=https://${CODESPACE_NAME}-PORT.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/PATH
```

For example, `codespaces:files:9001:/mcp` registers the upstream `files` using
the public Codespaces forwarded URL for port `9001`.

## Runtime helpers

- `snulbug-devcontainer-init` creates `policy.snulbug/` and `snulbug.toml` when
  they do not already exist.
- `snulbug-devcontainer-agent run` runs the configured gateway/member process in
  the foreground.
- `snulbug-devcontainer-agent start` starts the configured process in the
  background for `postStartCommand`.
- `snulbug-devcontainer-agent stop` stops the background process and unregisters
  the member when running in `member-agent` mode.

The helper mode is controlled by the Feature `mode` option:

- `cli`: install snulbug only; the agent helper is a no-op.
- `gateway`: run `snulbug mcp share run --config snulbug.toml`.
- `member-agent`: run `snulbug mcp fabric member agent` with the configured
  registry and upstream.

## Gateway discovery

A local gateway can route active Codespaces/devcontainers through the member
registry:

```toml
[[mcp.fabric.discovery.providers]]
name = "devcontainers"
type = "members"
state = "redis://redis:6379/0"
state_key = "snulbug:fabric:dev:members"
```

Every routed upstream then carries member identity into fabric status, topology
metadata, replay logs, and audit logs.

## Devcontainer metadata discovery

For static workspace metadata, snulbug can also read
`.devcontainer/devcontainer.json` directly:

```json
{
  "customizations": {
    "snulbug": {
      "upstreams": [
        {
          "name": "workspace",
          "url": "http://127.0.0.1:9006/mcp",
          "tool_prefix": "workspace."
        }
      ]
    }
  }
}
```

```toml
[[mcp.fabric.discovery.providers]]
name = "workspace-devcontainer"
type = "devcontainer"
path = ".devcontainer/devcontainer.json"
```

Use member-agent mode when the container should join and leave dynamically. Use
static devcontainer metadata when the gateway and workspace are managed from the
same repository.

## Codespace-to-local gateway

See [../examples/codespace_local_gateway](../examples/codespace_local_gateway/README.md)
for a complete demo. Demo A uses `snulbug mcp share member codespace serve-demo` in the
Codespace and `snulbug mcp share member codespace attach <url>` on the laptop to route a
single Codespace MCP URL with no Redis. Demo B shows the Redis-backed
member-agent flow where a Codespace registers and unregisters itself as a
remote fabric member.

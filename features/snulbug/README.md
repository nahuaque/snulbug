# snulbug devcontainer Feature

Installs the `snulbug` CLI in a dedicated Python virtual environment and adds
workspace helpers for Codespaces/devcontainers.

```json
{
  "features": {
    "ghcr.io/nahuaque/snulbug/features/snulbug:0.1.0": {
      "install_source": "github",
      "github_ref": "main",
      "mode": "member-agent",
      "policy_profile": "tunnel-safe",
      "registry": "redis://redis:6379/0",
      "registry_key": "snulbug:fabric:dev:members",
      "member_id": "codespace-files",
      "member_upstream": "codespaces:files:9001:/mcp"
    }
  },
  "postCreateCommand": "snulbug-devcontainer-init",
  "postStartCommand": "snulbug-devcontainer-agent start"
}
```

Runtime helpers:

- `snulbug-devcontainer-init`: creates `policy.snulbug/` and `snulbug.toml`
  when missing.
- `snulbug-devcontainer-agent run`: runs the configured gateway/member process
  in the foreground.
- `snulbug-devcontainer-agent start`: starts the configured process in the
  background for `postStartCommand`.
- `snulbug-devcontainer-agent stop`: stops the background process and unregisters
  the member when running in `member-agent` mode.

In GitHub Codespaces, set `member_upstream` to
`codespaces:NAME:PORT[:PATH]`. The agent resolves that to:

```text
NAME=https://${CODESPACE_NAME}-PORT.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}/mcp
```

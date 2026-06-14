# MCP container facade

This example shows snulbug as a thin MCP facade for containerized upstreams:

```text
MCP client
  -> snulbug-gateway container
      -> local-mcp container
      -> remote-by-peer-mcp container over Hypertele/Holepunch
```

The same file set is emitted by `snulbug mcp share` under
`<share>/containers/`, with a generated policy, lease, and client config for the
share session.

## Services

- `snulbug-gateway`: runs `snulbug mcp share run` with facade upstreams.
- `local-mcp`: runs a small HTTP MCP demo server on the Docker network.
- `remote-by-peer-mcp`: runs a Node demo server behind `hypertele-server`.

## Run

The default compose path starts the gateway against `snulbug.local.toml`, which
only uses the Docker-network local MCP upstream and does not install Node, npm,
or Hypertele in the gateway image:

```bash
docker compose up --build
```

For the remote peer path, edit `hypertele-server.json` and
`hypertele-client.json` with real peer material before using the peer bridge.
Then make Hypertele available to the gateway or run it as a sidecar, switch the
gateway command to `snulbug.facade.toml`, and start the peer profile:

```bash
docker compose --profile remote-peer up --build remote-by-peer-mcp
```

Point an MCP client at `mcp-client.json`. The client-facing tools are prefixed:

- `local.safe_read_file`
- `local.list_project_files`
- `remote.safe_read_file`
- `remote.list_project_files`

For real share sessions, prefer `snulbug mcp share`; it writes this recipe with a
fresh bearer token, lease, and audit paths.

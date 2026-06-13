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

- `snulbug-gateway`: runs `snulbug mcp proxy` with facade upstreams.
- `local-mcp`: runs a small HTTP MCP demo server on the Docker network.
- `remote-by-peer-mcp`: runs the same demo server behind `hypertele-server`.

## Run

Edit `hypertele-server.json` and `hypertele-client.json` with real peer material
before using the peer bridge. For local shape testing, start the peer profile:

```bash
docker compose --profile remote-peer up --build remote-by-peer-mcp
```

Then start the gateway and local MCP upstream:

```bash
docker compose up --build local-mcp snulbug-gateway
```

Point an MCP client at `mcp-client.json`. The client-facing tools are prefixed:

- `local.safe_read_file`
- `local.list_project_files`
- `remote.safe_read_file`
- `remote.list_project_files`

For real share sessions, prefer `snulbug mcp share`; it writes this recipe with a
fresh bearer token, lease, and audit paths.

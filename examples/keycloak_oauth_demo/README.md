# Keycloak OAuth MCP demo

This demo runs a real Keycloak dev server, a tiny local MCP upstream, and a
snulbug gateway from this source repo:

```text
MCP client
  -> http://127.0.0.1:18081/mcp
      -> snulbug OAuth protected-resource gateway
          -> Keycloak issuer/JWKS at http://localhost:8080/realms/snulbug-demo
          -> demo MCP upstream at http://mcp-upstream:9000/mcp
```

It consumes the checked-in output from:

```bash
uv run snulbug mcp share auth init \
  --provider keycloak \
  --url http://127.0.0.1:18081/mcp \
  --issuer http://localhost:8080/realms/snulbug-demo \
  --client-id snulbug-agent \
  --realm snulbug-demo \
  --output-dir examples/keycloak_oauth_demo/auth/keycloak \
  --force
```

The generated auth setup lives in `auth/keycloak/`. The runnable
`snulbug.toml` uses the generated issuer, resource, audience, scopes, and
anti-passthrough defaults, then maps `mcp:tool.files.read` to this demo's tool
names.

## Why the compose file shares Keycloak networking

snulbug allows remote HTTP issuer/JWKS URLs only for localhost. The gateway
container therefore uses `network_mode: service:keycloak`, which makes
`http://localhost:8080/realms/snulbug-demo` resolve to Keycloak from inside the
snulbug container without weakening the runtime auth safety model. The gateway
listens on container port `8081`, published as `http://127.0.0.1:18081/mcp`.

## Run

From this directory:

```bash
docker compose up --build
```

The compose file defaults to `linux/amd64` for all three services. That is
intentional: on some Apple Silicon Docker Desktop setups the ARM64 Keycloak JVM
or Python JWT stack can fail with `SIGILL` before the demo starts. If your
native ARM64 Docker stack is known-good, opt back in with:

```bash
SNULBUG_KEYCLOAK_DEMO_PLATFORM=linux/arm64 docker compose up --build
```

Wait for Keycloak to finish importing `snulbug-demo` and for uvicorn to print
that snulbug is running on `0.0.0.0:8081`.

In another shell from the repo root, request a Keycloak access token:

```bash
ACCESS_TOKEN=$(uv run python examples/keycloak_oauth_demo/get-token.py)
```

List tools through snulbug:

```bash
curl -sS http://127.0.0.1:18081/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d @examples/keycloak_oauth_demo/requests/tools-list.json
```

Call a scoped read-only tool:

```bash
curl -sS http://127.0.0.1:18081/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d @examples/keycloak_oauth_demo/requests/read-file.json
```

The response includes `upstream_authorization_seen=false`, showing that snulbug
terminated the caller OAuth token and stripped it before proxying upstream.

Try a tool that the token does not authorize:

```bash
curl -i http://127.0.0.1:18081/mcp \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d @examples/keycloak_oauth_demo/requests/blocked-write-file.json
```

Expected result: snulbug rejects the call before it reaches the upstream because
`keycloak_demo.write_file` is not covered by `[mcp.auth.scope_map]`.

Run the auth doctor against the live demo:

```bash
uv run snulbug mcp share auth doctor \
  --config examples/keycloak_oauth_demo/snulbug.toml \
  --url http://127.0.0.1:18081/mcp \
  --token "${ACCESS_TOKEN}"
```

## Credentials

- Keycloak admin console: `http://127.0.0.1:8080`
- Admin user: `admin`
- Admin password: `admin`
- Realm: `snulbug-demo`
- Client ID: `snulbug-agent`
- Client secret: `snulbug-agent-secret`

## Stop

```bash
docker compose down
```

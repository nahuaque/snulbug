from __future__ import annotations

import json
import secrets
import shlex
import shutil
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .leases import create_lease
from .presets import DEFAULT_ALLOWED_PATHS, DEFAULT_ALLOWED_TOOLS, McpPolicyOptions, generate_mcp_preset
from .quickstart import create_mcp_quickstart
from .tunnel import TUNNEL_PROVIDERS, init_tunnel_provider

DEFAULT_SHARE_PROVIDER = "holepunch"
DEFAULT_SHARE_PRESET = "tunnel-safe"
DEFAULT_SHARE_TTL = "30m"
DEFAULT_SHARE_DIR = Path(".snulbug") / "shares"
DEFAULT_SHARE_CLIENT_NAME = "snulbug-share"
DEFAULT_SHARE_TOKEN_ENV = "SNULBUG_SHARE_TOKEN"
DEFAULT_CONTAINER_RECIPE_DIR = "containers"
CONTAINER_BIND_HOST = ".".join(("0", "0", "0", "0"))
CONTAINER_REMOTE_BRIDGE_PORT = 19100


def create_mcp_share(
    directory: str | Path | None = None,
    *,
    provider: str = DEFAULT_SHARE_PROVIDER,
    preset: str = DEFAULT_SHARE_PRESET,
    upstream: str = "http://127.0.0.1:9000",
    hostname: str | None = None,
    public_url: str | None = None,
    token: str | None = None,
    ttl: str = DEFAULT_SHARE_TTL,
    task: str = "Ephemeral MCP share session",
    allowed_tools: Sequence[str] | None = None,
    allowed_paths: Sequence[str] | None = None,
    allowed_hosts: Sequence[str] | None = None,
    allowed_commands: Sequence[str] | None = None,
    max_calls: int | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    lease_required: bool = True,
    lease_header: str = "x-snulbug-lease",
    client_name: str = DEFAULT_SHARE_CLIENT_NAME,
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Create a bounded, ready-to-run MCP share session directory."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if not ttl.strip():
        raise ValueError("ttl must be non-empty")
    if not task.strip():
        raise ValueError("task must be non-empty")
    if not client_name.strip():
        raise ValueError("client_name must be non-empty")

    share_dir = _share_directory(directory)
    _preflight_share(share_dir, force=force)
    share_dir.mkdir(parents=True, exist_ok=True)

    bearer_token = token or _new_bearer_token()
    tools = list(allowed_tools) if allowed_tools else list(DEFAULT_ALLOWED_TOOLS)
    paths = list(allowed_paths) if allowed_paths else list(DEFAULT_ALLOWED_PATHS)
    hosts = list(allowed_hosts or [])
    commands = list(allowed_commands or [])

    local_url = f"http://{host}:{port}/mcp"
    tunnel_preview = init_tunnel_provider(
        provider=provider,
        local_url=local_url,
        public_url=public_url,
        hostname=hostname,
        token_env=DEFAULT_SHARE_TOKEN_ENV,
        write=False,
    )

    quickstart = create_mcp_quickstart(
        share_dir,
        preset=preset,
        upstream=upstream,
        token=bearer_token,
        allowed_tools=tools,
        allowed_paths=paths,
        host=host,
        port=port,
        state=state,
        lease_required=lease_required,
        lease_header=lease_header,
        tunnel_provider=provider,
        tunnel_public_url=tunnel_preview["public_url"],
        force=force,
        validate=validate,
    )
    lease = create_lease(
        share_dir / "leases.json",
        task=task,
        allow_tools=tools,
        allow_paths=paths,
        allow_hosts=hosts,
        allow_commands=commands,
        ttl=ttl,
        max_calls=max_calls,
    )
    tunnel = init_tunnel_provider(
        provider=provider,
        config=quickstart["config"],
        local_url=local_url,
        public_url=tunnel_preview["public_url"],
        token_env=DEFAULT_SHARE_TOKEN_ENV,
        output_dir=share_dir / "tunnel",
        force=force,
    )

    client_headers = {
        "Authorization": f"Bearer {bearer_token}",
        lease_header: lease["token"],
    }
    client_config = _client_config(client_name, tunnel["client"]["url"], client_headers)
    client_config_path = share_dir / "mcp-client.json"
    _write_json(client_config_path, client_config, force=force)

    container_recipe = _write_container_upstream_recipe(
        share_dir=share_dir,
        provider=provider,
        preset=preset,
        token=bearer_token,
        ttl=ttl,
        task=task,
        allowed_tools=tools,
        allowed_paths=paths,
        allowed_hosts=hosts,
        allowed_commands=commands,
        max_calls=max_calls,
        client_url=tunnel["client"]["url"],
        port=port,
        state=state,
        lease_required=lease_required,
        lease_header=lease_header,
        client_name=client_name,
        force=force,
    )

    session_id = share_dir.name
    command_plan = _command_plan(
        share_dir=share_dir,
        provider=provider,
        client_url=tunnel["client"]["url"],
        provider_commands=tunnel["commands"],
        token=bearer_token,
        lease_id=lease["lease"]["id"],
    )
    report_path = share_dir / "SHARE.md"
    report = _share_report(
        session_id=session_id,
        provider=provider,
        preset=preset,
        ttl=ttl,
        task=task,
        quickstart=quickstart,
        tunnel=tunnel,
        lease=lease,
        client_config_path=client_config_path,
        container_recipe=container_recipe,
        command_plan=command_plan,
    )
    _write_text(report_path, report, force=force)

    return {
        "ok": bool(quickstart["ok"]) and bool(tunnel["ok"]) and bool(lease["ok"]),
        "session": {
            "id": session_id,
            "directory": str(share_dir),
            "provider": provider,
            "preset": preset,
            "ttl": ttl,
            "task": task,
            "lease_required": lease_required,
            "lease_header": lease_header,
        },
        "quickstart": _quickstart_summary(quickstart),
        "tunnel": _tunnel_summary(tunnel),
        "lease": {
            "file": lease["file"],
            "lease": lease["lease"],
            "headers": {lease_header: lease["token"]},
        },
        "client": {
            "name": client_name,
            "url": tunnel["client"]["url"],
            "headers": client_headers,
            "config": str(client_config_path),
        },
        "recipes": {
            "remote_container_upstream": container_recipe,
        },
        "commands": command_plan,
        "files": {
            "config": quickstart["config"],
            "policy": quickstart["policy"],
            "lease_file": lease["file"],
            "client_config": str(client_config_path),
            "report": str(report_path),
            "tunnel_dir": str(share_dir / "tunnel"),
            "container_recipes": container_recipe["directory"],
        },
        "next_steps": [
            command_plan["proxy"],
            *command_plan["provider"],
            command_plan["doctor"],
            f"configure your MCP client from {client_config_path}",
            command_plan["inspect_audit"],
        ],
    }


def _share_directory(directory: str | Path | None) -> Path:
    if directory is not None:
        return Path(directory)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return DEFAULT_SHARE_DIR / f"share-{stamp}-{secrets.token_hex(3)}"


def _preflight_share(directory: Path, *, force: bool) -> None:
    if force:
        return
    for relative in (
        "policy.snulbug",
        "snulbug.toml",
        "leases.json",
        "mcp-client.json",
        "SHARE.md",
        "tunnel",
        DEFAULT_CONTAINER_RECIPE_DIR,
    ):
        path = directory / relative
        if path.exists():
            raise FileExistsError(f"share output already exists: {path}")


def _new_bearer_token() -> str:
    return f"sbt_{secrets.token_urlsafe(24)}"


def _client_config(name: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
    return {
        "mcpServers": {
            name: {
                "url": url,
                "headers": headers,
            }
        }
    }


def _command_plan(
    *,
    share_dir: Path,
    provider: str,
    client_url: str,
    provider_commands: Sequence[dict[str, Any]],
    token: str,
    lease_id: str,
) -> dict[str, Any]:
    config = share_dir / "snulbug.toml"
    audit = share_dir / "traces" / "audit.jsonl"
    session = share_dir / "traces" / "session.jsonl"
    lease_file = share_dir / "leases.json"
    tunnel_dir = share_dir / "tunnel"
    doctor_lines = ["uv run snulbug tunnel doctor \\"]
    if provider != "generic":
        doctor_lines.append(f"  --provider {provider} \\")
    doctor_lines.extend(
        [
            f"  --url {client_url} \\",
            f"  --config {shlex.quote(str(config))} \\",
            f"  --token ${{{DEFAULT_SHARE_TOKEN_ENV}}}",
        ]
    )
    return {
        "export_token": f"export {DEFAULT_SHARE_TOKEN_ENV}={shlex.quote(token)}",
        "proxy": f"uv run snulbug mcp proxy --config {shlex.quote(str(config))} --decision-console",
        "provider": [
            f"(cd {shlex.quote(str(tunnel_dir))} && {str(command['command'])})" for command in provider_commands
        ],
        "doctor": "\n".join(doctor_lines),
        "inspect_session": f"uv run snulbug mcp inspect {shlex.quote(str(session))}",
        "inspect_audit": (
            f"uv run snulbug mcp inspect {shlex.quote(str(audit))} "
            f"--kind audit --report-out {shlex.quote(str(share_dir / 'session-report.md'))}"
        ),
        "revoke_lease": (
            f"uv run snulbug mcp lease revoke {shlex.quote(lease_id)} --file {shlex.quote(str(lease_file))}"
        ),
    }


def _share_report(
    *,
    session_id: str,
    provider: str,
    preset: str,
    ttl: str,
    task: str,
    quickstart: dict[str, Any],
    tunnel: dict[str, Any],
    lease: dict[str, Any],
    client_config_path: Path,
    container_recipe: dict[str, Any],
    command_plan: dict[str, Any],
) -> str:
    provider_commands = "\n".join(command_plan["provider"])
    return (
        "# snulbug MCP share session\n\n"
        f"Session: `{session_id}`\n\n"
        f"Provider: `{provider}`\n\n"
        f"Preset: `{preset}`\n\n"
        f"Task: `{task}`\n\n"
        f"TTL: `{ttl}`\n\n"
        f"Client URL: `{tunnel['client']['url']}`\n\n"
        f"Lease: `{lease['lease']['id']}` expires at `{lease['lease']['expires_at']}`\n\n"
        "## MCP client config\n\n"
        f"Use `{client_config_path}`. It contains the bearer token and task lease token for this session.\n\n"
        "## Start the share\n\n"
        "```bash\n"
        f"{command_plan['export_token']}\n"
        f"{command_plan['proxy']}\n"
        "```\n\n"
        "In another shell, run the provider bridge/tunnel command:\n\n"
        "```bash\n"
        f"{provider_commands}\n"
        "```\n\n"
        "## Verify\n\n"
        "```bash\n"
        f"{command_plan['doctor']}\n"
        "```\n\n"
        "## Remote container as upstream\n\n"
        f"Optional Docker Compose recipe: `{container_recipe['readme']}`\n\n"
        "This recipe runs a snulbug facade gateway, a local MCP container, and a "
        "remote-by-peer MCP container reached through a managed Hypertele bridge. "
        f"Use `{container_recipe['client_config']}` for this facade recipe because it "
        "contains a lease scoped to prefixed facade tools.\n\n"
        "## Close out\n\n"
        "```bash\n"
        f"{command_plan['inspect_audit']}\n"
        f"{command_plan['revoke_lease']}\n"
        "```\n\n"
        "The bearer token is embedded in the generated policy. Stop the proxy and delete this share "
        "directory when the session is over.\n\n"
        "## Artifacts\n\n"
        f"- Config: `{quickstart['config']}`\n"
        f"- Policy: `{quickstart['policy']}`\n"
        f"- Lease file: `{lease['file']}`\n"
        f"- Tunnel setup: `{Path(tunnel['written_files'][0]).parent if tunnel.get('written_files') else ''}`\n"
    )


def _write_container_upstream_recipe(
    *,
    share_dir: Path,
    provider: str,
    preset: str,
    token: str,
    ttl: str,
    task: str,
    allowed_tools: Sequence[str],
    allowed_paths: Sequence[str],
    allowed_hosts: Sequence[str],
    allowed_commands: Sequence[str],
    max_calls: int | None,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
    client_name: str,
    force: bool,
) -> dict[str, Any]:
    recipe_dir = share_dir / DEFAULT_CONTAINER_RECIPE_DIR
    recipe_dir.mkdir(parents=True, exist_ok=True)
    facade_tools = _facade_allowed_tools(allowed_tools)

    policy_dir = recipe_dir / "policy.snulbug"
    generate_mcp_preset(
        preset,
        policy_dir,
        options=McpPolicyOptions(
            token=token,
            allowed_tools=facade_tools,
            allowed_paths=list(allowed_paths),
        ),
        force=force,
    )
    lease = create_lease(
        recipe_dir / "leases.json",
        task=f"{task} (container facade)",
        allow_tools=facade_tools,
        allow_paths=allowed_paths,
        allow_hosts=allowed_hosts,
        allow_commands=allowed_commands,
        ttl=ttl,
        max_calls=max_calls,
    )

    client_headers = {
        "Authorization": f"Bearer {token}",
        lease_header: lease["token"],
    }
    client_config_path = recipe_dir / "mcp-client.facade.json"
    _write_json(client_config_path, _client_config(f"{client_name}-facade", client_url, client_headers), force=force)

    facade_config_path = recipe_dir / "snulbug.facade.toml"
    local_config_path = recipe_dir / "snulbug.local.toml"
    _write_text(
        facade_config_path,
        _container_facade_config(
            provider=provider,
            client_url=client_url,
            port=port,
            state=state,
            lease_required=lease_required,
            lease_header=lease_header,
        ),
        force=force,
    )
    _write_text(
        local_config_path,
        _container_local_config(
            provider=provider,
            client_url=client_url,
            port=port,
            state=state,
            lease_required=lease_required,
            lease_header=lease_header,
        ),
        force=force,
    )
    files = {
        "compose": recipe_dir / "docker-compose.yml",
        "gateway_dockerfile": recipe_dir / "Dockerfile.gateway",
        "remote_peer_dockerfile": recipe_dir / "Dockerfile.remote-peer",
        "mock_server": recipe_dir / "mock_mcp_server.py",
        "mock_server_js": recipe_dir / "mock_mcp_server.js",
        "hypertele_server": recipe_dir / "hypertele-server.json",
        "hypertele_client": recipe_dir / "hypertele-client.json",
        "source": recipe_dir / "snulbug-src",
        "readme": recipe_dir / "README.md",
    }
    _copy_gateway_source(files["source"], force=force)
    _write_text(files["compose"], _container_compose(), force=force)
    _write_text(files["gateway_dockerfile"], _gateway_dockerfile(), force=force)
    _write_text(files["remote_peer_dockerfile"], _remote_peer_dockerfile(), force=force)
    _write_text(files["mock_server"], _mock_mcp_server(), force=force)
    _write_text(files["mock_server_js"], _mock_mcp_server_js(), force=force)
    _write_text(files["hypertele_server"], _hypertele_server_config(), force=force)
    _write_text(files["hypertele_client"], _hypertele_client_config(), force=force)
    _write_text(
        files["readme"],
        _container_recipe_readme(
            client_config_path=client_config_path,
            facade_config_path=facade_config_path,
            facade_tools=facade_tools,
        ),
        force=force,
    )
    return {
        "ok": True,
        "directory": str(recipe_dir),
        "kind": "remote-container-upstream",
        "compose": str(files["compose"]),
        "facade_config": str(facade_config_path),
        "local_config": str(local_config_path),
        "policy": str(policy_dir),
        "lease_file": lease["file"],
        "lease": lease["lease"],
        "client_config": str(client_config_path),
        "client": {
            "url": client_url,
            "headers": client_headers,
        },
        "readme": str(files["readme"]),
        "allowed_tools": facade_tools,
        "files": {name: str(path) for name, path in files.items()},
    }


def _facade_allowed_tools(allowed_tools: Sequence[str]) -> list[str]:
    tools: list[str] = []
    for tool in allowed_tools:
        if tool.startswith(("local.", "remote.")):
            _append_unique(tools, tool)
        else:
            _append_unique(tools, f"local.{tool}")
            _append_unique(tools, f"remote.{tool}")
    return tools


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _container_facade_config(
    *,
    provider: str,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
) -> str:
    lines = [
        "[mcp.proxy]",
        'policy = "policy.snulbug/policy.lua"',
        f"host = {_toml_value(CONTAINER_BIND_HOST)}",
        f"port = {port}",
        f"state = {_toml_value(state)}",
        "trace = true",
        'record_out = "../traces/container-session.jsonl"',
        'audit_out = "../traces/container-audit.jsonl"',
        "redact_records = true",
        "decision_console = true",
        'decision_console_format = "text"',
        "confirm = false",
        "max_body_bytes = 65536",
        "response_max_bytes = 262144",
        "response_redact_secrets = true",
        "response_block_instructions = false",
        "tool_pinning = true",
        'tool_pinning_action = "block"',
        "schema_validation = true",
        'schema_validation_action = "block"',
        'lease_file = "leases.json"',
        f"lease_required = {_toml_value(lease_required)}",
        f"lease_header = {_toml_value(lease_header)}",
        f"tunnel_provider = {_toml_value(provider)}",
        f"tunnel_public_url = {_toml_value(client_url)}",
        'cloudflare_access = "off"',
        "timeout = 30.0",
        "",
        "[[mcp.proxy.upstreams]]",
        'name = "local"',
        'transport = "http"',
        'url = "http://local-mcp:9000/mcp"',
        'tool_prefix = "local."',
        "default = true",
        "",
        "[[mcp.proxy.upstreams]]",
        'name = "remote"',
        'transport = "holepunch"',
        f'url = "http://127.0.0.1:{CONTAINER_REMOTE_BRIDGE_PORT}/mcp"',
        f"local_port = {CONTAINER_REMOTE_BRIDGE_PORT}",
        'bridge_config = "hypertele-client.json"',
        'bridge_cwd = "/share/containers"',
        'bridge_command = "hypertele"',
        "bridge_private = true",
        "bridge_ready_timeout = 15.0",
        'tool_prefix = "remote."',
    ]
    return "\n".join(lines) + "\n"


def _container_local_config(
    *,
    provider: str,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
) -> str:
    lines = [
        "[mcp.proxy]",
        'policy = "policy.snulbug/policy.lua"',
        f"host = {_toml_value(CONTAINER_BIND_HOST)}",
        f"port = {port}",
        f"state = {_toml_value(state)}",
        "trace = true",
        'record_out = "../traces/container-session.jsonl"',
        'audit_out = "../traces/container-audit.jsonl"',
        "redact_records = true",
        "decision_console = true",
        'decision_console_format = "text"',
        "confirm = false",
        "max_body_bytes = 65536",
        "response_max_bytes = 262144",
        "response_redact_secrets = true",
        "response_block_instructions = false",
        "tool_pinning = true",
        'tool_pinning_action = "block"',
        "schema_validation = true",
        'schema_validation_action = "block"',
        'lease_file = "leases.json"',
        f"lease_required = {_toml_value(lease_required)}",
        f"lease_header = {_toml_value(lease_header)}",
        f"tunnel_provider = {_toml_value(provider)}",
        f"tunnel_public_url = {_toml_value(client_url)}",
        'cloudflare_access = "off"',
        "timeout = 30.0",
        "",
        "[[mcp.proxy.upstreams]]",
        'name = "local"',
        'transport = "http"',
        'url = "http://local-mcp:9000/mcp"',
        'tool_prefix = "local."',
        "default = true",
    ]
    return "\n".join(lines) + "\n"


def _container_compose() -> str:
    return f"""name: snulbug-mcp-container-share

services:
  snulbug-gateway:
    build:
      context: .
      dockerfile: Dockerfile.gateway
    ports:
      - "8080:8080"
    volumes:
      - ..:/share
    depends_on:
      local-mcp:
        condition: service_started
    command:
      - snulbug
      - mcp
      - proxy
      - --config
      - /share/containers/snulbug.local.toml
      - --decision-console

  local-mcp:
    image: python:3.13-slim
    working_dir: /app
    volumes:
      - ./mock_mcp_server.py:/app/mock_mcp_server.py:ro
    command:
      - python
      - /app/mock_mcp_server.py
      - --host
      - {CONTAINER_BIND_HOST}
      - --port
      - "9000"
      - --name
      - local

  remote-by-peer-mcp:
    profiles:
      - remote-peer
    build:
      context: .
      dockerfile: Dockerfile.remote-peer
    volumes:
      - ./hypertele-server.json:/peer/hypertele-server.json:ro
    command:
      - sh
      - -lc
      - >-
        node /app/mock_mcp_server.js --host 127.0.0.1 --port 9000 --name remote &
        exec hypertele-server -l 9000 --address 127.0.0.1 -c /peer/hypertele-server.json --private
"""


def _gateway_dockerfile() -> str:
    return """FROM python:3.13-slim

WORKDIR /src

COPY snulbug-src/ /src/

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv pip install --system --no-cache "."

WORKDIR /share
"""


def _remote_peer_dockerfile() -> str:
    return """FROM node:22-bookworm-slim

RUN npm install -g hypertele

WORKDIR /app
COPY mock_mcp_server.js /app/mock_mcp_server.js
"""


def _copy_gateway_source(destination: Path, *, force: bool) -> None:
    source_root = Path(__file__).resolve().parents[1]
    package_source = source_root / "snulbug"
    required_files = ("pyproject.toml", "README.md", "LICENSE")
    missing = [name for name in required_files if not (source_root / name).is_file()]
    if missing or not package_source.is_dir():
        raise FileNotFoundError(
            "cannot create container gateway source snapshot; run `snulbug mcp share` from a source checkout "
            "until snulbug is published as a container-installable package"
        )
    if destination.exists():
        if not force:
            raise FileExistsError(f"share output already exists: {destination}")
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name in required_files:
        shutil.copy2(source_root / name, destination / name)
    shutil.copytree(package_source, destination / "snulbug", ignore=_ignore_source_artifacts)


def _ignore_source_artifacts(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name == "__pycache__" or name.endswith((".pyc", ".pyo")) or name in {".DS_Store", ".pytest_cache"}
    }


def _mock_mcp_server() -> str:
    return """from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "snulbug-mock-mcp/1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return

        method = request.get("method")
        if self.path != "/mcp":
            self.send_error(404)
            return
        if method == "tools/list":
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "safe_read_file",
                                "description": f"Read a demo file from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                            {
                                "name": "list_project_files",
                                "description": f"List demo files from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                            },
                        ]
                    },
                }
            )
            return
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            tool = params.get("name")
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"{self.server.server_name_label} handled {tool}",
                            }
                        ]
                    },
                }
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": {}})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--name", default="local")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.server_name_label = args.name
    server.serve_forever()


if __name__ == "__main__":
    main()
"""


def _mock_mcp_server_js() -> str:
    return """const http = require('node:http')

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

const host = arg('host', '127.0.0.1')
const port = Number(arg('port', '9000'))
const serverName = arg('name', 'remote')

function writeJson(response, payload) {
  const body = Buffer.from(JSON.stringify(payload))
  response.writeHead(200, {
    'content-type': 'application/json',
    'content-length': String(body.length)
  })
  response.end(body)
}

const server = http.createServer((request, response) => {
  if (request.method !== 'POST' || request.url !== '/mcp') {
    response.writeHead(404)
    response.end()
    return
  }

  const chunks = []
  request.on('data', chunk => chunks.push(chunk))
  request.on('end', () => {
    let message = {}
    try {
      const body = Buffer.concat(chunks).toString('utf8')
      message = body ? JSON.parse(body) : {}
    } catch {
      writeJson(response, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } })
      return
    }

    if (message.method === 'tools/list') {
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'safe_read_file',
              description: `Read a demo file from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: { path: { type: 'string' } },
                required: ['path'],
                additionalProperties: false
              }
            },
            {
              name: 'list_project_files',
              description: `List demo files from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: {},
                additionalProperties: false
              }
            }
          ]
        }
      })
      return
    }

    if (message.method === 'tools/call') {
      const params = message.params && typeof message.params === 'object' ? message.params : {}
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          content: [
            {
              type: 'text',
              text: `${serverName} handled ${params.name || ''}`
            }
          ]
        }
      })
      return
    }

    writeJson(response, { jsonrpc: '2.0', id: message.id, result: {} })
  })
})

server.listen(port, host)
"""


def _hypertele_server_config() -> str:
    return (
        json.dumps(
            {
                "seed": "REPLACE_WITH_32_BYTE_REMOTE_SERVER_SEED",
                "allow": ["REPLACE_WITH_GATEWAY_PEER_KEY"],
            },
            indent=2,
        )
        + "\n"
    )


def _hypertele_client_config() -> str:
    return json.dumps({"peer": "REPLACE_WITH_REMOTE_CONTAINER_PEER_KEY_OR_PRIVATE_SEED"}, indent=2) + "\n"


def _container_recipe_readme(
    *,
    client_config_path: Path,
    facade_config_path: Path,
    facade_tools: Sequence[str],
) -> str:
    tools = "\n".join(f"- `{tool}`" for tool in facade_tools)
    return (
        "# Remote container as upstream\n\n"
        "This optional recipe shows one snulbug facade gateway container, one local "
        "MCP container, and one remote-by-peer MCP container. The gateway exposes one "
        "client-facing MCP URL and routes prefixed tools to either the local container "
        "or the remote container reached through a managed Hypertele bridge.\n\n"
        "## Files\n\n"
        "- `docker-compose.yml`: gateway, local MCP, and remote-by-peer MCP services.\n"
        "- `snulbug.local.toml`: default compose config with only the `local.` upstream.\n"
        "- `snulbug.facade.toml`: peer facade config with both `local.` and `remote.` upstreams.\n"
        "- `policy.snulbug/`: policy generated for prefixed facade tools.\n"
        "- `leases.json`: task lease generated for prefixed facade tools.\n"
        "- `mcp-client.facade.json`: MCP client config for this container facade.\n"
        "- `mock_mcp_server.py` / `mock_mcp_server.js`: local and remote demo MCP servers.\n"
        "- `snulbug-src/`: local source snapshot installed into the gateway image.\n"
        "- `hypertele-server.json` / `hypertele-client.json`: placeholder peer bridge configs.\n\n"
        "## Run\n\n"
        "Start the local MCP container and snulbug gateway first. This default path "
        "does not install Node, npm, or Hypertele in the gateway image:\n\n"
        "```bash\n"
        "docker compose up --build local-mcp snulbug-gateway\n"
        "```\n\n"
        "For the remote peer path, edit `hypertele-server.json` and "
        "`hypertele-client.json` with real Hypertele peer material, make Hypertele "
        "available to the gateway or run it as a sidecar, then switch the gateway "
        "command to `snulbug.facade.toml`.\n\n"
        "`Dockerfile.gateway` installs from the generated `snulbug-src/` snapshot "
        "instead of PyPI, so this recipe works before snulbug has a published package "
        "release.\n\n"
        f"Point the MCP client at `{client_config_path}`. The facade config is "
        f"`{facade_config_path}`.\n\n"
        "## Facade tool names\n\n"
        f"{tools}\n\n"
        "The normal share config remains available at `../snulbug.toml`; this recipe "
        "uses a separate facade config, policy, lease, and client file so the "
        "container experiment does not change the default share session.\n"
    )


def _quickstart_summary(quickstart: dict[str, Any]) -> dict[str, Any]:
    validation = quickstart.get("validation")
    tests = quickstart.get("tests")
    return {
        "ok": quickstart.get("ok"),
        "directory": quickstart.get("directory"),
        "preset": quickstart.get("preset"),
        "config": quickstart.get("config"),
        "policy": quickstart.get("policy"),
        "policy_file": quickstart.get("policy_file"),
        "traces": quickstart.get("traces"),
        "upstream": quickstart.get("upstream"),
        "proxy": quickstart.get("proxy"),
        "validation": _ok_summary(validation),
        "tests": _ok_summary(tests),
    }


def _tunnel_summary(tunnel: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": tunnel.get("ok"),
        "provider": tunnel.get("provider"),
        "local_url": tunnel.get("local_url"),
        "public_url": tunnel.get("public_url"),
        "commands": tunnel.get("commands", []),
        "bridge": tunnel.get("bridge"),
        "client": tunnel.get("client"),
        "doctor": tunnel.get("doctor"),
        "traffic_policy": tunnel.get("traffic_policy"),
        "written_files": tunnel.get("written_files", []),
    }


def _ok_summary(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in ("ok", "name", "version", "fixture_count", "passed", "failed") if key in value}


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return json.dumps([str(item) for item in value])
    return json.dumps(str(value))


def _write_json(path: Path, value: Any, *, force: bool) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", force=force)


def _write_text(path: Path, value: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"share output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

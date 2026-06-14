from __future__ import annotations

import http.client
import json
import os
import threading
import time
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .config import default_event_sink_configs
from .gateway_templates import GatewayTemplate, render_gateway_toml
from .scaffolds import (
    GeneratedArtifact,
    GeneratedCommand,
    GeneratedEnv,
    GeneratedLog,
    GeneratedSession,
    ScaffoldFile,
    ScaffoldPlan,
    session_result,
    write_scaffold,
)

DEFAULT_CODESPACE_ATTACH_DIR = Path(".snulbug/codespace-local")
DEFAULT_CODESPACE_DISCOVERY_ENV = "SNULBUG_DISCOVERY_UPSTREAMS"
DEFAULT_CODESPACE_DEMO_HOST = "0.0.0.0"
DEFAULT_CODESPACE_DEMO_NAME = "codespace"
DEFAULT_CODESPACE_DEMO_PATH = "/mcp"
DEFAULT_CODESPACE_DEMO_PORT = 9001
DEFAULT_CODESPACE_UPSTREAM_NAME = "codespace-files"
DEFAULT_CODESPACE_TOOL_PREFIX = "codespace.files."
DEFAULT_CODESPACE_HOST = "127.0.0.1"
DEFAULT_CODESPACE_PORT = 8080

_TOOLS_LIST_REQUEST = {"jsonrpc": "2.0", "id": "snulbug-smoke", "method": "tools/list", "params": {}}
_DEMO_TOOLS = [
    {
        "name": "safe_read_file",
        "description": "Read a demo file from codespace",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_project_files",
        "description": "List demo files from codespace",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]

_ALLOW_POLICY = """return function()
  return {
    action = "continue",
    reason_code = "codespace.attach.allow",
  }
end
"""


def prepare_codespace_attach(
    upstream_url: str,
    *,
    directory: str | Path = DEFAULT_CODESPACE_ATTACH_DIR,
    name: str = DEFAULT_CODESPACE_UPSTREAM_NAME,
    tool_prefix: str = DEFAULT_CODESPACE_TOOL_PREFIX,
    host: str = DEFAULT_CODESPACE_HOST,
    port: int = DEFAULT_CODESPACE_PORT,
    state: str = "memory",
    discovery_env: str = DEFAULT_CODESPACE_DISCOVERY_ENV,
    force: bool = True,
) -> dict[str, Any]:
    """Write a runnable local gateway config for one Codespaces MCP upstream."""

    parsed = urlsplit(upstream_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Codespace MCP URL must be an absolute http:// or https:// URL")
    if not name:
        raise ValueError("upstream name must be non-empty")
    if not tool_prefix:
        raise ValueError("tool prefix must be non-empty")
    if port <= 0:
        raise ValueError("port must be positive")

    root = Path(directory)
    policy = root / "policy.lua"
    config = root / "snulbug.toml"
    traces = root / "traces"
    record_out = traces / "session.jsonl"
    audit_out = traces / "audit.jsonl"
    upstream = {"name": name, "url": upstream_url, "tool_prefix": tool_prefix}
    discovery_value = json.dumps([upstream], separators=(",", ":"))
    scaffold = write_scaffold(
        ScaffoldPlan(
            name="codespace attach",
            root=root,
            directories=[Path("."), "traces"],
            files=[
                ScaffoldFile(path=policy.name, content=_ALLOW_POLICY, kind="policy"),
                ScaffoldFile(
                    path=config.name,
                    content=_codespace_attach_toml(
                        discovery_env=discovery_env,
                        host=host,
                        port=port,
                        state=state,
                    ),
                    kind="config",
                ),
            ],
        ),
        force=force,
    )

    gateway_url = f"http://{host}:{port}/mcp"
    generated_session = session_result(
        GeneratedSession(
            name="codespace attach",
            root=root,
            generated_by="snulbug mcp codespace attach",
            artifacts=[
                GeneratedArtifact("policy", policy, "policy"),
                GeneratedArtifact("config", config, "config"),
                GeneratedArtifact("traces", traces, "directory"),
            ],
            commands=[
                GeneratedCommand("proxy", f"uv run snulbug mcp proxy --config {config}"),
                GeneratedCommand(
                    "inspect_audit",
                    f"uv run snulbug mcp evidence inspect {audit_out} --kind audit",
                ),
            ],
            env=[GeneratedEnv(discovery_env, discovery_value, "Discovered Codespaces MCP upstreams")],
            logs=[
                GeneratedLog("record_out", record_out, "record_jsonl"),
                GeneratedLog("audit_events", audit_out, "audit_jsonl"),
            ],
            next_steps=[
                f"export {discovery_env}='{discovery_value}'",
                f"uv run snulbug mcp proxy --config {config}",
                f"uv run snulbug mcp evidence inspect {audit_out} --kind audit",
            ],
            scaffolds=[scaffold],
            metadata={"upstream": upstream, "gateway": {"url": gateway_url, "host": host, "port": port}},
        )
    )
    return {
        "ok": True,
        "generated_by": "snulbug mcp codespace attach",
        "directory": str(root),
        "config": generated_session["file_map"]["config"],
        "policy": generated_session["file_map"]["policy"],
        "gateway": {"url": gateway_url, "host": host, "port": port},
        "upstream": upstream,
        "env": {"name": discovery_env, "value": generated_session["env_map"][discovery_env]},
        "logs": {
            "record_out": generated_session["log_map"]["record_out"],
            "audit_events": generated_session["log_map"]["audit_events"],
        },
        "scaffold": scaffold,
        "generated_session": generated_session,
        "commands": generated_session["command_map"],
    }


def prepare_codespace_demo(
    *,
    host: str = DEFAULT_CODESPACE_DEMO_HOST,
    port: int = DEFAULT_CODESPACE_DEMO_PORT,
    name: str = DEFAULT_CODESPACE_DEMO_NAME,
    path: str = DEFAULT_CODESPACE_DEMO_PATH,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the operator plan for the bundled Codespaces demo server."""

    if port < 0:
        raise ValueError("port must be non-negative")
    if not host:
        raise ValueError("host must be non-empty")
    if not name:
        raise ValueError("demo server name must be non-empty")
    path = _normalize_path(path)
    public_url = codespace_forwarded_url(port=port, path=path, environ=environ)
    local_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    local_url = f"http://{local_host}:{port}{path}"
    bind_url = f"http://{host}:{port}{path}"
    attach_url = public_url or local_url
    return {
        "ok": True,
        "generated_by": "snulbug mcp codespace serve-demo",
        "server": {
            "name": name,
            "host": host,
            "port": port,
            "path": path,
            "url": bind_url,
            "local_url": local_url,
            "public_url": public_url,
        },
        "tools": [tool["name"] for tool in _DEMO_TOOLS],
        "commands": {"attach": f"uv run snulbug mcp codespace attach {attach_url}"},
        "codespaces": {
            "detected": public_url is not None,
            "url": public_url,
            "required_env": ["CODESPACE_NAME", "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN"],
        },
        "serving": False,
        "ready_check": None,
    }


def codespace_forwarded_url(
    *,
    port: int,
    path: str = DEFAULT_CODESPACE_DEMO_PATH,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Return the GitHub Codespaces forwarded URL when Codespaces env vars exist."""

    env = environ if environ is not None else os.environ
    codespace_name = env.get("CODESPACE_NAME")
    domain = env.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
    if not codespace_name or not domain or port <= 0:
        return None
    return f"https://{codespace_name}-{port}.{domain}{_normalize_path(path)}"


def create_codespace_demo_server(
    *,
    host: str = DEFAULT_CODESPACE_DEMO_HOST,
    port: int = DEFAULT_CODESPACE_DEMO_PORT,
    name: str = DEFAULT_CODESPACE_DEMO_NAME,
    path: str = DEFAULT_CODESPACE_DEMO_PATH,
) -> ThreadingHTTPServer:
    """Create the bundled mock MCP HTTP server used by the Codespaces demo."""

    if port < 0:
        raise ValueError("port must be non-negative")
    server = ThreadingHTTPServer((host, port), _CodespaceDemoHandler)
    server.server_name_label = name
    server.mcp_path = _normalize_path(path)
    return server


def serve_codespace_demo(
    *,
    host: str = DEFAULT_CODESPACE_DEMO_HOST,
    port: int = DEFAULT_CODESPACE_DEMO_PORT,
    name: str = DEFAULT_CODESPACE_DEMO_NAME,
    path: str = DEFAULT_CODESPACE_DEMO_PATH,
    ready_check: bool = True,
    ready_timeout: float = 5.0,
    emit: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run the bundled Codespaces demo server until interrupted."""

    server = create_codespace_demo_server(host=host, port=port, name=name, path=path)
    actual_port = int(server.server_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    result = prepare_codespace_demo(
        host=host,
        port=actual_port,
        name=name,
        path=path,
        environ=environ,
    )
    result["serving"] = True
    if ready_check:
        result["ready_check"] = smoke_check_codespace_upstream(result["server"]["local_url"], timeout=ready_timeout)
        result["ok"] = bool(result["ready_check"]["ok"])
    if not result["ok"]:
        result["serving"] = False
        if emit is not None:
            emit(result)
        _stop_server(server, thread)
        return result
    if emit is not None:
        emit(result)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        result["interrupted"] = True
    finally:
        _stop_server(server, thread)
        result["serving"] = False
    return result


def format_codespace_demo_report(result: Mapping[str, Any]) -> str:
    """Render a short operator report for the Codespaces demo server."""

    server = _mapping(result.get("server"))
    codespaces = _mapping(result.get("codespaces"))
    commands = _mapping(result.get("commands"))
    ready = _mapping(result.get("ready_check"))
    lines = [
        "# snulbug codespace serve-demo",
        "",
        f"Server: `{server.get('url')}`",
        f"Local MCP URL: `{server.get('local_url')}`",
    ]
    public_url = server.get("public_url")
    if public_url:
        lines.append(f"Codespaces URL: `{public_url}`")
    else:
        lines.append("Codespaces URL: not detected")
    lines.extend(
        [
            f"Tools: `{', '.join(str(tool) for tool in result.get('tools', []))}`",
            "",
            "## Laptop Command",
            "",
            f"`{commands.get('attach')}`",
        ]
    )
    if ready:
        status = "ok" if ready.get("ok") else "failed"
        lines.extend(
            [
                "",
                "## Ready Check",
                "",
                f"- Status: {status}",
                f"- HTTP: `{ready.get('status')}`",
                f"- tools/list tools: `{ready.get('tool_count')}`",
            ]
        )
        if ready.get("error"):
            lines.append(f"- Error: `{ready.get('error')}`")
    if not codespaces.get("detected"):
        lines.extend(
            [
                "",
                "## Codespaces",
                "",
                "- Set the Codespaces port public or otherwise reachable from the laptop.",
                "- If this is not running inside Codespaces, replace the attach URL with the reachable MCP URL.",
            ]
        )
    if result.get("serving"):
        lines.extend(["", "Serving. Press Ctrl-C to stop."])
    return "\n".join(lines)


def smoke_check_codespace_upstream(upstream_url: str, *, timeout: float = 5.0) -> dict[str, Any]:
    """POST tools/list to the remote MCP URL and summarize the result."""

    probe = _post_tools_list(upstream_url, timeout=timeout)
    json_body = probe.get("json")
    result_body = json_body.get("result") if isinstance(json_body, Mapping) else None
    tools = result_body.get("tools") if isinstance(result_body, Mapping) else None
    tool_names = (
        [
            str(tool.get("name"))
            for tool in tools
            if isinstance(tool, Mapping) and isinstance(tool.get("name"), str) and tool.get("name")
        ]
        if isinstance(tools, list)
        else []
    )
    ok = probe.get("status") == 200 and isinstance(tools, list)
    return {
        "ok": ok,
        "url": upstream_url,
        "method": "tools/list",
        "status": probe.get("status"),
        "tool_count": len(tool_names),
        "tools": tool_names,
        "error": probe.get("error"),
        "body_sample": probe.get("body_sample") if not ok else None,
    }


def format_codespace_attach_report(result: Mapping[str, Any]) -> str:
    """Render a short operator report for the guided Codespaces attach command."""

    gateway = _mapping(result.get("gateway"))
    upstream = _mapping(result.get("upstream"))
    logs = _mapping(result.get("logs"))
    env = _mapping(result.get("env"))
    smoke = _mapping(result.get("smoke_check"))
    commands = _mapping(result.get("commands"))
    lines = [
        "# snulbug codespace attach",
        "",
        f"Gateway: `{gateway.get('url')}`",
        f"Upstream: `{upstream.get('url')}`",
        f"Tool prefix: `{upstream.get('tool_prefix')}`",
        f"Config: `{result.get('config')}`",
        f"Policy: `{result.get('policy')}`",
        "",
        "## Environment",
        "",
        f"- {env.get('name')}: `{env.get('value')}`",
        "",
        "## Logs",
        "",
        f"- Replay: `{logs.get('record_out')}`",
        f"- Audit events: `{logs.get('audit_events')}`",
    ]
    if smoke:
        ok = "ok" if smoke.get("ok") else "failed"
        lines.extend(
            [
                "",
                "## Smoke Check",
                "",
                f"- Status: {ok}",
                f"- HTTP: `{smoke.get('status')}`",
                f"- tools/list tools: `{smoke.get('tool_count')}`",
            ]
        )
        tools = smoke.get("tools")
        if isinstance(tools, list) and tools:
            lines.append(f"- Tool names: `{', '.join(str(tool) for tool in tools)}`")
        if smoke.get("error"):
            lines.append(f"- Error: `{smoke.get('error')}`")
    lines.extend(
        [
            "",
            "## Next",
            "",
            f"- Point the MCP client at `{gateway.get('url')}`.",
            f"- Inspect audit logs with `{commands.get('inspect_audit')}`.",
        ]
    )
    if result.get("starting_proxy"):
        lines.extend(["- Starting the local proxy now. Press Ctrl-C to stop it."])
    else:
        lines.extend([f"- Start later with `{commands.get('proxy')}`."])
    return "\n".join(lines)


def _codespace_attach_toml(
    *,
    discovery_env: str,
    host: str,
    port: int,
    state: str,
) -> str:
    return render_gateway_toml(
        GatewayTemplate(
            fabric={
                "name": "codespace-local",
                "description": "Laptop snulbug gateway routing one Codespace MCP URL",
                "gateway_url": f"http://{host}:{port}/mcp",
                "require_manifests": False,
                "probe_gateway": False,
                "probe_upstreams": False,
                "timeout": 5.0,
            },
            fabric_discovery={"enabled": True},
            fabric_discovery_providers=[
                {
                    "name": "codespace-env",
                    "type": "env",
                    "env": discovery_env,
                    "required": True,
                }
            ],
            proxy={
                "policy": "policy.lua",
                "host": host,
                "port": port,
                "state": state,
                "trace": True,
                "record_out": "traces/session.jsonl",
                "redact_records": True,
                "max_body_bytes": 65536,
                "response_max_bytes": 262144,
                "response_redact_secrets": True,
                "tool_pinning": True,
                "tool_pinning_action": "warn",
                "schema_validation": True,
                "schema_validation_action": "warn",
                "facade_health_routing": True,
                "facade_health_failure_threshold": 2,
                "facade_health_cooldown_seconds": 10.0,
                "facade_health_exclude_unhealthy": True,
                "timeout": 30.0,
            },
            event_sinks=default_event_sink_configs(audit_path="traces/audit.jsonl"),
        )
    )


def _post_tools_list(url: str, *, timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _probe_error(url, "invalid URL")
    body = json.dumps(_TOOLS_LIST_REQUEST, separators=(",", ":")).encode("utf-8")
    headers = {
        "Host": parsed.netloc,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "User-Agent": "snulbug-codespace-attach",
    }
    connection = None
    try:
        connection = _connection(parsed, timeout)
        connection.request("POST", _exact_target(parsed), body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        text = response_body.decode("utf-8", errors="replace")
        json_body = None
        try:
            json_body = json.loads(text) if text else None
        except json.JSONDecodeError:
            json_body = None
        return {
            "url": url,
            "status": int(response.status),
            "headers": {name.lower(): value for name, value in response.getheaders()},
            "body_size": len(response_body),
            "body_sample": text[:300],
            "json": json_body,
            "error": None,
        }
    except Exception as exc:
        return _probe_error(url, str(exc))
    finally:
        if connection is not None:
            connection.close()


def _probe_error(url: str, error: str) -> dict[str, Any]:
    return {
        "url": url,
        "status": None,
        "headers": {},
        "body_size": 0,
        "body_sample": "",
        "json": None,
        "error": error,
    }


class _CodespaceDemoHandler(BaseHTTPRequestHandler):
    server_version = "snulbug-codespace-mcp/1"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return

        if self.path != self.server.mcp_path:
            self.send_error(404)
            return

        method = request.get("method")
        if method == "initialize":
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": self.server.server_name_label, "version": "0.1.0"},
                    },
                }
            )
            return
        if method == "tools/list":
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                **tool,
                                "description": tool["description"].replace("codespace", self.server.server_name_label),
                            }
                            for tool in _DEMO_TOOLS
                        ]
                    },
                }
            )
            return
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            tool = params.get("name", "unknown")
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

    def _json(self, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _connection(upstream: SplitResult, timeout: float) -> http.client.HTTPConnection:
    host = upstream.hostname
    if host is None:
        raise ValueError("upstream host is required")
    if upstream.scheme == "https":
        return http.client.HTTPSConnection(host, port=upstream.port, timeout=timeout)
    return http.client.HTTPConnection(host, port=upstream.port, timeout=timeout)


def _exact_target(upstream: SplitResult) -> str:
    path = upstream.path or "/"
    return f"{path}?{upstream.query}" if upstream.query else path


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

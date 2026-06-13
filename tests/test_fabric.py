from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from snulbug import (
    append_audit_event,
    build_fabric_audit_metadata,
    discover_fabric_upstreams,
    doctor_fabric,
    fabric_status,
    learn_fabric_profile,
    sign_upstream_manifest,
)
from snulbug.simulator import main as simulator_main


def test_fabric_status_summarizes_declarative_config(tmp_path):
    manifest_path = write_signed_manifest(tmp_path, identity="files@local")
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
        [mcp.fabric]
        name = "dev-fabric"
        description = "local MCP fabric"

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"
        facade_health_routing = true
        facade_health_failure_threshold = 3
        facade_health_cooldown_seconds = 1.5
        facade_health_exclude_unhealthy = true

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        manifest = "{manifest_path.name}"
        manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
        manifest_identity = "files@local"

        [[mcp.proxy.upstreams]]
        name = "git"
        transport = "stdio"
        command = "{sys.executable}"
        args = ["server.py"]
        tool_prefix = "repo."
        """,
        encoding="utf-8",
    )

    result = fabric_status(config)

    assert result["ok"] is True
    assert result["name"] == "dev-fabric"
    assert result["gateway_url"] == "http://127.0.0.1:8181/mcp"
    assert result["proxy"]["facade"] is True
    assert result["proxy"]["facade_health_routing"] is True
    assert result["proxy"]["facade_health_failure_threshold"] == 3
    assert result["proxy"]["facade_health_cooldown_seconds"] == 1.5
    assert result["proxy"]["facade_health_exclude_unhealthy"] is True
    assert result["summary"]["upstream_count"] == 2
    assert result["summary"]["transports"] == {"http": 1, "stdio": 1}
    assert result["upstreams"][0]["manifest"]["exists"] is True
    assert result["upstreams"][0]["manifest"]["declared_identity"] == "files@local"


def test_fabric_doctor_verifies_manifests_and_probes_gateway_and_upstreams(tmp_path, monkeypatch):
    gateway = start_mcp_server(protected=True)
    upstream = start_mcp_server(protected=False)
    manifest_path = write_signed_manifest(tmp_path, identity="files@local")
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
        [mcp.fabric]
        name = "dev-fabric"
        gateway_url = "http://127.0.0.1:{gateway.server_port}/mcp"
        require_manifests = true

        [mcp.proxy]
        host = "127.0.0.1"
        port = {gateway.server_port}
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:{upstream.server_port}/mcp"
        manifest = "{manifest_path.name}"
        manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
        manifest_identity = "files@local"
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("SNULBUG_MANIFEST_SECRET", "dev-secret")

    try:
        result = doctor_fabric(config, headers={"Authorization": "Bearer local-dev-secret"})
    finally:
        stop_server(gateway)
        stop_server(upstream)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert checks["upstream.files.manifest_verified"]["status"] == "pass"
    assert checks["gateway.tools_list"]["status"] == "pass"
    assert checks["upstream.files.tools_list"]["status"] == "pass"


def test_fabric_doctor_fails_when_required_manifest_is_missing(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        require_manifests = true
        probe_gateway = false
        probe_upstreams = false

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        """,
        encoding="utf-8",
    )

    result = doctor_fabric(config)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is False
    assert checks["upstream.files.manifest_present"]["status"] == "fail"
    assert "signed manifests" in result["recommendations"][0]


def test_mcp_fabric_cli_emits_compact_status_and_doctor(tmp_path, capsys):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "cli-fabric"
        probe_gateway = false
        probe_upstreams = false

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        """,
        encoding="utf-8",
    )

    status_code = simulator_main(["mcp", "fabric", "status", "--config", str(config), "--compact"])
    status_output = json.loads(capsys.readouterr().out)
    doctor_code = simulator_main(["mcp", "fabric", "doctor", "--config", str(config), "--compact"])
    doctor_output = json.loads(capsys.readouterr().out)

    assert status_code == 0
    assert status_output["name"] == "cli-fabric"
    assert status_output["summary"]["upstream_count"] == 1
    assert doctor_code == 0
    assert doctor_output["ok"] is True
    assert doctor_output["summary"]["skipped"] >= 2


def test_fabric_discover_resolves_directory_provider(tmp_path):
    discovery_dir = tmp_path / "discovery"
    discovery_dir.mkdir()
    (discovery_dir / "files.json").write_text(
        json.dumps({"name": "files", "url": "http://127.0.0.1:9001/mcp", "tool_prefix": "files."}),
        encoding="utf-8",
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "directory-fabric"

        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "local-directory"
        type = "directory"
        path = "discovery"

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        """,
        encoding="utf-8",
    )

    discovery = discover_fabric_upstreams(config)
    status = fabric_status(config)

    assert discovery["ok"] is True
    assert discovery["summary"]["upstream_count"] == 1
    assert discovery["providers"][0]["status"] == "loaded"
    assert discovery["upstreams"][0]["name"] == "files"
    assert status["summary"]["discovered_upstream_count"] == 1
    assert status["discovery"]["summary"]["provider_count"] == 1
    assert status["upstreams"][0]["discovery"] == {
        "provider": "local-directory",
        "type": "directory",
        "source": str(discovery_dir),
    }


def test_mcp_fabric_discover_cli_emits_compact_result(tmp_path, capsys):
    registry = tmp_path / "upstreams.json"
    registry.write_text(json.dumps([{"name": "git", "url": "http://127.0.0.1:9002/mcp"}]), encoding="utf-8")
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "registry"
        type = "file"
        path = "upstreams.json"

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        """,
        encoding="utf-8",
    )

    status_code = simulator_main(["mcp", "fabric", "discover", "--config", str(config), "--compact"])
    output = json.loads(capsys.readouterr().out)

    assert status_code == 0
    assert output["summary"]["upstream_count"] == 1
    assert output["providers"][0]["name"] == "registry"
    assert output["upstreams"][0]["name"] == "git"


def test_fabric_learn_profile_from_topology_audit_log(tmp_path):
    log = write_fabric_learn_log(tmp_path)
    output = tmp_path / "learned-fabric"

    result = learn_fabric_profile(log, output, kind="audit")

    assert result["ok"] is True
    assert result["upstreams"] == ["files", "git"]
    profile = json.loads((output / "fabric.json").read_text(encoding="utf-8"))
    config = (output / "snulbug.fabric.toml").read_text(encoding="utf-8")
    report = (output / "FABRIC.md").read_text(encoding="utf-8")
    upstreams = {upstream["name"]: upstream for upstream in profile["upstreams"]}
    assert profile["generated_by"] == "snulbug mcp fabric learn"
    assert profile["fabric"]["name"] == "dev-fabric"
    assert profile["gateway"]["url"] == "http://127.0.0.1:8080/mcp"
    assert profile["route_event_count"] == 2
    assert "files.read_file" in upstreams["files"]["tools"]
    assert upstreams["files"]["manifest"]["identity"] == "files@local"
    assert upstreams["git"]["route_count"] == 1
    assert "[mcp.fabric]" in config
    assert "[[mcp.proxy.upstreams]]" in config
    assert 'name = "files"' in config
    assert 'tool_prefix = "files."' in config
    assert 'manifest_secret_env = "SNULBUG_MANIFEST_SECRET"' in config
    assert "files.read_file" in report


def test_mcp_fabric_learn_cli_emits_compact_result(tmp_path, capsys):
    log = write_fabric_learn_log(tmp_path)
    output = tmp_path / "cli-learned-fabric"

    status = simulator_main(["mcp", "fabric", "learn", str(log), "--out", str(output), "--kind", "audit", "--compact"])
    payload = json.loads(capsys.readouterr().out)

    assert status == 0
    assert payload["ok"] is True
    assert payload["upstreams"] == ["files", "git"]
    assert (output / "fabric.json").is_file()


def write_signed_manifest(tmp_path: Path, *, identity: str) -> Path:
    manifest = sign_upstream_manifest(
        {
            "schema": "snulbug.upstream-manifest.v1",
            "identity": identity,
            "transport": "http",
            "tool_prefix": "files.",
            "tools": [{"name": "read_file", "description": "Read a file"}],
        },
        secret="dev-secret",
        key_id="dev",
    )
    path = tmp_path / "files.manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def write_fabric_learn_log(tmp_path: Path) -> Path:
    manifest_path = write_signed_manifest(tmp_path, identity="files@local")
    topology = build_fabric_audit_metadata(
        {
            "name": "dev-fabric",
            "description": "local MCP fabric",
            "gateway_url": "http://127.0.0.1:8080/mcp",
            "require_manifests": True,
            "proxy": {
                "host": "127.0.0.1",
                "port": 8080,
                "lease_required": True,
                "upstreams": [
                    {
                        "name": "files",
                        "transport": "http",
                        "url": "http://127.0.0.1:9001/mcp",
                        "tool_prefix": "files.",
                        "manifest": str(manifest_path),
                    },
                    {
                        "name": "git",
                        "transport": "http",
                        "url": "http://127.0.0.1:9002/mcp",
                        "tool_prefix": "git.",
                    },
                ],
            },
        }
    )
    manifest = topology["upstreams"][0]["manifest"]
    log = tmp_path / "audit.jsonl"
    append_audit_event(
        log,
        fabric_audit_event(
            topology,
            route={
                "mode": "facade",
                "operation": "tools/list",
                "fanout": True,
                "upstreams": ["files", "git"],
                "upstream_count": 2,
            },
            mcp={"method": "tools/list", "body_kind": "object", "valid_json": True},
        ),
    )
    append_audit_event(
        log,
        fabric_audit_event(
            topology,
            route={
                "mode": "facade",
                "operation": "tools/call",
                "upstream": "files",
                "upstream_transport": "http",
                "tool_prefix": "files.",
                "tool": "files.read_file",
                "upstream_tool": "read_file",
                "upstream_identity": manifest["identity"],
                "manifest_digest": manifest["digest"],
                "manifest_key_id": manifest["key_id"],
            },
            mcp={
                "method": "tools/call",
                "tool": "files.read_file",
                "argument_keys": ["path"],
                "body_kind": "object",
                "valid_json": True,
            },
        ),
    )
    return log


def fabric_audit_event(
    topology: dict[str, Any],
    *,
    route: dict[str, Any],
    mcp: dict[str, Any],
) -> dict[str, Any]:
    event_topology = json.loads(json.dumps(topology))
    event_topology["route"] = route
    return {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-12T00:00:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": mcp,
        "decision": {"action": "continue", "allowed": True},
        "response": {"status": 200},
        "topology": event_topology,
    }


def start_mcp_server(*, protected: bool) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FabricDoctorHandler)
    server.protected = protected  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_server(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


class FabricDoctorHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        if self.path != "/mcp":
            self._send(404, b"not found", content_type="text/plain")
            return
        if getattr(self.server, "protected", False):
            if self.headers.get("authorization") != "Bearer local-dev-secret":
                self._send(401, b"Authorization required", content_type="text/plain")
                return
        request = json.loads(body.decode("utf-8"))
        response = {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"tools": [{"name": "read_file", "description": "Read a file"}]},
        }
        self._send(200, json.dumps(response).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, *, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

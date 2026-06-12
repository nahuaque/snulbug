from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from snulbug import doctor_tunnel, parse_tunnel_headers
from snulbug.simulator import main as simulator_main


def test_tunnel_doctor_checks_local_proxy_and_log_growth(tmp_path):
    record_log = tmp_path / "records.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    server = start_mcp_server(mode="protected", record_log=record_log, audit_log=audit_log)
    config = write_config(tmp_path, server.server_port)

    try:
        result = doctor_tunnel(
            config=config,
            headers={"Authorization": "Bearer local-dev-secret"},
        )
    finally:
        stop_server(server)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert result["local_url"] == f"http://127.0.0.1:{server.server_port}/mcp"
    assert checks["local.unauthenticated_blocked"]["status"] == "pass"
    assert checks["local.authenticated_mcp_round_trip"]["status"] == "pass"
    assert checks["logs.record_out_grew"]["status"] == "pass"
    assert checks["logs.audit_out_grew"]["status"] == "pass"


def test_tunnel_doctor_fails_when_public_url_reaches_unprotected_upstream():
    server = start_mcp_server(mode="unprotected")
    public_url = f"http://127.0.0.1:{server.server_port}/mcp"

    try:
        result = doctor_tunnel(
            url=public_url,
            headers={"Authorization": "Bearer local-dev-secret"},
        )
    finally:
        stop_server(server)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is False
    assert checks["public.reachable"]["status"] == "pass"
    assert checks["public.unauthenticated_blocked"]["status"] == "fail"
    assert checks["public.authenticated_mcp_round_trip"]["status"] == "pass"
    assert "Point the tunnel at snulbug" in result["recommendations"][0]


def test_tunnel_doctor_cli_emits_compact_json_for_local_url(capsys):
    server = start_mcp_server(mode="protected")
    local_url = f"http://127.0.0.1:{server.server_port}/mcp"

    try:
        status = simulator_main(
            [
                "tunnel",
                "doctor",
                "--local-url",
                local_url,
                "--token",
                "local-dev-secret",
                "--compact",
            ]
        )
    finally:
        stop_server(server)

    output = json.loads(capsys.readouterr().out)
    checks = {check["id"]: check for check in output["checks"]}
    assert status == 0
    assert output["ok"] is True
    assert output["local_url"] == local_url
    assert checks["local.authenticated_mcp_round_trip"]["status"] == "pass"


def test_tunnel_doctor_explicit_missing_config_fails(tmp_path):
    server = start_mcp_server(mode="protected")
    local_url = f"http://127.0.0.1:{server.server_port}/mcp"

    try:
        result = doctor_tunnel(
            local_url=local_url,
            config=tmp_path / "missing.toml",
            headers={"Authorization": "Bearer local-dev-secret"},
        )
    finally:
        stop_server(server)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is False
    assert checks["config.loaded"]["status"] == "fail"


def test_parse_tunnel_headers_accepts_token_and_repeated_headers():
    headers = parse_tunnel_headers(
        ["CF-Access-Client-Id: client-id", "CF-Access-Client-Secret=client-secret"],
        token="local-dev-secret",
    )

    assert headers == {
        "Authorization": "Bearer local-dev-secret",
        "CF-Access-Client-Id": "client-id",
        "CF-Access-Client-Secret": "client-secret",
    }


def write_config(tmp_path: Path, port: int) -> Path:
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
        [mcp.proxy]
        host = "127.0.0.1"
        port = {port}
        record_out = "records.jsonl"
        audit_out = "audit.jsonl"
        redact_records = true
        response_redact_secrets = true
        tool_pinning = true
        tool_pinning_action = "block"
        schema_validation = true
        """,
        encoding="utf-8",
    )
    return config


def start_mcp_server(
    *,
    mode: str,
    record_log: Path | None = None,
    audit_log: Path | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DoctorHandler)
    server.mode = mode  # type: ignore[attr-defined]
    server.record_log = record_log  # type: ignore[attr-defined]
    server.audit_log = audit_log  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_server(server: ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


class DoctorHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        self._append_logs(body)
        if self.path != "/mcp":
            self._send(404, b"not found", content_type="text/plain")
            return
        if getattr(self.server, "mode", None) == "protected":
            if self.headers.get("authorization") != "Bearer local-dev-secret":
                self._send(401, b"Authorization required", content_type="text/plain")
                return
        request = json.loads(body.decode("utf-8"))
        response = {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"tools": []},
        }
        self._send(200, json.dumps(response).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _append_logs(self, body: bytes) -> None:
        event = {"body_size": len(body)}
        for attribute in ("record_log", "audit_log"):
            path = getattr(self.server, attribute, None)
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as file:
                    file.write(json.dumps(event) + "\n")

    def _send(self, status: int, body: bytes, *, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

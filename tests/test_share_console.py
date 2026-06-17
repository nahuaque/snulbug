from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

import snulbug.share_console as share_console
from snulbug import (
    ShareConsoleServer,
    build_share_console_snapshot,
    create_mcp_share,
    load_share_session_model,
)
from snulbug.simulator import main as simulator_main


def test_share_console_snapshot_reads_existing_share_artifacts(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_capability_request_log(tmp_path)

    snapshot = build_share_console_snapshot(tmp_path)
    timeline = snapshot["decision_timeline"]

    assert snapshot["ok"] is True
    assert snapshot["share"] == str(tmp_path)
    assert snapshot["status"]["state"] == "created"
    assert snapshot["capability_requests"]["summary"]["pending"] == 1
    assert snapshot["capability_requests"]["requests"][0]["tool"] == "safe_read_file"
    assert snapshot["capability_requests"]["requests"][0]["argument_keys"] == ["path"]
    assert timeline["exists"] is True
    assert timeline["summary"]["shown"] == 1
    assert timeline["summary"]["capability_requested"] == 1
    assert timeline["events"][0]["outcome"] == "capability_requested"
    assert timeline["events"][0]["tool"] == "safe_read_file"
    assert timeline["events"][0]["auth_subject"] == "user-1"
    encoded = json.dumps(snapshot)
    assert "share-secret" not in encoded
    assert "sbl_" not in encoded
    assert "timeline-secret" not in encoded
    assert snapshot["status"]["client"]["headers"]["Authorization"] == "[REDACTED]"
    assert snapshot["status"]["client"]["headers"]["x-snulbug-lease"] == "[REDACTED]"


def test_share_console_snapshot_includes_ngrok_local_console_link(tmp_path, monkeypatch):
    unused_port = unused_local_port()
    monkeypatch.setitem(
        share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
        "ngrok",
        {
            "label": "ngrok local web console",
            "url": f"http://127.0.0.1:{unused_port}",
            "description": "Inspect ngrok tunnel requests, headers, and replay details.",
        },
    )
    create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    snapshot = build_share_console_snapshot(tmp_path)
    provider_console = snapshot["provider_console"]

    assert provider_console["provider"] == "ngrok"
    assert provider_console["label"] == "ngrok local web console"
    assert provider_console["url"] == f"http://127.0.0.1:{unused_port}"
    assert provider_console["checked"] is True
    assert provider_console["reachable"] is False
    assert provider_console["status"] is None
    assert provider_console["error"]


def test_share_console_serves_dashboard_and_approves_capability_request(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_capability_request_log(tmp_path)
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        snapshot = read_json(f"{server.url}/api/snapshot")
        request_id = snapshot["capability_requests"]["requests"][0]["id"]
        approved = post_json(
            f"{server.url}/api/requests/{request_id}/approve",
            {"ttl": "12m", "max_calls": 2, "reviewer": "ui"},
        )
        after = read_json(f"{server.url}/api/requests?status=all")
        session_model = load_share_session_model(tmp_path)
    finally:
        server.stop()

    assert "snulbug share console" in html
    assert "Capability Requests" in html
    assert "Live Decisions" in html
    assert 'id="requestDrawer"' in html
    assert "selectRequest" in html
    assert "renderRequestDrawer" in html
    assert "drawer-task" in html
    assert "requestField" in html
    assert "renderDecisionTimeline" in html
    assert "setInterval(loadSnapshot, 2000)" in html
    assert snapshot["ok"] is True
    assert "share-secret" not in json.dumps(snapshot)
    assert "sbl_" not in json.dumps(snapshot)
    assert approved["ok"] is True
    assert approved["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert approved["review"]["reviewer"] == "ui"
    assert after["summary"]["approved"] == 1
    assert session_model["capability_requests"]["last_review"]["lease_id"] == approved["review"]["lease_id"]


def test_share_console_serves_provider_console_metadata_for_ngrok(tmp_path, monkeypatch):
    unused_port = unused_local_port()
    monkeypatch.setitem(
        share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
        "ngrok",
        {
            "label": "ngrok local web console",
            "url": f"http://127.0.0.1:{unused_port}",
            "description": "Inspect ngrok tunnel requests, headers, and replay details.",
        },
    )
    create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        snapshot = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    assert "providerConsole" in html
    assert "externalLink(url, url)" in html
    assert 'target="_blank"' in html
    assert snapshot["provider_console"]["provider"] == "ngrok"
    assert snapshot["provider_console"]["url"] == f"http://127.0.0.1:{unused_port}"
    assert snapshot["provider_console"]["reachable"] is False


def test_share_console_cli_help_exposes_console_command(capsys):
    with pytest.raises(SystemExit) as exc:
        simulator_main(["mcp", "share", "console", "--help"])
    output = capsys.readouterr().out

    assert exc.value.code == 0
    assert "run a local web console" in output
    assert "--live-checks" in output


def read_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - local test server.
        return response.read().decode("utf-8")


def read_json(url: str) -> dict[str, object]:
    return json.loads(read_text(url))


def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - local test server.
        return json.loads(response.read().decode("utf-8"))


def unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_capability_request_log(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    event = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:03:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/call", "tool": "safe_read_file"},
        "decision": {
            "action": "reject",
            "allowed": False,
            "reason": "Bearer timeline-secret",
            "reason_code": "mcp.docs_capability_requested",
        },
        "metadata": {
            "auth": {
                "subject": "user-1",
                "issuer": "https://issuer.example",
                "tenant": "tenant-a",
                "client_id": "client-1",
                "groups": ["dev"],
                "profile_id": "tenant-a",
            },
            "capability_request": {
                "requested": True,
                "reason_code": "mcp.docs_capability_requested",
                "capability_request": {
                    "schema": "snulbug.capability_request.v1",
                    "kind": "task_lease",
                    "task": "Read project docs",
                    "reason_code": "mcp.docs_capability_requested",
                    "method": "tools/call",
                    "tool": "safe_read_file",
                    "argument_keys": ["path"],
                    "suggested_lease": {
                        "task": "Read project docs",
                        "ttl": "10m",
                        "max_calls": 2,
                        "allow_tools": ["safe_read_file"],
                        "allow_paths": ["README.md", "docs"],
                    },
                },
            },
        },
        "response": {"status": 403},
    }
    (traces / "audit.jsonl").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

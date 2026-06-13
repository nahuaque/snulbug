from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import snulbug.simulator as simulator
from snulbug import (
    load_mcp_fabric_config,
    load_mcp_proxy_config,
    prepare_codespace_attach,
    smoke_check_codespace_upstream,
)


def test_prepare_codespace_attach_writes_loadable_env_discovery_config(tmp_path, monkeypatch):
    result = prepare_codespace_attach(
        "https://example-9001.app.github.dev/mcp",
        directory=tmp_path,
        port=8181,
    )
    monkeypatch.setenv(result["env"]["name"], result["env"]["value"])

    proxy = load_mcp_proxy_config(result["config"])
    fabric = load_mcp_fabric_config(result["config"])

    assert result["ok"] is True
    assert result["gateway"]["url"] == "http://127.0.0.1:8181/mcp"
    assert result["commands"]["proxy"] == f"uv run snulbug mcp proxy --config {tmp_path / 'snulbug.toml'}"
    assert (tmp_path / "policy.lua").read_text(encoding="utf-8").count("codespace.attach.allow") == 1
    assert proxy["policy"] == tmp_path / "policy.lua"
    assert proxy["record_out"] == tmp_path / "traces/session.jsonl"
    assert proxy["audit_out"] == tmp_path / "traces/audit.jsonl"
    assert proxy["upstreams"][0]["name"] == "codespace-files"
    assert proxy["upstreams"][0]["url"] == "https://example-9001.app.github.dev/mcp"
    assert proxy["upstreams"][0]["tool_prefix"] == "codespace.files."
    assert fabric["gateway_url"] == "http://127.0.0.1:8181/mcp"


def test_smoke_check_codespace_upstream_lists_tools():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ToolsListHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = smoke_check_codespace_upstream(f"http://127.0.0.1:{server.server_port}/mcp", timeout=2)
    finally:
        server.shutdown()
        server.server_close()

    assert result["ok"] is True
    assert result["status"] == 200
    assert result["tool_count"] == 2
    assert result["tools"] == ["safe_read_file", "list_project_files"]


def test_mcp_codespace_attach_cli_dry_run_outputs_plan(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("SNULBUG_DISCOVERY_UPSTREAMS", raising=False)

    status = simulator.main(
        [
            "mcp",
            "codespace",
            "attach",
            "https://example-9001.app.github.dev/mcp",
            "--directory",
            str(tmp_path),
            "--port",
            "8181",
            "--no-smoke-check",
            "--dry-run",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["dry_run"] is True
    assert output["config"] == str(tmp_path / "snulbug.toml")
    assert output["gateway"]["url"] == "http://127.0.0.1:8181/mcp"
    assert output["env"]["name"] == "SNULBUG_DISCOVERY_UPSTREAMS"
    assert "example-9001.app.github.dev" in output["env"]["value"]
    assert "SNULBUG_DISCOVERY_UPSTREAMS" not in os.environ


def test_mcp_codespace_attach_cli_sets_env_and_starts_proxy(tmp_path, capsys, monkeypatch):
    started = {}

    def fake_run_loaded_mcp_proxy(proxy_config, fabric_config, **kwargs):
        started["proxy_config"] = proxy_config
        started["fabric_config"] = fabric_config
        started["kwargs"] = kwargs

    monkeypatch.delenv("SNULBUG_DISCOVERY_UPSTREAMS", raising=False)
    monkeypatch.setattr(simulator, "_run_loaded_mcp_proxy", fake_run_loaded_mcp_proxy)

    status = simulator.main(
        [
            "mcp",
            "codespace",
            "attach",
            "https://example-9001.app.github.dev/mcp",
            "--directory",
            str(tmp_path),
            "--no-smoke-check",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["starting_proxy"] is True
    assert started["proxy_config"]["upstreams"][0]["tool_prefix"] == "codespace.files."
    assert started["fabric_config"]["gateway_url"] == "http://127.0.0.1:8080/mcp"
    assert json.loads(os.environ["SNULBUG_DISCOVERY_UPSTREAMS"])[0]["name"] == "codespace-files"


class _ToolsListHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.path != "/mcp" or request.get("method") != "tools/list":
            self.send_error(404)
            return
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "tools": [
                        {"name": "safe_read_file", "description": "read", "inputSchema": {"type": "object"}},
                        {"name": "list_project_files", "description": "list", "inputSchema": {"type": "object"}},
                    ]
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return

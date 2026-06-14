from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import snulbug.codespaces as codespaces_module
import snulbug.simulator as simulator
from snulbug import (
    codespace_forwarded_url,
    create_codespace_demo_server,
    format_codespace_attach_report,
    load_mcp_fabric_config,
    load_mcp_proxy_config,
    prepare_codespace_attach,
    prepare_codespace_demo,
    serve_codespace_demo,
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
    assert result["scaffold"]["written_files"] == [str(tmp_path / "policy.lua"), str(tmp_path / "snulbug.toml")]
    assert result["scaffold"]["directories"] == [str(tmp_path), str(tmp_path / "traces")]
    assert result["generated_session"]["file_map"]["config"] == result["config"]
    assert result["generated_session"]["env_map"][result["env"]["name"]] == result["env"]["value"]
    assert result["commands"] == result["generated_session"]["command_map"]
    assert result["commands"]["proxy"] == f"uv run snulbug mcp share run --config {tmp_path / 'snulbug.toml'}"
    assert (tmp_path / "policy.lua").read_text(encoding="utf-8").count("codespace.attach.allow") == 1
    assert proxy["policy"] == tmp_path / "policy.lua"
    assert proxy["record_out"] == tmp_path / "traces/session.jsonl"
    assert proxy["event_sinks"][0]["type"] == "audit_jsonl"
    assert proxy["event_sinks"][0]["path"] == tmp_path / "traces/audit.jsonl"
    assert proxy["event_sinks"][1]["type"] == "console"
    assert proxy["upstreams"][0]["name"] == "codespace-files"
    assert proxy["upstreams"][0]["url"] == "https://example-9001.app.github.dev/mcp"
    assert proxy["upstreams"][0]["tool_prefix"] == "codespace.files."
    assert fabric["gateway_url"] == "http://127.0.0.1:8181/mcp"

    report = format_codespace_attach_report(result)
    assert "# snulbug codespace attach" in report
    assert "## Files" in report
    assert "## Environment" in report
    assert "https://example-9001.app.github.dev/mcp" in report


def test_prepare_codespace_demo_infers_forwarded_url():
    result = prepare_codespace_demo(
        port=9001,
        environ={
            "CODESPACE_NAME": "ideal-space",
            "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN": "app.github.dev",
        },
    )

    assert (
        codespace_forwarded_url(
            port=9001,
            environ={
                "CODESPACE_NAME": "ideal-space",
                "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN": "app.github.dev",
            },
        )
        == "https://ideal-space-9001.app.github.dev/mcp"
    )
    assert result["server"]["public_url"] == "https://ideal-space-9001.app.github.dev/mcp"
    assert result["commands"]["attach"] == (
        "uv run snulbug mcp codespace attach https://ideal-space-9001.app.github.dev/mcp"
    )
    assert result["tools"] == ["safe_read_file", "list_project_files"]


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


def test_create_codespace_demo_server_responds_to_tools_list():
    server = create_codespace_demo_server(host="127.0.0.1", port=0, name="codespace", path="/mcp")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = smoke_check_codespace_upstream(f"http://127.0.0.1:{server.server_port}/mcp", timeout=2)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["ok"] is True
    assert result["status"] == 200
    assert result["tools"] == ["safe_read_file", "list_project_files"]


def test_serve_codespace_demo_emits_ready_plan_and_stops_on_interrupt(monkeypatch):
    emitted = []

    def interrupt_sleep(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(codespaces_module.time, "sleep", interrupt_sleep)

    result = serve_codespace_demo(
        host="127.0.0.1",
        port=0,
        ready_timeout=2,
        emit=lambda payload: emitted.append(json.loads(json.dumps(payload))),
        environ={
            "CODESPACE_NAME": "ideal-space",
            "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN": "app.github.dev",
        },
    )

    assert emitted
    assert emitted[0]["serving"] is True
    assert emitted[0]["ready_check"]["ok"] is True
    assert emitted[0]["commands"]["attach"].startswith("uv run snulbug mcp codespace attach https://ideal-space-")
    assert result["interrupted"] is True
    assert result["serving"] is False


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
    assert output["name"] == "codespace attach"
    assert output["legacy"]["dry_run"] is True
    assert output["files"]["config"] == str(tmp_path / "snulbug.toml")
    assert output["metadata"]["gateway"]["url"] == "http://127.0.0.1:8181/mcp"
    assert "SNULBUG_DISCOVERY_UPSTREAMS" in output["env"]
    assert "example-9001.app.github.dev" in output["env"]["SNULBUG_DISCOVERY_UPSTREAMS"]
    assert "SNULBUG_DISCOVERY_UPSTREAMS" not in os.environ


def test_mcp_codespace_serve_demo_cli_dry_run_outputs_laptop_command(capsys, monkeypatch):
    monkeypatch.setenv("CODESPACE_NAME", "ideal-space")
    monkeypatch.setenv("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")

    status = simulator.main(
        [
            "mcp",
            "codespace",
            "serve-demo",
            "--port",
            "9001",
            "--dry-run",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["dry_run"] is True
    assert output["server"]["public_url"] == "https://ideal-space-9001.app.github.dev/mcp"
    assert output["commands"]["attach"] == (
        "uv run snulbug mcp codespace attach https://ideal-space-9001.app.github.dev/mcp"
    )


def test_mcp_codespace_attach_cli_sets_env_and_starts_proxy(tmp_path, capsys, monkeypatch):
    started = {}

    def fake_run_mcp_proxy_config(proxy_config, fabric_config, **kwargs):
        started["proxy_config"] = proxy_config
        started["fabric_config"] = fabric_config
        started["kwargs"] = kwargs

    monkeypatch.delenv("SNULBUG_DISCOVERY_UPSTREAMS", raising=False)
    monkeypatch.setattr("snulbug.proxy.run_mcp_proxy_config", fake_run_mcp_proxy_config)

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
    assert output["legacy"]["starting_proxy"] is True
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

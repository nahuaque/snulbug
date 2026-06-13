from __future__ import annotations

import http.client
import json
from pathlib import Path

from snulbug import (
    FabricControllerStatusServer,
    reconcile_fabric_controller,
    run_fabric_controller,
    run_fabric_data_plane,
)
from snulbug.simulator import main as simulator_main


def test_fabric_controller_writes_state_and_change_event(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"

    result = reconcile_fabric_controller(config, state_path=state, event_log=event_log)

    snapshot = json.loads(state.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
    assert result["ok"] is True
    assert result["changed"] is True
    assert result["changes"][0]["type"] == "controller_initialized"
    assert snapshot["fingerprint"] == result["fingerprint"]
    assert snapshot["summary"]["upstream_count"] == 1
    assert events[0]["type"] == "snulbug.fabric.reconcile"
    assert events[0]["changes"][0]["type"] == "controller_initialized"


def test_fabric_controller_detects_discovered_upstream_changes(tmp_path):
    registry = tmp_path / "upstreams.json"
    registry.write_text(json.dumps([{"name": "files", "url": "http://127.0.0.1:9001/mcp"}]), encoding="utf-8")
    config = write_controller_config(tmp_path, discovery_registry=registry)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"

    first = reconcile_fabric_controller(config, state_path=state, event_log=event_log)
    registry.write_text(
        json.dumps(
            [
                {"name": "files", "url": "http://127.0.0.1:9001/mcp"},
                {"name": "git", "url": "http://127.0.0.1:9002/mcp", "tool_prefix": "git."},
            ]
        ),
        encoding="utf-8",
    )
    second = reconcile_fabric_controller(config, state_path=state, event_log=event_log)

    change_types = {change["type"] for change in second["changes"]}
    assert first["changed"] is True
    assert second["changed"] is True
    assert "fabric_changed" in change_types
    assert {"type": "upstream_added", "target": "git", "message": "upstream was added"} in second["changes"]
    assert len(event_log.read_text(encoding="utf-8").splitlines()) == 2


def test_fabric_controller_does_not_append_event_when_unchanged(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"

    first = reconcile_fabric_controller(config, state_path=state, event_log=event_log)
    second = reconcile_fabric_controller(config, state_path=state, event_log=event_log)

    assert first["changed"] is True
    assert first["event_written"] is True
    assert second["changed"] is False
    assert second["event_written"] is False
    assert second["changes"] == []
    assert len(event_log.read_text(encoding="utf-8").splitlines()) == 1


def test_fabric_controller_recovers_from_unreadable_previous_state(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    state.parent.mkdir(parents=True)
    state.write_text("{not-json", encoding="utf-8")

    result = reconcile_fabric_controller(config, state_path=state, event_log=None)

    change_types = {change["type"] for change in result["changes"]}
    snapshot = json.loads(state.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert "previous_state_unreadable" in change_types
    assert snapshot["ok"] is True


def test_fabric_controller_recovers_from_invalid_previous_state_shape(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps(["not", "a", "snapshot"]), encoding="utf-8")

    result = reconcile_fabric_controller(config, state_path=state, event_log=None)

    change_types = {change["type"] for change in result["changes"]}
    assert result["ok"] is True
    assert "previous_state_unreadable" in change_types


def test_fabric_controller_records_config_error_and_recovers(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"
    reconcile_fabric_controller(config, state_path=state, event_log=event_log)
    config.write_text('[mcp.proxy]\nupstreams = "not-a-list"\n', encoding="utf-8")

    failed = reconcile_fabric_controller(config, state_path=state, event_log=event_log)
    write_controller_config(tmp_path)
    recovered = reconcile_fabric_controller(config, state_path=state, event_log=event_log)

    failed_change_types = {change["type"] for change in failed["changes"]}
    recovered_change_types = {change["type"] for change in recovered["changes"]}
    assert failed["ok"] is False
    assert failed["error"]
    assert "config_error" in failed_change_types
    assert "fabric_health_changed" in failed_change_types
    assert recovered["ok"] is True
    assert recovered["error"] is None
    assert "fabric_health_changed" in recovered_change_types
    assert len(event_log.read_text(encoding="utf-8").splitlines()) == 3


def test_mcp_fabric_controller_cli_emits_compact_result(tmp_path, capsys):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"

    status = simulator_main(
        [
            "mcp",
            "fabric",
            "controller",
            "--config",
            str(config),
            "--state",
            str(state),
            "--event-log",
            str(event_log),
            "--once",
            "--compact",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert status == 0
    assert payload["ok"] is True
    assert payload["summary"]["upstream_count"] == 1
    assert state.is_file()
    assert event_log.is_file()


def test_fabric_controller_status_server_has_explicit_uninitialized_status():
    server = FabricControllerStatusServer(host="127.0.0.1", port=0)
    server.start()
    try:
        health = read_status_server(server, "/healthz?probe=1")
        status = read_status_server(server, "/status")
        metrics = read_status_server(server, "/metrics")
    finally:
        server.stop()

    status_payload = json.loads(status["body"])
    assert health["status"] == 503
    assert json.loads(health["body"]) == {"ok": False}
    assert status["status"] == 503
    assert status_payload["initialized"] is False
    assert status_payload["ok"] is False
    assert metrics["status"] == 200
    assert "snulbug_fabric_controller_ok 0" in metrics["body"]


def test_fabric_controller_status_server_exposes_health_status_and_metrics(tmp_path):
    config = write_controller_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    server = FabricControllerStatusServer(host="127.0.0.1", port=0)
    server.start()
    try:
        result = run_fabric_controller(
            config,
            state_path=state,
            event_log=None,
            once=True,
            status_server=server,
        )
        health = read_status_server(server, "/healthz")
        metrics = read_status_server(server, "/metrics")
    finally:
        server.stop()

    assert result["ok"] is True
    assert health["status"] == 200
    assert json.loads(health["body"]) == {"ok": True}
    assert metrics["status"] == 200
    assert "snulbug_fabric_upstreams 1" in metrics["body"]


def test_fabric_data_plane_runner_starts_controller_and_proxy(tmp_path):
    config = write_fabric_run_config(tmp_path)
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"
    started = []
    proxy_calls = []
    health_checks = []

    def emit(payload):
        started.append(payload)

    def fake_proxy_runner(**kwargs):
        proxy_calls.append(kwargs)
        status = started[0]["status_server"]
        health_checks.append(read_http(status["host"], status["port"], "/healthz"))

    result = run_fabric_data_plane(
        config,
        state_path=state,
        event_log=event_log,
        controller_interval=0.01,
        reload_interval=0.02,
        status_port=0,
        emit=emit,
        proxy_runner=fake_proxy_runner,
    )

    snapshot = json.loads(state.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert result["stopped"] is True
    assert started[0]["generated_by"] == "snulbug mcp fabric run"
    assert started[0]["proxy"]["upstream_count"] == 1
    assert started[0]["proxy"]["reload_enabled"] is True
    assert proxy_calls[0]["fabric_reload_config"] == config
    assert proxy_calls[0]["fabric_reload_interval"] == 0.02
    assert proxy_calls[0]["upstreams"][0]["name"] == "files"
    assert health_checks[0]["status"] == 200
    assert json.loads(health_checks[0]["body"]) == {"ok": True}
    assert snapshot["initialized"] is True
    assert event_log.is_file()


def test_fabric_data_plane_runner_requires_facade_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "single-upstream"

        [mcp.proxy]
        upstream = "http://127.0.0.1:9000/mcp"
        policy = "policy.snulbug/policy.lua"
        """,
        encoding="utf-8",
    )

    try:
        run_fabric_data_plane(config, status_port=0, proxy_runner=lambda **kwargs: None)
    except ValueError as exc:
        assert "facade upstreams" in str(exc)
    else:  # pragma: no cover - assertion guard.
        raise AssertionError("expected fabric data plane to require facade upstreams")


def test_mcp_fabric_run_cli_emits_compact_startup(monkeypatch, tmp_path, capsys):
    config = write_fabric_run_config(tmp_path)
    calls = []

    def fake_run_fabric_data_plane(config_path, **kwargs):
        calls.append((config_path, kwargs))
        payload = {
            "ok": True,
            "generated_by": "snulbug mcp fabric run",
            "config": str(config_path),
            "status_server": {"url": "http://127.0.0.1:0"},
            "proxy": {"upstream_count": 1, "reload_enabled": True},
        }
        kwargs["emit"](payload)
        return {**payload, "stopped": True}

    monkeypatch.setattr("snulbug.controller.run_fabric_data_plane", fake_run_fabric_data_plane)

    status = simulator_main(
        [
            "mcp",
            "fabric",
            "run",
            "--config",
            str(config),
            "--state",
            str(tmp_path / "state.json"),
            "--event-log",
            str(tmp_path / "events.jsonl"),
            "--controller-interval",
            "0.5",
            "--reload-interval",
            "0.25",
            "--status-port",
            "0",
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["generated_by"] == "snulbug mcp fabric run"
    assert calls[0][0] == config
    assert calls[0][1]["controller_interval"] == 0.5
    assert calls[0][1]["reload_interval"] == 0.25
    assert calls[0][1]["status_port"] == 0


def write_controller_config(tmp_path: Path, *, discovery_registry: Path | None = None) -> Path:
    config = tmp_path / "snulbug.toml"
    if discovery_registry is None:
        config.write_text(
            """
            [mcp.fabric]
            name = "controller-fabric"
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
        return config

    config.write_text(
        f"""
        [mcp.fabric]
        name = "controller-fabric"
        probe_gateway = false
        probe_upstreams = false

        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "registry"
        type = "file"
        path = "{discovery_registry.name}"

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        """,
        encoding="utf-8",
    )
    return config


def write_fabric_run_config(tmp_path: Path) -> Path:
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "managed-fabric"
        probe_gateway = false
        probe_upstreams = false

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        policy = "policy.snulbug/policy.lua"
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        """,
        encoding="utf-8",
    )
    return config


def read_status_server(server: FabricControllerStatusServer, path: str) -> dict[str, object]:
    connection = http.client.HTTPConnection(server.host, server.port, timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        return {"status": response.status, "body": body}
    finally:
        connection.close()


def read_http(host: str, port: int, path: str) -> dict[str, object]:
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        return {"status": response.status, "body": body}
    finally:
        connection.close()

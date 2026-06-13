from __future__ import annotations

import http.client
import json
from pathlib import Path

from snulbug import (
    EVENT_DISCOVERY_DEGRADED,
    EVENT_MANIFEST_CHANGED,
    EVENT_POLICY_CHANGED,
    EVENT_ROUTE_CHANGED,
    EVENT_UPSTREAM_UNHEALTHY,
    FabricControllerStatusServer,
    MemoryFabricRuntimeStateStore,
    load_fabric_runtime_status,
    open_fabric_runtime_state_store,
    reconcile_fabric_controller,
    run_fabric_controller,
    run_fabric_data_plane,
    sign_upstream_manifest,
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
    assert EVENT_ROUTE_CHANGED in events[0]["event_types"]
    assert snapshot["control_events"][0]["schema"] == "snulbug.control-plane-event.v1"


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
    assert EVENT_ROUTE_CHANGED in second["event_types"]
    assert len(event_log.read_text(encoding="utf-8").splitlines()) == 2


def test_fabric_controller_emits_policy_and_manifest_control_events(tmp_path):
    manifest = write_controller_manifest(tmp_path, identity="files@local")
    config = write_controller_manifest_config(tmp_path, manifest=manifest, policy="policy-a.snulbug/policy.lua")
    state = tmp_path / ".snulbug/fabric-state.json"
    event_log = tmp_path / ".snulbug/fabric-events.jsonl"
    reconcile_fabric_controller(config, state_path=state, event_log=event_log)
    write_controller_manifest(tmp_path, identity="files@local-v2", path=manifest)
    write_controller_manifest_config(
        tmp_path,
        manifest=manifest,
        policy="policy-b.snulbug/policy.lua",
        manifest_identity="files@local-v2",
    )

    result = reconcile_fabric_controller(config, state_path=state, event_log=event_log)

    event_types = {event["type"] for event in result["control_events"]}
    assert EVENT_POLICY_CHANGED in event_types
    assert EVENT_MANIFEST_CHANGED in event_types
    policy_event = next(event for event in result["control_events"] if event["type"] == EVENT_POLICY_CHANGED)
    manifest_event = next(event for event in result["control_events"] if event["type"] == EVENT_MANIFEST_CHANGED)
    assert policy_event["previous"]["policy"].endswith("policy-a.snulbug/policy.lua")
    assert policy_event["current"]["policy"].endswith("policy-b.snulbug/policy.lua")
    assert manifest_event["subject"]["upstream"] == "files"
    assert manifest_event["current"]["declared_identity"] == "files@local-v2"


def test_fabric_controller_emits_discovery_degraded_control_event(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "degraded-discovery"
        probe_gateway = false
        probe_upstreams = false

        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "missing-required-registry"
        type = "file"
        path = "missing.json"
        required = true

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        """,
        encoding="utf-8",
    )

    result = reconcile_fabric_controller(config, state_path=tmp_path / "state.json", event_log=None)

    assert result["ok"] is False
    assert EVENT_DISCOVERY_DEGRADED in result["event_types"]
    event = next(event for event in result["control_events"] if event["type"] == EVENT_DISCOVERY_DEGRADED)
    assert event["severity"] == "warning"
    assert event["current"]["error_count"] == 1


def test_fabric_controller_emits_upstream_unhealthy_for_missing_required_manifest(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric]
        name = "missing-manifest"
        require_manifests = true
        probe_gateway = false
        probe_upstreams = false

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        manifest = "missing.files.manifest.json"
        manifest_required = true
        """,
        encoding="utf-8",
    )

    result = reconcile_fabric_controller(config, state_path=tmp_path / "state.json", event_log=None)

    assert result["ok"] is False
    assert EVENT_UPSTREAM_UNHEALTHY in result["event_types"]
    event = next(event for event in result["control_events"] if event["type"] == EVENT_UPSTREAM_UNHEALTHY)
    assert event["subject"] == {"kind": "upstream", "name": "files"}
    assert event["reason_code"] == "fabric.upstream.manifest_missing"


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
    runtime_state = f"sqlite:{tmp_path / '.snulbug/fabric-runtime.sqlite3'}"
    runtime_state_key = "test-runtime"
    started = []
    proxy_calls = []
    health_checks = []
    status_checks = []
    metric_checks = []

    def emit(payload):
        started.append(payload)

    def fake_proxy_runner(**kwargs):
        proxy_calls.append(kwargs)
        status = started[0]["status_server"]
        health_checks.append(read_http(status["host"], status["port"], "/healthz"))
        status_checks.append(read_http(status["host"], status["port"], "/status"))
        metric_checks.append(read_http(status["host"], status["port"], "/metrics"))

    result = run_fabric_data_plane(
        config,
        state_path=state,
        event_log=event_log,
        controller_interval=0.01,
        reload_interval=0.02,
        status_port=0,
        runtime_state=runtime_state,
        runtime_state_key=runtime_state_key,
        emit=emit,
        proxy_runner=fake_proxy_runner,
    )

    snapshot = json.loads(state.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert result["stopped"] is True
    assert started[0]["generated_by"] == "snulbug mcp fabric run"
    assert started[0]["proxy"]["upstream_count"] == 1
    assert started[0]["proxy"]["reload_enabled"] is True
    assert started[0]["runtime"]["data_plane"]["status"] == "running"
    assert started[0]["runtime"]["conformance"]["status"] == "not_configured"
    assert started[0]["runtime_owner"]["owner_id"]
    assert started[0]["runtime_owner"]["fencing_token"] == 1
    assert started[0]["share_gate"]["ok"] is True
    assert started[0]["share_gate"]["warnings"] == ["conformance_not_configured"]
    assert result["runtime"]["data_plane"]["status"] == "stopped"
    assert result["share_gate"]["ok"] is False
    assert result["share_gate"]["blocked_by"] == ["data_plane_stopped"]
    assert proxy_calls[0]["fabric_reload_config"] == config
    assert proxy_calls[0]["fabric_reload_interval"] == 0.02
    assert proxy_calls[0]["upstreams"][0]["name"] == "files"
    assert health_checks[0]["status"] == 200
    assert json.loads(health_checks[0]["body"]) == {"ok": True}
    status_payload = json.loads(status_checks[0]["body"])
    assert status_checks[0]["status"] == 200
    assert status_payload["runtime"]["data_plane"]["status"] == "running"
    assert status_payload["share_gate"]["ok"] is True
    assert metric_checks[0]["status"] == 200
    assert "snulbug_fabric_data_plane_running 1" in metric_checks[0]["body"]
    assert "snulbug_fabric_shareable 1" in metric_checks[0]["body"]
    assert snapshot["initialized"] is True
    assert event_log.is_file()
    persisted = load_fabric_runtime_status(runtime_state, key=runtime_state_key)
    assert persisted["ok"] is True
    assert persisted["status"]["runtime"]["data_plane"]["status"] == "stopped"
    assert "data_plane_stopped" in persisted["status"]["share_gate"]["blocked_by"]
    assert "runtime_lease_released" in persisted["status"]["share_gate"]["blocked_by"]
    assert persisted["status"]["runtime_owner"]["released_at"]


def test_fabric_runtime_store_uses_fencing_tokens_for_ownership():
    store = MemoryFabricRuntimeStateStore()
    first = store.acquire_lease("owner-a", ttl_seconds=60)
    second = store.acquire_lease("owner-b", ttl_seconds=60)
    renewed = store.renew_lease("owner-a", first["lease"]["fencing_token"], ttl_seconds=60)
    released = store.release_lease("owner-a", first["lease"]["fencing_token"])
    third = store.acquire_lease("owner-b", ttl_seconds=60)

    assert first["ok"] is True
    assert first["lease"]["fencing_token"] == 1
    assert second["ok"] is False
    assert second["reason"] == "owned_by_other_instance"
    assert second["lease"]["owner_id"] == "owner-a"
    assert renewed["owner_id"] == "owner-a"
    assert released is True
    assert third["ok"] is True
    assert third["lease"]["fencing_token"] == 2


def test_fabric_data_plane_runner_rejects_competing_runtime_owner(tmp_path):
    config = write_fabric_run_config(tmp_path)
    runtime_store = MemoryFabricRuntimeStateStore()
    started = []
    second_error = []

    def fake_proxy_runner(**kwargs):
        try:
            run_fabric_data_plane(
                config,
                status_port=0,
                runtime_state=runtime_store,
                runtime_instance_id="owner-b",
                proxy_runner=lambda **nested_kwargs: None,
            )
        except ValueError as exc:
            second_error.append(str(exc))
        else:  # pragma: no cover - assertion guard.
            raise AssertionError("expected competing fabric runtime owner to be rejected")

    result = run_fabric_data_plane(
        config,
        status_port=0,
        runtime_state=runtime_store,
        runtime_instance_id="owner-a",
        emit=lambda payload: started.append(payload),
        proxy_runner=fake_proxy_runner,
    )

    assert result["ok"] is True
    assert started[0]["runtime_owner"]["owner_id"] == "owner-a"
    assert started[0]["runtime_owner"]["fencing_token"] == 1
    assert second_error
    assert "owned by owner-a" in second_error[0]


def test_fabric_status_server_loads_shared_runtime_state():
    store = MemoryFabricRuntimeStateStore()
    first = FabricControllerStatusServer(host="127.0.0.1", port=0, runtime_store=store)
    first.update(
        {
            "ok": True,
            "summary": {"upstream_count": 1},
            "runtime": {
                "data_plane": {
                    "managed": True,
                    "status": "running",
                    "updated_at": "2000-01-01T00:00:00+00:00",
                    "heartbeat_at": "2000-01-01T00:00:00+00:00",
                    "heartbeat_ttl_seconds": 1,
                }
            },
        }
    )

    second = FabricControllerStatusServer(host="127.0.0.1", port=0, runtime_store=store)
    loaded = second.latest()
    loaded_runtime = load_fabric_runtime_status(store)

    assert loaded["runtime"]["data_plane"]["status"] == "running"
    assert loaded["share_gate"]["ok"] is False
    assert "data_plane_heartbeat_stale" in loaded["share_gate"]["blocked_by"]
    assert loaded_runtime["status"]["share_gate"]["ok"] is False
    assert "data_plane_heartbeat_stale" in loaded_runtime["status"]["share_gate"]["blocked_by"]


def test_fabric_data_plane_runner_blocks_when_required_conformance_fails(monkeypatch, tmp_path):
    config = write_fabric_run_config(tmp_path)
    conformance_pack = tmp_path / ".snulbug/fabric-conformance"
    proxy_calls = []

    def fake_conformance(pack):
        assert pack == conformance_pack
        return {
            "ok": False,
            "summary": {"failed": 1},
            "checks": [
                {
                    "id": "config.fingerprint",
                    "status": "fail",
                    "message": "fabric config changed",
                }
            ],
        }

    monkeypatch.setattr("snulbug.controller.run_fabric_conformance_pack", fake_conformance)

    try:
        run_fabric_data_plane(
            config,
            status_port=0,
            conformance_pack=conformance_pack,
            require_conformance=True,
            runtime_state="memory",
            proxy_runner=lambda **kwargs: proxy_calls.append(kwargs),
        )
    except ValueError as exc:
        assert "conformance gate failed" in str(exc)
    else:  # pragma: no cover - assertion guard.
        raise AssertionError("expected conformance gate to block data plane startup")

    assert proxy_calls == []


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
        run_fabric_data_plane(config, status_port=0, runtime_state="memory", proxy_runner=lambda **kwargs: None)
    except ValueError as exc:
        assert "facade upstreams" in str(exc)
    else:  # pragma: no cover - assertion guard.
        raise AssertionError("expected fabric data plane to require facade upstreams")


def test_mcp_fabric_run_cli_emits_compact_startup(monkeypatch, tmp_path, capsys):
    config = write_fabric_run_config(tmp_path)
    conformance_pack = tmp_path / ".snulbug/fabric-conformance"
    runtime_state = f"sqlite:{tmp_path / '.snulbug/fabric-runtime.sqlite3'}"
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
            "--conformance-pack",
            str(conformance_pack),
            "--require-conformance",
            "--runtime-state",
            runtime_state,
            "--runtime-state-key",
            "cli-runtime",
            "--runtime-heartbeat-ttl",
            "20",
            "--runtime-instance-id",
            "cli-owner",
            "--runtime-lease-ttl",
            "45",
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
    assert calls[0][1]["conformance_pack"] == conformance_pack
    assert calls[0][1]["require_conformance"] is True
    assert calls[0][1]["runtime_state"] == runtime_state
    assert calls[0][1]["runtime_state_key"] == "cli-runtime"
    assert calls[0][1]["runtime_heartbeat_ttl"] == 20.0
    assert calls[0][1]["runtime_instance_id"] == "cli-owner"
    assert calls[0][1]["runtime_lease_ttl"] == 45.0


def test_mcp_fabric_runtime_cli_reads_and_clears_persisted_state(tmp_path, capsys):
    runtime_state = f"sqlite:{tmp_path / '.snulbug/fabric-runtime.sqlite3'}"
    runtime_key = "cli-runtime"
    store = open_fabric_runtime_state_store(runtime_state, key=runtime_key)
    assert store is not None
    try:
        store.save_status(
            {
                "ok": True,
                "runtime": {
                    "data_plane": {
                        "managed": True,
                        "status": "stopped",
                        "updated_at": "2000-01-01T00:00:00+00:00",
                    }
                },
            }
        )
    finally:
        store.close()

    status = simulator_main(
        [
            "mcp",
            "fabric",
            "runtime",
            "status",
            "--runtime-state",
            runtime_state,
            "--runtime-state-key",
            runtime_key,
            "--compact",
        ]
    )
    status_output = json.loads(capsys.readouterr().out)
    clear_status = simulator_main(
        [
            "mcp",
            "fabric",
            "runtime",
            "clear",
            "--runtime-state",
            runtime_state,
            "--runtime-state-key",
            runtime_key,
            "--compact",
        ]
    )
    clear_output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert status_output["status"]["runtime"]["data_plane"]["status"] == "stopped"
    assert clear_status == 0
    assert clear_output["cleared"] is True
    assert load_fabric_runtime_status(runtime_state, key=runtime_key)["ok"] is False


def test_fabric_runtime_status_does_not_create_missing_sqlite_store(tmp_path):
    db_path = tmp_path / ".snulbug/missing-runtime.sqlite3"
    result = load_fabric_runtime_status(f"sqlite:{db_path}", key="missing")

    assert result["ok"] is False
    assert result["error"] == "fabric runtime state is empty"
    assert not db_path.exists()


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


def write_controller_manifest(tmp_path: Path, *, identity: str, path: Path | None = None) -> Path:
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
    output = path or (tmp_path / "files.manifest.json")
    output.write_text(json.dumps(manifest), encoding="utf-8")
    return output


def write_controller_manifest_config(
    tmp_path: Path,
    *,
    manifest: Path,
    policy: str,
    manifest_identity: str = "files@local",
) -> Path:
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
        [mcp.fabric]
        name = "manifest-fabric"
        require_manifests = true
        probe_gateway = false
        probe_upstreams = false

        [mcp.proxy]
        host = "127.0.0.1"
        port = 8181
        policy = "{policy}"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        tool_prefix = "files."
        manifest = "{manifest.name}"
        manifest_required = true
        manifest_identity = "{manifest_identity}"
        manifest_key_id = "dev"
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

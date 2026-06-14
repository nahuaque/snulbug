from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import DEFAULT_CONFIG_PATH, load_mcp_fabric_config, load_mcp_proxy_config
from .control_events import (
    EVENT_DISCOVERY_DEGRADED,
    EVENT_DISCOVERY_RECOVERED,
    EVENT_MANIFEST_CHANGED,
    EVENT_POLICY_CHANGED,
    EVENT_ROUTE_CHANGED,
    EVENT_UPSTREAM_RECOVERED,
    EVENT_UPSTREAM_UNHEALTHY,
    event_types,
    make_control_event,
)
from .fabric import build_fabric_audit_metadata, fabric_status, run_fabric_conformance_pack
from .fabric_control import (
    annotate_fabric_status_with_controls,
    control_share_gate_signals,
    summarize_fabric_control_state,
)
from .fabric_runtime import (
    DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    DEFAULT_FABRIC_RUNTIME_STATE,
    DEFAULT_FABRIC_RUNTIME_STATE_KEY,
    FabricRuntimeStateStore,
    open_fabric_runtime_state_store,
)
from .policy_activation import reconcile_policy_activation
from .webhooks import WebhookDispatcher, normalize_webhook_sinks

DEFAULT_CONTROLLER_STATE_PATH = Path(".snulbug/fabric-state.json")
DEFAULT_CONTROLLER_EVENT_LOG_PATH = Path(".snulbug/fabric-events.jsonl")
DEFAULT_CONTROLLER_STATUS_PORT = 8765
DEFAULT_RUNTIME_HEARTBEAT_TTL_SECONDS = 15.0

FabricProxyRunner = Callable[..., None]
FabricControlStateProvider = Callable[[], Mapping[str, Any] | None]


def reconcile_fabric_controller(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    state_path: str | Path = DEFAULT_CONTROLLER_STATE_PATH,
    event_log: str | Path | None = DEFAULT_CONTROLLER_EVENT_LOG_PATH,
    control_state: Mapping[str, Any] | None = None,
    webhook_dispatcher: Any = None,
) -> dict[str, Any]:
    """Reconcile declared fabric config into a durable controller state snapshot."""

    config_path = Path(config)
    state = Path(state_path)
    previous_error = None
    try:
        previous = _load_previous_state(state)
    except Exception as exc:
        previous = None
        previous_error = str(exc)
    observed_at = _utc_now()

    try:
        policy_activation = reconcile_policy_activation(config_path)
        status = fabric_status(config_path)
        status["policy_activation"] = policy_activation
        status = annotate_fabric_status_with_controls(status, control_state)
        if not policy_activation.get("ok"):
            status["ok"] = False
            recommendations = list(status.get("recommendations", []))
            recommendations.append("Promote and sign the configured policy bundle before starting the fabric.")
            status["recommendations"] = recommendations
        desired = _desired_state(status)
        load_error = None
    except Exception as exc:
        status = {
            "ok": False,
            "config": str(config_path),
            "summary": {},
            "upstreams": [],
            "discovery": {"providers": [], "summary": {"provider_count": 0, "upstream_count": 0, "error_count": 1}},
            "recommendations": ["Fix the snulbug.toml syntax or [mcp.fabric]/[mcp.proxy] configuration."],
        }
        desired = {"ok": False, "config": str(config_path), "error": str(exc)}
        load_error = str(exc)

    fingerprint = _fingerprint(desired)
    changes = _controller_changes(
        previous,
        desired,
        fingerprint=fingerprint,
        load_error=load_error,
        previous_error=previous_error,
    )
    control_events = _control_plane_events(
        previous,
        desired,
        observed_at=observed_at,
        fingerprint=fingerprint,
        load_error=load_error,
    )
    snapshot = _controller_snapshot(
        config=config_path,
        state_path=state,
        observed_at=observed_at,
        status=status,
        desired=desired,
        fingerprint=fingerprint,
        previous=previous,
        changes=changes,
        control_events=control_events,
        load_error=load_error,
    )
    _write_json(state, snapshot)

    event_written = False
    controller_event = _controller_event(snapshot) if changes or control_events else None
    if event_log is not None and controller_event is not None:
        _append_jsonl(Path(event_log), controller_event)
        event_written = True
    if webhook_dispatcher is not None and controller_event is not None:
        webhook_dispatcher.emit(controller_event)

    return {
        **snapshot,
        "event_log": str(event_log) if event_log is not None else None,
        "event_written": event_written,
    }


def run_fabric_controller(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    state_path: str | Path = DEFAULT_CONTROLLER_STATE_PATH,
    event_log: str | Path | None = DEFAULT_CONTROLLER_EVENT_LOG_PATH,
    interval: float = 2.0,
    once: bool = False,
    emit: Callable[[Mapping[str, Any]], None] | None = None,
    max_iterations: int | None = None,
    status_server: FabricControllerStatusServer | None = None,
    stop_event: threading.Event | None = None,
    control_state_provider: FabricControlStateProvider | None = None,
    webhooks: Sequence[Any] | None = None,
    webhook_dispatcher: Any = None,
) -> dict[str, Any]:
    """Run the fabric controller reconcile loop."""

    if interval <= 0:
        raise ValueError("interval must be positive")
    if max_iterations is not None and max_iterations <= 0:
        raise ValueError("max_iterations must be positive")
    if webhook_dispatcher is None:
        webhook_sinks = normalize_webhook_sinks(webhooks or [])
        webhook_dispatcher = WebhookDispatcher(webhook_sinks) if webhook_sinks else None

    iterations = 0
    while True:
        control_state = control_state_provider() if control_state_provider is not None else None
        result = reconcile_fabric_controller(
            config,
            state_path=state_path,
            event_log=event_log,
            control_state=control_state,
            webhook_dispatcher=webhook_dispatcher,
        )
        iterations += 1
        result["iteration"] = iterations
        if status_server is not None:
            status_server.update(result)
        if emit is not None:
            emit(result)
        if once or (max_iterations is not None and iterations >= max_iterations):
            return result
        if stop_event is not None and stop_event.wait(interval):
            return result
        if stop_event is None:
            time.sleep(interval)


def run_fabric_data_plane(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    state_path: str | Path = DEFAULT_CONTROLLER_STATE_PATH,
    event_log: str | Path | None = DEFAULT_CONTROLLER_EVENT_LOG_PATH,
    controller_interval: float = 2.0,
    reload_interval: float = 2.0,
    status_host: str = "127.0.0.1",
    status_port: int = DEFAULT_CONTROLLER_STATUS_PORT,
    conformance_pack: str | Path | None = None,
    require_conformance: bool = False,
    runtime_state: str | Path | FabricRuntimeStateStore | None = DEFAULT_FABRIC_RUNTIME_STATE,
    runtime_state_key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY,
    runtime_heartbeat_ttl: float = DEFAULT_RUNTIME_HEARTBEAT_TTL_SECONDS,
    runtime_instance_id: str | None = None,
    runtime_lease_ttl: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    emit: Callable[[Mapping[str, Any]], None] | None = None,
    proxy_runner: FabricProxyRunner | None = None,
    webhooks: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Run the controller and live-reloading proxy as one managed MCP fabric."""

    if controller_interval <= 0:
        raise ValueError("controller_interval must be positive")
    if reload_interval <= 0:
        raise ValueError("reload_interval must be positive")
    if require_conformance and conformance_pack is None:
        raise ValueError("require_conformance requires conformance_pack")
    if runtime_heartbeat_ttl <= 0:
        raise ValueError("runtime_heartbeat_ttl must be positive")
    if runtime_lease_ttl <= 0:
        raise ValueError("runtime_lease_ttl must be positive")

    config_path = Path(config)
    webhook_sinks = normalize_webhook_sinks(webhooks or _configured_webhooks(config_path))
    webhook_dispatcher = WebhookDispatcher(webhook_sinks) if webhook_sinks else None
    runtime_store = open_fabric_runtime_state_store(runtime_state, key=runtime_state_key)
    close_runtime_store = runtime_store if isinstance(runtime_state, str | Path) else None
    owner_id = runtime_instance_id or _new_runtime_owner_id()
    runtime_lease = None
    status_server = None
    stop_event = threading.Event()
    controller_errors: list[str] = []
    controller_thread: threading.Thread | None = None

    def load_control_state() -> Mapping[str, Any] | None:
        if runtime_store is None:
            return None
        load = getattr(runtime_store, "load_control_state", None)
        if not callable(load):
            return None
        return load()

    try:
        if runtime_store is not None:
            runtime_lease_result = runtime_store.acquire_lease(
                owner_id,
                ttl_seconds=runtime_lease_ttl,
                metadata={"config": str(config_path), "state": str(state_path), "event_log": str(event_log)},
            )
            if not runtime_lease_result.get("ok"):
                lease = _mapping(runtime_lease_result.get("lease"))
                raise ValueError(
                    "fabric runtime state is owned by "
                    f"{lease.get('owner_id', 'another instance')} until {lease.get('expires_at', 'unknown')}"
                )
            runtime_lease = _mapping(runtime_lease_result.get("lease"))

        status_server = FabricControllerStatusServer(
            host=status_host,
            port=status_port,
            runtime_store=runtime_store,
            runtime_owner_id=owner_id if runtime_store is not None else None,
            runtime_lease=runtime_lease,
            runtime_lease_ttl=runtime_lease_ttl,
        )
        status_server.start()
        initial = run_fabric_controller(
            config_path,
            state_path=state_path,
            event_log=event_log,
            interval=controller_interval,
            once=True,
            status_server=status_server,
            control_state_provider=load_control_state,
            webhook_dispatcher=webhook_dispatcher,
        )
        if not initial.get("ok"):
            raise ValueError(f"fabric controller reconcile failed: {initial.get('error') or 'fabric is not healthy'}")

        conformance_result = None
        if conformance_pack is not None:
            conformance_result = run_fabric_conformance_pack(conformance_pack)
            if require_conformance and not conformance_result.get("ok"):
                proxy_config = load_mcp_proxy_config(config_path)
                status_server.update_runtime(
                    _fabric_runtime_state(
                        status="blocked",
                        proxy_config=proxy_config,
                        reload_interval=reload_interval,
                        conformance_pack=conformance_pack,
                        conformance=conformance_result,
                        require_conformance=require_conformance,
                        heartbeat_ttl_seconds=runtime_heartbeat_ttl,
                        operational_controls=summarize_fabric_control_state(load_control_state()),
                        error="fabric conformance gate failed",
                    )
                )
                raise ValueError("fabric conformance gate failed; data plane was not started")

        def reconcile_loop() -> None:
            try:
                run_fabric_controller(
                    config_path,
                    state_path=state_path,
                    event_log=event_log,
                    interval=controller_interval,
                    status_server=status_server,
                    stop_event=stop_event,
                    control_state_provider=load_control_state,
                    webhook_dispatcher=webhook_dispatcher,
                )
            except Exception as exc:  # pragma: no cover - defensive; loop body is covered through reconcile tests.
                controller_errors.append(str(exc))
                latest = status_server.latest()
                status_server.update(
                    {
                        **latest,
                        "ok": False,
                        "controller_error": str(exc),
                    }
                )

        controller_thread = threading.Thread(target=reconcile_loop, daemon=True)
        controller_thread.start()

        proxy_config = load_mcp_proxy_config(config_path)
        operational_controls = summarize_fabric_control_state(load_control_state())
        fabric_config = load_mcp_fabric_config(config_path)
        fabric_config["proxy"] = proxy_config
        topology_audit = build_fabric_audit_metadata(fabric_config)
        if not proxy_config["upstreams"]:
            raise ValueError("fabric run requires facade upstreams in [mcp.proxy.upstreams] or discovery")

        started = _fabric_run_started_result(
            config=config_path,
            state_path=Path(state_path),
            event_log=event_log,
            status_server=status_server,
            proxy_config=proxy_config,
            controller_interval=controller_interval,
            reload_interval=reload_interval,
            initial=initial,
            conformance_pack=conformance_pack,
            conformance=conformance_result,
            require_conformance=require_conformance,
            heartbeat_ttl_seconds=runtime_heartbeat_ttl,
            operational_controls=operational_controls,
        )
        status_server.update_runtime(started["runtime"])
        if emit is not None:
            emit(started)

        runner = proxy_runner or _default_proxy_runner()
        try:
            runner(
                upstream=proxy_config["upstream"],
                upstreams=proxy_config["upstreams"],
                policy=proxy_config["policy"],
                host=proxy_config["host"],
                port=proxy_config["port"],
                state=proxy_config["state"],
                trace=proxy_config["trace"],
                max_body_bytes=proxy_config["max_body_bytes"],
                timeout=proxy_config["timeout"],
                record_out=proxy_config["record_out"],
                audit_out=proxy_config["audit_out"],
                redact_records=proxy_config["redact_records"],
                decision_console=proxy_config["decision_console"],
                decision_console_format=proxy_config["decision_console_format"],
                confirm=proxy_config["confirm"],
                response_max_bytes=proxy_config["response_max_bytes"],
                response_redact_secrets=proxy_config["response_redact_secrets"],
                response_block_instructions=proxy_config["response_block_instructions"],
                tool_pinning=proxy_config["tool_pinning"],
                tool_pinning_action=proxy_config["tool_pinning_action"],
                schema_validation=proxy_config["schema_validation"],
                schema_validation_action=proxy_config["schema_validation_action"],
                facade_health_routing=proxy_config["facade_health_routing"],
                facade_health_failure_threshold=proxy_config["facade_health_failure_threshold"],
                facade_health_cooldown_seconds=proxy_config["facade_health_cooldown_seconds"],
                facade_health_exclude_unhealthy=proxy_config["facade_health_exclude_unhealthy"],
                lease_file=proxy_config["lease_file"],
                lease_required=proxy_config["lease_required"],
                lease_header=proxy_config["lease_header"],
                tunnel_provider=proxy_config["tunnel_provider"],
                tunnel_public_url=proxy_config["tunnel_public_url"],
                cloudflare_access=proxy_config["cloudflare_access"],
                cloudflare_access_require_jwt=proxy_config["cloudflare_access_require_jwt"],
                cloudflare_access_require_email=proxy_config["cloudflare_access_require_email"],
                cloudflare_access_require_cf_ray=proxy_config["cloudflare_access_require_cf_ray"],
                cloudflare_access_allowed_emails=proxy_config["cloudflare_access_allowed_emails"],
                cloudflare_access_allowed_domains=proxy_config["cloudflare_access_allowed_domains"],
                topology_audit=topology_audit,
                fabric_reload_config=config_path,
                fabric_reload_interval=reload_interval,
                fabric_reload_overrides={},
                fabric_control_state_provider=load_control_state,
            )
        except Exception as exc:
            failed_runtime = _fabric_runtime_state(
                status="stopped",
                proxy_config=proxy_config,
                reload_interval=reload_interval,
                conformance_pack=conformance_pack,
                conformance=conformance_result,
                require_conformance=require_conformance,
                heartbeat_ttl_seconds=runtime_heartbeat_ttl,
                operational_controls=summarize_fabric_control_state(load_control_state()),
                error=str(exc),
            )
            status_server.update_runtime(failed_runtime)
            raise
        stopped_runtime = _fabric_runtime_state(
            status="stopped",
            proxy_config=proxy_config,
            reload_interval=reload_interval,
            conformance_pack=conformance_pack,
            conformance=conformance_result,
            require_conformance=require_conformance,
            heartbeat_ttl_seconds=runtime_heartbeat_ttl,
            operational_controls=summarize_fabric_control_state(load_control_state()),
        )
        status_server.update_runtime(stopped_runtime)
        stopped = _attach_share_gate(
            {
                **started,
                "runtime": stopped_runtime,
                "runtime_owner": _runtime_owner_summary(status_server.runtime_lease),
                "stopped": True,
            }
        )
        return {**stopped, "controller_errors": controller_errors}
    finally:
        stop_event.set()
        if controller_thread is not None:
            controller_thread.join(timeout=max(1.0, min(controller_interval, 5.0)))
        if status_server is not None:
            status_server.release_runtime_lease()
            status_server.stop()
        if close_runtime_store is not None:
            close_runtime_store.close()


def format_fabric_controller_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric controller",
        "",
        f"Config: {result.get('config')}",
        f"State: {result.get('state')}",
        f"Fingerprint: {result.get('fingerprint')}",
        f"Status: {'ok' if result.get('ok') else 'error'}",
    ]
    if result.get("event_log"):
        lines.append(f"Event log: {result.get('event_log')}")
    if result.get("error"):
        lines.append(f"Error: {result.get('error')}")

    summary = _mapping(result.get("summary"))
    policy_activation = _mapping(result.get("policy_activation"))
    operational_controls = _mapping(result.get("operational_controls"))
    lines.extend(
        [
            "",
            "## Summary",
            f"- upstreams: {summary.get('upstream_count', 0)}",
            f"- discovered upstreams: {summary.get('discovered_upstream_count', 0)}",
            f"- discovery errors: {summary.get('discovery_error_count', 0)}",
            f"- missing required manifests: {summary.get('missing_required_manifests', 0)}",
        ]
    )
    if policy_activation:
        lines.extend(
            [
                "",
                "## Policy Activation",
                f"- mode: `{policy_activation.get('mode', 'off')}`",
                f"- action: `{policy_activation.get('action', 'unknown')}`",
                f"- state: `{policy_activation.get('state', policy_activation.get('previous_state', 'unknown'))}`",
            ]
        )
        if policy_activation.get("bundle"):
            lines.append(f"- bundle: `{policy_activation.get('bundle')}`")
        if policy_activation.get("error"):
            lines.append(f"- error: {policy_activation.get('error')}")
    if operational_controls:
        lines.extend(
            [
                "",
                "## Operational Controls",
                f"- paused: `{str(bool(operational_controls.get('paused'))).lower()}`",
                f"- active actions: {operational_controls.get('active_count', 0)}",
                "- disabled upstreams: "
                f"`{', '.join(str(item) for item in operational_controls.get('disabled_upstreams', [])) or 'none'}`",
                f"- force reload: `{str(bool(operational_controls.get('force_reload'))).lower()}`",
            ]
        )

    changes = _sequence_mappings(result.get("changes"))
    lines.extend(["", "## Changes"])
    if not changes:
        lines.append("- none")
    for change in changes:
        target = change.get("target")
        suffix = f" `{target}`" if target else ""
        lines.append(f"- {change.get('type')}{suffix}: {change.get('message')}")

    upstreams = _sequence_mappings(result.get("upstreams"))
    lines.extend(["", "## Upstreams"])
    if not upstreams:
        lines.append("- none")
    for upstream in upstreams:
        manifest = _mapping(upstream.get("manifest"))
        manifest_text = "none"
        if manifest:
            manifest_text = f"{manifest.get('path')} ({'exists' if manifest.get('exists') else 'missing'})"
        lines.append(
            "- "
            f"{upstream.get('name')} [{upstream.get('transport')}] "
            f"prefix=`{upstream.get('tool_prefix')}` "
            f"status=`{upstream.get('operational_status', 'active')}` "
            f"manifest=`{manifest_text}`"
        )

    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip()


def format_fabric_run_report(result: Mapping[str, Any]) -> str:
    proxy = _mapping(result.get("proxy"))
    controller = _mapping(result.get("controller"))
    status_server = _mapping(result.get("status_server"))
    runtime = _mapping(result.get("runtime"))
    data_plane = _mapping(runtime.get("data_plane"))
    conformance = _mapping(runtime.get("conformance"))
    share_gate = _mapping(result.get("share_gate"))
    runtime_owner = _mapping(result.get("runtime_owner"))
    operational_controls = _mapping(result.get("operational_controls"))
    lines = [
        "# snulbug fabric run",
        "",
        f"Config: {result.get('config')}",
        f"Gateway: {proxy.get('url')}",
        f"Status: {status_server.get('url')}",
        f"State: {controller.get('state')}",
    ]
    if controller.get("event_log"):
        lines.append(f"Event log: {controller.get('event_log')}")
    lines.extend(
        [
            "",
            "## Controller",
            f"- interval: {controller.get('interval')}s",
            f"- fingerprint: `{controller.get('fingerprint')}`",
            "",
            "## Data plane",
            f"- bind: `{proxy.get('host')}:{proxy.get('port')}`",
            f"- runtime: `{data_plane.get('status', 'unknown')}`",
            f"- upstreams: {proxy.get('upstream_count', 0)}",
            f"- live reload: {str(bool(proxy.get('reload_enabled'))).lower()}",
            f"- reload interval: {proxy.get('reload_interval')}s",
            f"- share gate: `{'ok' if share_gate.get('ok') else 'blocked'}`",
            f"- conformance: `{conformance.get('status', 'not_configured')}`",
            f"- operational controls: {operational_controls.get('active_count', 0)}",
            f"- owner: `{runtime_owner.get('owner_id', 'none')}`",
            f"- fencing token: `{runtime_owner.get('fencing_token', 'none')}`",
            "",
            "## Endpoints",
            f"- health: `{status_server.get('url')}/healthz`",
            f"- status: `{status_server.get('url')}/status`",
            f"- metrics: `{status_server.get('url')}/metrics`",
        ]
    )
    if result.get("stopped"):
        lines.extend(["", "## Stop", "- data plane exited"])
    return "\n".join(lines).rstrip()


@dataclass
class FabricControllerStatusServer:
    host: str = "127.0.0.1"
    port: int = 0
    runtime_store: FabricRuntimeStateStore | None = None
    runtime_owner_id: str | None = None
    runtime_lease: Mapping[str, Any] | None = None
    runtime_lease_ttl: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _latest: dict[str, Any] = field(default_factory=lambda: _initial_controller_status(), init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.runtime_store is None:
            return
        if self.runtime_owner_id is None:
            stored = self.runtime_store.load_status()
            if stored is not None:
                self._latest = _attach_share_gate(stored)

    def start(self) -> None:
        if self._server is not None:
            return
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                latest = controller.latest()
                path = urlsplit(self.path).path
                if path == "/healthz":
                    body = json.dumps({"ok": bool(latest.get("ok", False))}, sort_keys=True).encode("utf-8")
                    self._send(200 if latest.get("ok") else 503, body, content_type="application/json")
                    return
                if path == "/status":
                    body = json.dumps(latest, indent=2, sort_keys=True).encode("utf-8")
                    self._send(200 if latest.get("ok") else 503, body, content_type="application/json")
                    return
                if path == "/metrics":
                    body = _controller_metrics(latest).encode("utf-8")
                    self._send(200, body, content_type="text/plain; version=0.0.4")
                    return
                self._send(404, b"not found\n", content_type="text/plain")

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, body: bytes, *, content_type: str) -> None:
                self.send_response(status)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.host = str(self._server.server_address[0])
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    def update(self, result: Mapping[str, Any]) -> None:
        with self._lock:
            latest = _copy_jsonish(result)
            previous_runtime = _mapping(self._latest.get("runtime"))
            if "runtime" not in latest and previous_runtime:
                latest["runtime"] = _heartbeat_runtime(previous_runtime)
            latest = _attach_share_gate(latest)
            self._latest = latest
            self._save_latest()

    def update_runtime(self, runtime: Mapping[str, Any]) -> None:
        with self._lock:
            latest = _copy_jsonish(self._latest)
            latest["runtime"] = _copy_jsonish(runtime)
            self._latest = _attach_share_gate(latest)
            self._save_latest()

    def latest(self) -> dict[str, Any]:
        stored = (
            self.runtime_store.load_status()
            if self.runtime_store is not None and self.runtime_owner_id is None
            else None
        )
        with self._lock:
            if stored is not None:
                self._latest = _attach_share_gate(stored)
            return _copy_jsonish(self._latest)

    def _save_latest(self) -> None:
        if self.runtime_store is None:
            return
        if self.runtime_owner_id is None or self.runtime_lease is None:
            self.runtime_store.save_status(self._latest)
            return
        lease = self.runtime_store.renew_lease(
            self.runtime_owner_id,
            int(self.runtime_lease.get("fencing_token", -1)),
            ttl_seconds=self.runtime_lease_ttl,
        )
        if lease is None:
            self.runtime_lease = _runtime_owner_lost(self.runtime_lease)
            self._latest["runtime_owner"] = _runtime_owner_summary(self.runtime_lease)
            self._latest = _attach_share_gate(self._latest)
            return
        self.runtime_lease = lease
        self._latest["runtime_owner"] = _runtime_owner_summary(lease)
        self._latest = _attach_share_gate(self._latest)
        self.runtime_store.save_status(self._latest, lease=lease)

    def release_runtime_lease(self) -> None:
        if self.runtime_store is None or self.runtime_owner_id is None or self.runtime_lease is None:
            return
        released = self.runtime_store.release_lease(
            self.runtime_owner_id,
            int(self.runtime_lease.get("fencing_token", -1)),
        )
        if not released:
            return
        current = self.runtime_store.load_lease()
        if current is not None:
            self.runtime_lease = current
            self._latest["runtime_owner"] = _runtime_owner_summary(current)
            self._latest = _attach_share_gate(self._latest)
            self.runtime_store.save_status(self._latest, lease=current)


def _desired_state(status: Mapping[str, Any]) -> dict[str, Any]:
    upstreams = sorted(_sequence_mappings(status.get("upstreams")), key=lambda item: str(item.get("name", "")))
    discovery = _mapping(status.get("discovery"))
    providers = sorted(_sequence_mappings(discovery.get("providers")), key=lambda item: str(item.get("name", "")))
    normalized_discovery = {
        **_copy_jsonish(discovery),
        "providers": providers,
    }
    return {
        "ok": bool(status.get("ok")),
        "name": status.get("name"),
        "description": status.get("description"),
        "config": status.get("config"),
        "gateway_url": status.get("gateway_url"),
        "require_manifests": status.get("require_manifests"),
        "proxy": _copy_jsonish(status.get("proxy", {})),
        "policy_activation": _copy_jsonish(status.get("policy_activation", {})),
        "operational_controls": _copy_jsonish(status.get("operational_controls", {})),
        "discovery": normalized_discovery,
        "upstreams": upstreams,
        "summary": _copy_jsonish(status.get("summary", {})),
        "recommendations": _copy_jsonish(status.get("recommendations", [])),
    }


def _controller_snapshot(
    *,
    config: Path,
    state_path: Path,
    observed_at: str,
    status: Mapping[str, Any],
    desired: Mapping[str, Any],
    fingerprint: str,
    previous: Mapping[str, Any] | None,
    changes: Sequence[Mapping[str, Any]],
    control_events: Sequence[Mapping[str, Any]],
    load_error: str | None,
) -> dict[str, Any]:
    typed_events = _copy_jsonish(list(control_events))
    return {
        "version": 1,
        "generated_by": "snulbug mcp fabric controller",
        "initialized": True,
        "time": observed_at,
        "config": str(config),
        "state": str(state_path),
        "ok": bool(status.get("ok")),
        "fingerprint": fingerprint,
        "previous_fingerprint": previous.get("fingerprint") if previous else None,
        "changed": bool(changes),
        "changes": _copy_jsonish(list(changes)),
        "control_events": typed_events,
        "event_types": event_types(typed_events),
        "error": load_error,
        "fabric": {
            "name": desired.get("name"),
            "description": desired.get("description"),
            "gateway_url": desired.get("gateway_url"),
            "require_manifests": desired.get("require_manifests"),
        },
        "proxy": _copy_jsonish(desired.get("proxy", {})),
        "policy_activation": _copy_jsonish(desired.get("policy_activation", {})),
        "operational_controls": _copy_jsonish(desired.get("operational_controls", {})),
        "discovery": _copy_jsonish(desired.get("discovery", {})),
        "upstreams": _copy_jsonish(desired.get("upstreams", [])),
        "summary": _copy_jsonish(desired.get("summary", {})),
        "recommendations": _copy_jsonish(desired.get("recommendations", [])),
        "desired": _copy_jsonish(desired),
    }


def _controller_event(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "snulbug.fabric.reconcile",
        "version": 1,
        "time": snapshot.get("time"),
        "ok": snapshot.get("ok"),
        "config": snapshot.get("config"),
        "state": snapshot.get("state"),
        "fingerprint": snapshot.get("fingerprint"),
        "previous_fingerprint": snapshot.get("previous_fingerprint"),
        "changes": _copy_jsonish(snapshot.get("changes", [])),
        "control_events": _copy_jsonish(snapshot.get("control_events", [])),
        "event_types": _copy_jsonish(snapshot.get("event_types", [])),
        "summary": _copy_jsonish(snapshot.get("summary", {})),
    }


def _control_plane_events(
    previous: Mapping[str, Any] | None,
    desired: Mapping[str, Any],
    *,
    observed_at: str,
    fingerprint: str,
    load_error: str | None,
) -> list[dict[str, Any]]:
    previous_desired = _mapping(previous.get("desired")) if previous else {}
    events: list[dict[str, Any]] = []
    events.extend(_route_events(previous_desired, desired, observed_at=observed_at, fingerprint=fingerprint))
    events.extend(_policy_events(previous_desired, desired, observed_at=observed_at))
    events.extend(_manifest_events(previous_desired, desired, observed_at=observed_at))
    events.extend(_discovery_events(previous_desired, desired, observed_at=observed_at, load_error=load_error))
    events.extend(_upstream_health_events(previous_desired, desired, observed_at=observed_at))
    return events


def _route_events(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    observed_at: str,
    fingerprint: str,
) -> list[dict[str, Any]]:
    previous_routes = _route_index(previous.get("upstreams"))
    current_routes = _route_index(desired.get("upstreams"))
    previous_fingerprint = _fingerprint({"routes": previous_routes}) if previous else None
    current_fingerprint = _fingerprint({"routes": current_routes})
    if previous and previous_fingerprint == current_fingerprint:
        return []

    added = sorted(current_routes.keys() - previous_routes.keys())
    removed = sorted(previous_routes.keys() - current_routes.keys())
    changed = [
        name
        for name in sorted(current_routes.keys() & previous_routes.keys())
        if _fingerprint(previous_routes[name]) != _fingerprint(current_routes[name])
    ]
    if previous and not added and not removed and not changed:
        return []

    reason_code = "fabric.route.initialized" if not previous else "fabric.route.changed"
    message = (
        f"route table initialized with {len(current_routes)} upstream(s)"
        if not previous
        else "fabric route table changed"
    )
    return [
        make_control_event(
            EVENT_ROUTE_CHANGED,
            time=observed_at,
            severity="info",
            reason_code=reason_code,
            message=message,
            subject={"kind": "route_table"},
            previous={"fingerprint": previous_fingerprint, "upstreams": sorted(previous_routes)} if previous else None,
            current={
                "fingerprint": current_fingerprint,
                "fabric_fingerprint": fingerprint,
                "upstreams": sorted(current_routes),
            },
            details={
                "added": added,
                "removed": removed,
                "changed": changed,
                "upstream_count": len(current_routes),
            },
        )
    ]


def _policy_events(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    observed_at: str,
) -> list[dict[str, Any]]:
    previous_policy = _mapping(previous.get("proxy")).get("policy") if previous else None
    current_policy = _mapping(desired.get("proxy")).get("policy")
    if previous and previous_policy == current_policy:
        return []
    if not previous and current_policy is None:
        return []
    return [
        make_control_event(
            EVENT_POLICY_CHANGED,
            time=observed_at,
            severity="info",
            reason_code="fabric.policy.initialized" if not previous else "fabric.policy.changed",
            message="fabric policy changed" if previous else "fabric policy observed",
            subject={"kind": "policy", "path": current_policy or previous_policy},
            previous={"policy": previous_policy} if previous else None,
            current={"policy": current_policy},
        )
    ]


def _manifest_events(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    observed_at: str,
) -> list[dict[str, Any]]:
    previous_upstreams = _index_by_name(previous.get("upstreams")) if previous else {}
    current_upstreams = _index_by_name(desired.get("upstreams"))
    events = []
    for name in sorted(previous_upstreams.keys() | current_upstreams.keys()):
        previous_manifest = _manifest_view(_mapping(previous_upstreams.get(name)).get("manifest"))
        current_manifest = _manifest_view(_mapping(current_upstreams.get(name)).get("manifest"))
        if previous and _fingerprint(previous_manifest) == _fingerprint(current_manifest):
            continue
        if not previous and not current_manifest:
            continue
        if not previous:
            reason_code = "fabric.manifest.observed"
            message = f"manifest observed for upstream {name!r}"
        elif previous_manifest and current_manifest:
            reason_code = "fabric.manifest.changed"
            message = f"manifest changed for upstream {name!r}"
        elif current_manifest:
            reason_code = "fabric.manifest.added"
            message = f"manifest added for upstream {name!r}"
        else:
            reason_code = "fabric.manifest.removed"
            message = f"manifest removed for upstream {name!r}"
        events.append(
            make_control_event(
                EVENT_MANIFEST_CHANGED,
                time=observed_at,
                severity="info",
                reason_code=reason_code,
                message=message,
                subject={"kind": "manifest", "upstream": name, "path": current_manifest.get("path")},
                previous=previous_manifest if previous else None,
                current=current_manifest,
            )
        )
    return events


def _discovery_events(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    observed_at: str,
    load_error: str | None,
) -> list[dict[str, Any]]:
    previous_errors = _discovery_error_count(previous)
    current_errors = _discovery_error_count(desired)
    if load_error and "fabric discovery failed" in load_error:
        current_errors = max(1, current_errors)
    if current_errors > 0 and (not previous or previous_errors == 0):
        return [
            make_control_event(
                EVENT_DISCOVERY_DEGRADED,
                time=observed_at,
                severity="warning",
                reason_code="fabric.discovery.degraded",
                message="fabric discovery degraded",
                subject={"kind": "discovery"},
                previous={"error_count": previous_errors} if previous else None,
                current={"error_count": current_errors},
                details={"error": load_error, "summary": _mapping(_mapping(desired.get("discovery")).get("summary"))},
            )
        ]
    if previous_errors > 0 and current_errors == 0:
        return [
            make_control_event(
                EVENT_DISCOVERY_RECOVERED,
                time=observed_at,
                severity="info",
                reason_code="fabric.discovery.recovered",
                message="fabric discovery recovered",
                subject={"kind": "discovery"},
                previous={"error_count": previous_errors},
                current={"error_count": current_errors},
            )
        ]
    return []


def _upstream_health_events(
    previous: Mapping[str, Any],
    desired: Mapping[str, Any],
    *,
    observed_at: str,
) -> list[dict[str, Any]]:
    previous_upstreams = _index_by_name(previous.get("upstreams")) if previous else {}
    current_upstreams = _index_by_name(desired.get("upstreams"))
    events = []
    for name in sorted(previous_upstreams.keys() | current_upstreams.keys()):
        previous_issue = _upstream_health_issue(previous_upstreams.get(name)) if previous else None
        current_issue = _upstream_health_issue(current_upstreams.get(name))
        if current_issue and (
            previous_issue is None or previous_issue.get("reason_code") != current_issue.get("reason_code")
        ):
            events.append(
                make_control_event(
                    EVENT_UPSTREAM_UNHEALTHY,
                    time=observed_at,
                    severity="warning",
                    reason_code=str(current_issue["reason_code"]),
                    message=f"upstream {name!r} is unhealthy: {current_issue['message']}",
                    subject={"kind": "upstream", "name": name},
                    previous=previous_issue,
                    current=current_issue,
                )
            )
        elif previous_issue and not current_issue:
            events.append(
                make_control_event(
                    EVENT_UPSTREAM_RECOVERED,
                    time=observed_at,
                    severity="info",
                    reason_code="fabric.upstream.recovered",
                    message=f"upstream {name!r} recovered",
                    subject={"kind": "upstream", "name": name},
                    previous=previous_issue,
                    current={"healthy": True},
                )
            )
    return events


def _controller_changes(
    previous: Mapping[str, Any] | None,
    desired: Mapping[str, Any],
    *,
    fingerprint: str,
    load_error: str | None,
    previous_error: str | None,
) -> list[dict[str, Any]]:
    if previous is None:
        changes = [
            {
                "type": "controller_initialized",
                "message": "created initial fabric controller state",
                "target": desired.get("name") or desired.get("config"),
            }
        ]
        if previous_error:
            changes.append(
                {
                    "type": "previous_state_unreadable",
                    "message": previous_error,
                }
            )
        return changes

    changes: list[dict[str, Any]] = []
    previous_fingerprint = previous.get("fingerprint")
    if previous_fingerprint != fingerprint:
        changes.append(
            {
                "type": "fabric_changed",
                "message": "desired fabric fingerprint changed",
                "previous": previous_fingerprint,
                "current": fingerprint,
            }
        )
    if load_error:
        changes.append({"type": "config_error", "message": load_error, "target": desired.get("config")})

    previous_desired = _mapping(previous.get("desired"))
    changes.extend(_diff_named_items("upstream", previous_desired.get("upstreams"), desired.get("upstreams")))
    changes.extend(
        _diff_named_items(
            "discovery_provider",
            _mapping(previous_desired.get("discovery")).get("providers"),
            _mapping(desired.get("discovery")).get("providers"),
        )
    )
    previous_ok = previous_desired.get("ok")
    current_ok = desired.get("ok")
    if previous_ok is not None and bool(previous_ok) != bool(current_ok):
        changes.append(
            {
                "type": "fabric_health_changed",
                "message": f"fabric health changed from {previous_ok} to {current_ok}",
                "previous": bool(previous_ok),
                "current": bool(current_ok),
            }
        )
    return changes


def _diff_named_items(kind: str, previous_items: Any, current_items: Any) -> list[dict[str, Any]]:
    previous = _index_by_name(previous_items)
    current = _index_by_name(current_items)
    changes: list[dict[str, Any]] = []
    for name in sorted(current.keys() - previous.keys()):
        changes.append({"type": f"{kind}_added", "target": name, "message": f"{kind} was added"})
    for name in sorted(previous.keys() - current.keys()):
        changes.append({"type": f"{kind}_removed", "target": name, "message": f"{kind} was removed"})
    for name in sorted(current.keys() & previous.keys()):
        previous_fingerprint = _fingerprint(previous[name])
        current_fingerprint = _fingerprint(current[name])
        if previous_fingerprint != current_fingerprint:
            changes.append(
                {
                    "type": f"{kind}_changed",
                    "target": name,
                    "message": f"{kind} declaration changed",
                    "previous": previous_fingerprint,
                    "current": current_fingerprint,
                }
            )
    return changes


def _route_index(items: Any) -> dict[str, dict[str, Any]]:
    return {name: _route_view(item) for name, item in _index_by_name(items).items()}


def _route_view(upstream: Mapping[str, Any]) -> dict[str, Any]:
    return _copy_jsonish(
        {
            key: upstream.get(key)
            for key in (
                "name",
                "transport",
                "tool_prefix",
                "default",
                "url",
                "command",
                "args",
                "cwd",
                "peer",
                "local_port",
                "bridge_command",
                "bridge_config",
                "bridge_args",
            )
            if upstream.get(key) is not None
        }
    )


def _manifest_view(value: Any) -> dict[str, Any]:
    manifest = _mapping(value)
    return _copy_jsonish(
        {
            key: manifest.get(key)
            for key in (
                "path",
                "required",
                "exists",
                "expected_identity",
                "configured_key_id",
                "signed",
                "signature_key_id",
                "digest",
                "algorithm",
                "declared_schema",
                "declared_identity",
                "declared_transport",
                "declared_tool_prefix",
                "declared_tool_count",
                "load_error",
            )
            if manifest.get(key) is not None
        }
    )


def _discovery_error_count(desired: Mapping[str, Any]) -> int:
    summary = _mapping(_mapping(desired.get("discovery")).get("summary"))
    try:
        return int(summary.get("error_count", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _upstream_health_issue(upstream: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(upstream, Mapping):
        return None
    manifest = _mapping(upstream.get("manifest"))
    if manifest.get("required") and manifest.get("exists") is False:
        return {
            "healthy": False,
            "reason_code": "fabric.upstream.manifest_missing",
            "message": "required manifest is missing",
            "manifest": _manifest_view(manifest),
        }
    if manifest.get("load_error"):
        return {
            "healthy": False,
            "reason_code": "fabric.upstream.manifest_load_error",
            "message": "manifest could not be loaded",
            "manifest": _manifest_view(manifest),
        }
    return None


def _index_by_name(items: Any) -> dict[str, Mapping[str, Any]]:
    indexed = {}
    for item in _sequence_mappings(items):
        name = item.get("name")
        if isinstance(name, str) and name:
            indexed[name] = item
    return indexed


def _controller_metrics(result: Mapping[str, Any]) -> str:
    summary = _mapping(result.get("summary"))
    changed = 1 if result.get("changed") else 0
    ok = 1 if result.get("ok") else 0
    runtime = _mapping(result.get("runtime"))
    data_plane = _mapping(runtime.get("data_plane"))
    share_gate = _mapping(result.get("share_gate"))
    operational_controls = _mapping(result.get("operational_controls"))
    data_plane_running = 1 if data_plane.get("status") == "running" else 0
    shareable = 1 if share_gate.get("ok") is True else 0
    paused = 1 if operational_controls.get("paused") else 0
    lines = [
        "# HELP snulbug_fabric_controller_ok Whether the last fabric reconcile was healthy.",
        "# TYPE snulbug_fabric_controller_ok gauge",
        f"snulbug_fabric_controller_ok {ok}",
        "# HELP snulbug_fabric_data_plane_running Whether the managed data plane is running.",
        "# TYPE snulbug_fabric_data_plane_running gauge",
        f"snulbug_fabric_data_plane_running {data_plane_running}",
        "# HELP snulbug_fabric_shareable Whether controller and runtime gates allow sharing the gateway.",
        "# TYPE snulbug_fabric_shareable gauge",
        f"snulbug_fabric_shareable {shareable}",
        "# HELP snulbug_fabric_operational_controls Number of active fabric operational controls.",
        "# TYPE snulbug_fabric_operational_controls gauge",
        f"snulbug_fabric_operational_controls {int(operational_controls.get('active_count', 0) or 0)}",
        "# HELP snulbug_fabric_sharing_paused Whether sharing is paused by an operational control.",
        "# TYPE snulbug_fabric_sharing_paused gauge",
        f"snulbug_fabric_sharing_paused {paused}",
        "# HELP snulbug_fabric_controller_changed Whether the last reconcile changed desired state.",
        "# TYPE snulbug_fabric_controller_changed gauge",
        f"snulbug_fabric_controller_changed {changed}",
        "# HELP snulbug_fabric_upstreams Number of declared fabric upstreams.",
        "# TYPE snulbug_fabric_upstreams gauge",
        f"snulbug_fabric_upstreams {int(summary.get('upstream_count', 0) or 0)}",
        "# HELP snulbug_fabric_discovery_errors Number of discovery provider errors.",
        "# TYPE snulbug_fabric_discovery_errors gauge",
        f"snulbug_fabric_discovery_errors {int(summary.get('discovery_error_count', 0) or 0)}",
        "# HELP snulbug_fabric_missing_required_manifests Number of required manifests missing from disk.",
        "# TYPE snulbug_fabric_missing_required_manifests gauge",
        f"snulbug_fabric_missing_required_manifests {int(summary.get('missing_required_manifests', 0) or 0)}",
    ]
    return "\n".join(lines) + "\n"


def _fabric_runtime_state(
    *,
    status: str,
    proxy_config: Mapping[str, Any],
    reload_interval: float,
    conformance_pack: str | Path | None = None,
    conformance: Mapping[str, Any] | None = None,
    require_conformance: bool = False,
    heartbeat_ttl_seconds: float = DEFAULT_RUNTIME_HEARTBEAT_TTL_SECONDS,
    operational_controls: Mapping[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    host = proxy_config.get("host")
    port = proxy_config.get("port")
    now = _utc_now()
    data_plane = _drop_empty(
        {
            "managed": True,
            "status": status,
            "updated_at": now,
            "heartbeat_at": now,
            "heartbeat_ttl_seconds": heartbeat_ttl_seconds,
            "gateway_url": f"http://{host}:{port}/mcp",
            "host": host,
            "port": port,
            "policy": str(proxy_config.get("policy")) if proxy_config.get("policy") else None,
            "state": proxy_config.get("state"),
            "record_out": str(proxy_config.get("record_out")) if proxy_config.get("record_out") else None,
            "audit_out": str(proxy_config.get("audit_out")) if proxy_config.get("audit_out") else None,
            "upstream_count": len(proxy_config.get("upstreams", [])),
            "upstreams": [upstream.get("name") for upstream in _sequence_mappings(proxy_config.get("upstreams"))],
            "reload_enabled": True,
            "reload_interval": reload_interval,
            "error": error,
        }
    )
    return _drop_empty(
        {
            "data_plane": data_plane,
            "conformance": _runtime_conformance_summary(
                conformance_pack,
                conformance,
                required=require_conformance,
            ),
            "operational_controls": _copy_jsonish(operational_controls or {}),
        }
    )


def _runtime_conformance_summary(
    pack: str | Path | None,
    result: Mapping[str, Any] | None,
    *,
    required: bool,
) -> dict[str, Any]:
    if pack is None:
        return _drop_empty({"required": required, "status": "not_configured"})
    if result is None:
        return _drop_empty({"required": required, "pack": str(pack), "status": "not_checked"})
    failed_checks = [
        check.get("id")
        for check in _sequence_mappings(result.get("checks"))
        if check.get("status") == "fail" and check.get("id")
    ]
    return _drop_empty(
        {
            "required": required,
            "pack": str(pack),
            "status": "passed" if result.get("ok") else "failed",
            "ok": bool(result.get("ok")),
            "summary": _copy_jsonish(result.get("summary", {})),
            "failed_checks": failed_checks,
        }
    )


def _attach_share_gate(result: Mapping[str, Any]) -> dict[str, Any]:
    latest = _copy_jsonish(result)
    runtime = _mapping(latest.get("runtime"))
    if not runtime:
        return latest
    blocks = []
    warnings = []
    if not latest.get("ok"):
        blocks.append("controller_not_healthy")
    data_plane = _mapping(runtime.get("data_plane"))
    if data_plane and data_plane.get("status") != "running":
        blocks.append(f"data_plane_{data_plane.get('status', 'unknown')}")
    if data_plane.get("status") == "running" and _data_plane_heartbeat_stale(data_plane):
        blocks.append("data_plane_heartbeat_stale")
    control_blocks, control_warnings = control_share_gate_signals(latest.get("operational_controls"))
    blocks.extend(control_blocks)
    warnings.extend(control_warnings)
    runtime_owner = _mapping(latest.get("runtime_owner"))
    if runtime_owner.get("lost"):
        blocks.append("runtime_lease_lost")
    elif runtime_owner.get("released_at"):
        blocks.append("runtime_lease_released")
    elif runtime_owner and _runtime_owner_lease_expired(runtime_owner):
        blocks.append("runtime_lease_expired")
    conformance = _mapping(runtime.get("conformance"))
    if conformance:
        if conformance.get("required") and conformance.get("ok") is not True:
            blocks.append("conformance_not_passing")
        elif conformance.get("status") == "not_configured":
            warnings.append("conformance_not_configured")
        elif conformance.get("ok") is False:
            warnings.append("conformance_failed")
    latest["share_gate"] = _drop_empty(
        {
            "ok": not blocks,
            "blocked_by": blocks,
            "warnings": warnings,
            "updated_at": _utc_now(),
        }
    )
    return latest


def _runtime_owner_summary(lease: Mapping[str, Any] | None) -> dict[str, Any]:
    lease_mapping = _mapping(lease)
    return _drop_empty(
        {
            "owner_id": lease_mapping.get("owner_id"),
            "fencing_token": lease_mapping.get("fencing_token"),
            "acquired_at": lease_mapping.get("acquired_at"),
            "heartbeat_at": lease_mapping.get("heartbeat_at"),
            "expires_at": lease_mapping.get("expires_at"),
            "ttl_seconds": lease_mapping.get("ttl_seconds"),
            "released_at": lease_mapping.get("released_at"),
            "lost": lease_mapping.get("lost"),
        }
    )


def _runtime_owner_lost(lease: Mapping[str, Any]) -> dict[str, Any]:
    now = _utc_now()
    return _drop_empty(
        {
            **_copy_jsonish(lease),
            "lost": True,
            "lost_at": now,
            "heartbeat_at": now,
        }
    )


def _runtime_owner_lease_expired(runtime_owner: Mapping[str, Any]) -> bool:
    expires_at = runtime_owner.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        return False
    parsed = _parse_timestamp(expires_at)
    return parsed is not None and parsed <= datetime.now(timezone.utc)


def _heartbeat_runtime(runtime: Mapping[str, Any]) -> dict[str, Any]:
    updated = _copy_jsonish(runtime)
    data_plane = _mapping(updated.get("data_plane"))
    if data_plane.get("status") == "running":
        now = _utc_now()
        updated["data_plane"] = {
            **dict(data_plane),
            "updated_at": now,
            "heartbeat_at": now,
        }
    return updated


def _data_plane_heartbeat_stale(data_plane: Mapping[str, Any]) -> bool:
    timestamp = data_plane.get("heartbeat_at") or data_plane.get("updated_at")
    if not isinstance(timestamp, str) or not timestamp:
        return False
    try:
        ttl = float(data_plane.get("heartbeat_ttl_seconds") or 0)
    except (TypeError, ValueError):
        return False
    if ttl <= 0:
        return False
    observed_at = _parse_timestamp(timestamp)
    if observed_at is None:
        return False
    return (datetime.now(timezone.utc) - observed_at).total_seconds() > ttl


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _new_runtime_owner_id() -> str:
    host = socket.gethostname().split(".")[0] or "host"
    return f"{host}-{os.getpid()}-{uuid.uuid4().hex[:12]}"


def _fabric_run_started_result(
    *,
    config: Path,
    state_path: Path,
    event_log: str | Path | None,
    status_server: FabricControllerStatusServer,
    proxy_config: Mapping[str, Any],
    controller_interval: float,
    reload_interval: float,
    initial: Mapping[str, Any],
    conformance_pack: str | Path | None,
    conformance: Mapping[str, Any] | None,
    require_conformance: bool,
    heartbeat_ttl_seconds: float,
    operational_controls: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    host = proxy_config.get("host")
    port = proxy_config.get("port")
    gateway_url = _mapping(initial.get("fabric")).get("gateway_url") or f"http://{host}:{port}/mcp"
    runtime = _fabric_runtime_state(
        status="running",
        proxy_config=proxy_config,
        reload_interval=reload_interval,
        conformance_pack=conformance_pack,
        conformance=conformance,
        require_conformance=require_conformance,
        heartbeat_ttl_seconds=heartbeat_ttl_seconds,
        operational_controls=operational_controls,
    )
    runtime_owner = _runtime_owner_summary(status_server.runtime_lease)
    return _attach_share_gate(
        {
            "ok": True,
            "generated_by": "snulbug mcp fabric run",
            "config": str(config),
            "status_server": {
                "host": status_server.host,
                "port": status_server.port,
                "url": _status_server_url(status_server),
            },
            "controller": {
                "state": str(state_path),
                "event_log": str(event_log) if event_log is not None else None,
                "interval": controller_interval,
                "fingerprint": initial.get("fingerprint"),
                "summary": _copy_jsonish(initial.get("summary", {})),
            },
            "proxy": {
                "host": host,
                "port": port,
                "url": gateway_url,
                "policy": str(proxy_config.get("policy")),
                "record_out": str(proxy_config.get("record_out")) if proxy_config.get("record_out") else None,
                "audit_out": str(proxy_config.get("audit_out")) if proxy_config.get("audit_out") else None,
                "upstream_count": len(proxy_config.get("upstreams", [])),
                "reload_enabled": True,
                "reload_interval": reload_interval,
            },
            "runtime": runtime,
            "operational_controls": _copy_jsonish(operational_controls or {}),
            "runtime_owner": runtime_owner,
            "stopped": False,
        }
    )


def _status_server_url(status_server: FabricControllerStatusServer) -> str:
    return f"http://{status_server.host}:{status_server.port}"


def _default_proxy_runner() -> FabricProxyRunner:
    from .proxy import run_proxy

    return run_proxy


def _initial_controller_status() -> dict[str, Any]:
    return {
        "version": 1,
        "generated_by": "snulbug mcp fabric controller",
        "initialized": False,
        "ok": False,
        "changed": False,
        "summary": {},
        "changes": [],
        "recommendations": ["Run the fabric controller reconcile loop to initialize status."],
    }


def _load_previous_state(path: Path) -> Mapping[str, Any] | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    if not isinstance(loaded, Mapping):
        raise ValueError("previous controller state must be a JSON object")
    if loaded.get("version") != 1:
        raise ValueError("previous controller state version is unsupported")
    if not isinstance(loaded.get("fingerprint"), str) or not isinstance(loaded.get("desired"), Mapping):
        raise ValueError("previous controller state is missing fingerprint or desired state")
    return loaded


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _configured_webhooks(config: Path) -> list[Any]:
    try:
        return list(load_mcp_fabric_config(config).get("webhooks", []))
    except Exception:
        return []


def _fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(_copy_jsonish(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sequence_mappings(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, tuple):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import DEFAULT_CONFIG_PATH, load_mcp_fabric_config, load_mcp_proxy_config
from .fabric import build_fabric_audit_metadata, fabric_status

DEFAULT_CONTROLLER_STATE_PATH = Path(".snulbug/fabric-state.json")
DEFAULT_CONTROLLER_EVENT_LOG_PATH = Path(".snulbug/fabric-events.jsonl")
DEFAULT_CONTROLLER_STATUS_PORT = 8765

FabricProxyRunner = Callable[..., None]


def reconcile_fabric_controller(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    state_path: str | Path = DEFAULT_CONTROLLER_STATE_PATH,
    event_log: str | Path | None = DEFAULT_CONTROLLER_EVENT_LOG_PATH,
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
        status = fabric_status(config_path)
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
    snapshot = _controller_snapshot(
        config=config_path,
        state_path=state,
        observed_at=observed_at,
        status=status,
        desired=desired,
        fingerprint=fingerprint,
        previous=previous,
        changes=changes,
        load_error=load_error,
    )
    _write_json(state, snapshot)

    event_written = False
    if event_log is not None and changes:
        _append_jsonl(Path(event_log), _controller_event(snapshot))
        event_written = True

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
) -> dict[str, Any]:
    """Run the fabric controller reconcile loop."""

    if interval <= 0:
        raise ValueError("interval must be positive")
    if max_iterations is not None and max_iterations <= 0:
        raise ValueError("max_iterations must be positive")

    iterations = 0
    while True:
        result = reconcile_fabric_controller(config, state_path=state_path, event_log=event_log)
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
    emit: Callable[[Mapping[str, Any]], None] | None = None,
    proxy_runner: FabricProxyRunner | None = None,
) -> dict[str, Any]:
    """Run the controller and live-reloading proxy as one managed MCP fabric."""

    if controller_interval <= 0:
        raise ValueError("controller_interval must be positive")
    if reload_interval <= 0:
        raise ValueError("reload_interval must be positive")

    config_path = Path(config)
    status_server = FabricControllerStatusServer(host=status_host, port=status_port)
    status_server.start()
    stop_event = threading.Event()
    controller_errors: list[str] = []
    controller_thread: threading.Thread | None = None

    try:
        initial = run_fabric_controller(
            config_path,
            state_path=state_path,
            event_log=event_log,
            interval=controller_interval,
            once=True,
            status_server=status_server,
        )
        if not initial.get("ok"):
            raise ValueError(f"fabric controller reconcile failed: {initial.get('error') or 'fabric is not healthy'}")

        def reconcile_loop() -> None:
            try:
                run_fabric_controller(
                    config_path,
                    state_path=state_path,
                    event_log=event_log,
                    interval=controller_interval,
                    status_server=status_server,
                    stop_event=stop_event,
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
        )
        if emit is not None:
            emit(started)

        runner = proxy_runner or _default_proxy_runner()
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
        )
        return {
            **started,
            "stopped": True,
            "controller_errors": controller_errors,
        }
    finally:
        stop_event.set()
        if controller_thread is not None:
            controller_thread.join(timeout=max(1.0, min(controller_interval, 5.0)))
        status_server.stop()


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
            f"- upstreams: {proxy.get('upstream_count', 0)}",
            f"- live reload: {str(bool(proxy.get('reload_enabled'))).lower()}",
            f"- reload interval: {proxy.get('reload_interval')}s",
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
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _latest: dict[str, Any] = field(default_factory=lambda: _initial_controller_status(), init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

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
            self._latest = _copy_jsonish(result)

    def latest(self) -> dict[str, Any]:
        with self._lock:
            return _copy_jsonish(self._latest)


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
    load_error: str | None,
) -> dict[str, Any]:
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
        "error": load_error,
        "fabric": {
            "name": desired.get("name"),
            "description": desired.get("description"),
            "gateway_url": desired.get("gateway_url"),
            "require_manifests": desired.get("require_manifests"),
        },
        "proxy": _copy_jsonish(desired.get("proxy", {})),
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
        "summary": _copy_jsonish(snapshot.get("summary", {})),
    }


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
    lines = [
        "# HELP snulbug_fabric_controller_ok Whether the last fabric reconcile was healthy.",
        "# TYPE snulbug_fabric_controller_ok gauge",
        f"snulbug_fabric_controller_ok {ok}",
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
) -> dict[str, Any]:
    host = proxy_config.get("host")
    port = proxy_config.get("port")
    gateway_url = _mapping(initial.get("fabric")).get("gateway_url") or f"http://{host}:{port}/mcp"
    return {
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
        "stopped": False,
    }


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

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

from .config import DEFAULT_CONFIG_PATH
from .fabric import fabric_status

DEFAULT_CONTROLLER_STATE_PATH = Path(".snulbug/fabric-state.json")
DEFAULT_CONTROLLER_EVENT_LOG_PATH = Path(".snulbug/fabric-events.jsonl")


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
        time.sleep(interval)


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


@dataclass
class FabricControllerStatusServer:
    host: str = "127.0.0.1"
    port: int = 0
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _latest: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def start(self) -> None:
        if self._server is not None:
            return
        controller = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                latest = controller.latest()
                if self.path == "/healthz":
                    body = json.dumps({"ok": bool(latest.get("ok", False))}, sort_keys=True).encode("utf-8")
                    self._send(200 if latest.get("ok") else 503, body, content_type="application/json")
                    return
                if self.path == "/status":
                    body = json.dumps(latest, indent=2, sort_keys=True).encode("utf-8")
                    self._send(200 if latest.get("ok") else 503, body, content_type="application/json")
                    return
                if self.path == "/metrics":
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


def _load_previous_state(path: Path) -> Mapping[str, Any] | None:
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    return loaded if isinstance(loaded, Mapping) else None


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

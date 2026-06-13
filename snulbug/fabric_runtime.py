from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .state import PolicyStateStore, RedisStateStore, SQLiteStateStore

FABRIC_RUNTIME_STATE_SCHEMA = "snulbug.fabric-runtime-state.v1"
DEFAULT_FABRIC_RUNTIME_STATE = "sqlite:.snulbug/fabric-runtime.sqlite3"
DEFAULT_FABRIC_RUNTIME_STATE_KEY = "snulbug:fabric:runtime"


class FabricRuntimeStateStore(Protocol):
    def load_status(self) -> dict[str, Any] | None: ...

    def save_status(self, status: Mapping[str, Any]) -> None: ...

    def clear(self) -> bool: ...

    def close(self) -> None: ...


class MemoryFabricRuntimeStateStore:
    def __init__(self) -> None:
        self._status: dict[str, Any] | None = None
        self._lock = threading.RLock()

    def load_status(self) -> dict[str, Any] | None:
        with self._lock:
            return None if self._status is None else _attach_share_gate(self._status)

    def save_status(self, status: Mapping[str, Any]) -> None:
        with self._lock:
            self._status = _copy_jsonish(status)

    def clear(self) -> bool:
        with self._lock:
            existed = self._status is not None
            self._status = None
            return existed

    def close(self) -> None:
        return None


class PolicyFabricRuntimeStateStore:
    def __init__(self, store: PolicyStateStore, *, key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY) -> None:
        if not key:
            raise ValueError("fabric runtime state key must not be empty")
        self.store = store
        self.key = key

    def load_status(self) -> dict[str, Any] | None:
        raw = self.store.get(self.key)
        if raw is None:
            return None
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("fabric runtime state is not valid JSON") from exc
        if not isinstance(envelope, Mapping):
            raise ValueError("fabric runtime state must be a JSON object")
        if envelope.get("schema") != FABRIC_RUNTIME_STATE_SCHEMA or envelope.get("version") != 1:
            raise ValueError("fabric runtime state schema is unsupported")
        status = envelope.get("status")
        if not isinstance(status, Mapping):
            raise ValueError("fabric runtime state is missing status")
        return _attach_share_gate(status)

    def save_status(self, status: Mapping[str, Any]) -> None:
        envelope = {
            "schema": FABRIC_RUNTIME_STATE_SCHEMA,
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "status": _copy_jsonish(status),
        }
        self.store.put(self.key, json.dumps(envelope, sort_keys=True, separators=(",", ":")))

    def clear(self) -> bool:
        return self.store.delete(self.key)

    def close(self) -> None:
        close = getattr(self.store, "close", None)
        if callable(close):
            close()


def open_fabric_runtime_state_store(
    spec: str | Path | FabricRuntimeStateStore | None = DEFAULT_FABRIC_RUNTIME_STATE,
    *,
    key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY,
) -> FabricRuntimeStateStore | None:
    if spec is None:
        return None
    if _looks_like_runtime_store(spec):
        return spec
    if isinstance(spec, Path):
        return PolicyFabricRuntimeStateStore(SQLiteStateStore(spec), key=key)

    value = str(spec)
    if value == "none":
        return None
    if value == "memory":
        return MemoryFabricRuntimeStateStore()
    if value.startswith("sqlite:"):
        path = value.removeprefix("sqlite:")
        if not path:
            raise ValueError("sqlite fabric runtime state requires a database path")
        return PolicyFabricRuntimeStateStore(SQLiteStateStore(path), key=key)
    if value.startswith(("redis://", "rediss://")):
        return PolicyFabricRuntimeStateStore(RedisStateStore(value), key=key)
    if value.startswith("redis:"):
        url = value.removeprefix("redis:") or None
        return PolicyFabricRuntimeStateStore(RedisStateStore(url), key=key)
    raise ValueError("runtime_state must be 'memory', 'none', 'sqlite:/path/to/state.sqlite3', or 'redis://...'")


def load_fabric_runtime_status(
    spec: str | Path | FabricRuntimeStateStore | None = DEFAULT_FABRIC_RUNTIME_STATE,
    *,
    key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY,
) -> dict[str, Any]:
    if _sqlite_state_missing(spec):
        return {
            "ok": False,
            "runtime_state": str(spec),
            "runtime_state_key": key,
            "status": None,
            "error": "fabric runtime state is empty",
        }
    store = open_fabric_runtime_state_store(spec, key=key)
    if store is None:
        return {
            "ok": False,
            "runtime_state": "none",
            "runtime_state_key": key,
            "status": None,
            "error": "fabric runtime state is disabled",
        }
    should_close = not _looks_like_runtime_store(spec)
    try:
        status = store.load_status()
        return {
            "ok": status is not None,
            "runtime_state": str(spec),
            "runtime_state_key": key,
            "status": status,
            **({} if status is not None else {"error": "fabric runtime state is empty"}),
        }
    finally:
        if should_close:
            store.close()


def clear_fabric_runtime_status(
    spec: str | Path | FabricRuntimeStateStore | None = DEFAULT_FABRIC_RUNTIME_STATE,
    *,
    key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY,
) -> dict[str, Any]:
    if _sqlite_state_missing(spec):
        return {
            "ok": True,
            "runtime_state": str(spec),
            "runtime_state_key": key,
            "cleared": False,
        }
    store = open_fabric_runtime_state_store(spec, key=key)
    if store is None:
        return {
            "ok": False,
            "runtime_state": "none",
            "runtime_state_key": key,
            "cleared": False,
            "error": "fabric runtime state is disabled",
        }
    should_close = not _looks_like_runtime_store(spec)
    try:
        cleared = store.clear()
        return {
            "ok": True,
            "runtime_state": str(spec),
            "runtime_state_key": key,
            "cleared": cleared,
        }
    finally:
        if should_close:
            store.close()


def format_fabric_runtime_report(result: Mapping[str, Any]) -> str:
    status = _mapping(result.get("status"))
    runtime = _mapping(status.get("runtime"))
    data_plane = _mapping(runtime.get("data_plane"))
    conformance = _mapping(runtime.get("conformance"))
    share_gate = _mapping(status.get("share_gate"))
    lines = [
        "# snulbug fabric runtime",
        "",
        f"Store: {result.get('runtime_state')}",
        f"Key: {result.get('runtime_state_key')}",
        f"Status: {'ok' if result.get('ok') else 'empty'}",
    ]
    if result.get("error"):
        lines.append(f"Error: {result.get('error')}")
    if status:
        lines.extend(
            [
                "",
                "## Runtime",
                f"- data plane: `{data_plane.get('status', 'unknown')}`",
                f"- gateway: `{data_plane.get('gateway_url', '')}`",
                f"- heartbeat: `{data_plane.get('heartbeat_at', data_plane.get('updated_at', 'unknown'))}`",
                f"- share gate: `{'ok' if share_gate.get('ok') else 'blocked'}`",
                f"- conformance: `{conformance.get('status', 'not_configured')}`",
            ]
        )
        blocked_by = share_gate.get("blocked_by")
        if blocked_by:
            lines.append(f"- blocked by: `{', '.join(str(item) for item in blocked_by)}`")
        warnings = share_gate.get("warnings")
        if warnings:
            lines.append(f"- warnings: `{', '.join(str(item) for item in warnings)}`")
    return "\n".join(lines).rstrip()


def _looks_like_runtime_store(value: Any) -> bool:
    return all(callable(getattr(value, name, None)) for name in ("load_status", "save_status", "clear"))


def _sqlite_state_missing(spec: Any) -> bool:
    if spec is None or _looks_like_runtime_store(spec):
        return False
    if isinstance(spec, Path):
        return not spec.exists()
    value = str(spec)
    if not value.startswith("sqlite:"):
        return False
    path = value.removeprefix("sqlite:")
    return bool(path) and not Path(path).exists()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _attach_share_gate(status: Mapping[str, Any]) -> dict[str, Any]:
    latest = _copy_jsonish(status)
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
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return latest


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

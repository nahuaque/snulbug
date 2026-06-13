from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .fabric_control import control_share_gate_signals
from .state import PolicyStateStore, RedisStateStore, SQLiteStateStore

FABRIC_RUNTIME_STATE_SCHEMA = "snulbug.fabric-runtime-state.v1"
FABRIC_RUNTIME_LEASE_SCHEMA = "snulbug.fabric-runtime-lease.v1"
DEFAULT_FABRIC_RUNTIME_STATE = "sqlite:.snulbug/fabric-runtime.sqlite3"
DEFAULT_FABRIC_RUNTIME_STATE_KEY = "snulbug:fabric:runtime"
DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS = 30.0


class FabricRuntimeStateStore(Protocol):
    def load_status(self) -> dict[str, Any] | None: ...

    def save_status(self, status: Mapping[str, Any], *, lease: Mapping[str, Any] | None = None) -> None: ...

    def clear(self) -> bool: ...

    def load_control_state(self) -> dict[str, Any] | None: ...

    def save_control_state(self, state: Mapping[str, Any]) -> None: ...

    def clear_control_state(self) -> bool: ...

    def load_lease(self) -> dict[str, Any] | None: ...

    def acquire_lease(
        self,
        owner_id: str,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def renew_lease(
        self,
        owner_id: str,
        fencing_token: int,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    ) -> dict[str, Any] | None: ...

    def release_lease(self, owner_id: str, fencing_token: int) -> bool: ...

    def close(self) -> None: ...


class MemoryFabricRuntimeStateStore:
    def __init__(self) -> None:
        self._status: dict[str, Any] | None = None
        self._control_state: dict[str, Any] | None = None
        self._lease: dict[str, Any] | None = None
        self._generation = 0
        self._lock = threading.RLock()

    def load_status(self) -> dict[str, Any] | None:
        with self._lock:
            return None if self._status is None else _attach_share_gate(self._status)

    def save_status(self, status: Mapping[str, Any], *, lease: Mapping[str, Any] | None = None) -> None:
        with self._lock:
            if lease is not None and not _lease_matches(self._lease, lease):
                raise RuntimeError("fabric runtime lease no longer owns the status key")
            self._status = _copy_jsonish(status)

    def clear(self) -> bool:
        with self._lock:
            existed = self._status is not None
            self._status = None
            return existed

    def load_control_state(self) -> dict[str, Any] | None:
        with self._lock:
            return None if self._control_state is None else _copy_jsonish(self._control_state)

    def save_control_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            self._control_state = _copy_jsonish(state)

    def clear_control_state(self) -> bool:
        with self._lock:
            existed = self._control_state is not None
            self._control_state = None
            return existed

    def load_lease(self) -> dict[str, Any] | None:
        with self._lock:
            return None if self._lease is None else _copy_jsonish(self._lease)

    def acquire_lease(
        self,
        owner_id: str,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_lease_input(owner_id, ttl_seconds)
        with self._lock:
            current = self._lease
            if _lease_is_active(current):
                if current.get("owner_id") != owner_id:
                    return {
                        "ok": False,
                        "reason": "owned_by_other_instance",
                        "lease": _copy_jsonish(current),
                    }
                renewed = _renewed_lease(current, ttl_seconds=ttl_seconds)
                self._lease = renewed
                return {"ok": True, "lease": _copy_jsonish(renewed), "acquired": False}

            self._generation += 1
            lease = _new_lease(
                owner_id,
                fencing_token=self._generation,
                ttl_seconds=ttl_seconds,
                metadata=metadata,
            )
            self._lease = lease
            return {"ok": True, "lease": _copy_jsonish(lease), "acquired": True}

    def renew_lease(
        self,
        owner_id: str,
        fencing_token: int,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    ) -> dict[str, Any] | None:
        _validate_lease_input(owner_id, ttl_seconds)
        with self._lock:
            if not _lease_matches(self._lease, {"owner_id": owner_id, "fencing_token": fencing_token}):
                return None
            if not _lease_is_active(self._lease):
                return None
            self._lease = _renewed_lease(self._lease, ttl_seconds=ttl_seconds)
            return _copy_jsonish(self._lease)

    def release_lease(self, owner_id: str, fencing_token: int) -> bool:
        with self._lock:
            if not _lease_matches(self._lease, {"owner_id": owner_id, "fencing_token": fencing_token}):
                return False
            self._lease = _released_lease(self._lease)
            return True

    def close(self) -> None:
        return None


class PolicyFabricRuntimeStateStore:
    def __init__(self, store: PolicyStateStore, *, key: str = DEFAULT_FABRIC_RUNTIME_STATE_KEY) -> None:
        if not key:
            raise ValueError("fabric runtime state key must not be empty")
        self.store = store
        self.key = key
        self.lease_key = f"{key}:lease"
        self.generation_key = f"{key}:generation"
        self.control_key = f"{key}:controls"

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

    def save_status(self, status: Mapping[str, Any], *, lease: Mapping[str, Any] | None = None) -> None:
        if lease is not None and not _lease_matches(self.load_lease(), lease):
            raise RuntimeError("fabric runtime lease no longer owns the status key")
        envelope = {
            "schema": FABRIC_RUNTIME_STATE_SCHEMA,
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "status": _copy_jsonish(status),
        }
        self.store.put(self.key, json.dumps(envelope, sort_keys=True, separators=(",", ":")))

    def clear(self) -> bool:
        return self.store.delete(self.key)

    def load_control_state(self) -> dict[str, Any] | None:
        raw = self.store.get(self.control_key)
        if raw is None:
            return None
        try:
            state = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("fabric control state is not valid JSON") from exc
        if not isinstance(state, Mapping):
            raise ValueError("fabric control state must be a JSON object")
        return _copy_jsonish(state)

    def save_control_state(self, state: Mapping[str, Any]) -> None:
        self.store.put(self.control_key, json.dumps(_copy_jsonish(state), sort_keys=True, separators=(",", ":")))

    def clear_control_state(self) -> bool:
        return self.store.delete(self.control_key)

    def load_lease(self) -> dict[str, Any] | None:
        raw = self.store.get(self.lease_key)
        if raw is None:
            return None
        return _decode_lease(raw)

    def acquire_lease(
        self,
        owner_id: str,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_lease_input(owner_id, ttl_seconds)
        for _ in range(8):
            raw = self.store.get(self.lease_key)
            current = _decode_lease(raw) if raw is not None else None
            if _lease_is_active(current):
                if current.get("owner_id") != owner_id:
                    return {
                        "ok": False,
                        "reason": "owned_by_other_instance",
                        "lease": _copy_jsonish(current),
                    }
                lease = _renewed_lease(current, ttl_seconds=ttl_seconds)
                if self.store.cas(self.lease_key, raw, _encode_lease(lease)):
                    return {"ok": True, "lease": _copy_jsonish(lease), "acquired": False}
                continue

            token = self.store.incr(self.generation_key, 1)
            lease = _new_lease(
                owner_id,
                fencing_token=token,
                ttl_seconds=ttl_seconds,
                metadata=metadata,
            )
            if self.store.cas(self.lease_key, raw, _encode_lease(lease)):
                return {"ok": True, "lease": _copy_jsonish(lease), "acquired": True}
        return {"ok": False, "reason": "lease_contended", "lease": self.load_lease()}

    def renew_lease(
        self,
        owner_id: str,
        fencing_token: int,
        *,
        ttl_seconds: float = DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    ) -> dict[str, Any] | None:
        _validate_lease_input(owner_id, ttl_seconds)
        for _ in range(8):
            raw = self.store.get(self.lease_key)
            current = _decode_lease(raw) if raw is not None else None
            if not _lease_matches(current, {"owner_id": owner_id, "fencing_token": fencing_token}):
                return None
            if not _lease_is_active(current):
                return None
            lease = _renewed_lease(current, ttl_seconds=ttl_seconds)
            if self.store.cas(self.lease_key, raw, _encode_lease(lease)):
                return _copy_jsonish(lease)
        return None

    def release_lease(self, owner_id: str, fencing_token: int) -> bool:
        for _ in range(8):
            raw = self.store.get(self.lease_key)
            current = _decode_lease(raw) if raw is not None else None
            if not _lease_matches(current, {"owner_id": owner_id, "fencing_token": fencing_token}):
                return False
            released = _released_lease(current)
            if self.store.cas(self.lease_key, raw, _encode_lease(released)):
                return True
        return False

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
    runtime_owner = _mapping(status.get("runtime_owner"))
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
        if runtime_owner:
            lines.append(
                "- owner: "
                f"`{runtime_owner.get('owner_id')}` "
                f"token=`{runtime_owner.get('fencing_token')}` "
                f"expires=`{runtime_owner.get('expires_at')}`"
            )
        blocked_by = share_gate.get("blocked_by")
        if blocked_by:
            lines.append(f"- blocked by: `{', '.join(str(item) for item in blocked_by)}`")
        warnings = share_gate.get("warnings")
        if warnings:
            lines.append(f"- warnings: `{', '.join(str(item) for item in warnings)}`")
    return "\n".join(lines).rstrip()


def _validate_lease_input(owner_id: str, ttl_seconds: float) -> None:
    if not isinstance(owner_id, str) or not owner_id:
        raise ValueError("fabric runtime owner_id must be a non-empty string")
    if ttl_seconds <= 0:
        raise ValueError("fabric runtime lease ttl must be positive")


def _new_lease(
    owner_id: str,
    *,
    fencing_token: int,
    ttl_seconds: float,
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return _drop_empty(
        {
            "schema": FABRIC_RUNTIME_LEASE_SCHEMA,
            "version": 1,
            "owner_id": owner_id,
            "fencing_token": int(fencing_token),
            "acquired_at": now.isoformat(),
            "heartbeat_at": now.isoformat(),
            "expires_at": _expires_at(now, ttl_seconds),
            "ttl_seconds": float(ttl_seconds),
            "metadata": _copy_jsonish(metadata or {}),
        }
    )


def _renewed_lease(lease: Mapping[str, Any], *, ttl_seconds: float) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return _drop_empty(
        {
            **_copy_jsonish(lease),
            "heartbeat_at": now.isoformat(),
            "expires_at": _expires_at(now, ttl_seconds),
            "ttl_seconds": float(ttl_seconds),
            "released_at": None,
        }
    )


def _released_lease(lease: Mapping[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return _drop_empty(
        {
            **_copy_jsonish(lease),
            "heartbeat_at": now.isoformat(),
            "expires_at": now.isoformat(),
            "released_at": now.isoformat(),
        }
    )


def _expires_at(now: datetime, ttl_seconds: float) -> str:
    return datetime.fromtimestamp(now.timestamp() + ttl_seconds, timezone.utc).isoformat()


def _lease_is_active(lease: Mapping[str, Any] | None) -> bool:
    if not isinstance(lease, Mapping):
        return False
    if lease.get("released_at"):
        return False
    expires_at = lease.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        return False
    parsed = _parse_timestamp(expires_at)
    return parsed is not None and parsed > datetime.now(timezone.utc)


def _lease_matches(current: Mapping[str, Any] | None, expected: Mapping[str, Any]) -> bool:
    if not isinstance(current, Mapping):
        return False
    try:
        current_token = int(current.get("fencing_token", -1))
        expected_token = int(expected.get("fencing_token", -2))
    except (TypeError, ValueError):
        return False
    return current.get("owner_id") == expected.get("owner_id") and current_token == expected_token


def _encode_lease(lease: Mapping[str, Any]) -> str:
    return json.dumps(_copy_jsonish(lease), sort_keys=True, separators=(",", ":"))


def _decode_lease(raw: str) -> dict[str, Any]:
    try:
        lease = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("fabric runtime lease is not valid JSON") from exc
    if not isinstance(lease, Mapping):
        raise ValueError("fabric runtime lease must be a JSON object")
    if lease.get("schema") != FABRIC_RUNTIME_LEASE_SCHEMA or lease.get("version") != 1:
        raise ValueError("fabric runtime lease schema is unsupported")
    return _copy_jsonish(lease)


def _looks_like_runtime_store(value: Any) -> bool:
    return all(
        callable(getattr(value, name, None))
        for name in (
            "load_status",
            "save_status",
            "clear",
            "load_lease",
            "acquire_lease",
            "renew_lease",
            "release_lease",
        )
    )


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


def _runtime_owner_lease_expired(runtime_owner: Mapping[str, Any]) -> bool:
    expires_at = runtime_owner.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        return False
    parsed = _parse_timestamp(expires_at)
    return parsed is not None and parsed <= datetime.now(timezone.utc)


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

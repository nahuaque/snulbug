from __future__ import annotations

import json
import os
import re
import socket
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FABRIC_MEMBER_REGISTRY_SCHEMA = "snulbug.fabric-members.v1"
FABRIC_MEMBER_ROLES = ("data_plane", "control_plane", "observer")
FABRIC_MEMBER_STATUSES = ("active", "draining", "left")
DEFAULT_FABRIC_MEMBER_REGISTRY = ".snulbug/fabric-members.json"
DEFAULT_FABRIC_MEMBER_REGISTRY_KEY = "snulbug:fabric:members"
DEFAULT_FABRIC_MEMBER_TTL_SECONDS = 60.0


def load_fabric_member_registry(
    registry: str | Path | Any = DEFAULT_FABRIC_MEMBER_REGISTRY,
    *,
    key: str = DEFAULT_FABRIC_MEMBER_REGISTRY_KEY,
) -> dict[str, Any]:
    opened = _open_registry_store(registry)
    if opened is not None:
        store, should_close = opened
        try:
            return _decode_registry(store.get(key))
        finally:
            if should_close:
                _close_store(store)

    registry_path = Path(registry)
    if not registry_path.exists():
        return _empty_registry()
    with registry_path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    return _normalize_registry(loaded)


def register_fabric_member(
    registry: str | Path | Any = DEFAULT_FABRIC_MEMBER_REGISTRY,
    *,
    key: str = DEFAULT_FABRIC_MEMBER_REGISTRY_KEY,
    member_id: str,
    role: str = "data_plane",
    upstreams: Sequence[Mapping[str, Any]] = (),
    ttl_seconds: float = DEFAULT_FABRIC_MEMBER_TTL_SECONDS,
    status: str = "active",
    labels: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    safe_member_id = _safe_name(member_id)

    def update(current: dict[str, Any]) -> dict[str, Any]:
        member = _member_record(
            member_id=safe_member_id,
            role=role,
            upstreams=upstreams,
            ttl_seconds=ttl_seconds,
            status=status,
            labels=labels,
            metadata=metadata,
            created_at=_mapping(current["members"].get(safe_member_id)).get("created_at"),
        )
        current["members"][safe_member_id] = member
        current["updated_at"] = _utc_now()
        return {
            "ok": True,
            "member": member,
            "summary": summarize_fabric_members(current),
        }

    return _update_registry(registry, key=key, update=update)


def heartbeat_fabric_member(
    registry: str | Path | Any = DEFAULT_FABRIC_MEMBER_REGISTRY,
    *,
    key: str = DEFAULT_FABRIC_MEMBER_REGISTRY_KEY,
    member_id: str,
    ttl_seconds: float = DEFAULT_FABRIC_MEMBER_TTL_SECONDS,
    status: str = "active",
) -> dict[str, Any]:
    if status not in FABRIC_MEMBER_STATUSES:
        raise ValueError(f"fabric member status must be one of: {', '.join(FABRIC_MEMBER_STATUSES)}")
    safe_member_id = _safe_name(member_id)

    def update(current: dict[str, Any]) -> dict[str, Any]:
        member = _mapping(current["members"].get(safe_member_id))
        if not member:
            return {
                "ok": False,
                "member_id": safe_member_id,
                "error": f"fabric member is not registered: {safe_member_id}",
            }
        now = _utc_now()
        updated = {
            **dict(member),
            "status": status,
            "heartbeat_at": now,
            "ttl_seconds": float(ttl_seconds),
            "expires_at": _expires_at(now, ttl_seconds),
        }
        current["members"][safe_member_id] = updated
        current["updated_at"] = now
        return {
            "ok": True,
            "member": updated,
            "summary": summarize_fabric_members(current),
        }

    return _update_registry(registry, key=key, update=update)


def unregister_fabric_member(
    registry: str | Path | Any = DEFAULT_FABRIC_MEMBER_REGISTRY,
    *,
    key: str = DEFAULT_FABRIC_MEMBER_REGISTRY_KEY,
    member_id: str,
) -> dict[str, Any]:
    safe_member_id = _safe_name(member_id)

    def update(current: dict[str, Any]) -> dict[str, Any]:
        member = _mapping(current["members"].get(safe_member_id))
        if not member:
            return {
                "ok": True,
                "member_id": safe_member_id,
                "unregistered": False,
                "summary": summarize_fabric_members(current),
            }
        now = _utc_now()
        current["members"][safe_member_id] = {
            **dict(member),
            "status": "left",
            "left_at": now,
            "heartbeat_at": now,
            "expires_at": now,
        }
        current["updated_at"] = now
        return {
            "ok": True,
            "member_id": safe_member_id,
            "unregistered": True,
            "summary": summarize_fabric_members(current),
        }

    return _update_registry(registry, key=key, update=update)


def active_fabric_members(
    registry: Mapping[str, Any],
    *,
    roles: Sequence[str] = ("data_plane",),
    statuses: Sequence[str] = ("active",),
    include_expired: bool = False,
) -> list[dict[str, Any]]:
    normalized = _normalize_registry(registry)
    role_set = {str(role).replace("-", "_") for role in roles}
    status_set = {str(status).replace("-", "_") for status in statuses}
    members = []
    for member in _sequence_mappings(normalized.get("members", {}).values()):
        if member.get("role") not in role_set:
            continue
        if member.get("status") not in status_set:
            continue
        if not include_expired and _member_expired(member):
            continue
        members.append(_copy_jsonish(member))
    return sorted(members, key=lambda item: str(item.get("id", "")))


def member_upstreams(
    registry: Mapping[str, Any],
    *,
    roles: Sequence[str] = ("data_plane",),
    statuses: Sequence[str] = ("active",),
    include_expired: bool = False,
    prefix_member_names: bool = True,
) -> list[dict[str, Any]]:
    upstreams = []
    for member in active_fabric_members(registry, roles=roles, statuses=statuses, include_expired=include_expired):
        for upstream in _sequence_mappings(member.get("upstreams")):
            upstreams.append(_member_upstream(member, upstream, prefix_member_names=prefix_member_names))
    return upstreams


def summarize_fabric_members(registry: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_registry(registry)
    members = list(_sequence_mappings(normalized.get("members", {}).values()))
    active = [member for member in members if member.get("status") == "active" and not _member_expired(member)]
    expired = [member for member in members if _member_expired(member)]
    return {
        "member_count": len(members),
        "active_count": len(active),
        "expired_count": len(expired),
        "data_plane_count": sum(1 for member in active if member.get("role") == "data_plane"),
        "upstream_count": sum(len(_sequence_mappings(member.get("upstreams"))) for member in active),
        "roles": _count_by(members, "role"),
        "statuses": _count_by(members, "status"),
    }


def format_fabric_member_report(result: Mapping[str, Any]) -> str:
    summary = _mapping(result.get("summary"))
    registry = _mapping(result.get("registry_state"))
    members = _sequence_mappings(_mapping(registry.get("members")).values())
    lines = [
        "# snulbug fabric members",
        "",
        f"Registry: {result.get('registry')}",
        f"Status: {'ok' if result.get('ok') else 'error'}",
    ]
    if result.get("registry_key"):
        lines.insert(3, f"Registry key: {result.get('registry_key')}")
    if result.get("error"):
        lines.append(f"Error: {result.get('error')}")
    if result.get("member"):
        member = _mapping(result["member"])
        lines.append(f"Member: `{member.get('id')}` role=`{member.get('role')}` status=`{member.get('status')}`")
    if "unregistered" in result:
        lines.append(f"Unregistered: {str(bool(result.get('unregistered'))).lower()}")
    lines.extend(
        [
            "",
            "## Summary",
            f"- members: {summary.get('member_count', 0)}",
            f"- active: {summary.get('active_count', 0)}",
            f"- data planes: {summary.get('data_plane_count', 0)}",
            f"- upstreams: {summary.get('upstream_count', 0)}",
        ]
    )
    if members:
        lines.extend(["", "## Members"])
        for member in sorted(members, key=lambda item: str(item.get("id", ""))):
            lines.append(
                "- "
                f"{member.get('id')} "
                f"role=`{member.get('role')}` "
                f"status=`{member.get('status')}` "
                f"upstreams={len(_sequence_mappings(member.get('upstreams')))} "
                f"expires=`{member.get('expires_at')}`"
            )
    return "\n".join(lines).rstrip()


def _update_registry(
    registry: str | Path | Any,
    *,
    key: str,
    update: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    opened = _open_registry_store(registry)
    if opened is not None:
        store, should_close = opened
        try:
            for _ in range(8):
                raw = store.get(key)
                current = _decode_registry(raw)
                result = update(current)
                if store.cas(key, raw, _encode_registry(current)):
                    return _attach_registry_location(result, registry=registry, key=key, state_backed=True)
            raise RuntimeError("fabric member registry update contended")
        finally:
            if should_close:
                _close_store(store)

    registry_path = Path(registry)
    current = load_fabric_member_registry(registry_path)
    result = update(current)
    _write_registry(registry_path, current)
    return _attach_registry_location(result, registry=registry_path, key=key, state_backed=False)


def _attach_registry_location(
    result: Mapping[str, Any],
    *,
    registry: str | Path | Any,
    key: str,
    state_backed: bool,
) -> dict[str, Any]:
    updated = dict(result)
    updated.setdefault("registry", str(registry))
    if state_backed:
        updated.setdefault("registry_key", key)
    return updated


def _member_record(
    *,
    member_id: str,
    role: str,
    upstreams: Sequence[Mapping[str, Any]],
    ttl_seconds: float,
    status: str,
    labels: Mapping[str, str] | None,
    metadata: Mapping[str, Any] | None,
    created_at: Any,
) -> dict[str, Any]:
    member_id = _safe_name(member_id)
    role = role.replace("-", "_")
    status = status.replace("-", "_")
    if role not in FABRIC_MEMBER_ROLES:
        raise ValueError(f"fabric member role must be one of: {', '.join(FABRIC_MEMBER_ROLES)}")
    if status not in FABRIC_MEMBER_STATUSES:
        raise ValueError(f"fabric member status must be one of: {', '.join(FABRIC_MEMBER_STATUSES)}")
    if ttl_seconds <= 0:
        raise ValueError("fabric member ttl_seconds must be positive")
    normalized_upstreams = [_normalize_upstream(upstream, member_id=member_id) for upstream in upstreams]
    if role == "data_plane" and not normalized_upstreams:
        raise ValueError("data_plane fabric members require at least one upstream")
    now = _utc_now()
    return _drop_empty(
        {
            "id": member_id,
            "role": role,
            "status": status,
            "created_at": created_at or now,
            "heartbeat_at": now,
            "ttl_seconds": float(ttl_seconds),
            "expires_at": _expires_at(now, ttl_seconds),
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "labels": _string_mapping(labels),
            "metadata": _copy_jsonish(metadata or {}),
            "upstreams": normalized_upstreams,
        }
    )


def _member_upstream(
    member: Mapping[str, Any], upstream: Mapping[str, Any], *, prefix_member_names: bool
) -> dict[str, Any]:
    member_id = str(member["id"])
    result = _copy_jsonish(upstream)
    if prefix_member_names:
        result["name"] = _member_prefixed_name(member_id, str(result.get("name") or member_id))
        result["tool_prefix"] = _member_prefixed_tool_prefix(
            member_id, str(result.get("tool_prefix") or f"{result['name']}.")
        )
    return {
        **result,
        "fabric_member_id": member_id,
        "fabric_member_role": member.get("role"),
        "fabric_member_status": member.get("status"),
        "fabric_member_heartbeat_at": member.get("heartbeat_at"),
        "fabric_member_expires_at": member.get("expires_at"),
    }


def _normalize_upstream(upstream: Mapping[str, Any], *, member_id: str) -> dict[str, Any]:
    if not isinstance(upstream, Mapping):
        raise ValueError("fabric member upstreams must be tables")
    name = _safe_name(str(upstream.get("name") or member_id))
    result = {str(key): _copy_jsonish(value) for key, value in upstream.items() if value is not None}
    result["name"] = name
    result.setdefault("tool_prefix", f"{name}.")
    return result


def _empty_registry() -> dict[str, Any]:
    return {
        "schema": FABRIC_MEMBER_REGISTRY_SCHEMA,
        "version": 1,
        "updated_at": None,
        "members": {},
    }


def _normalize_registry(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return _empty_registry()
    if not isinstance(value, Mapping):
        raise ValueError("fabric member registry must be a JSON object")
    if value.get("schema") != FABRIC_MEMBER_REGISTRY_SCHEMA or value.get("version") != 1:
        raise ValueError("fabric member registry schema is unsupported")
    members = value.get("members", {})
    if isinstance(members, list):
        members = {str(_mapping(member).get("id")): member for member in members if _mapping(member).get("id")}
    if not isinstance(members, Mapping):
        raise ValueError("fabric member registry members must be a table")
    normalized_members = {}
    for member_id, member in members.items():
        if not isinstance(member, Mapping):
            continue
        normalized = _normalize_member(member, fallback_id=str(member_id))
        normalized_members[normalized["id"]] = normalized
    return {
        "schema": FABRIC_MEMBER_REGISTRY_SCHEMA,
        "version": 1,
        "updated_at": value.get("updated_at"),
        "members": normalized_members,
    }


def _normalize_member(member: Mapping[str, Any], *, fallback_id: str) -> dict[str, Any]:
    member_id = _safe_name(str(member.get("id") or fallback_id))
    role = str(member.get("role", "data_plane")).replace("-", "_")
    status = str(member.get("status", "active")).replace("-", "_")
    return _drop_empty(
        {
            **_copy_jsonish(member),
            "id": member_id,
            "role": role if role in FABRIC_MEMBER_ROLES else "data_plane",
            "status": status if status in FABRIC_MEMBER_STATUSES else "active",
            "upstreams": [
                _normalize_upstream(upstream, member_id=member_id)
                for upstream in _sequence_mappings(member.get("upstreams"))
            ],
        }
    )


def _write_registry(path: Path, registry: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = _normalize_registry(registry)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _open_registry_store(registry: Any) -> tuple[Any, bool] | None:
    if _looks_like_policy_state_store(registry):
        return registry, False
    if isinstance(registry, Path):
        return None
    value = str(registry)
    if value == "memory":
        from .state import MemoryStateStore

        return MemoryStateStore(), True
    if value.startswith("sqlite:"):
        path = value.removeprefix("sqlite:")
        if not path:
            raise ValueError("sqlite fabric member registry requires a database path")
        from .state import SQLiteStateStore

        return SQLiteStateStore(path), True
    if value.startswith(("redis://", "rediss://")):
        from .state import RedisStateStore

        return RedisStateStore(value), True
    if value.startswith("redis:"):
        url = value.removeprefix("redis:") or None
        from .state import RedisStateStore

        return RedisStateStore(url), True
    return None


def _looks_like_policy_state_store(value: Any) -> bool:
    return all(callable(getattr(value, name, None)) for name in ("get", "put", "delete", "incr", "cas"))


def _decode_registry(raw: str | None) -> dict[str, Any]:
    if raw is None:
        return _empty_registry()
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("fabric member registry state is not valid JSON") from exc
    return _normalize_registry(loaded)


def _encode_registry(registry: Mapping[str, Any]) -> str:
    return json.dumps(_normalize_registry(registry), sort_keys=True, separators=(",", ":"))


def _close_store(store: Any) -> None:
    close = getattr(store, "close", None)
    if callable(close):
        close()


def _member_expired(member: Mapping[str, Any]) -> bool:
    expires_at = member.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at:
        return False
    parsed = _parse_timestamp(expires_at)
    return parsed is not None and parsed <= datetime.now(timezone.utc)


def _expires_at(now: str, ttl_seconds: float) -> str:
    observed = _parse_timestamp(now) or datetime.now(timezone.utc)
    return datetime.fromtimestamp(observed.timestamp() + ttl_seconds, timezone.utc).isoformat()


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _member_prefixed_name(member_id: str, upstream_name: str) -> str:
    prefix = f"{member_id}-"
    return upstream_name if upstream_name.startswith(prefix) else f"{prefix}{upstream_name}"


def _member_prefixed_tool_prefix(member_id: str, tool_prefix: str) -> str:
    prefix = f"{member_id}."
    return tool_prefix if tool_prefix.startswith(prefix) else f"{prefix}{tool_prefix}"


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "member"


def _count_by(items: Sequence[Mapping[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(field, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts


def _string_mapping(value: Mapping[str, str] | None) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _sequence_mappings(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        iterable = value.values()
    elif isinstance(value, Iterable) and not isinstance(value, str | bytes | bytearray):
        iterable = value
    else:
        return []
    return [item for item in iterable if isinstance(item, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

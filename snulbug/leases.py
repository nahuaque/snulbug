from __future__ import annotations

import hashlib
import json
import posixpath
import secrets
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .middleware import Scope

LEASE_HEADER = "x-snulbug-lease"
LEASE_TOKEN_PREFIX = "sbl_"

PATH_KEYS = {
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filenames",
    "directory",
    "directories",
    "dir",
    "cwd",
}
URL_KEYS = {"url", "urls", "uri", "uris", "endpoint", "endpoints", "href"}
COMMAND_KEYS = {"cmd", "command", "commands", "shell", "script"}


@dataclass(frozen=True)
class LeasePolicyConfig:
    """Task-scoped MCP capability lease enforcement."""

    lease_file: Path | None = None
    required: bool = False
    header: str = LEASE_HEADER


def create_lease(
    path: str | Path,
    *,
    task: str,
    allow_tools: Sequence[str],
    allow_paths: Sequence[str] = (),
    allow_hosts: Sequence[str] = (),
    allow_commands: Sequence[str] = (),
    ttl: str | int | float = "1h",
    max_calls: int | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Create a task-scoped lease and return the one-time plaintext token."""

    if not task.strip():
        raise ValueError("task must be non-empty")
    if not allow_tools:
        raise ValueError("at least one --allow-tool is required")
    if max_calls is not None and max_calls <= 0:
        raise ValueError("max_calls must be positive when set")

    lease_token = token or _new_token()
    now = _now()
    lease = {
        "id": f"lease_{secrets.token_urlsafe(9).replace('-', '').replace('_', '')[:12]}",
        "task": task,
        "created_at": _format_time(now),
        "expires_at": _format_time(now + timedelta(seconds=_parse_ttl(ttl))),
        "revoked_at": None,
        "token_hash": _token_hash(lease_token),
        "allow_tools": _dedupe(allow_tools),
        "allow_paths": _dedupe(allow_paths),
        "allow_hosts": _dedupe(host.lower() for host in allow_hosts),
        "allow_commands": _dedupe(allow_commands),
        "max_calls": max_calls,
        "use_count": 0,
        "last_used_at": None,
        "last_tool": None,
    }
    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    store.setdefault("leases", []).append(lease)
    _write_store(store_path, store)
    return {
        "ok": True,
        "lease": _lease_view(lease),
        "token": lease_token,
        "headers": {LEASE_HEADER: lease_token},
        "file": str(store_path),
    }


def list_leases(path: str | Path, *, include_inactive: bool = True) -> dict[str, Any]:
    """List leases without revealing plaintext tokens."""

    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    leases = [_lease_view(lease) for lease in _leases(store)]
    if not include_inactive:
        leases = [lease for lease in leases if lease["active"]]
    return {"ok": True, "file": str(store_path), "leases": leases}


def revoke_lease(path: str | Path, lease_id: str) -> dict[str, Any]:
    """Revoke a lease by id."""

    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    now = _format_time(_now())
    for lease in _leases(store):
        if lease.get("id") == lease_id:
            lease["revoked_at"] = lease.get("revoked_at") or now
            _write_store(store_path, store)
            return {"ok": True, "file": str(store_path), "lease": _lease_view(lease)}
    return {"ok": False, "file": str(store_path), "error": f"lease not found: {lease_id}"}


def enforce_mcp_lease_policy(
    request: Mapping[str, Any] | None,
    scope: Scope,
    *,
    config: LeasePolicyConfig,
) -> tuple[bool, dict[str, Any]]:
    """Validate a tools/call request against a task-scoped lease."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.lease_file is not None,
        "required": config.required,
        "header": config.header.lower(),
        "checked": False,
        "method": method,
    }
    if config.lease_file is None or method != "tools/call":
        return True, metadata

    token = _header_value(scope, config.header)
    if token is None:
        metadata["skipped"] = "missing_header"
        if config.required:
            metadata["reason_code"] = "lease.missing"
            metadata["blocked"] = True
            return False, metadata
        return True, metadata

    metadata["checked"] = True
    try:
        store = _load_store(config.lease_file, create_missing=False)
    except FileNotFoundError:
        metadata["reason_code"] = "lease.store_missing"
        metadata["blocked"] = True
        return False, metadata
    except ValueError as exc:
        metadata["reason_code"] = "lease.store_invalid"
        metadata["error"] = str(exc)
        metadata["blocked"] = True
        return False, metadata

    lease = _find_lease(store, token)
    if lease is None:
        metadata["reason_code"] = "lease.invalid"
        metadata["blocked"] = True
        return False, metadata

    metadata.update(
        {
            "id": lease.get("id"),
            "task": lease.get("task"),
            "expires_at": lease.get("expires_at"),
            "use_count": int(lease.get("use_count") or 0),
            "max_calls": lease.get("max_calls"),
        }
    )
    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    tool = params.get("name")
    if isinstance(tool, str):
        metadata["tool"] = tool

    denied_reason = _lease_denial_reason(lease, request)
    if denied_reason is not None:
        metadata.update(denied_reason)
        metadata["blocked"] = True
        return False, metadata

    _record_lease_use(config.lease_file, store, lease, tool if isinstance(tool, str) else None)
    metadata["allowed"] = True
    metadata["use_count"] = int(lease.get("use_count") or 0)
    metadata["last_used_at"] = lease.get("last_used_at")
    return True, metadata


def preview_mcp_lease_coverage(
    request: Mapping[str, Any] | None,
    path: str | Path,
    *,
    consumption: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Evaluate whether any active lease would cover a tools/call request without mutating lease state."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "checked": False,
        "covered": False,
        "method": method,
        "file": str(path),
    }
    if method != "tools/call" or not isinstance(request, Mapping):
        metadata["skipped"] = "not_tool_call"
        return metadata

    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    tool = params.get("name")
    if isinstance(tool, str):
        metadata["tool"] = tool

    try:
        store = _load_store(Path(path), create_missing=False)
    except FileNotFoundError:
        metadata["reason_code"] = "lease.store_missing"
        return metadata
    except ValueError as exc:
        metadata["reason_code"] = "lease.store_invalid"
        metadata["error"] = str(exc)
        return metadata

    metadata["checked"] = True
    matches = []
    denials = []
    for lease in _leases(store):
        lease_id = str(lease.get("id", ""))
        extra_consumption = consumption.get(lease_id, 0) if consumption is not None else 0
        use_count = int(lease.get("use_count") or 0) + extra_consumption
        denial = _lease_denial_reason(lease, request, use_count=use_count)
        if denial is None:
            matches.append(_lease_view(lease))
        else:
            denials.append({"lease": lease_id or None, **denial})

    if matches:
        metadata["covered"] = True
        metadata["matches"] = matches
        if consumption is not None:
            lease_id = str(matches[0].get("id", ""))
            if lease_id:
                consumption[lease_id] = consumption.get(lease_id, 0) + 1
    else:
        metadata["reason_code"] = _coverage_reason(denials)
        metadata["denials"] = denials[:5]
    return metadata


def mcp_lease_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    reason = metadata.get("reason_code", "lease.rejected")
    tool = metadata.get("tool")
    detail = f" for {tool}" if isinstance(tool, str) else ""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32000,
                "message": f"MCP tool call{detail} rejected by task lease ({reason})",
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "status": 200,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
        "body": body,
    }


def _lease_denial_reason(
    lease: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    use_count: int | None = None,
) -> dict[str, Any] | None:
    now = _now()
    revoked_at = lease.get("revoked_at")
    if revoked_at:
        return {"reason_code": "lease.revoked", "revoked_at": revoked_at}
    expires_at = _parse_time(lease.get("expires_at"))
    if expires_at is None or expires_at <= now:
        return {"reason_code": "lease.expired"}

    max_calls = lease.get("max_calls")
    effective_use_count = int(lease.get("use_count") or 0) if use_count is None else use_count
    if isinstance(max_calls, int) and effective_use_count >= max_calls:
        return {"reason_code": "lease.max_calls_exceeded"}

    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    tool = params.get("name")
    if not isinstance(tool, str) or not _tool_allowed(tool, lease.get("allow_tools", [])):
        return {"reason_code": "lease.tool_not_allowed", "tool": tool}

    arguments = params.get("arguments")
    arguments = arguments if isinstance(arguments, Mapping) else {}

    allow_paths = [str(path) for path in lease.get("allow_paths", []) if str(path)]
    path_values = _collect_keyed_strings(arguments, PATH_KEYS)
    denied_paths = [path for path in path_values if allow_paths and not _path_allowed(path, allow_paths)]
    if denied_paths:
        return {"reason_code": "lease.path_not_allowed", "path": denied_paths[0]}

    allow_hosts = [str(host).lower() for host in lease.get("allow_hosts", []) if str(host)]
    host_values = _collect_hosts(arguments)
    denied_hosts = [host for host in host_values if allow_hosts and host.lower() not in allow_hosts]
    if denied_hosts:
        return {"reason_code": "lease.host_not_allowed", "host": denied_hosts[0]}

    allow_commands = [str(command) for command in lease.get("allow_commands", []) if str(command)]
    command_values = _collect_keyed_strings(arguments, COMMAND_KEYS)
    denied_commands = [
        command
        for command in command_values
        if allow_commands and _command_name(command) not in allow_commands and command not in allow_commands
    ]
    if denied_commands:
        return {"reason_code": "lease.command_not_allowed", "command": denied_commands[0]}

    return None


def _coverage_reason(denials: Sequence[Mapping[str, Any]]) -> str:
    if not denials:
        return "lease.none"
    counts: dict[str, int] = {}
    for denial in denials:
        reason = str(denial.get("reason_code") or "lease.rejected")
        counts[reason] = counts.get(reason, 0) + 1
    return max(counts, key=counts.get)


def _record_lease_use(path: Path, store: dict[str, Any], lease: dict[str, Any], tool: str | None) -> None:
    lease["use_count"] = int(lease.get("use_count") or 0) + 1
    lease["last_used_at"] = _format_time(_now())
    lease["last_tool"] = tool
    _write_store(path, store)


def _load_store(path: Path, *, create_missing: bool) -> dict[str, Any]:
    if not path.exists():
        if create_missing:
            return {"version": 1, "leases": []}
        raise FileNotFoundError(str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid lease file JSON: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ValueError("lease file must contain a JSON object")
    leases = data.get("leases", [])
    if not isinstance(leases, list):
        raise ValueError("lease file field 'leases' must be a list")
    return {"version": int(data.get("version", 1)), "leases": leases}


def _write_store(path: Path, store: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _leases(store: Mapping[str, Any]) -> list[dict[str, Any]]:
    leases = store.get("leases", [])
    return [lease for lease in leases if isinstance(lease, dict)] if isinstance(leases, list) else []


def _find_lease(store: Mapping[str, Any], token: str) -> dict[str, Any] | None:
    digest = _token_hash(token)
    for lease in _leases(store):
        if lease.get("token_hash") == digest:
            return lease
    return None


def _lease_view(lease: Mapping[str, Any]) -> dict[str, Any]:
    expires_at = _parse_time(lease.get("expires_at"))
    active = bool(not lease.get("revoked_at") and expires_at is not None and expires_at > _now())
    return {
        "id": lease.get("id"),
        "task": lease.get("task"),
        "active": active,
        "created_at": lease.get("created_at"),
        "expires_at": lease.get("expires_at"),
        "revoked_at": lease.get("revoked_at"),
        "allow_tools": list(lease.get("allow_tools", [])),
        "allow_paths": list(lease.get("allow_paths", [])),
        "allow_hosts": list(lease.get("allow_hosts", [])),
        "allow_commands": list(lease.get("allow_commands", [])),
        "max_calls": lease.get("max_calls"),
        "use_count": int(lease.get("use_count") or 0),
        "last_used_at": lease.get("last_used_at"),
        "last_tool": lease.get("last_tool"),
    }


def _header_value(scope: Scope, name: str) -> str | None:
    target = name.lower().encode("latin-1")
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() == target:
            value = raw_value.decode("latin-1").strip()
            return value or None
    return None


def _tool_allowed(tool: str, allow_tools: Any) -> bool:
    if not isinstance(allow_tools, Sequence) or isinstance(allow_tools, str | bytes | bytearray):
        return False
    allowed = {str(item) for item in allow_tools}
    return "*" in allowed or tool in allowed


def _collect_keyed_strings(value: Any, keys: set[str], *, key: str | None = None) -> list[str]:
    values: list[str] = []
    normalized_key = key.lower().replace("-", "_") if key is not None else None
    if isinstance(value, str):
        if normalized_key in keys:
            values.append(value)
        return values
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            values.extend(_collect_keyed_strings(child_value, keys, key=str(child_key)))
        return values
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            values.extend(_collect_keyed_strings(item, keys, key=key))
    return values


def _collect_hosts(arguments: Mapping[str, Any]) -> list[str]:
    hosts = []
    for value in _collect_keyed_strings(arguments, URL_KEYS):
        parsed = urlparse(value)
        host = parsed.hostname if parsed.scheme else None
        if host:
            hosts.append(host.lower())
    return hosts


def _path_allowed(value: str, allow_paths: Sequence[str]) -> bool:
    candidate = _normalize_path(value)
    for allowed in allow_paths:
        prefix = _normalize_path(allowed)
        if prefix in {"", "."}:
            if not candidate.startswith("/") and candidate not in {".."} and not candidate.startswith("../"):
                return True
            continue
        if candidate == prefix or candidate.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def _normalize_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    normalized = posixpath.normpath(normalized)
    return "." if normalized == "" else normalized


def _command_name(value: str) -> str:
    try:
        parts = shlex.split(value)
    except ValueError:
        parts = value.split()
    if not parts:
        return ""
    return Path(parts[0]).name


def _parse_ttl(value: str | int | float) -> float:
    if isinstance(value, int | float):
        seconds = float(value)
    else:
        raw = value.strip().lower()
        if not raw:
            raise ValueError("ttl must be non-empty")
        unit = raw[-1]
        amount = raw[:-1] if unit.isalpha() else raw
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 1)
        seconds = float(amount) * multiplier
    if seconds <= 0:
        raise ValueError("ttl must be positive")
    return seconds


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_token() -> str:
    return f"{LEASE_TOKEN_PREFIX}{secrets.token_urlsafe(24)}"


def _token_hash(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _dedupe(values: Sequence[str] | Any) -> list[str]:
    result = []
    seen = set()
    for value in values:
        item = str(value)
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in request:
        return None
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)

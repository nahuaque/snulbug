from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import posixpath
import secrets
import shlex
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

from .middleware import Scope

LEASE_HEADER = "x-snulbug-lease"
LEASE_TOKEN_PREFIX = "sbl_"
LEASE_RENEWAL_METHOD = "snulbug/lease/renew"
LEASE_RENEWAL_HEADER = "x-snulbug-renewal"
TRUSTED_LEASE_SCOPE_KEY = "snulbug.trusted_lease"
_STORE_LOCK = threading.RLock()


@contextmanager
def _store_transaction(path: str | Path) -> Iterator[None]:
    """Serialize read/modify/write across gateway workers and console threads."""

    store_path = Path(path)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with _STORE_LOCK, store_path.with_name(store_path.name + ".lock").open("a+b") as lock:
        if os.name == "nt":  # pragma: no cover - Windows CI
            import msvcrt

            if not lock.seek(0, 2):
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _lease_transaction(function):
    @wraps(function)
    def locked(path, *args, **kwargs):
        with _store_transaction(path):
            return function(path, *args, **kwargs)

    return locked


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


@dataclass(frozen=True)
class TrustedLeaseSelection:
    """An exact lease reference selected by trusted, in-process gateway code."""

    lease_id: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.lease_id, str)
            or not self.lease_id
            or len(self.lease_id) > 256
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in self.lease_id)
        ):
            raise ValueError("lease_id must be a non-empty, bounded lease reference without whitespace")


def select_mcp_lease(scope: Scope, *, lease_id: str) -> Scope:
    """Copy a request scope with a trusted selection; does not authorize or consume it.

    Call only after the hosting gateway authorizes the selection. Never populate
    this context from an unvalidated public header, query parameter, or body.
    """

    selection = TrustedLeaseSelection(lease_id)
    if TRUSTED_LEASE_SCOPE_KEY in scope and scope[TRUSTED_LEASE_SCOPE_KEY] != selection:
        raise ValueError("request already has a different or invalid trusted lease selection")
    return {**scope, TRUSTED_LEASE_SCOPE_KEY: selection}


@_lease_transaction
def create_lease(
    path: str | Path,
    *,
    task: str,
    allow_tools: Sequence[str],
    capabilities: Sequence[str] = (),
    allow_paths: Sequence[str] = (),
    allow_hosts: Sequence[str] = (),
    allow_commands: Sequence[str] = (),
    allow_subjects: Sequence[str] = (),
    allow_issuers: Sequence[str] = (),
    allow_tenants: Sequence[str] = (),
    allow_client_ids: Sequence[str] = (),
    allow_groups: Sequence[str] = (),
    allow_auth_profiles: Sequence[str] = (),
    ttl: str | int | float = "1h",
    max_calls: int | None = None,
    token: str | None = None,
    invite: Mapping[str, Any] | None = None,
    renewal_ttl: str | int | float | None = None,
    renewal_token: str | None = None,
    renewal_bearer: str | None = None,
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
        "capabilities": _dedupe(capabilities),
        "allow_tools": _dedupe(allow_tools),
        "allow_paths": _dedupe(allow_paths),
        "allow_hosts": _dedupe(host.lower() for host in allow_hosts),
        "allow_commands": _dedupe(allow_commands),
        "allow_subjects": _dedupe(allow_subjects),
        "allow_issuers": _dedupe(allow_issuers),
        "allow_tenants": _dedupe(allow_tenants),
        "allow_client_ids": _dedupe(allow_client_ids),
        "allow_groups": _dedupe(allow_groups),
        "allow_auth_profiles": _dedupe(allow_auth_profiles),
        "max_calls": max_calls,
        "use_count": 0,
        "last_used_at": None,
        "last_tool": None,
    }
    invite_metadata = _lease_invite_metadata(invite)
    if invite_metadata:
        lease["invite"] = invite_metadata
    if renewal_ttl is not None:
        if not invite_metadata.get("id"):
            raise ValueError("renewable leases must belong to a share invite")
        lease_seconds = _parse_ttl(ttl)
        authorization_seconds = _parse_ttl(renewal_ttl)
        if not math.isfinite(lease_seconds) or not math.isfinite(authorization_seconds):
            raise ValueError("renewal and lease TTL must be finite")
        if authorization_seconds < lease_seconds:
            raise ValueError("renewal authorization TTL must be at least the lease TTL")
        if not renewal_bearer and not (allow_issuers and (allow_subjects or allow_client_ids)):
            raise ValueError("renewal requires bearer authentication or an issuer-bound subject/client identity")
        renewal_token = renewal_token or "sbr_" + secrets.token_urlsafe(32)
        lease_token = lease_token_for_renewal(renewal_token, lease["id"], 0)
        lease["token_hash"] = _token_hash(lease_token)
        lease["renewal"] = {
            "authorization_expires_at": _format_time(now + timedelta(seconds=authorization_seconds)),
            "lease_ttl_seconds": lease_seconds,
            "token_hash": _token_hash(renewal_token),
            "bearer_hash": _token_hash(renewal_bearer) if renewal_bearer else None,
            "generation": 0,
            "renewal_count": 0,
            "last_renewed_at": None,
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
        **({"renewal_token": renewal_token} if renewal_ttl is not None else {}),
    }


def list_leases(path: str | Path, *, include_inactive: bool = True) -> dict[str, Any]:
    """List leases without revealing plaintext tokens."""

    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    leases = [_lease_view(lease) for lease in _leases(store)]
    if not include_inactive:
        leases = [lease for lease in leases if lease["active"]]
    return {"ok": True, "file": str(store_path), "leases": leases}


@_lease_transaction
def cleanup_inactive_leases(path: str | Path) -> dict[str, Any]:
    """Remove revoked or expired leases from a lease store."""

    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    leases = list(_leases(store))
    kept = [lease for lease in leases if _lease_view(lease)["active"] or _renewal_view(lease).get("active")]
    removed = [lease for lease in leases if lease not in kept]
    store["leases"] = kept
    _write_store(store_path, store)
    return {
        "ok": True,
        "file": str(store_path),
        "removed_count": len(removed),
        "active_count": sum(bool(_lease_view(lease)["active"]) for lease in kept),
        "retained_renewable_count": sum(not _lease_view(lease)["active"] for lease in kept),
        "leases": [_lease_view(lease) for lease in kept],
    }


@_lease_transaction
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


@_lease_transaction
def revoke_invite_renewal(path: str | Path, invite_id: str) -> None:
    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    for lease in _leases(store):
        if lease.get("invite", {}).get("id") == invite_id and isinstance(lease.get("renewal"), dict):
            lease["renewal"]["revoked_at"] = lease["renewal"].get("revoked_at") or _format_time(_now())
            _write_store(store_path, store)


@_lease_transaction
def reactivate_lease(
    path: str | Path,
    lease_id: str,
    *,
    ttl: str | int | float = "1h",
    max_calls: int | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Reactivate an existing lease id with a fresh token and expiry."""

    if max_calls is not None and max_calls <= 0:
        raise ValueError("max_calls must be positive when set")
    store_path = Path(path)
    store = _load_store(store_path, create_missing=True)
    lease_token = token or _new_token()
    now = _now()
    for lease in _leases(store):
        if lease.get("id") == lease_id:
            if lease.get("renewal"):
                raise ValueError("create a new automation invite instead of reactivating a renewable lease")
            lease["revoked_at"] = None
            lease["expires_at"] = _format_time(now + timedelta(seconds=_parse_ttl(ttl)))
            lease["reactivated_at"] = _format_time(now)
            lease["token_hash"] = _token_hash(lease_token)
            lease["use_count"] = 0
            lease["last_used_at"] = None
            lease["last_tool"] = None
            if max_calls is not None:
                lease["max_calls"] = max_calls
            _write_store(store_path, store)
            return {
                "ok": True,
                "file": str(store_path),
                "lease": _lease_view(lease),
                "token": lease_token,
                "headers": {LEASE_HEADER: lease_token},
            }
    return {"ok": False, "file": str(store_path), "error": f"lease not found: {lease_id}"}


def lease_token_for_renewal(renewal_token: str, lease_id: str, generation: int) -> str:
    """Recover the current access token without persisting plaintext in the lease store."""

    payload = f"snulbug.lease.v1:{lease_id}:{generation}".encode()
    return LEASE_TOKEN_PREFIX + hmac.new(renewal_token.encode(), payload, hashlib.sha256).hexdigest()


@_lease_transaction
def renew_lease(
    path: str | Path,
    *,
    invite_id: str,
    renewal_token: str,
    bearer: str | None = None,
    auth_context: Mapping[str, Any] | None = None,
    policy_capabilities: Sequence[str] | Callable[[], Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Renew or recover an invite's existing lease, never its permissions or budget."""

    def denied(reason: str) -> dict[str, Any]:
        return {"ok": False, "reason_code": reason}

    store = _load_store(Path(path), create_missing=False)
    lease = next((item for item in _leases(store) if item.get("invite", {}).get("id") == invite_id), None)
    renewal = lease.get("renewal") if lease else None
    if (
        not isinstance(renewal, dict)
        or not renewal_token
        or not hmac.compare_digest(str(renewal.get("token_hash") or ""), _token_hash(renewal_token))
    ):
        return denied("lease.renewal_invalid")
    if lease.get("revoked_at") or renewal.get("revoked_at"):
        return denied("lease.revoked")
    now = _now()
    until = _parse_time(renewal.get("authorization_expires_at"))
    if until is None or until <= now:
        return denied("lease.renewal_expired")
    auth = auth_context or {}
    if renewal.get("bearer_hash") and auth.get("enabled") is not True:
        if not bearer or not hmac.compare_digest(str(renewal["bearer_hash"]), _token_hash(bearer)):
            return denied("lease.renewal_auth_required")
    elif auth.get("enabled") is not True:
        return denied("lease.auth_missing")
    auth_denial = _lease_auth_denial_reason(lease, auth)
    if auth_denial:
        return denied(str(auth_denial["reason_code"]))
    if callable(policy_capabilities):
        policy_capabilities = policy_capabilities()
    if policy_capabilities is not None and not set(lease.get("capabilities", [])).issubset(policy_capabilities):
        return denied("lease.renewal_capability_removed")
    if isinstance(lease.get("max_calls"), int) and int(lease.get("use_count") or 0) >= lease["max_calls"]:
        return denied("lease.max_calls_exceeded")

    expires = _parse_time(lease.get("expires_at"))
    seconds = float(renewal["lease_ttl_seconds"])
    # Retrying/restarting inside a healthy lease window returns the same token.
    # A short overlap lets in-flight requests finish when the next window opens.
    next_expiry = min(until, now + timedelta(seconds=seconds))
    changed = expires is None or ((expires - now).total_seconds() <= seconds / 2 and next_expiry > expires)
    if changed:
        if expires is not None and expires > now:
            renewal["previous_token_hash"] = lease["token_hash"]
            renewal["previous_token_expires_at"] = _format_time(min(expires, now + timedelta(seconds=30)))
        else:
            renewal.pop("previous_token_hash", None)
            renewal.pop("previous_token_expires_at", None)
        renewal["generation"] = int(renewal.get("generation") or 0) + 1
        renewal["renewal_count"] = int(renewal.get("renewal_count") or 0) + 1
        renewal["last_renewed_at"] = _format_time(now)
        lease["expires_at"] = _format_time(next_expiry)
        token = lease_token_for_renewal(renewal_token, str(lease["id"]), renewal["generation"])
        lease["token_hash"] = _token_hash(token)
        _write_store(Path(path), store)
    token = lease_token_for_renewal(renewal_token, str(lease["id"]), int(renewal.get("generation") or 0))
    return {
        "ok": True,
        "reason_code": "lease.renewed" if changed else "lease.recovered",
        "lease": _lease_view(lease),
        "token": token,
    }


def enforce_mcp_lease_policy(
    request: Mapping[str, Any] | None,
    scope: Scope,
    *,
    config: LeasePolicyConfig,
) -> tuple[bool, dict[str, Any]]:
    """Validate a tools/call request against a task-scoped lease."""

    return _evaluate_mcp_lease_policy(request, scope, config=config, consume=True)


def preview_mcp_lease_policy(
    request: Mapping[str, Any] | None,
    scope: Scope,
    *,
    config: LeasePolicyConfig,
) -> tuple[bool, dict[str, Any]]:
    """Validate a presented task lease without consuming a lease use."""

    return _evaluate_mcp_lease_policy(request, scope, config=config, consume=False)


def preview_mcp_lease_catalog(
    scope: Scope,
    *,
    config: LeasePolicyConfig,
) -> dict[str, Any]:
    """Validate a presented task lease for catalog projection without consuming it."""

    auth_context = _scope_auth_context(scope)
    metadata: dict[str, Any] = {
        "enabled": config.lease_file is not None,
        "required": config.required,
        "header": config.header.lower(),
        "checked": False,
        "catalog_checked": False,
        "method": "tools/list",
        "consume": False,
    }
    if config.lease_file is None:
        return metadata

    _store, lease = _resolve_presented_lease(scope, config=config, metadata=metadata)
    metadata["catalog_checked"] = metadata["checked"]
    if lease is None:
        if config.required and not metadata.get("blocked"):
            metadata["reason_code"] = "lease.missing"
            metadata["blocked"] = True
        if metadata.get("blocked"):
            metadata["allowed"] = False
        return metadata

    invite_metadata = _lease_invite_metadata(lease.get("invite"))
    metadata.update(
        {
            "id": lease.get("id"),
            "task": lease.get("task"),
            "expires_at": lease.get("expires_at"),
            "use_count": int(lease.get("use_count") or 0),
            "max_calls": lease.get("max_calls"),
            **({"invite": invite_metadata} if invite_metadata else {}),
            "capabilities": list(lease.get("capabilities", [])),
            "allow_tools": list(lease.get("allow_tools", [])),
            **_lease_auth_metadata(lease, auth_context),
        }
    )
    denied_reason = _lease_catalog_denial_reason(lease, auth_context=auth_context)
    if denied_reason is not None:
        metadata.update(denied_reason)
        metadata["blocked"] = True
        metadata["allowed"] = False
        return metadata

    metadata["allowed"] = True
    metadata["last_used_at"] = lease.get("last_used_at")
    return metadata


def _evaluate_mcp_lease_policy(
    request: Mapping[str, Any] | None,
    scope: Scope,
    *,
    config: LeasePolicyConfig,
    consume: bool,
) -> tuple[bool, dict[str, Any]]:
    if consume and config.lease_file is not None:
        with _store_transaction(config.lease_file):
            return _evaluate_locked_lease_policy(request, scope, config=config, consume=consume)
    return _evaluate_locked_lease_policy(request, scope, config=config, consume=consume)


def _evaluate_locked_lease_policy(
    request: Mapping[str, Any] | None,
    scope: Scope,
    *,
    config: LeasePolicyConfig,
    consume: bool,
) -> tuple[bool, dict[str, Any]]:
    method = request.get("method") if isinstance(request, Mapping) else None
    auth_context = _scope_auth_context(scope)
    metadata: dict[str, Any] = {
        "enabled": config.lease_file is not None,
        "required": config.required,
        "header": config.header.lower(),
        "checked": False,
        "method": method,
        "consume": consume,
    }
    if config.lease_file is None:
        return True, metadata

    store, lease = _resolve_presented_lease(scope, config=config, metadata=metadata)
    if lease is None:
        if config.required and method == "tools/call" and not metadata.get("blocked"):
            metadata["reason_code"] = "lease.missing"
            metadata["blocked"] = True
        return not metadata.get("blocked", False), metadata

    invite_metadata = _lease_invite_metadata(lease.get("invite"))
    metadata.update(
        {
            "id": lease.get("id"),
            "task": lease.get("task"),
            "expires_at": lease.get("expires_at"),
            "use_count": int(lease.get("use_count") or 0),
            "max_calls": lease.get("max_calls"),
            **({"invite": invite_metadata} if invite_metadata else {}),
            "capabilities": list(lease.get("capabilities", [])),
            **_lease_auth_metadata(lease, auth_context),
        }
    )
    params = request.get("params") if isinstance(request, Mapping) else None
    params = params if isinstance(params, Mapping) else {}
    tool = params.get("name")
    if isinstance(tool, str):
        metadata["tool"] = tool

    if method == "tools/call":
        denied_reason = _lease_denial_reason(lease, request, auth_context=auth_context)
    else:
        denied_reason = _lease_catalog_denial_reason(lease, auth_context=auth_context)
    if denied_reason is not None:
        metadata.update(denied_reason)
        metadata["blocked"] = True
        return False, metadata

    if consume and method == "tools/call":
        _record_lease_use(config.lease_file, store, lease, tool if isinstance(tool, str) else None)
    metadata["allowed"] = True
    metadata["use_count"] = int(lease.get("use_count") or 0)
    metadata["last_used_at"] = lease.get("last_used_at")
    return True, metadata


def _resolve_presented_lease(
    scope: Scope,
    *,
    config: LeasePolicyConfig,
    metadata: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve references inside the caller's existing consumption transaction."""

    trusted = scope.get(TRUSTED_LEASE_SCOPE_KEY)
    target = config.header.lower().encode("latin-1")
    values = [value.decode("latin-1").strip() for name, value in scope.get("headers", []) if name.lower() == target]
    reason = None
    if TRUSTED_LEASE_SCOPE_KEY in scope and not isinstance(trusted, TrustedLeaseSelection):
        reason = "lease.selection_invalid"
    elif len(values) > 1:
        reason = "lease.selection_conflict"
    elif values and not values[0]:
        reason = "lease.invalid"
    elif not values and trusted is None:
        metadata["skipped"] = "missing_header"
        return None, None
    metadata["checked"] = True
    metadata["selection"] = "trusted" if trusted is not None else "header"
    store = None
    lease = None
    if reason is None:
        try:
            store = _load_store(config.lease_file, create_missing=False)
        except FileNotFoundError:
            reason = "lease.store_missing"
        except ValueError as exc:
            reason = "lease.store_invalid"
            metadata["error"] = str(exc)
        else:
            if trusted is not None:
                matches = [item for item in _leases(store) if item.get("id") == trusted.lease_id]
                lease = matches[0] if len(matches) == 1 else None
            else:
                lease = _find_lease(store, values[0])
            if lease is None:
                reason = "lease.invalid"
            elif trusted is not None and values and _find_lease(store, values[0]) is not lease:
                reason = "lease.selection_conflict"
    if reason is not None:
        metadata.update(reason_code=reason, blocked=True)
        return None, None
    return store, lease


def preview_mcp_lease_coverage(
    request: Mapping[str, Any] | None,
    path: str | Path,
    *,
    consumption: dict[str, int] | None = None,
    auth_context: Mapping[str, Any] | None = None,
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
        denial = _lease_denial_reason(lease, request, use_count=use_count, auth_context=auth_context)
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
    auth_context: Mapping[str, Any] | None = None,
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

    auth_denial = _lease_auth_denial_reason(lease, auth_context)
    if auth_denial is not None:
        return auth_denial

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


def _lease_catalog_denial_reason(
    lease: Mapping[str, Any],
    *,
    auth_context: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    now = _now()
    revoked_at = lease.get("revoked_at")
    if revoked_at:
        return {"reason_code": "lease.revoked", "revoked_at": revoked_at}
    expires_at = _parse_time(lease.get("expires_at"))
    if expires_at is None or expires_at <= now:
        return {"reason_code": "lease.expired"}

    max_calls = lease.get("max_calls")
    if isinstance(max_calls, int) and int(lease.get("use_count") or 0) >= max_calls:
        return {"reason_code": "lease.max_calls_exceeded"}

    return _lease_auth_denial_reason(lease, auth_context)


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
    tmp.chmod(0o600)
    tmp.replace(path)


def _leases(store: Mapping[str, Any]) -> list[dict[str, Any]]:
    leases = store.get("leases", [])
    return [lease for lease in leases if isinstance(lease, dict)] if isinstance(leases, list) else []


def _find_lease(store: Mapping[str, Any], token: str) -> dict[str, Any] | None:
    digest = _token_hash(token)
    for lease in _leases(store):
        if hmac.compare_digest(str(lease.get("token_hash") or ""), digest):
            return lease
        renewal = lease.get("renewal", {})
        previous_until = _parse_time(renewal.get("previous_token_expires_at"))
        if (
            previous_until is not None
            and previous_until > _now()
            and hmac.compare_digest(str(renewal.get("previous_token_hash") or ""), digest)
        ):
            return lease
    return None


def _lease_view(lease: Mapping[str, Any]) -> dict[str, Any]:
    expires_at = _parse_time(lease.get("expires_at"))
    active = bool(not lease.get("revoked_at") and expires_at is not None and expires_at > _now())
    invite_metadata = _lease_invite_metadata(lease.get("invite"))
    return {
        "id": lease.get("id"),
        "task": lease.get("task"),
        "active": active,
        "created_at": lease.get("created_at"),
        "expires_at": lease.get("expires_at"),
        "revoked_at": lease.get("revoked_at"),
        "capabilities": list(lease.get("capabilities", [])),
        "allow_tools": list(lease.get("allow_tools", [])),
        "allow_paths": list(lease.get("allow_paths", [])),
        "allow_hosts": list(lease.get("allow_hosts", [])),
        "allow_commands": list(lease.get("allow_commands", [])),
        "allow_subjects": list(lease.get("allow_subjects", [])),
        "allow_issuers": list(lease.get("allow_issuers", [])),
        "allow_tenants": list(lease.get("allow_tenants", [])),
        "allow_client_ids": list(lease.get("allow_client_ids", [])),
        "allow_groups": list(lease.get("allow_groups", [])),
        "allow_auth_profiles": list(lease.get("allow_auth_profiles", [])),
        "auth_bound": _lease_auth_bound(lease),
        **({"invite": invite_metadata} if invite_metadata else {}),
        "max_calls": lease.get("max_calls"),
        "use_count": int(lease.get("use_count") or 0),
        "last_used_at": lease.get("last_used_at"),
        "last_tool": lease.get("last_tool"),
        **({"renewal": _renewal_view(lease)} if lease.get("renewal") else {}),
    }


def _renewal_view(lease: Mapping[str, Any]) -> dict[str, Any]:
    renewal = lease.get("renewal")
    if not isinstance(renewal, Mapping):
        return {}
    until = _parse_time(renewal.get("authorization_expires_at"))
    expires = _parse_time(lease.get("expires_at"))
    ttl = float(renewal.get("lease_ttl_seconds") or 0)
    return {
        "active": bool(
            not lease.get("revoked_at") and not renewal.get("revoked_at") and until is not None and until > _now()
        ),
        "revoked_at": renewal.get("revoked_at"),
        "authorization_expires_at": renewal.get("authorization_expires_at"),
        "lease_ttl_seconds": ttl,
        "generation": int(renewal.get("generation") or 0),
        "renewal_count": int(renewal.get("renewal_count") or 0),
        "last_renewed_at": renewal.get("last_renewed_at"),
        "renew_after": _format_time(expires if expires == until else expires - timedelta(seconds=ttl / 2))
        if expires
        else None,
    }


def _lease_auth_bound(lease: Mapping[str, Any]) -> bool:
    return any(
        _string_list(lease.get(field))
        for field in (
            "allow_subjects",
            "allow_issuers",
            "allow_tenants",
            "allow_client_ids",
            "allow_groups",
            "allow_auth_profiles",
        )
    )


def _lease_auth_metadata(lease: Mapping[str, Any], auth_context: Mapping[str, Any] | None) -> dict[str, Any]:
    bound = _lease_auth_bound(lease)
    metadata: dict[str, Any] = {"auth_bound": bound}
    if not bound:
        return metadata
    auth = auth_context if isinstance(auth_context, Mapping) else {}
    return {
        **metadata,
        "auth": _drop_empty(
            {
                "subject": auth.get("subject"),
                "issuer": auth.get("issuer"),
                "tenant": auth.get("tenant"),
                "client_id": auth.get("client_id"),
                "groups": _string_list(auth.get("groups")),
                "profile_id": auth.get("profile_id"),
            }
        ),
    }


def _lease_invite_metadata(value: Any) -> dict[str, Any]:
    invite = value if isinstance(value, Mapping) else {}
    return _drop_empty(
        {
            "id": invite.get("id"),
            "recipient": invite.get("recipient"),
            "client_name": invite.get("client_name"),
            "capabilities": _string_list(invite.get("capabilities")),
        }
    )


def _lease_auth_denial_reason(
    lease: Mapping[str, Any],
    auth_context: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not _lease_auth_bound(lease):
        return None
    auth = auth_context if isinstance(auth_context, Mapping) else {}
    if not auth or auth.get("enabled") is not True:
        return {"reason_code": "lease.auth_missing", "auth_bound": True}

    subjects = _string_list(lease.get("allow_subjects"))
    if subjects and str(auth.get("subject") or "") not in subjects:
        return {
            "reason_code": "lease.subject_not_allowed",
            "auth_bound": True,
            "auth_subject": auth.get("subject"),
        }

    issuers = _string_list(lease.get("allow_issuers"))
    if issuers and str(auth.get("issuer") or "") not in issuers:
        return {
            "reason_code": "lease.issuer_not_allowed",
            "auth_bound": True,
            "auth_issuer": auth.get("issuer"),
        }

    tenants = _string_list(lease.get("allow_tenants"))
    if tenants and str(auth.get("tenant") or "") not in tenants:
        return {
            "reason_code": "lease.tenant_not_allowed",
            "auth_bound": True,
            "auth_tenant": auth.get("tenant"),
        }

    client_ids = _string_list(lease.get("allow_client_ids"))
    if client_ids and str(auth.get("client_id") or "") not in client_ids:
        return {
            "reason_code": "lease.client_id_not_allowed",
            "auth_bound": True,
            "auth_client_id": auth.get("client_id"),
        }

    groups = _string_list(lease.get("allow_groups"))
    if groups:
        auth_groups = set(_string_list(auth.get("groups")))
        if not auth_groups.intersection(groups):
            return {
                "reason_code": "lease.group_not_allowed",
                "auth_bound": True,
                "auth_groups": sorted(auth_groups),
            }

    profiles = _string_list(lease.get("allow_auth_profiles"))
    if profiles and str(auth.get("profile_id") or "") not in profiles:
        return {
            "reason_code": "lease.auth_profile_not_allowed",
            "auth_bound": True,
            "auth_profile_id": auth.get("profile_id"),
        }

    return None


def _scope_auth_context(scope: Scope) -> Mapping[str, Any] | None:
    state = scope.get("state")
    proxy_metadata = state.get("snulbug_proxy") if isinstance(state, Mapping) else {}
    if isinstance(proxy_metadata, Mapping) and isinstance(proxy_metadata.get("auth"), Mapping):
        return proxy_metadata["auth"]

    lua_context = scope.get("lua")
    if isinstance(lua_context, Mapping) and isinstance(lua_context.get("auth"), Mapping):
        return lua_context["auth"]
    return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item) for item in value if str(item)]
    return []


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, [], {}, "")}


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

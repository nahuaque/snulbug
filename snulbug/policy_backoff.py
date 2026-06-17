from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .state import PolicyStateStore

DEFAULT_POLICY_BACKOFF_REASON_CODES = ("mcp.*", "oauth.scope_map_denied", "lease.tool_not_allowed")
DEFAULT_POLICY_BACKOFF_EXCLUDE_REASON_CODES = ("oauth.invalid_token", "cloudflare_access.*")
DEFAULT_POLICY_BACKOFF_KEY_FIELDS = (
    "auth.subject",
    "auth.client_id",
    "auth.tenant",
    "lease.id",
    "mcp.method",
    "mcp.tool",
    "mcp.target",
    "upstream.name",
    "decision.reason_code",
)


@dataclass(frozen=True)
class PolicyBackoffConfig:
    """Exponential backoff for repeated Lua policy denies."""

    enabled: bool = False
    base_seconds: float = 2.0
    factor: float = 2.0
    max_seconds: float = 60.0
    window_seconds: float = 300.0
    jitter: bool = True
    status: int = 429
    reason_codes: tuple[str, ...] = DEFAULT_POLICY_BACKOFF_REASON_CODES
    exclude_reason_codes: tuple[str, ...] = DEFAULT_POLICY_BACKOFF_EXCLUDE_REASON_CODES
    key_fields: tuple[str, ...] = DEFAULT_POLICY_BACKOFF_KEY_FIELDS

    def __post_init__(self) -> None:
        if self.base_seconds <= 0:
            raise ValueError("policy backoff base_seconds must be positive")
        if self.factor < 1:
            raise ValueError("policy backoff factor must be at least 1")
        if self.max_seconds <= 0:
            raise ValueError("policy backoff max_seconds must be positive")
        if self.window_seconds <= 0:
            raise ValueError("policy backoff window_seconds must be positive")
        if self.status < 400 or self.status > 599:
            raise ValueError("policy backoff status must be an HTTP error status")
        if not self.reason_codes:
            raise ValueError("policy backoff reason_codes must not be empty")
        if not self.key_fields:
            raise ValueError("policy backoff key_fields must not be empty")


class PolicyDenyBackoff:
    """State-backed exponential backoff for equivalent policy denies."""

    def __init__(
        self,
        config: PolicyBackoffConfig | None = None,
        *,
        store: PolicyStateStore | None = None,
        key_prefix: str = "",
    ) -> None:
        self.config = config or PolicyBackoffConfig()
        self.store = store
        self.key_prefix = key_prefix

    def preflight(self, request: Mapping[str, Any], scope: Mapping[str, Any]) -> dict[str, Any]:
        if not self.config.enabled:
            return {"enabled": False, "active": False}
        if self.store is None:
            return {"enabled": True, "active": False, "skipped": "state_store_missing"}
        lookup_key, lookup_parts = self._lookup_key(request, scope)
        encoded = self.store.get(lookup_key)
        if not encoded:
            return {"enabled": True, "active": False, "lookup_key": lookup_key, "key_parts": lookup_parts}
        record = _decode_record(encoded)
        now = time.time()
        cooldown_until = _float_value(record.get("cooldown_until"))
        if cooldown_until is None or cooldown_until <= now:
            return {
                "enabled": True,
                "active": False,
                "lookup_key": lookup_key,
                "key_parts": lookup_parts,
                "last_count": int(record.get("count") or 0),
                "last_reason_code": record.get("reason_code"),
            }
        retry_after = max(1, math.ceil(cooldown_until - now))
        return {
            **_metadata_from_record(record),
            "enabled": True,
            "active": True,
            "reason_code": "policy.backoff_active",
            "lookup_key": lookup_key,
            "key_parts": lookup_parts,
            "retry_after": retry_after,
            "status": self.config.status,
        }

    def record_deny(
        self,
        request: Mapping[str, Any],
        scope: Mapping[str, Any],
        decision: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not self.config.enabled:
            return {"enabled": False, "recorded": False}
        if self.store is None:
            return {"enabled": True, "recorded": False, "skipped": "state_store_missing"}
        action = str(decision.get("action") or "")
        if action not in {"reject", "challenge"}:
            return {"enabled": True, "recorded": False, "skipped": "action_not_denied", "action": action}
        reason_code = str(decision.get("reason_code") or "unknown")
        if not _matches_any(reason_code, self.config.reason_codes) or _matches_any(
            reason_code, self.config.exclude_reason_codes
        ):
            return {
                "enabled": True,
                "recorded": False,
                "skipped": "reason_code_not_selected",
                "reason_code": reason_code,
            }

        lookup_key, lookup_parts = self._lookup_key(request, scope)
        deny_key, deny_parts = self._deny_key(request, scope, decision)
        now = time.time()
        previous = _decode_record(self.store.get(deny_key))
        count = int(previous.get("count") or 0) + 1
        delay = self._delay_seconds(count, deny_key)
        cooldown_until = now + delay
        record = {
            "version": 1,
            "count": count,
            "reason_code": reason_code,
            "action": action,
            "delay_seconds": delay,
            "retry_after": max(1, math.ceil(delay)),
            "cooldown_until": cooldown_until,
            "created_at": previous.get("created_at") or now,
            "updated_at": now,
            "lookup_key": lookup_key,
            "deny_key": deny_key,
            "key_parts": deny_parts,
        }
        ttl = max(self.config.window_seconds, delay)
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        self.store.put(deny_key, encoded, ttl=ttl)
        self.store.put(lookup_key, encoded, ttl=ttl)
        return {
            **_metadata_from_record(record),
            "enabled": True,
            "recorded": True,
            "active": False,
            "lookup_key": lookup_key,
            "deny_key": deny_key,
            "lookup_parts": lookup_parts,
        }

    def _delay_seconds(self, count: int, key: str) -> float:
        exponent = max(0, count - 1)
        delay = min(self.config.max_seconds, self.config.base_seconds * (self.config.factor**exponent))
        if not self.config.jitter:
            return delay
        digest = hashlib.sha256(f"{key}:{count}".encode("utf-8")).digest()[0]
        multiplier = 0.8 + (digest / 255.0) * 0.4
        return max(1.0, min(self.config.max_seconds, delay * multiplier))

    def _lookup_key(self, request: Mapping[str, Any], scope: Mapping[str, Any]) -> tuple[str, dict[str, str]]:
        return self._key(request, scope, None, include_reason=False, kind="lookup")

    def _deny_key(
        self,
        request: Mapping[str, Any],
        scope: Mapping[str, Any],
        decision: Mapping[str, Any],
    ) -> tuple[str, dict[str, str]]:
        return self._key(request, scope, decision, include_reason=True, kind="deny")

    def _key(
        self,
        request: Mapping[str, Any],
        scope: Mapping[str, Any],
        decision: Mapping[str, Any] | None,
        *,
        include_reason: bool,
        kind: str,
    ) -> tuple[str, dict[str, str]]:
        context = _backoff_context(request, scope, decision)
        parts: dict[str, str] = {}
        for field in self.config.key_fields:
            if field == "decision.reason_code" and not include_reason:
                continue
            value = _field_value(field, context)
            if value not in (None, ""):
                parts[field] = str(value)
        if not any(field.startswith("auth.") for field in parts) and "client.ip" not in parts:
            client_ip = _field_value("client.ip", context)
            if client_ip:
                parts["client.ip"] = str(client_ip)
        payload = json.dumps(parts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        prefix = f"{self.key_prefix}policy_backoff:{kind}:"
        return f"{prefix}{digest}", parts


def policy_backoff_headers(metadata: Mapping[str, Any], *, include_retry_after: bool) -> list[tuple[bytes, bytes]]:
    headers = [
        (b"x-snulbug-backoff-count", str(metadata.get("count", 0)).encode("ascii")),
        (b"x-snulbug-backoff-reason", str(metadata.get("original_reason_code") or "").encode("latin-1")),
    ]
    retry_after = metadata.get("retry_after")
    if retry_after is not None:
        if include_retry_after:
            headers.append((b"retry-after", str(retry_after).encode("ascii")))
        else:
            headers.append((b"x-snulbug-backoff-retry-after", str(retry_after).encode("ascii")))
    return headers


def policy_backoff_active_decision(metadata: Mapping[str, Any]) -> dict[str, Any]:
    retry_after = int(metadata.get("retry_after") or 1)
    original_reason = str(metadata.get("original_reason_code") or "policy.denied")
    return {
        "action": "reject",
        "status": int(metadata.get("status") or 429),
        "body": f"policy deny backoff active; retry after {retry_after}s",
        "reason": "policy deny backoff active",
        "reason_code": "policy.backoff_active",
        "context": {
            "retry_after": retry_after,
            "count": int(metadata.get("count") or 0),
            "original_reason_code": original_reason,
        },
    }


def _backoff_context(
    request: Mapping[str, Any],
    scope: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
) -> dict[str, Any]:
    lua_context = scope.get("lua")
    lua_context = lua_context if isinstance(lua_context, Mapping) else {}
    state = scope.get("state")
    proxy_metadata = state.get("snulbug_proxy") if isinstance(state, Mapping) else {}
    proxy_metadata = proxy_metadata if isinstance(proxy_metadata, Mapping) else {}
    mcp = _mcp_context(request)
    auth = {
        **_mapping(lua_context.get("auth")),
        **_mapping(proxy_metadata.get("auth")),
    }
    lease = {
        **_mapping(lua_context.get("lease")),
        **_mapping(proxy_metadata.get("lease_preview")),
        **_mapping(proxy_metadata.get("lease")),
    }
    upstream = {
        **_mapping(lua_context.get("upstream")),
        **_mapping(proxy_metadata.get("upstream_preview")),
        **_mapping(proxy_metadata.get("upstream_metadata")),
    }
    if proxy_metadata.get("upstream") and "name" not in upstream:
        upstream["name"] = proxy_metadata.get("upstream")
    client = request.get("client")
    client_ip = client[0] if isinstance(client, Sequence) and not isinstance(client, str | bytes | bytearray) else None
    return {
        "request": request,
        "mcp": mcp,
        "auth": auth,
        "lease": lease,
        "upstream": upstream,
        "decision": decision or {},
        "client": {"ip": client_ip},
    }


def _mcp_context(request: Mapping[str, Any]) -> dict[str, Any]:
    body = request.get("body")
    payload = None
    if isinstance(body, str) and body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
    payload = payload if isinstance(payload, Mapping) else {}
    method = payload.get("method")
    params = payload.get("params") if isinstance(payload.get("params"), Mapping) else {}
    tool = params.get("name")
    target = tool or params.get("uri")
    if not isinstance(method, str):
        method = None
    return {
        "method": method,
        "tool": tool if isinstance(tool, str) else None,
        "target": target if isinstance(target, str) else None,
    }


def _field_value(field: str, context: Mapping[str, Any]) -> Any:
    value: Any = context
    for part in field.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _metadata_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "count": int(record.get("count") or 0),
        "retry_after": int(record.get("retry_after") or 0),
        "delay_seconds": float(record.get("delay_seconds") or 0.0),
        "cooldown_until": record.get("cooldown_until"),
        "original_reason_code": record.get("reason_code"),
        "deny_key": record.get("deny_key"),
        "key_parts": record.get("key_parts"),
    }


def _decode_record(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return dict(loaded) if isinstance(loaded, Mapping) else {}


def _matches_any(value: str, patterns: Sequence[str]) -> bool:
    return any(_matches_pattern(value, str(pattern)) for pattern in patterns)


def _matches_pattern(value: str, pattern: str) -> bool:
    if pattern == "*" or pattern == value:
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return False


def _float_value(value: Any) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

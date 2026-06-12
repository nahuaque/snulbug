from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SECRET_REPLACEMENT = "[REDACTED]"

DEFAULT_SECRET_KEYS = {
    "api-key",
    "apikey",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "set-cookie",
    "token",
    "x-api-key",
}

DEFAULT_SECRET_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9._:-]*(?:token|secret|password)[A-Za-z0-9._:-]*\b", re.IGNORECASE),
]


@dataclass(frozen=True)
class RedactionConfig:
    replacement: str = SECRET_REPLACEMENT
    secret_keys: set[str] = field(default_factory=lambda: set(DEFAULT_SECRET_KEYS))
    secret_patterns: list[re.Pattern[str]] = field(default_factory=lambda: list(DEFAULT_SECRET_PATTERNS))


def redact_secrets(value: Any, config: RedactionConfig | None = None) -> Any:
    """Recursively redact likely secrets from JSON-compatible data."""

    redactor = config or RedactionConfig()
    return _redact(value, redactor, key=None)


def build_audit_event(record: Mapping[str, Any], *, redact: bool = True) -> dict[str, Any]:
    """Build a compact JSONL audit event from a request record."""

    request = _mapping(record.get("request"))
    result = _mapping(record.get("result"))
    decision = _mapping(result.get("decision"))
    action = str(result.get("action", decision.get("action", "")))
    event: dict[str, Any] = {
        "type": "asgi-lua.audit",
        "version": 1,
        "time": record.get("recorded_at") or datetime.now(timezone.utc).isoformat(),
        "policy": record.get("policy", {}),
        "request": {
            "method": request.get("method"),
            "path": request.get("path"),
            "query_string": request.get("query_string", ""),
            "headers": request.get("headers", {}),
        },
        "mcp": _mcp_summary(request, decision),
        "decision": {
            "action": action,
            "allowed": action in {"continue", "set_context", "rewrite", "rate_limit"},
            "status": decision.get("status"),
            "context": decision.get("context", {}),
        },
    }
    if "response" in record:
        event["response"] = record["response"]
    if "metadata" in record:
        event["metadata"] = record["metadata"]
    return redact_secrets(event) if redact else event


def append_audit_event(path: str | Path, event: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
        file.write("\n")


def _redact(value: Any, config: RedactionConfig, *, key: str | None) -> Any:
    if key is not None and _is_secret_key(key, config):
        return config.replacement
    if isinstance(value, Mapping):
        return {str(item_key): _redact(item_value, config, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_redact(item, config, key=None) for item in value]
    if isinstance(value, str):
        return _redact_string(value, config)
    return value


def _redact_string(value: str, config: RedactionConfig) -> str:
    if _looks_like_json(value):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            pass
        else:
            return json.dumps(redact_secrets(parsed, config), sort_keys=True, separators=(",", ":"))
    redacted = value
    for pattern in config.secret_patterns:
        redacted = pattern.sub(config.replacement, redacted)
    return redacted


def _is_secret_key(key: str, config: RedactionConfig) -> bool:
    normalized = key.lower().replace("_", "-")
    if normalized in config.secret_keys:
        return True
    return any(part in normalized for part in ("token", "secret", "password", "credential"))


def _looks_like_json(value: str) -> bool:
    stripped = value.strip()
    return (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    )


def _mcp_summary(request: Mapping[str, Any], decision: Mapping[str, Any]) -> dict[str, Any]:
    context = decision.get("context")
    context = context if isinstance(context, Mapping) else {}
    summary: dict[str, Any] = {
        "method": context.get("method"),
        "tool": context.get("tool"),
    }
    body = request.get("body")
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            summary["method"] = summary["method"] or parsed.get("method")
            params = parsed.get("params")
            if isinstance(params, Mapping):
                summary["tool"] = summary["tool"] or params.get("name")
    return summary


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

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
    "cf-access-client-secret",
    "cf-access-jwt-assertion",
    "password",
    "refresh_token",
    "secret",
    "set-cookie",
    "snulbug-lease",
    "token",
    "x-snulbug-lease",
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
        "type": "snulbug.audit",
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
            "reason": decision.get("reason"),
            "reason_code": decision.get("reason_code"),
            "context": decision.get("context", {}),
            "confirmation": decision.get("confirmation"),
        },
    }
    if "response" in record:
        event["response"] = record["response"]
    if "metadata" in record:
        metadata = _mapping(record["metadata"])
        tunnel = _mapping(metadata.get("tunnel"))
        if tunnel:
            event["tunnel"] = tunnel
        cloudflare_access = _mapping(metadata.get("cloudflare_access"))
        if cloudflare_access:
            event["cloudflare_access"] = cloudflare_access
        auth = _mapping(metadata.get("auth"))
        if auth:
            event["auth"] = auth
        topology = _mapping(metadata.get("topology"))
        if topology:
            event["topology"] = topology
        facade = _facade_summary(metadata)
        if facade:
            event["facade"] = facade
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
        if key in {"argument_keys", "capabilities", "methods", "params_keys"}:
            return list(value)
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
    if not isinstance(body, str):
        summary["body_kind"] = "missing"
        return _drop_empty(summary)

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        summary["body_kind"] = "invalid"
        summary["valid_json"] = False
        return _drop_empty(summary)

    summary["valid_json"] = True
    if isinstance(parsed, Sequence) and not isinstance(parsed, str | bytes | bytearray):
        summary["body_kind"] = "batch"
        summary["batch"] = True
        summary["batch_count"] = len(parsed)
        methods = [_jsonrpc_method(item) for item in parsed if isinstance(item, Mapping)]
        methods = [method for method in methods if method is not None]
        if methods:
            summary["methods"] = methods[:20]
        return _drop_empty(summary)

    if not isinstance(parsed, Mapping):
        summary["body_kind"] = "unknown"
        return _drop_empty(summary)

    summary["body_kind"] = "object"
    _merge_jsonrpc_summary(summary, parsed)
    return _drop_empty(summary)


def _facade_summary(metadata: Mapping[str, Any]) -> dict[str, Any]:
    if not metadata.get("facade"):
        return {}
    summary: dict[str, Any] = {
        "operation": metadata.get("operation"),
        "upstream": metadata.get("upstream"),
        "upstream_transport": metadata.get("upstream_transport"),
        "upstream_tool": metadata.get("upstream_tool"),
        "tool": metadata.get("tool"),
        "upstream_metadata": metadata.get("upstream_metadata"),
        "upstreams": metadata.get("upstreams"),
        "upstream_transports": metadata.get("upstream_transports"),
    }
    return _drop_empty(summary)


def _merge_jsonrpc_summary(summary: dict[str, Any], body: Mapping[str, Any]) -> None:
    method = _jsonrpc_method(body)
    params = body.get("params")
    params = params if isinstance(params, Mapping) else {}

    summary["jsonrpc"] = body.get("jsonrpc")
    summary["request_id"] = _jsonrpc_id(body)
    summary["notification"] = "id" not in body
    summary["method"] = summary.get("method") or method
    if method is not None:
        operation, _, operation_detail = method.partition("/")
        summary["operation"] = operation
        if operation_detail:
            summary["operation_detail"] = operation_detail
    if params:
        summary["params_keys"] = sorted(str(key) for key in params)

    target = _mcp_target(method, params)
    if target is not None:
        summary["target"] = target
    if method == "tools/call":
        summary["tool"] = summary.get("tool") or target
        arguments = params.get("arguments")
        if isinstance(arguments, Mapping):
            summary["argument_keys"] = sorted(str(key) for key in arguments)

    if method == "initialize":
        _merge_initialize_summary(summary, params)


def _merge_initialize_summary(summary: dict[str, Any], params: Mapping[str, Any]) -> None:
    if isinstance(params.get("protocolVersion"), str):
        summary["protocol_version"] = params["protocolVersion"]
    client = params.get("clientInfo")
    if isinstance(client, Mapping):
        summary["client"] = {
            "name": client.get("name"),
            "version": client.get("version"),
        }
    capabilities = params.get("capabilities")
    if isinstance(capabilities, Mapping):
        summary["capabilities"] = sorted(str(key) for key in capabilities)


def _jsonrpc_method(body: Mapping[str, Any]) -> str | None:
    method = body.get("method")
    return method if isinstance(method, str) else None


def _jsonrpc_id(body: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in body:
        return None
    value = body.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _mcp_target(method: str | None, params: Mapping[str, Any]) -> Any:
    if method == "tools/call":
        return _string_param(params, "name")
    if method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}:
        return _string_param(params, "uri")
    if method == "prompts/get":
        return _string_param(params, "name")
    if method == "completion/complete":
        ref = params.get("ref")
        if isinstance(ref, Mapping):
            return _string_param(ref, "name") or _string_param(ref, "uri")
    return _string_param(params, "name") or _string_param(params, "uri")


def _string_param(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    return item if isinstance(item, str) else None


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

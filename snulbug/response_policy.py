from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .redaction import DEFAULT_SECRET_KEYS, DEFAULT_SECRET_PATTERNS, RedactionConfig, redact_secrets
from .state import PolicyStateStore

MCP_RESPONSE_METHODS = ("tools/call", "resources/read", "prompts/get")

RESPONSE_SECRET_PATTERNS = tuple(DEFAULT_SECRET_PATTERNS[:-1])
RESPONSE_REDACTION_CONFIG = RedactionConfig(
    secret_keys=set(DEFAULT_SECRET_KEYS),
    secret_patterns=list(RESPONSE_SECRET_PATTERNS),
)

INSTRUCTION_LIKE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.I),
    ),
    (
        "disregard_previous_instructions",
        re.compile(r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.I),
    ),
    ("system_prompt_reference", re.compile(r"\bsystem\s+prompt\b", re.I)),
    ("developer_message_reference", re.compile(r"\bdeveloper\s+message\b", re.I)),
    (
        "secret_exfiltration_instruction",
        re.compile(r"\b(?:exfiltrate|leak|reveal)\b.{0,80}\b(?:secret|token|credential|key)s?\b", re.I),
    ),
)


@dataclass(frozen=True)
class ResponsePolicyConfig:
    """Return-path controls for MCP JSON-RPC responses."""

    max_body_bytes: int | None = 256 * 1024
    redact_secrets: bool = True
    block_instruction_like_content: bool = False
    tool_pinning: bool = True
    tool_pinning_action: str = "block"
    target_methods: tuple[str, ...] = MCP_RESPONSE_METHODS
    instruction_patterns: tuple[tuple[str, re.Pattern[str]], ...] = field(
        default_factory=lambda: INSTRUCTION_LIKE_PATTERNS
    )

    def __post_init__(self) -> None:
        if self.max_body_bytes is not None and self.max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive when set")
        if self.tool_pinning_action not in {"warn", "block"}:
            raise ValueError("tool_pinning_action must be 'warn' or 'block'")


def enforce_mcp_response_policy(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: ResponsePolicyConfig,
    tool_pin_store: PolicyStateStore | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply MCP response-side controls and return the possibly rewritten response plus metadata."""

    method = request.get("method") if isinstance(request, Mapping) else None
    response_body = _response_body(response)
    metadata: dict[str, Any] = {
        "checked": False,
        "method": method,
        "body_bytes": len(response_body),
    }
    if not isinstance(method, str) or not _is_success_response(response):
        return dict(response), metadata

    if method == "tools/list":
        updated, pin_metadata = _enforce_tool_pinning(
            response,
            request=request,
            config=config,
            tool_pin_store=tool_pin_store,
        )
        metadata.update(pin_metadata)
        return updated, metadata

    if method not in config.target_methods:
        return dict(response), metadata

    metadata["checked"] = True
    if config.max_body_bytes is not None and len(response_body) > config.max_body_bytes:
        metadata["blocked"] = True
        metadata["reason_code"] = "response.too_large"
        metadata["max_body_bytes"] = config.max_body_bytes
        return _jsonrpc_error_response(
            request,
            f"MCP response body exceeds response_max_bytes ({config.max_body_bytes})",
        ), metadata

    payload, parse_error = _decode_json(response_body)
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata

    warnings = _instruction_warnings(payload, config)
    if warnings:
        metadata["warnings"] = warnings
        if config.block_instruction_like_content:
            metadata["blocked"] = True
            metadata["reason_code"] = "response.instruction_like_content"
            return _jsonrpc_error_response(
                request,
                "MCP response blocked because it contains instruction-like content",
            ), metadata

    updated_payload = payload
    if config.redact_secrets:
        redacted = redact_secrets(payload, RESPONSE_REDACTION_CONFIG)
        if redacted != payload:
            metadata["redacted"] = True
            updated_payload = redacted

    if updated_payload is payload:
        return dict(response), metadata
    return _replace_json_body(response, updated_payload), metadata


def _enforce_tool_pinning(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    config: ResponsePolicyConfig,
    tool_pin_store: PolicyStateStore | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata: dict[str, Any] = {
        "checked": bool(config.tool_pinning and tool_pin_store is not None),
        "tool_pinning": {
            "enabled": config.tool_pinning,
            "action": config.tool_pinning_action,
            "store": tool_pin_store is not None,
        },
    }
    if not config.tool_pinning or tool_pin_store is None:
        return dict(response), metadata

    payload, parse_error = _decode_json(_response_body(response))
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata
    tools = _tools_from_response(payload)
    if tools is None:
        metadata["tool_pinning"]["checked"] = False
        return dict(response), metadata

    result = pin_tool_descriptions(tools, tool_pin_store)
    metadata["tool_pinning"].update(result)
    changed = result.get("changed", [])
    if changed and config.tool_pinning_action == "block":
        metadata["blocked"] = True
        metadata["reason_code"] = "response.tool_description_changed"
        changed_names = ", ".join(item["tool"] for item in changed[:5])
        return _jsonrpc_error_response(
            request,
            f"MCP tools/list blocked because pinned tool descriptions changed: {changed_names}",
        ), metadata
    return dict(response), metadata


def pin_tool_descriptions(tools: Sequence[Any], store: PolicyStateStore) -> dict[str, Any]:
    """Pin tool descriptions and input schemas by stable hash."""

    pinned = []
    unchanged = []
    changed = []
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            continue
        name = tool["name"]
        digest = _tool_digest(tool)
        key = f"snulbug:tool-pin:{name}"
        existing = store.get(key)
        if existing is None:
            if store.cas(key, None, digest):
                pinned.append({"tool": name, "hash": digest[:12]})
            else:
                existing = store.get(key)
        if existing is not None:
            if existing == digest:
                unchanged.append({"tool": name, "hash": digest[:12]})
            else:
                changed.append({"tool": name, "expected": existing[:12], "actual": digest[:12]})
    return {
        "pinned": pinned,
        "unchanged": unchanged,
        "changed": changed,
    }


def _tool_digest(tool: Mapping[str, Any]) -> str:
    pinned_shape = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }
    data = json.dumps(pinned_shape, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _tools_from_response(payload: Any) -> list[Any] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    tools = result.get("tools")
    return tools if isinstance(tools, list) else None


def _instruction_warnings(payload: Any, config: ResponsePolicyConfig) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    for path, text in _walk_strings(payload):
        for code, pattern in config.instruction_patterns:
            if pattern.search(text):
                warnings.append({"path": path, "reason_code": code})
                break
        if len(warnings) >= 20:
            break
    return warnings


def _walk_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, Mapping):
        result = []
        for key, item in value.items():
            result.extend(_walk_strings(item, f"{path}.{key}"))
        return result
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        result = []
        for index, item in enumerate(value):
            result.extend(_walk_strings(item, f"{path}[{index}]"))
        return result
    return []


def _decode_json(body: bytes) -> tuple[Any, str | None]:
    try:
        return json.loads(body.decode("utf-8")), None
    except UnicodeDecodeError as exc:
        return None, f"invalid UTF-8: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def _response_body(response: Mapping[str, Any]) -> bytes:
    body = response.get("body", b"")
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _is_success_response(response: Mapping[str, Any]) -> bool:
    status = int(response.get("status", 0))
    return 200 <= status < 300


def _replace_json_body(response: Mapping[str, Any], payload: Any) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        **dict(response),
        "headers": _replace_content_length(response.get("headers", []), len(body)),
        "body": body,
    }


def _jsonrpc_error_response(request: Mapping[str, Any], message: str) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id(request),
        "error": {
            "code": -32000,
            "message": message,
        },
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "status": 200,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
        "body": body,
    }


def _replace_content_length(headers: Any, length: int) -> list[tuple[bytes, bytes]]:
    result: list[tuple[bytes, bytes]] = []
    if isinstance(headers, Sequence) and not isinstance(headers, str | bytes | bytearray):
        for pair in headers:
            if not isinstance(pair, Sequence) or isinstance(pair, str | bytes | bytearray) or len(pair) != 2:
                continue
            name = _header_bytes(pair[0])
            if name.lower() == b"content-length":
                continue
            result.append((name, _header_bytes(pair[1])))
    result.append((b"content-length", str(length).encode("ascii")))
    return result


def _header_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("latin-1")


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in request:
        return None
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)

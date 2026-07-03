from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .mcp_client_requests import (
    MCP_SERVER_TO_CLIENT_REQUEST_METHODS,
    mcp_server_to_client_request_metadata,
    mcp_server_to_client_requests_from_payload,
)
from .mcp_completion import MCP_COMPLETION_METHOD, mcp_completion_response_metadata
from .redaction import DEFAULT_SECRET_KEYS, DEFAULT_SECRET_PATTERNS, RedactionConfig, redact_secrets
from .schema_policy import normalize_mcp_tool_metadata
from .state import PolicyStateStore

MCP_RESPONSE_METHODS = ("tools/call", "resources/read", "prompts/get", "tasks/result", MCP_COMPLETION_METHOD)
SERVER_TO_CLIENT_REQUEST_ACTIONS = ("allow", "warn", "block")

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
    server_to_client_request_action: str = "block"
    server_to_client_request_methods: tuple[str, ...] = MCP_SERVER_TO_CLIENT_REQUEST_METHODS
    target_methods: tuple[str, ...] = MCP_RESPONSE_METHODS
    instruction_patterns: tuple[tuple[str, re.Pattern[str]], ...] = field(
        default_factory=lambda: INSTRUCTION_LIKE_PATTERNS
    )

    def __post_init__(self) -> None:
        if self.max_body_bytes is not None and self.max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive when set")
        if self.tool_pinning_action not in {"warn", "block"}:
            raise ValueError("tool_pinning_action must be 'warn' or 'block'")
        if self.server_to_client_request_action not in SERVER_TO_CLIENT_REQUEST_ACTIONS:
            raise ValueError("server_to_client_request_action must be 'allow', 'warn', or 'block'")


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
    if not _is_success_response(response):
        return dict(response), metadata

    updated, server_request_metadata = _enforce_server_to_client_request_policy(response, config=config)
    if server_request_metadata:
        metadata["server_to_client"] = server_request_metadata
        if server_request_metadata.get("checked"):
            metadata["checked"] = True
        if server_request_metadata.get("blocked"):
            metadata["blocked"] = True
            metadata["reason_code"] = server_request_metadata.get("reason_code")
            return updated, metadata
        response = updated
        response_body = _response_body(response)

    if not isinstance(method, str):
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

    payload, parse_error, response_format = _decode_response_payload(response)
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata
    if method == MCP_COMPLETION_METHOD:
        completion_metadata = mcp_completion_response_metadata(payload)
        if completion_metadata:
            metadata["completion"] = completion_metadata

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
    return _replace_response_payload(response, updated_payload, response_format=response_format), metadata


def _enforce_server_to_client_request_policy(
    response: Mapping[str, Any],
    *,
    config: ResponsePolicyConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload, parse_error, response_format = _decode_response_payload(response)
    if parse_error is not None:
        return dict(response), {}
    requests = [
        item
        for item in mcp_server_to_client_requests_from_payload(payload)
        if item.get("method") in config.server_to_client_request_methods
    ]
    if not requests:
        return dict(response), {}

    metadata: dict[str, Any] = {
        "checked": True,
        "action": config.server_to_client_request_action,
        "count": len(requests),
        "requests": requests,
    }
    if config.server_to_client_request_action != "block":
        return dict(response), metadata

    metadata["blocked"] = True
    metadata["reason_code"] = "response.server_to_client_request_blocked"
    return (
        _replace_response_payload(
            response,
            _block_server_to_client_requests(payload),
            response_format=response_format,
        ),
        metadata,
    )


def _block_server_to_client_requests(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        blocked = _blocked_server_to_client_message(payload)
        return blocked if blocked is not None else payload
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        return [_blocked_server_to_client_message(item) or item for item in payload]
    return payload


def _blocked_server_to_client_message(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return None
    metadata = mcp_server_to_client_request_metadata(message)
    method = metadata.get("method")
    if not method:
        return None
    return {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id(message),
        "error": {
            "code": -32000,
            "message": f"MCP server-to-client request blocked by snulbug policy: {method}",
            "data": {
                "reason_code": "response.server_to_client_request_blocked",
                "method": method,
                "feature": metadata.get("feature"),
            },
        },
    }


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

    payload, parse_error, _response_format = _decode_response_payload(response)
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
        metadata["reason_code"] = "response.tool_metadata_changed"
        changed_names = ", ".join(item["tool"] for item in changed[:5])
        return _jsonrpc_error_response(
            request,
            f"MCP tools/list blocked because pinned tool metadata changed: {changed_names}",
        ), metadata
    return dict(response), metadata


def pin_tool_descriptions(tools: Sequence[Any], store: PolicyStateStore) -> dict[str, Any]:
    """Pin tool metadata and schemas by stable hash."""

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
    pinned_shape = normalize_mcp_tool_metadata(tool) or {"name": tool.get("name")}
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


def _decode_response_payload(response: Mapping[str, Any]) -> tuple[Any, str | None, str]:
    body = _response_body(response)
    content_type = _response_content_type(response)
    text = body.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type.lower() or text.lstrip().startswith(("event:", "data:")):
        events: list[Any] = []
        for data in _sse_data_events(text):
            stripped = data.strip()
            if not stripped or stripped == "[DONE]":
                continue
            parsed, parse_error = _decode_json(stripped.encode("utf-8"))
            if parse_error is not None:
                return None, parse_error, "sse"
            events.append(parsed)
        if not events:
            return None, "MCP SSE response did not contain a JSON data event", "sse"
        return events[0] if len(events) == 1 else events, None, "sse"
    payload, parse_error = _decode_json(body)
    return payload, parse_error, "json"


def _sse_data_events(text: str) -> list[str]:
    events = []
    data_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if line == "":
            if data_lines:
                events.append("\n".join(data_lines))
                data_lines = []
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        events.append("\n".join(data_lines))
    return events


def _response_body(response: Mapping[str, Any]) -> bytes:
    body = response.get("body", b"")
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _response_content_type(response: Mapping[str, Any]) -> str:
    headers = response.get("headers", [])
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                return str(value)
        return ""
    if isinstance(headers, Sequence) and not isinstance(headers, str | bytes | bytearray):
        for pair in headers:
            if not isinstance(pair, Sequence) or isinstance(pair, str | bytes | bytearray) or len(pair) != 2:
                continue
            if _header_bytes(pair[0]).lower() == b"content-type":
                return _header_bytes(pair[1]).decode("latin-1", errors="replace")
    return ""


def _is_success_response(response: Mapping[str, Any]) -> bool:
    status = int(response.get("status", 0))
    return 200 <= status < 300


def _replace_response_payload(
    response: Mapping[str, Any],
    payload: Any,
    *,
    response_format: str,
) -> dict[str, Any]:
    if response_format == "sse":
        return _replace_sse_body(response, payload)
    return _replace_json_body(response, payload)


def _replace_json_body(response: Mapping[str, Any], payload: Any) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        **dict(response),
        "headers": _replace_content_length(response.get("headers", []), len(body)),
        "body": body,
    }


def _replace_sse_body(response: Mapping[str, Any], payload: Any) -> dict[str, Any]:
    events = (
        payload if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray) else [payload]
    )
    body = "".join(f"data: {json.dumps(item, separators=(',', ':'))}\n\n" for item in events).encode("utf-8")
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

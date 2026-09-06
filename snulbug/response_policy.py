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
from .mcp_mrtr import input_required, mrtr_result_metadata
from .redaction import DEFAULT_SECRET_KEYS, DEFAULT_SECRET_PATTERNS, RedactionConfig, redact_secrets
from .schema_policy import normalize_mcp_tool_metadata
from .state import PolicyStateStore

MCP_RESPONSE_METHODS = (
    "tools/call",
    "resources/read",
    "prompts/get",
    "tasks/result",
    MCP_COMPLETION_METHOD,
    "subscriptions/listen",
)
SERVER_TO_CLIENT_REQUEST_ACTIONS = ("allow", "warn", "block")
PINNED_CATALOG_METHODS = {
    "tools/list": {
        "surface": "tools",
        "kind": "tool",
        "result_key": "tools",
        "id_field": "name",
    },
    "resources/list": {
        "surface": "resources",
        "kind": "resource",
        "result_key": "resources",
        "id_field": "uri",
    },
    "resources/templates/list": {
        "surface": "resource_templates",
        "kind": "resource_template",
        "result_key": "resourceTemplates",
        "id_field": "uriTemplate",
    },
    "prompts/list": {
        "surface": "prompts",
        "kind": "prompt",
        "result_key": "prompts",
        "id_field": "name",
    },
}

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
    tool_schema_store: PolicyStateStore | None = None,
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

    if method == "tools/list":
        from .mcp_parameter_headers import filter_header_tools
        from .mcp_protocol import is_modern_request

        if is_modern_request(request):
            payload, parse_error, response_format = _decode_response_payload(response)
            if parse_error is None:
                filtered, header_metadata = filter_header_tools(payload, tool_schema_store)
                metadata["parameter_headers"] = header_metadata
                if filtered is not payload:
                    response = _replace_response_payload(response, filtered, response_format=response_format)

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

    if method in PINNED_CATALOG_METHODS:
        updated, pin_metadata = _enforce_catalog_pinning(
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

    interim = input_required(payload)
    subscription_result = method == "subscriptions/listen"
    if subscription_result:
        from .mcp_protocol import is_modern_request, modern_response_issue

        if not is_modern_request(request) or modern_response_issue(response_body, request):
            metadata.update(blocked=True, reason_code="response.subscription_invalid")
            return _jsonrpc_error_response(request, "Invalid subscription result"), metadata
    if interim is not None:
        from .mcp_protocol import is_modern_request, modern_response_issue

        if not is_modern_request(request) or modern_response_issue(_response_body(response), request):
            metadata.update(blocked=True, reason_code="response.mrtr_invalid")
            return _jsonrpc_error_response(request, "Invalid MRTR result"), metadata
        metadata["mrtr"] = mrtr_result_metadata(payload)
        # Inspect/redact content, not opaque continuation state or input correlation keys.
        inputs = interim.get("inputRequests", {})
        inspection = {
            **payload,
            "result": {
                **{key: value for key, value in interim.items() if key not in {"requestState", "inputRequests"}},
                "inputRequests": list(inputs.values()),
            },
        }
    else:
        inspection = payload

    warnings = _instruction_warnings(inspection, config)
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
        redacted = redact_secrets(inspection, RESPONSE_REDACTION_CONFIG)
        if subscription_result:
            redacted["id"] = payload["id"]
            if "result" in payload:
                redacted["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"] = payload["id"]
        if interim is not None:
            redacted["id"] = payload["id"]
            redacted["result"]["inputRequests"] = dict(zip(inputs, redacted["result"]["inputRequests"]))
            for key, original in inputs.items():
                if original.get("method") == "sampling/createMessage":
                    redacted["result"]["inputRequests"][key]["params"]["maxTokens"] = original["params"]["maxTokens"]
            if "inputRequests" not in interim:
                del redacted["result"]["inputRequests"]
            if "requestState" in interim:
                redacted["result"]["requestState"] = interim["requestState"]
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
    if input_required(message) is not None:
        requests = mcp_server_to_client_requests_from_payload(message)
        metadata = requests[0] if requests else {}
    else:
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


def _enforce_catalog_pinning(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    config: ResponsePolicyConfig,
    tool_pin_store: PolicyStateStore | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    method = request.get("method")
    surface_config = PINNED_CATALOG_METHODS.get(str(method))
    metadata: dict[str, Any] = {
        "checked": bool(config.tool_pinning and tool_pin_store is not None),
        "tool_pinning": {
            "enabled": config.tool_pinning,
            "action": config.tool_pinning_action,
            "store": tool_pin_store is not None,
            "method": method,
            "surface": surface_config.get("surface") if surface_config else None,
        },
    }
    if not config.tool_pinning or tool_pin_store is None or surface_config is None:
        return dict(response), metadata

    payload, parse_error, _response_format = _decode_response_payload(response)
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata
    items = _catalog_items_from_response(payload, surface_config)
    if items is None:
        metadata["tool_pinning"]["checked"] = False
        return dict(response), metadata

    result = pin_catalog_metadata(str(method), items, tool_pin_store)
    metadata["tool_pinning"].update(result)
    changed = result.get("changed", [])
    if changed and config.tool_pinning_action == "block":
        metadata["blocked"] = True
        metadata["reason_code"] = (
            "response.tool_metadata_changed" if method == "tools/list" else "response.catalog_metadata_changed"
        )
        changed_names = ", ".join(_pin_item_label(item) for item in changed[:5])
        return _jsonrpc_error_response(
            request,
            f"MCP {method} blocked because pinned {surface_config['kind']} metadata changed: {changed_names}",
        ), metadata
    return dict(response), metadata


def pin_tool_descriptions(tools: Sequence[Any], store: PolicyStateStore) -> dict[str, Any]:
    """Pin tool metadata and schemas by stable hash."""

    return pin_catalog_metadata("tools/list", tools, store)


def pin_catalog_metadata(method: str, items: Sequence[Any], store: PolicyStateStore) -> dict[str, Any]:
    """Pin MCP list metadata by stable hash."""

    surface_config = PINNED_CATALOG_METHODS.get(method)
    if surface_config is None:
        return {"pinned": [], "unchanged": [], "changed": []}
    pinned = []
    unchanged = []
    changed = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        normalized = _normalize_catalog_item(item, surface_config)
        if normalized is None:
            continue
        item_id = str(normalized[surface_config["id_field"]])
        digest = _catalog_item_digest(normalized)
        key = _pin_key(surface_config["surface"], item_id)
        existing = store.get(key)
        if existing is None:
            if store.cas(key, None, digest):
                pinned.append(_pin_item(surface_config, item_id, digest))
            else:
                existing = store.get(key)
        if existing is not None:
            if existing == digest:
                unchanged.append(_pin_item(surface_config, item_id, digest))
            else:
                changed.append(_pin_item(surface_config, item_id, digest, expected=existing))
    return {
        "pinned": pinned,
        "unchanged": unchanged,
        "changed": changed,
    }


def _catalog_item_digest(item: Mapping[str, Any]) -> str:
    data = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _catalog_items_from_response(payload: Any, surface_config: Mapping[str, str]) -> list[Any] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    items = result.get(surface_config["result_key"])
    return items if isinstance(items, list) else None


def _normalize_catalog_item(item: Mapping[str, Any], surface_config: Mapping[str, str]) -> dict[str, Any] | None:
    kind = surface_config["kind"]
    if kind == "tool":
        return normalize_mcp_tool_metadata(item)
    item_id = item.get(surface_config["id_field"])
    if not isinstance(item_id, str) or not item_id:
        return None
    if kind == "resource":
        return _drop_catalog_metadata_empty(
            {
                "uri": item_id,
                "name": item.get("name") if isinstance(item.get("name"), str) else None,
                "title": item.get("title") if isinstance(item.get("title"), str) else None,
                "description": item.get("description") if isinstance(item.get("description"), str) else None,
                "icons": list(item.get("icons")) if _is_sequence(item.get("icons")) else None,
                "mimeType": item.get("mimeType") if isinstance(item.get("mimeType"), str) else None,
                "size": item.get("size") if isinstance(item.get("size"), int | float) else None,
                "annotations": dict(item.get("annotations")) if isinstance(item.get("annotations"), Mapping) else None,
            }
        )
    if kind == "resource_template":
        return _drop_catalog_metadata_empty(
            {
                "uriTemplate": item_id,
                "name": item.get("name") if isinstance(item.get("name"), str) else None,
                "title": item.get("title") if isinstance(item.get("title"), str) else None,
                "description": item.get("description") if isinstance(item.get("description"), str) else None,
                "icons": list(item.get("icons")) if _is_sequence(item.get("icons")) else None,
                "mimeType": item.get("mimeType") if isinstance(item.get("mimeType"), str) else None,
                "annotations": dict(item.get("annotations")) if isinstance(item.get("annotations"), Mapping) else None,
            }
        )
    if kind == "prompt":
        return _drop_catalog_metadata_empty(
            {
                "name": item_id,
                "title": item.get("title") if isinstance(item.get("title"), str) else None,
                "description": item.get("description") if isinstance(item.get("description"), str) else None,
                "icons": list(item.get("icons")) if _is_sequence(item.get("icons")) else None,
                "arguments": _normalize_prompt_arguments(item.get("arguments")),
            }
        )
    return None


def _normalize_prompt_arguments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    arguments = []
    for item in value:
        if isinstance(item, Mapping) and isinstance(item.get("name"), str):
            arguments.append(
                _drop_catalog_metadata_empty(
                    {
                        "name": item["name"],
                        "title": item.get("title") if isinstance(item.get("title"), str) else None,
                        "description": item.get("description") if isinstance(item.get("description"), str) else None,
                        "required": bool(item.get("required", False)),
                    }
                )
            )
    return sorted(arguments, key=lambda argument: str(argument["name"]))


def _pin_key(surface: str, item_id: str) -> str:
    if surface == "tools":
        return f"snulbug:tool-pin:{item_id}"
    digest = hashlib.sha256(item_id.encode("utf-8")).hexdigest()
    return f"snulbug:catalog-pin:{surface}:{digest}"


def _pin_item(
    surface_config: Mapping[str, str],
    item_id: str,
    digest: str,
    *,
    expected: str | None = None,
) -> dict[str, Any]:
    item = {
        "surface": surface_config["surface"],
        "kind": surface_config["kind"],
        "id": item_id,
        "hash": digest[:12],
    }
    if surface_config["kind"] == "tool":
        item["tool"] = item_id
    if expected is not None:
        item["expected"] = expected[:12]
        item["actual"] = digest[:12]
        item["previous_hash"] = expected[:12]
        item["current_hash"] = digest[:12]
    return item


def _pin_item_label(item: Mapping[str, Any]) -> str:
    return str(item.get("tool") or item.get("id") or item.get("kind") or "unknown")


def _drop_catalog_metadata_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)


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

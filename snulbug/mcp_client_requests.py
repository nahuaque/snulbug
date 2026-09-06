from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from .mcp_mrtr import input_required

MCP_SERVER_TO_CLIENT_REQUEST_METHODS = (
    "sampling/createMessage",
    "elicitation/create",
    "roots/list",
)
MCP_SERVER_TO_CLIENT_HIGH_RISK_METHODS = MCP_SERVER_TO_CLIENT_REQUEST_METHODS


def is_mcp_server_to_client_request_method(method: Any) -> bool:
    return isinstance(method, str) and method in MCP_SERVER_TO_CLIENT_REQUEST_METHODS


def is_mcp_sampling_request(method: Any) -> bool:
    return method == "sampling/createMessage"


def is_mcp_elicitation_request(method: Any) -> bool:
    return method == "elicitation/create"


def is_mcp_roots_request(method: Any) -> bool:
    return method == "roots/list"


def mcp_server_to_client_request_metadata(message: Mapping[str, Any]) -> dict[str, Any]:
    method = message.get("method")
    if not is_mcp_server_to_client_request_method(method):
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    metadata: dict[str, Any] = {
        "method": method,
        "feature": str(method).partition("/")[0],
        "direction": "server_to_client",
        "high_risk": method in MCP_SERVER_TO_CLIENT_HIGH_RISK_METHODS,
        "request_id": _jsonrpc_id(message),
        "notification": "id" not in message,
    }
    if method == "sampling/createMessage":
        metadata["sampling"] = _sampling_metadata(params)
    elif method == "elicitation/create":
        metadata["elicitation"] = _elicitation_metadata(params)
    elif method == "roots/list":
        metadata["roots"] = {"list": True}
    return _drop_empty(metadata)


def mcp_server_to_client_requests_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, Mapping):
        interim = input_required(payload)
        if interim is not None and isinstance(interim.get("inputRequests"), Mapping):
            return [
                {**mcp_server_to_client_request_metadata(item), "transport": "mrtr", "notification": False}
                for item in interim["inputRequests"].values()
                if isinstance(item, Mapping) and is_mcp_server_to_client_request_method(item.get("method"))
            ]
        metadata = mcp_server_to_client_request_metadata(payload)
        return [metadata] if metadata else []
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        results: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, Mapping):
                metadata = mcp_server_to_client_request_metadata(item)
                if metadata:
                    results.append(metadata)
        return results
    return []


def _sampling_metadata(params: Mapping[str, Any]) -> dict[str, Any]:
    messages = params.get("messages")
    tools = params.get("tools")
    model_preferences = params.get("modelPreferences")
    model_preferences = model_preferences if isinstance(model_preferences, Mapping) else {}
    tool_choice = params.get("toolChoice")
    tool_choice = tool_choice if isinstance(tool_choice, Mapping) else {}
    metadata: dict[str, Any] = {
        "message_count": len(messages) if _is_sequence(messages) else None,
        "content_types": sorted(_sampling_content_types(messages)),
        "max_tokens": params.get("maxTokens") if isinstance(params.get("maxTokens"), int | float) else None,
        "include_context": params.get("includeContext") if isinstance(params.get("includeContext"), str) else None,
        "has_system_prompt": isinstance(params.get("systemPrompt"), str) and bool(params.get("systemPrompt")),
        "tools_requested": _is_sequence(tools) and len(tools) > 0,
        "tools_count": len(tools) if _is_sequence(tools) else None,
        "tool_names": _tool_names(tools),
        "tool_choice_mode": tool_choice.get("mode") if isinstance(tool_choice.get("mode"), str) else None,
        "model_hints": _model_hints(model_preferences.get("hints")),
    }
    return _drop_empty(metadata)


def _elicitation_metadata(params: Mapping[str, Any]) -> dict[str, Any]:
    mode = params.get("mode")
    mode = mode if isinstance(mode, str) and mode else "form"
    url = params.get("url")
    parsed_url = urlsplit(url) if isinstance(url, str) and url else None
    requested_schema = params.get("requestedSchema")
    requested_schema = requested_schema if isinstance(requested_schema, Mapping) else {}
    metadata: dict[str, Any] = {
        "mode": mode,
        "message_present": isinstance(params.get("message"), str) and bool(params.get("message")),
        "requested_schema": bool(requested_schema),
        "requested_schema_type": (
            requested_schema.get("type") if isinstance(requested_schema.get("type"), str) else None
        ),
        "url": url if isinstance(url, str) and url else None,
        "url_scheme": parsed_url.scheme if parsed_url else None,
        "url_host": parsed_url.netloc if parsed_url else None,
        "elicitation_id": params.get("elicitationId") if isinstance(params.get("elicitationId"), str) else None,
    }
    return _drop_empty(metadata)


def _sampling_content_types(messages: Any) -> set[str]:
    types: set[str] = set()
    if not _is_sequence(messages):
        return types
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        content = message.get("content")
        for block in _content_blocks(content):
            block_type = block.get("type")
            if isinstance(block_type, str) and block_type:
                types.add(block_type)
    return types


def _content_blocks(content: Any) -> list[Mapping[str, Any]]:
    if isinstance(content, Mapping):
        return [content]
    if _is_sequence(content):
        return [item for item in content if isinstance(item, Mapping)]
    return []


def _tool_names(tools: Any) -> list[str]:
    if not _is_sequence(tools):
        return []
    names = [item.get("name") for item in tools if isinstance(item, Mapping)]
    return sorted(name for name in names if isinstance(name, str) and name)


def _model_hints(hints: Any) -> list[str]:
    if not _is_sequence(hints):
        return []
    names = [item.get("name") for item in hints if isinstance(item, Mapping)]
    return [name for name in names if isinstance(name, str) and name]


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)


def _jsonrpc_id(message: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in message:
        return None
    value = message.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}

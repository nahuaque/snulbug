from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .state import PolicyStateStore

MCP_RESOURCES_SUBSCRIBE_METHOD = "resources/subscribe"
MCP_RESOURCES_UNSUBSCRIBE_METHOD = "resources/unsubscribe"
MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD = "notifications/resources/updated"
MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD = "notifications/resources/list_changed"
MCP_RESOURCE_POLICY_ACTIONS = ("allow", "warn", "block")
MCP_RESOURCE_METHODS = {
    MCP_RESOURCES_SUBSCRIBE_METHOD,
    MCP_RESOURCES_UNSUBSCRIBE_METHOD,
    MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD,
    MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD,
}


@dataclass(frozen=True)
class ResourcePolicyConfig:
    """MCP resource subscription and change-notification controls."""

    action: str = "warn"
    subscription_ttl_seconds: float = 3600.0

    def __post_init__(self) -> None:
        if self.action not in MCP_RESOURCE_POLICY_ACTIONS:
            raise ValueError("resource_subscription_policy_action must be 'allow', 'warn', or 'block'")
        if self.subscription_ttl_seconds <= 0:
            raise ValueError("resource_subscription_ttl_seconds must be positive")


def mcp_resource_request_metadata(message: Mapping[str, Any]) -> dict[str, Any]:
    method = message.get("method")
    if method not in MCP_RESOURCE_METHODS:
        return {}
    return _resource_message_metadata(message, source="request")


def mcp_resource_response_metadata(payload: Any) -> dict[str, Any]:
    messages = mcp_resource_messages_from_payload(payload)
    if not messages:
        return {}
    events = [_resource_message_metadata(item, source="response") for item in messages]
    events = [item for item in events if item]
    updated = [item for item in events if item.get("operation") == "updated"]
    list_changed = [item for item in events if item.get("operation") == "list_changed"]
    return _drop_empty(
        {
            "count": len(events),
            "updated_count": len(updated),
            "list_changed_count": len(list_changed),
            "events": events,
        }
    )


def mcp_resource_messages_from_payload(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        method = payload.get("method")
        if method in {
            MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD,
            MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD,
        }:
            return [payload]
        return []
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        messages: list[Mapping[str, Any]] = []
        for item in payload:
            if isinstance(item, Mapping):
                messages.extend(mcp_resource_messages_from_payload(item))
        return messages
    return []


def enforce_mcp_resource_request_policy(
    request: Mapping[str, Any] | None,
    *,
    config: ResourcePolicyConfig,
    state_store: PolicyStateStore | None,
) -> tuple[bool, dict[str, Any]]:
    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "checked": False,
        "action": config.action,
        "method": method,
        "state_store": state_store is not None,
    }
    if not isinstance(request, Mapping):
        return True, metadata

    request_metadata = mcp_resource_request_metadata(request)
    if request_metadata:
        metadata["request"] = request_metadata

    if method in {MCP_RESOURCES_SUBSCRIBE_METHOD, MCP_RESOURCES_UNSUBSCRIBE_METHOD}:
        metadata["checked"] = True
        uri = _resource_uri(request)
        operation = "subscribe" if method == MCP_RESOURCES_SUBSCRIBE_METHOD else "unsubscribe"
        metadata["operation"] = operation
        if not uri:
            metadata["reason_code"] = "request.resource_uri_missing"
            return _allowed(_flag(metadata, config), config), metadata
        metadata["resource"] = _resource_uri_summary(uri)
        return True, metadata

    if method == MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD:
        check = _check_resource_updated_notification(
            request,
            state_store=state_store,
            config=config,
            direction="client_to_server",
        )
        metadata.update(check)
        return _allowed(metadata, config), metadata

    if method == MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD:
        metadata["checked"] = True
        metadata["operation"] = "list_changed"
        metadata["direction"] = "client_to_server"
        return True, metadata

    return True, metadata


def enforce_mcp_resource_response_policy(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: ResourcePolicyConfig,
    state_store: PolicyStateStore | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    response_body = _response_body(response)
    metadata: dict[str, Any] = {
        "checked": False,
        "action": config.action,
        "body_bytes": len(response_body),
        "state_store": state_store is not None,
    }
    if not _is_success_response(response):
        return dict(response), metadata

    payload, parse_error, response_format = _decode_response_payload(response)
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata

    _observe_subscription_response(
        request,
        payload,
        state_store=state_store,
        config=config,
        metadata=metadata,
    )

    messages = mcp_resource_messages_from_payload(payload)
    checks = [
        _check_resource_updated_notification(
            message,
            state_store=state_store,
            config=config,
            direction="server_to_client",
        )
        if message.get("method") == MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD
        else _check_resource_list_changed_notification(message, direction="server_to_client")
        for message in messages
    ]
    checks = [item for item in checks if item]
    if checks:
        metadata["checked"] = True
        metadata["notifications"] = checks
        metadata["count"] = len(checks)
        if any(item.get("warning") for item in checks):
            metadata["warning"] = True
        if any(item.get("blocked") for item in checks):
            metadata["blocked"] = True
            metadata["reason_code"] = next(
                (str(item.get("reason_code")) for item in checks if item.get("blocked") and item.get("reason_code")),
                "response.resource_change_blocked",
            )
            updated_payload = _block_resource_messages(payload)
            response = _replace_response_payload(response, updated_payload, response_format=response_format)

    return dict(response), metadata


def mcp_resource_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    reason = metadata.get("reason_code", "request.resource_policy")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32000,
                "message": f"MCP resource subscription/change message blocked by snulbug policy ({reason})",
                "data": {"reason_code": reason},
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


def _observe_subscription_response(
    request: Mapping[str, Any] | None,
    payload: Any,
    *,
    state_store: PolicyStateStore | None,
    config: ResourcePolicyConfig,
    metadata: dict[str, Any],
) -> None:
    if state_store is None or not isinstance(request, Mapping):
        return
    method = request.get("method")
    if method not in {MCP_RESOURCES_SUBSCRIBE_METHOD, MCP_RESOURCES_UNSUBSCRIBE_METHOD}:
        return
    uri = _resource_uri(request)
    if not uri or _jsonrpc_error(payload):
        return
    operation = "subscribe" if method == MCP_RESOURCES_SUBSCRIBE_METHOD else "unsubscribe"
    if method == MCP_RESOURCES_SUBSCRIBE_METHOD:
        record = {
            "uri_hash": _uri_hash(uri),
            "uri_scheme": _uri_scheme(uri),
            "subscribed": True,
        }
        state_store.put(
            _subscription_key(uri),
            json.dumps(record, separators=(",", ":")),
            ttl=config.subscription_ttl_seconds,
        )
    else:
        state_store.delete(_subscription_key(uri))
    metadata["checked"] = True
    metadata["subscription"] = _drop_empty(
        {
            "operation": operation,
            "resource": _resource_uri_summary(uri),
        }
    )


def _check_resource_updated_notification(
    message: Mapping[str, Any],
    *,
    state_store: PolicyStateStore | None,
    config: ResourcePolicyConfig,
    direction: str,
) -> dict[str, Any]:
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    uri = params.get("uri")
    metadata: dict[str, Any] = {
        "checked": True,
        "method": MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD,
        "operation": "updated",
        "direction": direction,
        "notification": _resource_message_metadata(
            message, source="response" if direction == "server_to_client" else "request"
        ),
    }
    if not isinstance(uri, str) or not uri:
        metadata["reason_code"] = "request.resource_uri_missing"
        return _flag(metadata, config)
    metadata["resource"] = _resource_uri_summary(uri)
    if state_store is None:
        return metadata
    if not state_store.get(_subscription_key(uri)):
        metadata["reason_code"] = "request.resource_update_unknown_subscription"
        return _flag(metadata, config)
    metadata["tracked"] = True
    return metadata


def _check_resource_list_changed_notification(message: Mapping[str, Any], *, direction: str) -> dict[str, Any]:
    if message.get("method") != MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD:
        return {}
    return {
        "checked": True,
        "method": MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD,
        "operation": "list_changed",
        "direction": direction,
    }


def _resource_message_metadata(message: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    method = message.get("method")
    if method not in MCP_RESOURCE_METHODS:
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    uri = params.get("uri")
    operation = {
        MCP_RESOURCES_SUBSCRIBE_METHOD: "subscribe",
        MCP_RESOURCES_UNSUBSCRIBE_METHOD: "unsubscribe",
        MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD: "updated",
        MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD: "list_changed",
    }.get(method)
    direction = "server_to_client" if source == "response" else "client_to_server"
    return _drop_empty(
        {
            "method": method,
            "source": source,
            "direction": direction,
            "operation": operation,
            "resource": _resource_uri_summary(uri) if isinstance(uri, str) and uri else None,
        }
    )


def _block_resource_messages(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        blocked = _blocked_resource_message(payload)
        return blocked if blocked is not None else payload
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        return [_blocked_resource_message(item) or item for item in payload]
    return payload


def _blocked_resource_message(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return None
    method = message.get("method")
    if method not in {
        MCP_RESOURCES_UPDATED_NOTIFICATION_METHOD,
        MCP_RESOURCES_LIST_CHANGED_NOTIFICATION_METHOD,
    }:
        return None
    return {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id(message),
        "error": {
            "code": -32000,
            "message": f"MCP {method} blocked by snulbug policy",
            "data": {
                "reason_code": "response.resource_change_blocked",
                "method": method,
            },
        },
    }


def _resource_uri(request: Mapping[str, Any]) -> str | None:
    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    uri = params.get("uri")
    return uri if isinstance(uri, str) and uri else None


def _resource_uri_summary(uri: str) -> dict[str, Any]:
    return {
        "uri": uri,
        "uri_hash": _uri_hash(uri)[:16],
        "scheme": _uri_scheme(uri),
    }


def _uri_scheme(uri: str) -> str | None:
    parsed = urlsplit(uri)
    return parsed.scheme or None


def _uri_hash(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()


def _subscription_key(uri: str) -> str:
    return f"snulbug:mcp-resource-subscription:{_uri_hash(uri)}"


def _allowed(metadata: Mapping[str, Any], config: ResourcePolicyConfig) -> bool:
    return not (metadata.get("blocked") is True and config.action == "block")


def _flag(metadata: dict[str, Any], config: ResourcePolicyConfig) -> dict[str, Any]:
    if config.action == "allow":
        return metadata
    if config.action == "warn":
        metadata["warning"] = True
        return metadata
    metadata["blocked"] = True
    return metadata


def _jsonrpc_error(payload: Any) -> bool:
    return isinstance(payload, Mapping) and isinstance(payload.get("error"), Mapping)


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


def _header_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("latin-1")


def _is_success_response(response: Mapping[str, Any]) -> bool:
    status = int(response.get("status", 0))
    return 200 <= status < 300


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in request:
        return None
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, {}, [], "")}

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .mcp_tasks import mcp_task_request_metadata, mcp_task_response_metadata
from .state import PolicyStateStore

MCP_PROGRESS_NOTIFICATION_METHOD = "notifications/progress"
MCP_CANCELLED_NOTIFICATION_METHOD = "notifications/cancelled"
MCP_TASK_CANCEL_METHOD = "tasks/cancel"
MCP_PROGRESS_POLICY_ACTIONS = ("allow", "warn", "block")
MCP_TERMINAL_TASK_STATUSES = {"completed", "failed", "cancelled"}


@dataclass(frozen=True)
class ProgressPolicyConfig:
    """MCP progress and cancellation controls."""

    action: str = "warn"
    progress_rate_limit: int = 60
    progress_rate_window_seconds: float = 60.0
    state_ttl_seconds: float = 3600.0

    def __post_init__(self) -> None:
        if self.action not in MCP_PROGRESS_POLICY_ACTIONS:
            raise ValueError("progress_policy_action must be 'allow', 'warn', or 'block'")
        if self.progress_rate_limit <= 0:
            raise ValueError("progress_rate_limit must be positive")
        if self.progress_rate_window_seconds <= 0:
            raise ValueError("progress_rate_window_seconds must be positive")
        if self.state_ttl_seconds <= 0:
            raise ValueError("progress_state_ttl_seconds must be positive")


def mcp_progress_request_metadata(message: Mapping[str, Any]) -> dict[str, Any]:
    method = message.get("method")
    if not isinstance(method, str):
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    metadata: dict[str, Any] = {}

    progress_token = _progress_token_from_request(message)
    if progress_token is not None:
        metadata["progress_token"] = _token_summary(progress_token)

    if method == MCP_PROGRESS_NOTIFICATION_METHOD:
        metadata.update(_progress_notification_metadata(message, source="request"))
    elif method == MCP_CANCELLED_NOTIFICATION_METHOD:
        metadata.update(_cancelled_notification_metadata(message, source="request"))
    elif method == MCP_TASK_CANCEL_METHOD:
        task_id = params.get("taskId")
        metadata["task_cancel"] = _drop_empty(
            {
                "method": method,
                "direction": "client_to_server",
                "task_id": task_id if isinstance(task_id, str) and task_id else None,
            }
        )
    task_metadata = mcp_task_request_metadata(message)
    if task_metadata:
        metadata["task"] = task_metadata
    return _drop_empty(metadata)


def mcp_progress_response_metadata(payload: Any) -> dict[str, Any]:
    messages = mcp_progress_messages_from_payload(payload)
    if not messages:
        return {}
    progress = [_progress_notification_metadata(item, source="response") for item in messages]
    progress = [item for item in progress if item]
    cancelled = [_cancelled_notification_metadata(item, source="response") for item in messages]
    cancelled = [item for item in cancelled if item]
    return _drop_empty(
        {
            "count": len(messages),
            "progress_count": len(progress),
            "cancelled_count": len(cancelled),
            "progress": progress,
            "cancelled": cancelled,
        }
    )


def mcp_progress_messages_from_payload(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        method = payload.get("method")
        if method in {MCP_PROGRESS_NOTIFICATION_METHOD, MCP_CANCELLED_NOTIFICATION_METHOD}:
            return [payload]
        return []
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        messages: list[Mapping[str, Any]] = []
        for item in payload:
            if isinstance(item, Mapping):
                messages.extend(mcp_progress_messages_from_payload(item))
        return messages
    return []


def enforce_mcp_progress_request_policy(
    request: Mapping[str, Any] | None,
    *,
    config: ProgressPolicyConfig,
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

    request_metadata = mcp_progress_request_metadata(request)
    if request_metadata:
        metadata["request"] = request_metadata

    _register_request(request, state_store=state_store, config=config, metadata=metadata)
    _observe_task_status_request(request, state_store=state_store, metadata=metadata)

    if method == MCP_PROGRESS_NOTIFICATION_METHOD:
        checked = _check_progress_notification(
            request,
            state_store=state_store,
            config=config,
            direction="client_to_server",
        )
        metadata.update(checked)
        return _allowed(checked, config), metadata

    if method == MCP_CANCELLED_NOTIFICATION_METHOD:
        checked = _check_cancelled_notification(
            request,
            state_store=state_store,
            config=config,
            direction="client_to_server",
        )
        metadata.update(checked)
        return _allowed(checked, config), metadata

    if method == MCP_TASK_CANCEL_METHOD:
        metadata["checked"] = True
        params = request.get("params")
        params = params if isinstance(params, Mapping) else {}
        task_id = params.get("taskId")
        if not isinstance(task_id, str) or not task_id:
            metadata["reason_code"] = "request.tasks_cancel_missing_task_id"
            return _allowed(metadata, config), metadata
        _cancel_task(task_id, state_store=state_store, metadata=metadata)
        return True, metadata

    return True, metadata


def enforce_mcp_progress_response_policy(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: ProgressPolicyConfig,
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
        _observe_request_completion(request, None, state_store=state_store, metadata=metadata)
        metadata["json_error"] = parse_error
        return dict(response), metadata

    messages = mcp_progress_messages_from_payload(payload)
    checks: list[dict[str, Any]] = []
    blocked_methods: list[str] = []
    for message in messages:
        method = message.get("method")
        if method == MCP_PROGRESS_NOTIFICATION_METHOD:
            check = _check_progress_notification(
                message,
                state_store=state_store,
                config=config,
                direction="server_to_client",
            )
        elif method == MCP_CANCELLED_NOTIFICATION_METHOD:
            check = _check_cancelled_notification(
                message,
                state_store=state_store,
                config=config,
                direction="server_to_client",
            )
        else:
            continue
        checks.append(check)
        if check.get("blocked"):
            blocked_methods.append(str(method))

    if checks:
        metadata["checked"] = True
        metadata["notifications"] = checks
        metadata["count"] = len(checks)
        if any(item.get("warning") for item in checks):
            metadata["warning"] = True
        if blocked_methods:
            metadata["blocked"] = True
            metadata["reason_code"] = next(
                (str(item.get("reason_code")) for item in checks if item.get("blocked") and item.get("reason_code")),
                "response.progress_cancel_blocked",
            )
            updated_payload = _block_progress_messages(payload)
            response = _replace_response_payload(response, updated_payload, response_format=response_format)

    _observe_request_completion(request, payload, state_store=state_store, metadata=metadata)
    return dict(response), metadata


def mcp_progress_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    reason = metadata.get("reason_code", "request.progress_policy")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32000,
                "message": f"MCP progress/cancellation message blocked by snulbug policy ({reason})",
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


def _register_request(
    request: Mapping[str, Any],
    *,
    state_store: PolicyStateStore | None,
    config: ProgressPolicyConfig,
    metadata: dict[str, Any],
) -> None:
    if state_store is None:
        return
    method = request.get("method")
    if not isinstance(method, str):
        return
    request_id = _jsonrpc_id(request)
    if request_id is None:
        return
    if method in {MCP_PROGRESS_NOTIFICATION_METHOD, MCP_CANCELLED_NOTIFICATION_METHOD}:
        return
    task_metadata = mcp_task_request_metadata(request)
    progress_token = _progress_token_from_request(request)
    record = _drop_empty(
        {
            "request_id": request_id,
            "method": method,
            "task_augmented": task_metadata.get("task_augmented") is True,
            "progress_token_hash": _token_hash(progress_token) if progress_token is not None else None,
        }
    )
    state_store.put(_request_key(request_id), json.dumps(record, separators=(",", ":")), ttl=config.state_ttl_seconds)
    metadata["tracked_request"] = _drop_empty(
        {
            "request_id": request_id,
            "method": method,
            "task_augmented": task_metadata.get("task_augmented") is True or None,
            "progress_token": _token_summary(progress_token) if progress_token is not None else None,
        }
    )
    if progress_token is None:
        return
    progress_record = _drop_empty(
        {
            "token_hash": _token_hash(progress_token),
            "request_id": request_id,
            "method": method,
            "task_augmented": task_metadata.get("task_augmented") is True,
            "last_progress": None,
            "terminal": False,
        }
    )
    state_store.put(
        _progress_key(progress_token),
        json.dumps(progress_record, separators=(",", ":")),
        ttl=config.state_ttl_seconds,
    )
    metadata["registered_progress_token"] = _token_summary(progress_token)


def _observe_request_completion(
    request: Mapping[str, Any] | None,
    payload: Any,
    *,
    state_store: PolicyStateStore | None,
    metadata: dict[str, Any],
) -> None:
    if state_store is None or not isinstance(request, Mapping):
        return
    request_id = _jsonrpc_id(request)
    if request_id is None:
        return
    token = _progress_token_from_request(request)
    task_metadata = mcp_task_request_metadata(request)
    response_task = mcp_task_response_metadata(payload)
    task_id = response_task.get("task_id")
    task_status = response_task.get("task_status")
    task_augmented = task_metadata.get("task_augmented") is True

    if isinstance(task_id, str) and token is not None:
        state_store.put(
            _task_key(task_id),
            json.dumps(
                {
                    "task_id": task_id,
                    "request_id": request_id,
                    "progress_token_hash": _token_hash(token),
                    "progress_key": _progress_key(token),
                },
                separators=(",", ":"),
            ),
            ttl=3600.0,
        )
        metadata["tracked_task"] = _drop_empty(
            {
                "task_id": task_id,
                "task_status": task_status if isinstance(task_status, str) else None,
                "progress_token": _token_summary(token),
            }
        )

    if isinstance(task_status, str) and task_status in MCP_TERMINAL_TASK_STATUSES and isinstance(task_id, str):
        _cancel_task(task_id, state_store=state_store, metadata=metadata, terminal_status=task_status)
        return

    if task_augmented and (not isinstance(task_status, str) or task_status not in MCP_TERMINAL_TASK_STATUSES):
        return

    state_store.delete(_request_key(request_id))
    if token is not None:
        state_store.delete(_progress_key(token))
        metadata["completed_progress_token"] = _token_summary(token)


def _observe_task_status_request(
    request: Mapping[str, Any],
    *,
    state_store: PolicyStateStore | None,
    metadata: dict[str, Any],
) -> None:
    if state_store is None:
        return
    task_metadata = mcp_task_request_metadata(request)
    task_id = task_metadata.get("task_id") or task_metadata.get("related_task_id")
    status = task_metadata.get("task_status")
    if isinstance(task_id, str) and isinstance(status, str) and status in MCP_TERMINAL_TASK_STATUSES:
        _cancel_task(task_id, state_store=state_store, metadata=metadata, terminal_status=status)


def _check_progress_notification(
    message: Mapping[str, Any],
    *,
    state_store: PolicyStateStore | None,
    config: ProgressPolicyConfig,
    direction: str,
) -> dict[str, Any]:
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    token = params.get("progressToken")
    progress = params.get("progress")
    total = params.get("total")
    metadata: dict[str, Any] = {
        "checked": True,
        "method": MCP_PROGRESS_NOTIFICATION_METHOD,
        "direction": direction,
        "progress_notification": _progress_notification_metadata(message, source="request"),
    }
    if not _valid_token(token):
        metadata["reason_code"] = "request.progress_missing_token"
        return _flag(metadata, config)
    metadata["progress_token"] = _token_summary(token)
    if not isinstance(progress, int | float) or isinstance(progress, bool):
        metadata["reason_code"] = "request.progress_invalid_value"
        return _flag(metadata, config)
    if total is not None and (not isinstance(total, int | float) or isinstance(total, bool)):
        metadata["reason_code"] = "request.progress_invalid_total"
        return _flag(metadata, config)
    if isinstance(total, int | float) and not isinstance(total, bool) and progress > total:
        metadata["reason_code"] = "request.progress_exceeds_total"
        return _flag(metadata, config)

    if state_store is None:
        return metadata
    rate_count = state_store.incr(
        _progress_rate_key(token),
        1,
        ttl=config.progress_rate_window_seconds,
    )
    metadata["rate_count"] = rate_count
    metadata["rate_limit"] = config.progress_rate_limit
    if rate_count > config.progress_rate_limit:
        metadata["reason_code"] = "request.progress_rate_limited"
        return _flag(metadata, config)

    record = _load_json(state_store.get(_progress_key(token)))
    if not record:
        metadata["reason_code"] = "request.progress_unknown_token"
        return _flag(metadata, config)
    if record.get("terminal") is True:
        metadata["reason_code"] = "request.progress_after_terminal"
        return _flag(metadata, config)
    previous = record.get("last_progress")
    if isinstance(previous, int | float) and progress <= previous:
        metadata["previous_progress"] = previous
        metadata["reason_code"] = "request.progress_non_monotonic"
        return _flag(metadata, config)

    record["last_progress"] = progress
    if isinstance(total, int | float):
        record["total"] = total
    state_store.put(_progress_key(token), json.dumps(record, separators=(",", ":")), ttl=config.state_ttl_seconds)
    metadata["tracked"] = True
    metadata["previous_progress"] = previous
    return metadata


def _check_cancelled_notification(
    message: Mapping[str, Any],
    *,
    state_store: PolicyStateStore | None,
    config: ProgressPolicyConfig,
    direction: str,
) -> dict[str, Any]:
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    request_id = params.get("requestId")
    metadata: dict[str, Any] = {
        "checked": True,
        "method": MCP_CANCELLED_NOTIFICATION_METHOD,
        "direction": direction,
        "cancelled_notification": _cancelled_notification_metadata(message, source="request"),
    }
    if request_id is None:
        metadata["reason_code"] = "request.cancel_missing_request_id"
        return _flag(metadata, config)
    metadata["cancelled_request_id"] = _request_id_summary(request_id)
    if state_store is None:
        return metadata

    record = _load_json(state_store.get(_request_key(request_id)))
    if not record:
        metadata["reason_code"] = "request.cancel_unknown_request"
        return _flag(metadata, config)
    if record.get("method") == "initialize":
        metadata["reason_code"] = "request.cancel_initialize_forbidden"
        return _flag(metadata, config)
    if record.get("task_augmented") is True:
        metadata["reason_code"] = "request.cancel_task_requires_tasks_cancel"
        return _flag(metadata, config)

    state_store.delete(_request_key(request_id))
    token_hash = record.get("progress_token_hash")
    if isinstance(token_hash, str):
        state_store.delete(_progress_key_from_hash(token_hash))
    metadata["cancelled"] = True
    return metadata


def _cancel_task(
    task_id: str,
    *,
    state_store: PolicyStateStore | None,
    metadata: dict[str, Any],
    terminal_status: str | None = None,
) -> None:
    if state_store is None:
        return
    record = _load_json(state_store.get(_task_key(task_id)))
    if not record:
        return
    progress_key = record.get("progress_key")
    request_id = record.get("request_id")
    if isinstance(progress_key, str):
        progress = _load_json(state_store.get(progress_key))
        if progress:
            progress["terminal"] = True
            if terminal_status:
                progress["terminal_status"] = terminal_status
            state_store.put(progress_key, json.dumps(progress, separators=(",", ":")), ttl=60.0)
        state_store.delete(progress_key)
    if request_id is not None:
        state_store.delete(_request_key(request_id))
    state_store.delete(_task_key(task_id))
    metadata["cancelled_task"] = _drop_empty({"task_id": task_id, "terminal_status": terminal_status})


def _allowed(metadata: Mapping[str, Any], config: ProgressPolicyConfig) -> bool:
    return not (metadata.get("blocked") is True and config.action == "block")


def _flag(metadata: dict[str, Any], config: ProgressPolicyConfig) -> dict[str, Any]:
    if config.action == "allow":
        return metadata
    if config.action == "warn":
        metadata["warning"] = True
        return metadata
    metadata["blocked"] = True
    return metadata


def _block_progress_messages(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        blocked = _blocked_progress_message(payload)
        return blocked if blocked is not None else payload
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        return [_blocked_progress_message(item) or item for item in payload]
    return payload


def _blocked_progress_message(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return None
    method = message.get("method")
    if method not in {MCP_PROGRESS_NOTIFICATION_METHOD, MCP_CANCELLED_NOTIFICATION_METHOD}:
        return None
    return {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id(message),
        "error": {
            "code": -32000,
            "message": f"MCP {method} blocked by snulbug policy",
            "data": {
                "reason_code": "response.progress_cancel_blocked",
                "method": method,
            },
        },
    }


def _progress_notification_metadata(message: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if message.get("method") != MCP_PROGRESS_NOTIFICATION_METHOD:
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    token = params.get("progressToken")
    progress = params.get("progress")
    total = params.get("total")
    message_value = params.get("message")
    return _drop_empty(
        {
            "method": MCP_PROGRESS_NOTIFICATION_METHOD,
            "source": source,
            "direction": "server_to_client" if source == "response" else "client_to_server",
            "token": _token_summary(token) if _valid_token(token) else None,
            "progress": progress if isinstance(progress, int | float) and not isinstance(progress, bool) else None,
            "total": total if isinstance(total, int | float) and not isinstance(total, bool) else None,
            "message_present": isinstance(message_value, str),
            "message_length": len(message_value) if isinstance(message_value, str) else None,
        }
    )


def _cancelled_notification_metadata(message: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    if message.get("method") != MCP_CANCELLED_NOTIFICATION_METHOD:
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    request_id = params.get("requestId")
    reason = params.get("reason")
    return _drop_empty(
        {
            "method": MCP_CANCELLED_NOTIFICATION_METHOD,
            "source": source,
            "direction": "server_to_client" if source == "response" else "client_to_server",
            "request_id": _request_id_summary(request_id) if request_id is not None else None,
            "reason_present": isinstance(reason, str),
            "reason_length": len(reason) if isinstance(reason, str) else None,
        }
    )


def _progress_token_from_request(request: Mapping[str, Any]) -> str | int | None:
    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    meta = params.get("_meta")
    meta = meta if isinstance(meta, Mapping) else {}
    token = meta.get("progressToken")
    return token if _valid_token(token) else None


def _valid_token(value: Any) -> bool:
    return (isinstance(value, str) and value != "") or (isinstance(value, int) and not isinstance(value, bool))


def _token_summary(value: Any) -> dict[str, Any]:
    return {
        "hash": _token_hash(value)[:16],
        "type": type(value).__name__,
    }


def _request_id_summary(value: Any) -> dict[str, Any]:
    return {
        "hash": _token_hash(value)[:16],
        "type": type(value).__name__,
    }


def _token_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _progress_key(value: Any) -> str:
    return _progress_key_from_hash(_token_hash(value))


def _progress_key_from_hash(value: str) -> str:
    return f"snulbug:mcp-progress:token:{value}"


def _progress_rate_key(value: Any) -> str:
    return f"snulbug:mcp-progress:rate:{_token_hash(value)}"


def _request_key(value: Any) -> str:
    return f"snulbug:mcp-progress:request:{_token_hash(value)}"


def _task_key(value: str) -> str:
    return f"snulbug:mcp-progress:task:{_token_hash(value)}"


def _load_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


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

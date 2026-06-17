from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

CAPABILITY_REQUEST_SCHEMA = "snulbug.capability_request.v1"
CAPABILITY_ERROR_CODE = -32001


def capability_request_from_decision(
    decision: Mapping[str, Any],
    request: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    raw = decision.get("capability_request")
    if not isinstance(raw, Mapping):
        return None
    mcp = _mcp_request(request)
    suggested = _mapping(raw.get("suggested_lease"))
    tool = _string(raw.get("tool")) or _string(mcp.get("tool"))
    method = _string(raw.get("method")) or _string(mcp.get("method"))
    argument_keys = _string_list(raw.get("argument_keys")) or _string_list(mcp.get("argument_keys"))
    allow_tools = _string_list(raw.get("allow_tools")) or _string_list(suggested.get("allow_tools"))
    if not allow_tools and tool:
        allow_tools = [tool]

    suggested_lease = _drop_empty(
        {
            "task": _string(raw.get("task")) or _string(suggested.get("task")) or _default_task(method, tool),
            "ttl": _string(raw.get("ttl")) or _string(suggested.get("ttl")) or "30m",
            "allow_tools": allow_tools,
            "allow_paths": _string_list(raw.get("allow_paths")) or _string_list(suggested.get("allow_paths")),
            "allow_hosts": _string_list(raw.get("allow_hosts")) or _string_list(suggested.get("allow_hosts")),
            "allow_commands": _string_list(raw.get("allow_commands")) or _string_list(suggested.get("allow_commands")),
            "max_calls": _positive_int(raw.get("max_calls"), suggested.get("max_calls")),
        }
    )
    return _drop_empty(
        {
            "schema": CAPABILITY_REQUEST_SCHEMA,
            "kind": _string(raw.get("kind")) or "task_lease",
            "task": _string(raw.get("task")) or suggested_lease.get("task"),
            "reason": _string(decision.get("reason")),
            "reason_code": _string(decision.get("reason_code")) or "mcp.capability_request",
            "method": method,
            "tool": tool,
            "argument_keys": argument_keys,
            "suggested_lease": suggested_lease,
        }
    )


def mcp_capability_error_response(
    request: Mapping[str, Any],
    decision: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any] | None:
    capability_request = capability_request_from_decision(decision, request)
    if capability_request is None:
        return None
    mcp = _mcp_request(request)
    reason_code = (
        _string(decision.get("reason_code")) or capability_request.get("reason_code") or "mcp.capability_request"
    )
    payload = {
        "jsonrpc": "2.0",
        "id": mcp.get("id"),
        "error": {
            "code": CAPABILITY_ERROR_CODE,
            "message": _string(decision.get("body"))
            or _string(decision.get("reason"))
            or "MCP capability requires approval",
            "data": _drop_empty(
                {
                    "type": "snulbug.capability_request",
                    "schema": CAPABILITY_REQUEST_SCHEMA,
                    "reason_code": reason_code,
                    "capability_request": capability_request,
                    "confirmation": _confirmation_metadata(confirmation),
                    "approval": {
                        "mechanism": "snulbug.confirm",
                        "lease_mechanism": "snulbug.task_lease",
                    },
                }
            ),
        },
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {
        "status": 200,
        "headers": {
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
        "body": body,
    }


def capability_request_metadata(
    decision: Mapping[str, Any],
    request: Mapping[str, Any],
    confirmation: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    capability_request = capability_request_from_decision(decision, request)
    if capability_request is None:
        return None
    metadata: dict[str, Any] = {
        "requested": True,
        "reason_code": capability_request.get("reason_code"),
        "capability_request": capability_request,
    }
    if confirmation is not None:
        metadata["confirmation"] = _confirmation_metadata(confirmation)
    return metadata


def _mcp_request(request: Mapping[str, Any] | None) -> dict[str, Any]:
    body = request.get("body") if isinstance(request, Mapping) else None
    if not isinstance(body, str) or not body:
        return {}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, Mapping):
        return {}
    params = payload.get("params") if isinstance(payload.get("params"), Mapping) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), Mapping) else {}
    tool = params.get("name")
    method = payload.get("method")
    return _drop_empty(
        {
            "id": _jsonrpc_id(payload),
            "method": method if isinstance(method, str) else None,
            "tool": tool if isinstance(tool, str) else None,
            "argument_keys": sorted(str(key) for key in arguments),
        }
    )


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _confirmation_metadata(confirmation: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "approved": bool(confirmation.get("approved", False)),
            "mode": _string(confirmation.get("mode")),
            "reason": _string(confirmation.get("reason")),
            "reason_code": _string(confirmation.get("reason_code")),
            "remember_key": _string(confirmation.get("remember_key")),
        }
    )


def _default_task(method: str | None, tool: str | None) -> str:
    if tool:
        return f"Temporary MCP access for {tool}"
    if method:
        return f"Temporary MCP access for {method}"
    return "Temporary MCP access"


def _positive_int(*values: Any) -> int | None:
    for value in values:
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str):
            try:
                parsed = int(value)
            except ValueError:
                continue
            if parsed > 0:
                return parsed
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item) for item in value if str(item)]
    if isinstance(value, Mapping):
        return [str(key) for key, enabled in value.items() if enabled is True and str(key)]
    return []


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}

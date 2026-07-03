from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MCP_COMPLETION_METHOD = "completion/complete"
COMPLETION_POLICY_ACTIONS = ("allow", "warn", "block")

PATH_LIKE_RE = re.compile(r"(?:^|[/\\])(?:\.{1,2}|[A-Za-z0-9_.-]+)(?:[/\\][A-Za-z0-9_.-]+)+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
SECRET_LIKE_RE = re.compile(r"(?:token|secret|credential|password|api[_-]?key|private)", re.I)
TENANT_LIKE_RE = re.compile(r"(?:tenant|org|organization|workspace|project|repo|user|account)", re.I)


@dataclass(frozen=True)
class CompletionPolicyConfig:
    """Request-side MCP completion controls."""

    action: str = "warn"

    def __post_init__(self) -> None:
        if self.action not in COMPLETION_POLICY_ACTIONS:
            raise ValueError("completion_policy_action must be 'allow', 'warn', or 'block'")


def is_mcp_completion_request_method(method: Any) -> bool:
    return method == MCP_COMPLETION_METHOD


def mcp_completion_request_metadata(message: Mapping[str, Any]) -> dict[str, Any]:
    method = message.get("method")
    if not is_mcp_completion_request_method(method):
        return {}
    params = message.get("params")
    params = params if isinstance(params, Mapping) else {}
    ref = params.get("ref")
    ref = ref if isinstance(ref, Mapping) else {}
    argument = params.get("argument")
    argument = argument if isinstance(argument, Mapping) else {}
    context = params.get("context")
    context = context if isinstance(context, Mapping) else {}
    context_arguments = context.get("arguments")
    context_arguments = context_arguments if isinstance(context_arguments, Mapping) else {}

    ref_type = _string(ref.get("type"))
    ref_name = _string(ref.get("name"))
    ref_uri = _string(ref.get("uri"))
    argument_name = _string(argument.get("name"))
    argument_value = argument.get("value")
    risk_flags = _completion_risk_flags(
        ref_type=ref_type,
        ref_name=ref_name,
        ref_uri=ref_uri,
        argument_name=argument_name,
        argument_value=argument_value,
        context_arguments=context_arguments,
    )
    metadata: dict[str, Any] = {
        "method": MCP_COMPLETION_METHOD,
        "feature": "completion",
        "direction": "client_to_server",
        "high_risk": bool(risk_flags),
        "request_id": _jsonrpc_id(message),
        "ref": _drop_empty(
            {
                "type": ref_type,
                "name": ref_name,
                "uri": ref_uri,
                "uri_scheme": _uri_scheme(ref_uri),
                "uri_template": _has_template_variable(ref_uri),
            }
        ),
        "argument": _drop_empty(
            {
                "name": argument_name,
                "value_present": "value" in argument,
                "value_type": type(argument_value).__name__ if "value" in argument else None,
                "value_length": len(argument_value) if isinstance(argument_value, str) else None,
                "value_empty": argument_value == "" if isinstance(argument_value, str) else None,
            }
        ),
        "context": _drop_empty(
            {
                "argument_count": len(context_arguments),
                "argument_keys": sorted(str(key) for key in context_arguments),
            }
        ),
        "risk_flags": risk_flags,
        "target": ref_name or ref_uri,
    }
    return _drop_empty(metadata)


def mcp_completion_response_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return {}
    completion = result.get("completion")
    if not isinstance(completion, Mapping):
        return {}
    values = completion.get("values")
    values_list = [value for value in values if isinstance(value, str)] if _is_sequence(values) else []
    value_risks = sorted({flag for value in values_list for flag in _value_risk_flags(value)})
    metadata = {
        "values_count": len(values_list),
        "total": completion.get("total") if isinstance(completion.get("total"), int | float) else None,
        "has_more": completion.get("hasMore") if isinstance(completion.get("hasMore"), bool) else None,
        "max_value_length": max((len(value) for value in values_list), default=0) if values_list else None,
        "value_risk_flags": value_risks,
        "truncated": len(values_list) >= 100 or completion.get("hasMore") is True,
    }
    return _drop_empty(metadata)


def enforce_mcp_completion_request_policy(
    request: Mapping[str, Any] | None,
    *,
    config: CompletionPolicyConfig,
) -> tuple[bool, dict[str, Any]]:
    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "checked": False,
        "action": config.action,
        "method": method,
    }
    if not isinstance(request, Mapping) or method != MCP_COMPLETION_METHOD:
        return True, metadata
    completion = mcp_completion_request_metadata(request)
    metadata.update(
        {
            "checked": True,
            "completion": completion,
        }
    )
    if config.action == "allow":
        return True, metadata
    metadata["reason_code"] = "request.completion_policy"
    if config.action == "warn":
        metadata["warning"] = True
        return True, metadata
    metadata["blocked"] = True
    metadata["reason_code"] = "request.completion_blocked"
    return False, metadata


def mcp_completion_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    reason = metadata.get("reason_code", "request.completion_blocked")
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32000,
                "message": f"MCP completion request blocked by snulbug policy ({reason})",
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


def _completion_risk_flags(
    *,
    ref_type: str | None,
    ref_name: str | None,
    ref_uri: str | None,
    argument_name: str | None,
    argument_value: Any,
    context_arguments: Mapping[str, Any],
) -> list[str]:
    flags: set[str] = set()
    if ref_type == "ref/resource":
        flags.add("resource_ref")
    elif ref_type == "ref/prompt":
        flags.add("prompt_ref")
    if ref_uri:
        flags.add("resource_uri")
        if _has_template_variable(ref_uri):
            flags.add("uri_template")
        scheme = _uri_scheme(ref_uri)
        if scheme in {"file", "ssh", "sftp"}:
            flags.add(f"{scheme}_uri")
    for name in (ref_name, argument_name):
        if name and TENANT_LIKE_RE.search(name):
            flags.add("tenant_like_name")
        if name and SECRET_LIKE_RE.search(name):
            flags.add("sensitive_like_name")
    if isinstance(argument_value, str):
        flags.update(_value_risk_flags(argument_value, prefix="argument"))
    for key, value in context_arguments.items():
        if SECRET_LIKE_RE.search(str(key)):
            flags.add("sensitive_like_context_key")
        if TENANT_LIKE_RE.search(str(key)):
            flags.add("tenant_like_context_key")
        if isinstance(value, str):
            flags.update(_value_risk_flags(value, prefix="context"))
    if context_arguments:
        flags.add("context_arguments")
    return sorted(flags)


def _value_risk_flags(value: str, *, prefix: str = "value") -> set[str]:
    flags: set[str] = set()
    if _looks_like_uri(value):
        flags.add(f"{prefix}_uri_like")
    if _looks_like_path(value):
        flags.add(f"{prefix}_path_like")
    if SECRET_LIKE_RE.search(value):
        flags.add(f"{prefix}_sensitive_like")
    if TENANT_LIKE_RE.search(value):
        flags.add(f"{prefix}_tenant_like")
    return flags


def _looks_like_uri(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(parsed.scheme and (parsed.netloc or parsed.path))


def _looks_like_path(value: str) -> bool:
    if not value or " " in value:
        return False
    return bool(
        value.startswith(("/", "~/", "../", "./")) or WINDOWS_PATH_RE.match(value) or PATH_LIKE_RE.search(value)
    )


def _uri_scheme(value: str | None) -> str | None:
    if not value:
        return None
    return urlsplit(value).scheme or None


def _has_template_variable(value: str | None) -> bool | None:
    if not value:
        return None
    return "{" in value and "}" in value


def _jsonrpc_id(message: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in message:
        return None
    value = message.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}

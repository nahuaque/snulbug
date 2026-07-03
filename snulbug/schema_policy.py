from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .mcp_tasks import normalize_task_support
from .state import PolicyStateStore

TOOL_SCHEMA_KEY_PREFIX = "snulbug:tool-schema:"
TOOL_METADATA_KEY_PREFIX = "snulbug:tool-metadata:"
SERVER_METADATA_KEY = "snulbug:server-metadata"


@dataclass(frozen=True)
class SchemaPolicyConfig:
    """Request-side MCP tool argument validation."""

    enabled: bool = True
    action: str = "block"

    def __post_init__(self) -> None:
        if self.action not in {"warn", "block"}:
            raise ValueError("schema_validation_action must be 'warn' or 'block'")


def observe_mcp_tool_schemas(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore | None,
) -> dict[str, Any]:
    """Persist tool schemas and metadata from a successful MCP tools/list response."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.enabled,
        "action": config.action,
        "store": tool_schema_store is not None,
        "observed": False,
        "method": method,
    }
    if not config.enabled or tool_schema_store is None or not _is_success_response(response):
        return metadata

    payload, parse_error = _decode_json(_response_body(response))
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return metadata

    if method == "initialize":
        server_metadata = normalize_mcp_server_metadata(payload)
        if server_metadata is not None:
            encoded_server_metadata = json.dumps(server_metadata, sort_keys=True, separators=(",", ":"), default=str)
            tool_schema_store.put(SERVER_METADATA_KEY, encoded_server_metadata)
            metadata["observed"] = True
            metadata["stored_server_metadata"] = True
            metadata["server_tasks_capability"] = server_metadata["tasks"]["tools_call"] is True
        return metadata

    if method != "tools/list":
        return metadata

    tools = _tools_from_response(payload)
    if tools is None:
        return metadata

    stored = []
    stored_metadata = []
    skipped = []
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            continue
        tool_metadata = normalize_mcp_tool_metadata(tool)
        if tool_metadata is not None:
            encoded_metadata = json.dumps(tool_metadata, sort_keys=True, separators=(",", ":"), default=str)
            tool_schema_store.put(f"{TOOL_METADATA_KEY_PREFIX}{tool['name']}", encoded_metadata)
            stored_metadata.append({"tool": tool["name"]})
        schema = tool.get("inputSchema")
        if not _is_schema(schema):
            skipped.append({"tool": tool["name"], "reason_code": "schema.missing_or_invalid"})
            continue
        encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str)
        tool_schema_store.put(f"{TOOL_SCHEMA_KEY_PREFIX}{tool['name']}", encoded)
        stored.append({"tool": tool["name"]})

    metadata["observed"] = True
    metadata["stored"] = stored
    if stored_metadata:
        metadata["stored_metadata"] = stored_metadata
    if skipped:
        metadata["skipped"] = skipped
    return metadata


def enforce_mcp_request_schema_policy(
    request: Mapping[str, Any] | None,
    *,
    config: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore | None,
) -> tuple[bool, dict[str, Any]]:
    """Validate MCP tools/call params.arguments against the cached inputSchema."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.enabled,
        "action": config.action,
        "store": tool_schema_store is not None,
        "checked": False,
        "method": method,
    }
    if not config.enabled or tool_schema_store is None or method != "tools/call":
        return True, metadata

    params = request.get("params")
    if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
        return True, metadata

    tool_name = params["name"]
    metadata["tool"] = tool_name
    metadata["checked"] = True

    task_allowed, task_metadata = _enforce_task_support(
        params,
        tool_name=tool_name,
        config=config,
        tool_schema_store=tool_schema_store,
    )
    if task_metadata:
        metadata["task"] = task_metadata
        if task_metadata.get("reason_code"):
            metadata["reason_code"] = task_metadata["reason_code"]
        if task_metadata.get("valid") is False:
            metadata["valid"] = False
        if task_metadata.get("blocked") is True:
            metadata["blocked"] = True
            metadata["issues"] = task_metadata.get("issues", [])
    if not task_allowed:
        return False, metadata

    encoded = tool_schema_store.get(f"{TOOL_SCHEMA_KEY_PREFIX}{tool_name}")
    if encoded is None:
        metadata["known_schema"] = False
        metadata["skipped"] = "schema_not_seen"
        return True, metadata

    metadata["known_schema"] = True
    try:
        schema = json.loads(encoded)
    except json.JSONDecodeError as exc:
        metadata["valid"] = False
        metadata["reason_code"] = "request.schema_cache_invalid"
        metadata["issues"] = [{"path": "$", "message": f"cached schema is invalid JSON: {exc}"}]
        return config.action != "block", metadata

    arguments = params.get("arguments", {})
    issues = _validate_value(arguments, schema, path="$", root=schema, seen_refs=())
    if not issues:
        metadata["valid"] = True
        return True, metadata

    metadata["valid"] = False
    metadata["reason_code"] = "request.schema_argument_invalid"
    metadata["issues"] = issues[:20]
    if config.action == "block":
        metadata["blocked"] = True
        return False, metadata
    return True, metadata


def mcp_schema_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    issue = _first_issue(metadata)
    detail = f": {issue}" if issue else ""
    message = _schema_error_message(metadata)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32602,
                "message": f"{message}{detail}",
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


def enforce_mcp_response_schema_policy(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate MCP tools/call result.structuredContent against cached outputSchema."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.enabled,
        "action": config.action,
        "store": tool_schema_store is not None,
        "checked": False,
        "method": method,
    }
    if not config.enabled or tool_schema_store is None or method != "tools/call":
        return dict(response), metadata

    params = request.get("params") if isinstance(request, Mapping) else None
    if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
        return dict(response), metadata
    tool_name = params["name"]
    metadata["tool"] = tool_name

    encoded = tool_schema_store.get(f"{TOOL_METADATA_KEY_PREFIX}{tool_name}")
    if encoded is None:
        metadata["known_schema"] = False
        metadata["skipped"] = "schema_not_seen"
        return dict(response), metadata
    metadata["known_schema"] = True
    try:
        tool_metadata = json.loads(encoded)
    except json.JSONDecodeError as exc:
        metadata["checked"] = True
        metadata["valid"] = False
        metadata["reason_code"] = "response.schema_cache_invalid"
        metadata["issues"] = [{"path": "$", "message": f"cached tool metadata is invalid JSON: {exc}"}]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata

    if not isinstance(tool_metadata, Mapping):
        metadata["checked"] = True
        metadata["valid"] = False
        metadata["reason_code"] = "response.schema_cache_invalid"
        metadata["issues"] = [{"path": "$", "message": "cached tool metadata is not an object"}]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata

    output_schema = tool_metadata.get("outputSchema")
    task_support = _task_support_from_metadata(tool_metadata)
    if task_support is not None:
        metadata["taskSupport"] = task_support
    if not _is_schema(output_schema):
        metadata["skipped"] = "output_schema_not_declared"
        return dict(response), metadata

    metadata["checked"] = True
    payload, parse_error = _decode_json(_response_body(response))
    if parse_error is not None:
        metadata["valid"] = False
        metadata["reason_code"] = "response.json_invalid"
        metadata["issues"] = [{"path": "$", "reason_code": "json.invalid", "message": parse_error}]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata
    if not isinstance(payload, Mapping):
        metadata["valid"] = False
        metadata["reason_code"] = "response.jsonrpc_invalid"
        metadata["issues"] = [{"path": "$", "reason_code": "jsonrpc.invalid", "message": "response is not an object"}]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata

    if isinstance(payload.get("error"), Mapping):
        metadata["skipped"] = "jsonrpc_error"
        return dict(response), metadata
    result = payload.get("result")
    if not isinstance(result, Mapping):
        metadata["valid"] = False
        metadata["reason_code"] = "response.tool_result_missing"
        metadata["issues"] = [
            {"path": "$.result", "reason_code": "jsonrpc.result_missing", "message": "tool result is missing"}
        ]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata
    if result.get("isError") is True:
        metadata["skipped"] = "tool_execution_error"
        return dict(response), metadata
    if "structuredContent" not in result:
        metadata["valid"] = False
        metadata["reason_code"] = "response.structured_content_missing"
        metadata["issues"] = [
            {
                "path": "$.result.structuredContent",
                "reason_code": "schema.required",
                "message": "structuredContent is required when outputSchema is declared",
            }
        ]
        if config.action == "block":
            metadata["blocked"] = True
            return mcp_output_schema_error_response(request, metadata), metadata
        return dict(response), metadata

    structured_content = result.get("structuredContent")
    issues = _validate_value(
        structured_content, output_schema, path="$.result.structuredContent", root=output_schema, seen_refs=()
    )
    if not issues:
        metadata["valid"] = True
        metadata["structuredContent"] = True
        return dict(response), metadata

    metadata["valid"] = False
    metadata["structuredContent"] = True
    metadata["reason_code"] = "response.output_schema_invalid"
    metadata["issues"] = issues[:20]
    if config.action == "block":
        metadata["blocked"] = True
        return mcp_output_schema_error_response(request, metadata), metadata
    return dict(response), metadata


def mcp_output_schema_error_response(request: Mapping[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    issue = _first_issue(metadata)
    detail = f": {issue}" if issue else ""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32000,
                "message": f"MCP tool result rejected by outputSchema{detail}",
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


def normalize_mcp_tool_metadata(tool: Mapping[str, Any]) -> dict[str, Any] | None:
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        return None
    execution = _normalize_tool_execution(tool.get("execution"))
    if execution is None:
        execution = {"taskSupport": "forbidden"}
    elif "taskSupport" not in execution:
        execution = {**execution, "taskSupport": "forbidden"}
    return _drop_tool_metadata_empty(
        {
            "name": name,
            "title": tool.get("title") if isinstance(tool.get("title"), str) else None,
            "description": tool.get("description") if isinstance(tool.get("description"), str) else None,
            "icons": list(tool.get("icons")) if _is_sequence(tool.get("icons")) else None,
            "inputSchema": tool.get("inputSchema") if _is_schema(tool.get("inputSchema")) else None,
            "outputSchema": tool.get("outputSchema") if _is_schema(tool.get("outputSchema")) else None,
            "annotations": dict(tool.get("annotations")) if isinstance(tool.get("annotations"), Mapping) else None,
            "execution": execution,
        }
    )


def normalize_mcp_server_metadata(payload: Mapping[str, Any]) -> dict[str, Any] | None:
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    capabilities = result.get("capabilities")
    capabilities = capabilities if isinstance(capabilities, Mapping) else {}
    return {
        "protocolVersion": result.get("protocolVersion") if isinstance(result.get("protocolVersion"), str) else None,
        "tasks": {"tools_call": _server_tasks_tools_call_supported(capabilities)},
    }


def _server_tasks_tools_call_supported(capabilities: Mapping[str, Any]) -> bool:
    tasks = capabilities.get("tasks")
    tasks = tasks if isinstance(tasks, Mapping) else {}
    requests = tasks.get("requests")
    requests = requests if isinstance(requests, Mapping) else {}
    tools = requests.get("tools")
    tools = tools if isinstance(tools, Mapping) else {}
    return isinstance(tools.get("call"), Mapping)


def _enforce_task_support(
    params: Mapping[str, Any],
    *,
    tool_name: str,
    config: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore,
) -> tuple[bool, dict[str, Any]]:
    metadata: dict[str, Any] = {
        "checked": True,
        "tool": tool_name,
        "task_augmented": isinstance(params.get("task"), Mapping),
    }

    tool_metadata, tool_error = _cached_json(tool_schema_store, f"{TOOL_METADATA_KEY_PREFIX}{tool_name}")
    if tool_error:
        metadata.update(
            {
                "known_metadata": True,
                "valid": False,
                "reason_code": "request.task_metadata_cache_invalid",
                "issues": [_issue("$", "cache.invalid", tool_error)],
            }
        )
        return config.action != "block", _blocked_metadata(metadata, config)
    if not isinstance(tool_metadata, Mapping):
        metadata["known_metadata"] = False
        metadata["skipped"] = "tool_metadata_not_seen"
        return True, metadata

    task_support = _task_support_from_metadata(tool_metadata) or "forbidden"
    metadata["known_metadata"] = True
    metadata["taskSupport"] = task_support

    server_metadata, server_error = _cached_json(tool_schema_store, SERVER_METADATA_KEY)
    if server_error:
        metadata.update(
            {
                "server_metadata_seen": True,
                "valid": False,
                "reason_code": "request.server_task_capability_cache_invalid",
                "issues": [_issue("$", "cache.invalid", server_error)],
            }
        )
        return config.action != "block", _blocked_metadata(metadata, config)
    server_tasks_capability = _server_tasks_tools_call_capability_from_metadata(server_metadata)
    metadata["server_tasks_capability"] = server_tasks_capability
    metadata["server_metadata_seen"] = isinstance(server_metadata, Mapping)

    if metadata["task_augmented"] and task_support == "forbidden":
        metadata.update(
            {
                "valid": False,
                "reason_code": "request.task_forbidden",
                "issues": [
                    _issue(
                        "$.params.task",
                        "task.forbidden",
                        "tool execution.taskSupport is forbidden",
                    )
                ],
            }
        )
        return config.action != "block", _blocked_metadata(metadata, config)

    if task_support == "required" and not metadata["task_augmented"]:
        metadata.update(
            {
                "valid": False,
                "reason_code": "request.task_required",
                "issues": [
                    _issue(
                        "$.params.task",
                        "task.required",
                        "tool execution.taskSupport requires a task wrapper",
                    )
                ],
            }
        )
        return config.action != "block", _blocked_metadata(metadata, config)

    if metadata["task_augmented"] and server_tasks_capability is not True:
        metadata.update(
            {
                "valid": False,
                "reason_code": "request.server_tasks_capability_missing",
                "issues": [
                    _issue(
                        "$.params.task",
                        "task.server_capability_missing",
                        "server capabilities do not declare tasks.requests.tools.call",
                    )
                ],
            }
        )
        return config.action != "block", _blocked_metadata(metadata, config)

    metadata["valid"] = True
    return True, metadata


def _blocked_metadata(metadata: Mapping[str, Any], config: SchemaPolicyConfig) -> dict[str, Any]:
    result = dict(metadata)
    if config.action == "block":
        result["blocked"] = True
    return result


def _cached_json(store: PolicyStateStore, key: str) -> tuple[Any, str | None]:
    encoded = store.get(key)
    if encoded is None:
        return None, None
    try:
        return json.loads(encoded), None
    except json.JSONDecodeError as exc:
        return None, f"cached JSON is invalid: {exc}"


def _server_tasks_tools_call_capability_from_metadata(metadata: Any) -> bool | None:
    if not isinstance(metadata, Mapping):
        return None
    tasks = metadata.get("tasks")
    tasks = tasks if isinstance(tasks, Mapping) else {}
    value = tasks.get("tools_call")
    return value if isinstance(value, bool) else None


def _normalize_tool_execution(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    normalized = dict(value)
    task_support = normalize_task_support(normalized.get("taskSupport"))
    if task_support is not None:
        normalized["taskSupport"] = task_support
    elif "taskSupport" in normalized:
        normalized.pop("taskSupport", None)
    return normalized or None


def _task_support_from_metadata(metadata: Mapping[str, Any]) -> str | None:
    execution = metadata.get("execution")
    execution = execution if isinstance(execution, Mapping) else {}
    return normalize_task_support(execution.get("taskSupport"))


def _validate_value(
    value: Any,
    schema: Any,
    *,
    path: str,
    root: Any,
    seen_refs: tuple[str, ...],
) -> list[dict[str, str]]:
    if schema is True:
        return []
    if schema is False:
        return [_issue(path, "schema.false", "value is not allowed")]
    if not isinstance(schema, Mapping):
        return []

    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen_refs:
            return [_issue(path, "schema.ref_cycle", f"cyclic $ref {ref!r}")]
        resolved = _resolve_ref(root, ref)
        if resolved is None:
            return [_issue(path, "schema.ref_unresolved", f"unresolved $ref {ref!r}")]
        return _validate_value(value, resolved, path=path, root=root, seen_refs=(*seen_refs, ref))

    issues: list[dict[str, str]] = []

    type_issues = _validate_type(value, schema, path)
    if type_issues:
        issues.extend(type_issues)
        return issues

    if "const" in schema and value != schema["const"]:
        issues.append(_issue(path, "schema.const", "value does not match const"))
    enum = schema.get("enum")
    if isinstance(enum, Sequence) and not isinstance(enum, str | bytes | bytearray) and value not in enum:
        issues.append(_issue(path, "schema.enum", "value is not in enum"))

    for keyword in ("allOf", "anyOf", "oneOf"):
        issues.extend(_validate_combinator(value, schema, keyword, path=path, root=root, seen_refs=seen_refs))

    if isinstance(value, Mapping):
        issues.extend(_validate_object(value, schema, path=path, root=root, seen_refs=seen_refs))
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        issues.extend(_validate_array(value, schema, path=path, root=root, seen_refs=seen_refs))
    elif isinstance(value, str):
        issues.extend(_validate_string(value, schema, path=path))
    elif isinstance(value, int | float) and not isinstance(value, bool):
        issues.extend(_validate_number(value, schema, path=path))

    return issues


def _validate_type(value: Any, schema: Mapping[str, Any], path: str) -> list[dict[str, str]]:
    expected = schema.get("type")
    if expected is None:
        return []
    expected_types = [expected] if isinstance(expected, str) else expected
    if not isinstance(expected_types, Sequence) or isinstance(expected_types, str | bytes | bytearray):
        return []
    allowed = [item for item in expected_types if isinstance(item, str)]
    if not allowed or any(_matches_type(value, item) for item in allowed):
        return []
    return [_issue(path, "schema.type", f"expected type {' or '.join(allowed)}")]


def _validate_object(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    path: str,
    root: Any,
    seen_refs: tuple[str, ...],
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    properties = schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}

    required = schema.get("required", [])
    if isinstance(required, Sequence) and not isinstance(required, str | bytes | bytearray):
        for key in required:
            if isinstance(key, str) and key not in value:
                issues.append(_issue(_child_path(path, key), "schema.required", "required property is missing"))

    for key, item in value.items():
        child_schema = properties.get(key)
        if child_schema is not None:
            issues.extend(
                _validate_value(item, child_schema, path=_child_path(path, str(key)), root=root, seen_refs=seen_refs)
            )

    additional = schema.get("additionalProperties", True)
    extras = [(key, str(key), item) for key, item in value.items() if key not in properties]
    if additional is False:
        for _key, key_path, _item in extras:
            issues.append(
                _issue(_child_path(path, key_path), "schema.additional_properties", "property is not allowed")
            )
    elif _is_schema(additional):
        for _key, key_path, item in extras:
            issues.extend(
                _validate_value(item, additional, path=_child_path(path, key_path), root=root, seen_refs=seen_refs)
            )

    return issues


def _validate_array(
    value: Sequence[Any],
    schema: Mapping[str, Any],
    *,
    path: str,
    root: Any,
    seen_refs: tuple[str, ...],
) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    min_items = schema.get("minItems")
    max_items = schema.get("maxItems")
    if isinstance(min_items, int) and len(value) < min_items:
        issues.append(_issue(path, "schema.min_items", f"expected at least {min_items} items"))
    if isinstance(max_items, int) and len(value) > max_items:
        issues.append(_issue(path, "schema.max_items", f"expected at most {max_items} items"))
    item_schema = schema.get("items")
    if _is_schema(item_schema):
        for index, item in enumerate(value):
            issues.extend(_validate_value(item, item_schema, path=f"{path}[{index}]", root=root, seen_refs=seen_refs))
    return issues


def _validate_string(value: str, schema: Mapping[str, Any], *, path: str) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    min_length = schema.get("minLength")
    max_length = schema.get("maxLength")
    if isinstance(min_length, int) and len(value) < min_length:
        issues.append(_issue(path, "schema.min_length", f"expected at least {min_length} characters"))
    if isinstance(max_length, int) and len(value) > max_length:
        issues.append(_issue(path, "schema.max_length", f"expected at most {max_length} characters"))
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        try:
            matched = re.search(pattern, value) is not None
        except re.error as exc:
            issues.append(_issue(path, "schema.pattern_invalid", f"invalid pattern: {exc}"))
        else:
            if not matched:
                issues.append(_issue(path, "schema.pattern", "string does not match pattern"))
    return issues


def _validate_number(value: int | float, schema: Mapping[str, Any], *, path: str) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    exclusive_minimum = schema.get("exclusiveMinimum")
    exclusive_maximum = schema.get("exclusiveMaximum")
    if isinstance(minimum, int | float) and value < minimum:
        issues.append(_issue(path, "schema.minimum", f"expected >= {minimum}"))
    if isinstance(maximum, int | float) and value > maximum:
        issues.append(_issue(path, "schema.maximum", f"expected <= {maximum}"))
    if isinstance(exclusive_minimum, int | float) and value <= exclusive_minimum:
        issues.append(_issue(path, "schema.exclusive_minimum", f"expected > {exclusive_minimum}"))
    elif exclusive_minimum is True and isinstance(minimum, int | float) and value <= minimum:
        issues.append(_issue(path, "schema.exclusive_minimum", f"expected > {minimum}"))
    if isinstance(exclusive_maximum, int | float) and value >= exclusive_maximum:
        issues.append(_issue(path, "schema.exclusive_maximum", f"expected < {exclusive_maximum}"))
    elif exclusive_maximum is True and isinstance(maximum, int | float) and value >= maximum:
        issues.append(_issue(path, "schema.exclusive_maximum", f"expected < {maximum}"))
    return issues


def _validate_combinator(
    value: Any,
    schema: Mapping[str, Any],
    keyword: str,
    *,
    path: str,
    root: Any,
    seen_refs: tuple[str, ...],
) -> list[dict[str, str]]:
    subschemas = schema.get(keyword)
    if not isinstance(subschemas, Sequence) or isinstance(subschemas, str | bytes | bytearray):
        return []
    candidates = [item for item in subschemas if _is_schema(item)]
    if not candidates:
        return []
    matches = [
        item for item in candidates if not _validate_value(value, item, path=path, root=root, seen_refs=seen_refs)
    ]
    if keyword == "allOf":
        issues = []
        for item in candidates:
            issues.extend(_validate_value(value, item, path=path, root=root, seen_refs=seen_refs))
        return issues
    if keyword == "anyOf" and not matches:
        return [_issue(path, "schema.any_of", "value does not match any allowed schema")]
    if keyword == "oneOf" and len(matches) != 1:
        return [_issue(path, "schema.one_of", "value must match exactly one allowed schema")]
    return []


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _resolve_ref(root: Any, ref: str) -> Any:
    if not ref.startswith("#"):
        return None
    if ref == "#":
        return root
    pointer = ref[1:]
    if not pointer.startswith("/"):
        return None
    current = root
    for raw_part in pointer.lstrip("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(current, str | bytes | bytearray) and part.isdigit():
            index = int(part)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


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
    try:
        status = int(response.get("status", 0))
    except (TypeError, ValueError):
        return False
    return 200 <= status < 300


def _tools_from_response(payload: Any) -> list[Any] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    tools = result.get("tools")
    return tools if isinstance(tools, list) else None


def _is_schema(value: Any) -> bool:
    return isinstance(value, Mapping) or isinstance(value, bool)


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _drop_tool_metadata_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if item in (None, "", []):
            continue
        if item == {} and key not in {"inputSchema", "outputSchema"}:
            continue
        result[key] = item
    return result


def _child_path(path: str, key: str) -> str:
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
        return f"{path}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{path}["{escaped}"]'


def _issue(path: str, reason_code: str, message: str) -> dict[str, str]:
    return {"path": path, "reason_code": reason_code, "message": message}


def _first_issue(metadata: Mapping[str, Any]) -> str | None:
    issues = metadata.get("issues")
    if not isinstance(issues, Sequence) or isinstance(issues, str | bytes | bytearray) or not issues:
        return None
    first = issues[0]
    if not isinstance(first, Mapping):
        return None
    path = first.get("path")
    message = first.get("message")
    if isinstance(path, str) and isinstance(message, str):
        return f"{path} {message}"
    return str(first)


def _schema_error_message(metadata: Mapping[str, Any]) -> str:
    reason_code = str(metadata.get("reason_code") or "")
    if reason_code.startswith("request.task") or reason_code == "request.server_tasks_capability_missing":
        return "MCP task invocation rejected"
    return "MCP tool arguments rejected by inputSchema"


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in request:
        return None
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)

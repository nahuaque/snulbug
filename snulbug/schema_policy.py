from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .state import PolicyStateStore

TOOL_SCHEMA_KEY_PREFIX = "snulbug:tool-schema:"


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
    """Persist tool input schemas from a successful MCP tools/list response."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.enabled,
        "action": config.action,
        "store": tool_schema_store is not None,
        "observed": False,
        "method": method,
    }
    if not config.enabled or tool_schema_store is None or method != "tools/list" or not _is_success_response(response):
        return metadata

    payload, parse_error = _decode_json(_response_body(response))
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return metadata

    tools = _tools_from_response(payload)
    if tools is None:
        return metadata

    stored = []
    skipped = []
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            continue
        schema = tool.get("inputSchema")
        if not _is_schema(schema):
            skipped.append({"tool": tool["name"], "reason_code": "schema.missing_or_invalid"})
            continue
        encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str)
        tool_schema_store.put(f"{TOOL_SCHEMA_KEY_PREFIX}{tool['name']}", encoded)
        stored.append({"tool": tool["name"]})

    metadata["observed"] = True
    metadata["stored"] = stored
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
    encoded = tool_schema_store.get(f"{TOOL_SCHEMA_KEY_PREFIX}{tool_name}")
    if encoded is None:
        metadata["known_schema"] = False
        metadata["skipped"] = "schema_not_seen"
        return True, metadata

    metadata["checked"] = True
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
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": _jsonrpc_id(request),
            "error": {
                "code": -32602,
                "message": f"MCP tool arguments rejected by inputSchema{detail}",
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


def _jsonrpc_id(request: Mapping[str, Any]) -> str | int | float | bool | None:
    if "id" not in request:
        return None
    value = request.get("id")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)

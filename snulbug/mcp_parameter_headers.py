"""Schema-derived HTTP mirrors. Bindings describe paths, never authorization grants."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
SAFE_INTEGER = 2**53 - 1
VALIDATED_SCOPE_KEY = "snulbug.parameter_headers"


@dataclass(frozen=True)
class HeaderBinding:
    path: tuple[str, ...]
    name: str
    kind: str


def header_bindings(schema: Any) -> tuple[HeaderBinding, ...]:
    bindings = []
    names = set()
    nodes = 0

    def visit(node, path, reachable, depth):
        nonlocal nodes
        if not isinstance(node, Mapping):
            return
        nodes += 1
        if nodes > 4096 or depth > 64:
            raise ValueError("Tool header schema exceeds traversal limits")
        if "x-mcp-header" in node:
            name, kind = node["x-mcp-header"], node.get("type")
            if (
                not reachable
                or not path
                or not isinstance(name, str)
                or len(name) > 128
                or not TOKEN.fullmatch(name)
                or kind not in ("string", "integer", "boolean")
            ):
                raise ValueError("Invalid x-mcp-header name, type, or schema location")
            name = "mcp-param-" + name.lower()
            if name in names or len(bindings) >= 128:
                raise ValueError("Duplicate or excessive x-mcp-header annotations")
            names.add(name)
            bindings.append(HeaderBinding(path, name, kind))
        # Walk schema-bearing keywords only; example/const/enum objects are instance data.
        for keyword in ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"):
            children = node.get(keyword)
            if isinstance(children, Mapping):
                for key, child in children.items():
                    visit(child, (*path, key), reachable and keyword == "properties", depth + 1)
        for keyword in (
            "items",
            "prefixItems",
            "allOf",
            "anyOf",
            "oneOf",
            "not",
            "if",
            "then",
            "else",
            "contains",
            "additionalItems",
            "additionalProperties",
            "unevaluatedItems",
            "unevaluatedProperties",
            "propertyNames",
            "contentSchema",
        ):
            child = node.get(keyword)
            for item in child if isinstance(child, list) else (child,):
                visit(item, path, False, depth + 1)

    visit(schema, (), True, 0)
    return tuple(bindings)


def cached_header_bindings(request: Any, store: Any) -> tuple[HeaderBinding, ...]:
    from .schema_policy import TOOL_SCHEMA_KEY_PREFIX

    if not isinstance(request, Mapping) or request.get("method") != "tools/call" or store is None:
        return ()
    params = request.get("params")
    if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
        return ()
    encoded = store.get(TOOL_SCHEMA_KEY_PREFIX + params["name"])
    if encoded is None:
        return ()
    try:
        return header_bindings(json.loads(encoded))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Tool header schema is invalid; refresh the tool catalog") from exc


def parameter_values(arguments: Any, bindings: tuple[HeaderBinding, ...]) -> dict[str, str]:
    values = {}
    for binding in bindings:
        value = arguments
        for part in binding.path:
            value = value.get(part) if isinstance(value, Mapping) else None
        if value is None:
            continue
        if binding.kind == "string" and isinstance(value, str):
            text = value
        elif binding.kind == "boolean" and type(value) is bool:
            text = "true" if value else "false"
        elif (
            binding.kind == "integer"
            and type(value) in (int, float)
            and abs(value) <= SAFE_INTEGER
            and math.isfinite(value)
            and int(value) == value
        ):
            text = str(int(value))
        else:
            raise ValueError("Mirrored parameter has an invalid primitive value")
        values[binding.name] = text
    return values


def validate_parameter_headers(headers: Mapping[str, Any], arguments: Any, bindings: tuple[HeaderBinding, ...]) -> None:
    from .mcp_protocol import decode_mcp_header

    values = parameter_values(arguments, bindings)
    for binding in bindings:
        raw = headers.get(binding.name)
        if binding.name not in values:
            if raw is not None:
                raise ValueError("Mirrored header is present for an absent or null parameter")
            continue
        try:
            decoded = decode_mcp_header(raw)
            expected = values[binding.name]
            if binding.kind == "integer":
                matches = bool(NUMBER.fullmatch(decoded)) and Decimal(decoded) == Decimal(expected)
            else:
                matches = decoded == expected
        except (ValueError, InvalidOperation):
            matches = False
        if not matches:
            raise ValueError("Recognized Mcp-Param header is missing, duplicated, malformed, or mismatched")


def rebuild_parameter_headers(headers, arguments, bindings, previous=()):
    from .mcp_protocol import encode_mcp_header

    recognized = {binding.name for binding in (*bindings, *previous)}
    result = [(name, value) for name, value in headers if name.decode("latin-1").lower() not in recognized]
    result.extend(
        (name.encode("ascii"), encode_mcp_header(value).encode("ascii"))
        for name, value in parameter_values(arguments, bindings).items()
    )
    return result


def filter_header_tools(payload: Any, store: Any) -> tuple[Any, dict[str, Any]]:
    from .schema_policy import TOOL_SCHEMA_KEY_PREFIX

    result = payload.get("result") if isinstance(payload, Mapping) else None
    tools = result.get("tools") if isinstance(result, Mapping) else None
    if not isinstance(tools, list):
        return payload, {}
    kept, rejected = [], []
    for tool in tools:
        if not isinstance(tool, Mapping):
            kept.append(tool)
            continue
        try:
            header_bindings(tool.get("inputSchema"))
        except (ValueError, RecursionError):
            rejected.append({"tool": tool.get("name"), "reason_code": "schema.header_annotation_invalid"})
            if store is not None and isinstance(tool.get("name"), str):
                # Retain the invalid definition in the existing cache so guessing its name cannot bypass rejection.
                store.put(TOOL_SCHEMA_KEY_PREFIX + tool["name"], json.dumps(tool.get("inputSchema")))
        else:
            kept.append(tool)
    return (
        {**payload, "result": {**result, "tools": kept}} if rejected else payload,
        {"checked": True, "rejected": rejected, "rejected_count": len(rejected)},
    )

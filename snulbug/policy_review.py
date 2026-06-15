from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

ALLOWED_POLICY_ACTIONS = {"continue", "set_context", "rewrite", "rate_limit"}


def policy_capability_surface(
    *,
    paths: Sequence[str] = (),
    methods: Sequence[str] = (),
    tools: Sequence[str] = (),
    resources: Sequence[str] = (),
    prompts: Sequence[str] = (),
    tool_argument_keys: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Return a stable, secret-safe summary of the MCP surface a policy permits."""

    normalized_tools = sorted(set(str(tool) for tool in tools if str(tool)))
    argument_keys = _normalize_tool_argument_keys(tool_argument_keys or {}, tools=normalized_tools)
    argument_shapes = [_argument_shape_item(tool, keys) for tool, keys in sorted(argument_keys.items())]
    return {
        "path_patterns": sorted(set(str(path) for path in paths if str(path))),
        "methods": sorted(set(str(method) for method in methods if str(method))),
        "tools": normalized_tools,
        "resources": sorted(set(str(resource) for resource in resources if str(resource))),
        "prompts": sorted(set(str(prompt) for prompt in prompts if str(prompt))),
        "tool_argument_keys": argument_keys,
        "argument_shapes": argument_shapes,
    }


def diff_capability_surfaces(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two policy capability surfaces and summarize newly allowed scope."""

    new_paths = _sorted_set_difference(new.get("path_patterns"), old.get("path_patterns"))
    new_methods = _sorted_set_difference(new.get("methods"), old.get("methods"))
    new_tools = _sorted_set_difference(new.get("tools"), old.get("tools"))
    new_resources = _sorted_set_difference(new.get("resources"), old.get("resources"))
    new_prompts = _sorted_set_difference(new.get("prompts"), old.get("prompts"))
    new_argument_shapes = _new_argument_shapes(old.get("argument_shapes"), new.get("argument_shapes"))
    items = [
        *({"kind": "path_pattern", "value": value} for value in new_paths),
        *({"kind": "method", "value": value} for value in new_methods),
        *({"kind": "tool", "value": value} for value in new_tools),
        *({"kind": "resource", "value": value} for value in new_resources),
        *({"kind": "prompt", "value": value} for value in new_prompts),
        *(
            {
                "kind": "argument_shape",
                "value": item["shape"],
                "parent": item["tool"],
                "keys": item["keys"],
            }
            for item in new_argument_shapes
        ),
    ]
    summary = {
        "newly_allowed_tools": len(new_tools),
        "newly_allowed_path_patterns": len(new_paths),
        "newly_allowed_argument_shapes": len(new_argument_shapes),
        "newly_allowed_methods": len(new_methods),
        "newly_allowed_resources": len(new_resources),
        "newly_allowed_prompts": len(new_prompts),
    }
    summary["total_new_capabilities"] = sum(summary.values())
    return {
        "summary": summary,
        "newly_allowed": {
            "path_patterns": new_paths,
            "methods": new_methods,
            "tools": new_tools,
            "resources": new_resources,
            "prompts": new_prompts,
            "argument_shapes": new_argument_shapes,
        },
        "items": items,
    }


def request_capability_summary(request: Mapping[str, Any]) -> dict[str, Any]:
    """Extract secret-safe MCP capability metadata from a replay fixture request."""

    path = request.get("path")
    summary: dict[str, Any] = {}
    if isinstance(path, str) and path:
        summary["path_pattern"] = path

    body = request.get("body")
    if not isinstance(body, str):
        return summary
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return summary
    if not isinstance(parsed, Mapping) or isinstance(parsed, list):
        return summary

    method = parsed.get("method")
    params = parsed.get("params")
    params = params if isinstance(params, Mapping) else {}
    if isinstance(method, str) and method:
        summary["method"] = method
    target = _target_for_method(method, params)
    if target is not None:
        summary["target"] = target
    if method == "tools/call" and isinstance(target, str) and target:
        summary["tool"] = target
        arguments = params.get("arguments")
        keys = sorted(str(key) for key in arguments) if isinstance(arguments, Mapping) else []
        summary["argument_keys"] = keys
        summary["argument_shape"] = _argument_shape_item(target, keys)
    elif method in {"resources/read", "resources/subscribe", "resources/unsubscribe"} and isinstance(target, str):
        summary["resource"] = target
    elif method == "prompts/get" and isinstance(target, str):
        summary["prompt"] = target
    return summary


def newly_allowed_capability_delta(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize fixture capabilities that changed from blocked to allowed."""

    paths: set[str] = set()
    methods: set[str] = set()
    tools: set[str] = set()
    resources: set[str] = set()
    prompts: set[str] = set()
    tool_argument_keys: dict[str, set[str]] = {}
    examples: list[dict[str, Any]] = []

    for result in results:
        old_action = _result_action(result.get("old"))
        new_action = _result_action(result.get("new"))
        if _action_allowed(old_action) or not _action_allowed(new_action):
            continue
        request = _mapping(result.get("request"))
        if request.get("path_pattern"):
            paths.add(str(request["path_pattern"]))
        if request.get("method"):
            methods.add(str(request["method"]))
        if request.get("tool"):
            tool = str(request["tool"])
            tools.add(tool)
            keys = set(str(key) for key in _sequence(request.get("argument_keys")))
            tool_argument_keys.setdefault(tool, set()).update(keys)
        if request.get("resource"):
            resources.add(str(request["resource"]))
        if request.get("prompt"):
            prompts.add(str(request["prompt"]))
        examples.append(
            {
                "fixture": result.get("fixture"),
                "old_action": old_action,
                "new_action": new_action,
                **request,
            }
        )

    surface = policy_capability_surface(
        paths=sorted(paths),
        methods=sorted(methods),
        tools=sorted(tools),
        resources=sorted(resources),
        prompts=sorted(prompts),
        tool_argument_keys={tool: sorted(keys) for tool, keys in sorted(tool_argument_keys.items())},
    )
    delta = diff_capability_surfaces(policy_capability_surface(), surface)
    delta["summary"]["newly_allowed_decisions"] = len(examples)
    delta["examples"] = examples[:50]
    return delta


def format_capability_delta_summary(delta: Mapping[str, Any]) -> str:
    summary = _mapping(delta.get("summary"))
    return (
        "newly allows "
        f"{_count_phrase(summary.get('newly_allowed_tools', 0), 'tool')}, "
        f"{_count_phrase(summary.get('newly_allowed_path_patterns', 0), 'path pattern')}, "
        f"{_count_phrase(summary.get('newly_allowed_argument_shapes', 0), 'argument shape')}"
    )


def format_capability_delta_markdown(delta: Mapping[str, Any]) -> str:
    newly_allowed = _mapping(delta.get("newly_allowed"))
    lines = [
        f"This candidate {format_capability_delta_summary(delta)}.",
        "",
        "### Newly Allowed Tools",
        "",
        _markdown_list(newly_allowed.get("tools")),
        "",
        "### Newly Allowed Path Patterns",
        "",
        _markdown_list(newly_allowed.get("path_patterns")),
        "",
        "### Newly Allowed Argument Shapes",
        "",
        _argument_shapes_table(newly_allowed.get("argument_shapes")),
    ]
    return "\n".join(lines)


def _normalize_tool_argument_keys(
    value: Mapping[str, Sequence[str]],
    *,
    tools: Sequence[str],
) -> dict[str, list[str]]:
    result = {str(tool): [] for tool in tools}
    for tool, keys in value.items():
        name = str(tool)
        if not name:
            continue
        result[name] = sorted(set(str(key) for key in _sequence(keys) if str(key)))
    return dict(sorted(result.items()))


def _argument_shape_item(tool: str, keys: Sequence[str]) -> dict[str, Any]:
    normalized_keys = sorted(set(str(key) for key in keys if str(key)))
    return {
        "tool": tool,
        "keys": normalized_keys,
        "shape": f"{tool}({', '.join(normalized_keys)})" if normalized_keys else f"{tool}()",
    }


def _new_argument_shapes(old: Any, new: Any) -> list[dict[str, Any]]:
    old_shapes = {str(item.get("shape")) for item in _mapping_sequence(old) if item.get("shape")}
    return [dict(item) for item in _mapping_sequence(new) if item.get("shape") and str(item["shape"]) not in old_shapes]


def _target_for_method(method: Any, params: Mapping[str, Any]) -> str | None:
    if method == "tools/call":
        return _string_param(params, "name")
    if method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}:
        return _string_param(params, "uri")
    if method == "prompts/get":
        return _string_param(params, "name")
    return _string_param(params, "name") or _string_param(params, "uri")


def _result_action(value: Any) -> str:
    result = _mapping(value)
    decision = _mapping(result.get("decision"))
    return str(result.get("action") or decision.get("action") or "")


def _action_allowed(action: str) -> bool:
    return action in ALLOWED_POLICY_ACTIONS


def _sorted_set_difference(new: Any, old: Any) -> list[str]:
    return sorted(set(_string_sequence(new)) - set(_string_sequence(old)))


def _string_sequence(value: Any) -> list[str]:
    return [str(item) for item in _sequence(value) if str(item)]


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in _sequence(value) if isinstance(item, Mapping)]


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    return []


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_param(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    return item if isinstance(item, str) and item else None


def _markdown_list(value: Any) -> str:
    values = _string_sequence(value)
    if not values:
        return "- -"
    return "\n".join(f"- `{item}`" for item in values)


def _argument_shapes_table(value: Any) -> str:
    rows = []
    for item in _mapping_sequence(value):
        rows.append([item.get("tool"), ", ".join(_string_sequence(item.get("keys"))), item.get("shape")])
    return _table(["Tool", "Keys", "Shape"], rows)


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not rows:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")
        return "\n".join(lines)
    for row in rows:
        lines.append("| " + " | ".join(_markdown_cell(value) for value in row) + " |")
    return "\n".join(lines)


def _markdown_cell(value: Any) -> str:
    text = "-" if value in (None, "") else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _count_phrase(value: Any, singular: str) -> str:
    count = int(value or 0)
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"

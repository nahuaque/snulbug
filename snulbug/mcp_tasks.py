from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

MCP_TASK_METHODS = ("tasks/get", "tasks/result", "tasks/list", "tasks/cancel")
MCP_TASK_NOTIFICATION_METHODS = ("notifications/tasks/status",)
MCP_TASK_STATUSES = ("working", "input_required", "completed", "failed", "cancelled")
MCP_TASK_SUPPORT_VALUES = ("forbidden", "optional", "required")
MCP_RELATED_TASK_META_KEY = "io.modelcontextprotocol/related-task"


def is_mcp_task_method(method: Any) -> bool:
    return isinstance(method, str) and method in MCP_TASK_METHODS


def is_mcp_task_notification(method: Any) -> bool:
    return isinstance(method, str) and method in MCP_TASK_NOTIFICATION_METHODS


def normalize_task_support(value: Any) -> str | None:
    return value if isinstance(value, str) and value in MCP_TASK_SUPPORT_VALUES else None


def mcp_task_request_metadata(request: Mapping[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    if not isinstance(method, str):
        return {}
    params = request.get("params")
    params = params if isinstance(params, Mapping) else {}
    metadata: dict[str, Any] = {}
    if is_mcp_task_method(method):
        metadata["task_method"] = method
        metadata["task_operation"] = method.removeprefix("tasks/")
    if is_mcp_task_notification(method):
        metadata["task_notification"] = method
        metadata["task_operation"] = "status"

    task = params.get("task")
    if isinstance(task, Mapping):
        metadata["task_augmented"] = True
        ttl = task.get("ttl")
        if isinstance(ttl, int | float) and ttl >= 0:
            metadata["task_ttl_ms"] = ttl

    task_id = params.get("taskId")
    if isinstance(task_id, str) and task_id:
        metadata["task_id"] = task_id
    status = params.get("status")
    if isinstance(status, str) and status:
        metadata["task_status"] = status

    related_task_id = related_task_id_from_meta(params.get("_meta"))
    if related_task_id:
        metadata["related_task_id"] = related_task_id
    return metadata


def mcp_task_response_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    result = payload.get("result")
    result = result if isinstance(result, Mapping) else {}
    task = result.get("task")
    task = task if isinstance(task, Mapping) else result
    metadata: dict[str, Any] = {}

    task_id = task.get("taskId")
    if isinstance(task_id, str) and task_id:
        metadata["task_id"] = task_id
    status = task.get("status")
    if isinstance(status, str) and status:
        metadata["task_status"] = status
    ttl = task.get("ttl")
    if isinstance(ttl, int | float) and ttl >= 0:
        metadata["task_ttl_ms"] = ttl
    poll_interval = task.get("pollInterval")
    if isinstance(poll_interval, int | float) and poll_interval >= 0:
        metadata["task_poll_interval_ms"] = poll_interval

    related_task_id = related_task_id_from_meta(result.get("_meta"))
    if related_task_id:
        metadata["related_task_id"] = related_task_id
    return metadata


def related_task_id_from_meta(meta: Any) -> str | None:
    if not isinstance(meta, Mapping):
        return None
    related = meta.get(MCP_RELATED_TASK_META_KEY)
    if not isinstance(related, Mapping):
        return None
    task_id = related.get("taskId")
    return task_id if isinstance(task_id, str) and task_id else None


def task_support_summary(tools: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = {value: 0 for value in MCP_TASK_SUPPORT_VALUES}
    tool_names: dict[str, list[str]] = {value: [] for value in MCP_TASK_SUPPORT_VALUES}
    for tool in tools:
        execution = tool.get("execution")
        execution = execution if isinstance(execution, Mapping) else {}
        support = normalize_task_support(execution.get("taskSupport")) or "forbidden"
        counts[support] += 1
        name = tool.get("name")
        if isinstance(name, str) and name:
            tool_names[support].append(name)
    return {
        "counts": counts,
        "tools": {key: sorted(value) for key, value in tool_names.items() if value},
        "task_capable_tools": counts["optional"] + counts["required"],
        "task_required_tools": counts["required"],
    }

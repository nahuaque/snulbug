from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .mcp_schemas import MCP_SCHEMA_CATALOG_SCHEMA, build_mcp_schema_catalog

MCP_TOOL_SNAPSHOT_SCHEMA = "snulbug.mcp-tools-snapshot.v1"
MCP_TOOL_SNAPSHOT_VERSION = 1
MCP_TOOL_DIFF_SCHEMA = "snulbug.mcp-tools-diff.v1"
MCP_TOOL_DIFF_VERSION = 1
MCP_TOOLS_LIST_REQUEST = {"jsonrpc": "2.0", "id": "snulbug-tools-snapshot", "method": "tools/list", "params": {}}
MCP_TOOL_DIFF_KINDS = ("added", "changed", "removed")


def snapshot_mcp_tools(
    *,
    source: str | Path | None = None,
    url: str | None = None,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
    label: str | None = None,
    out: str | Path | None = None,
) -> dict[str, Any]:
    """Capture a stable MCP tools/list snapshot from a file or live MCP HTTP URL."""

    if source is not None and url is not None:
        raise ValueError("pass only one of source or url")
    if source is None and url is None:
        raise ValueError("one of source or url is required")

    if source is not None:
        source_path = Path(source)
        payload = _read_json(source_path)
        source_metadata = {"type": "file", "path": str(source_path)}
    else:
        if url is None:
            raise ValueError("url is required when source is omitted")
        payload, fetch_metadata = fetch_mcp_tools_list(url, headers=headers, token=token, timeout=timeout)
        source_metadata = {"type": "url", **fetch_metadata}

    snapshot = build_mcp_tool_snapshot(_tools_from_payload(payload), source=source_metadata, label=label)
    if out is not None:
        output_path = Path(out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        snapshot["output"] = str(output_path)
    return snapshot


def fetch_mcp_tools_list(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
) -> tuple[Any, dict[str, Any]]:
    """POST tools/list to an MCP Streamable HTTP endpoint and decode JSON or SSE JSON."""

    parsed_url = urlsplit(url)
    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError("MCP tools/list URL must use http or https")
    request_headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        **{str(name).lower(): str(value) for name, value in (headers or {}).items()},
    }
    if token is not None and "authorization" not in request_headers:
        request_headers["authorization"] = f"Bearer {token}"
    body = json.dumps(MCP_TOOLS_LIST_REQUEST, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body, headers=request_headers, method="POST")
    try:
        # URL scheme is restricted to HTTP(S) above.
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            response_body = response.read()
            status = int(response.status)
            content_type = response.headers.get("content-type", "")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MCP tools/list failed with HTTP {exc.code}: {detail[:300]}") from exc
    except URLError as exc:
        raise RuntimeError(f"MCP tools/list request failed: {exc.reason}") from exc

    if status < 200 or status >= 300:
        raise RuntimeError(f"MCP tools/list failed with HTTP {status}")
    return _decode_http_tools_payload(response_body, content_type), {
        "url": url,
        "status": status,
        "content_type": content_type,
    }


def build_mcp_tool_snapshot(
    tools: Sequence[Any],
    *,
    source: Mapping[str, Any] | None = None,
    label: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    normalized = _normalize_tools_with_schema_catalog(tools)
    names = [tool["name"] for tool in normalized]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"MCP tools/list contains duplicate tool names: {', '.join(duplicates)}")
    normalized.sort(key=lambda item: item["name"])
    return {
        "schema": MCP_TOOL_SNAPSHOT_SCHEMA,
        "version": MCP_TOOL_SNAPSHOT_VERSION,
        "ok": True,
        "created_at": created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "label": label,
        "source": dict(source or {}),
        "tool_count": len(normalized),
        "tools": normalized,
    }


def diff_mcp_tool_snapshots(
    baseline: str | Path | Mapping[str, Any],
    current: str | Path | Mapping[str, Any],
    *,
    fail_on: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Compare two MCP tool snapshots and optionally mark selected change kinds as failures."""

    baseline_snapshot = _load_snapshot_like(baseline)
    current_snapshot = _load_snapshot_like(current)
    baseline_tools = _tools_by_name(baseline_snapshot)
    current_tools = _tools_by_name(current_snapshot)
    baseline_names = set(baseline_tools)
    current_names = set(current_tools)

    added = [_tool_summary(current_tools[name]) for name in sorted(current_names - baseline_names)]
    removed = [_tool_summary(baseline_tools[name]) for name in sorted(baseline_names - current_names)]
    changed = []
    unchanged = []
    for name in sorted(baseline_names & current_names):
        before = baseline_tools[name]
        after = current_tools[name]
        if before["hash"] == after["hash"]:
            unchanged.append(_tool_summary(after))
            continue
        changed.append(
            {
                "name": name,
                "before_hash": before["hash"],
                "after_hash": after["hash"],
                "before_short_hash": before["hash"][:12],
                "after_short_hash": after["hash"][:12],
                "changed_fields": _changed_tool_fields(before, after),
            }
        )

    fail_on_kinds = _normalize_fail_on(fail_on or [])
    failing_changes = {
        "added": len(added) if "added" in fail_on_kinds else 0,
        "changed": len(changed) if "changed" in fail_on_kinds else 0,
        "removed": len(removed) if "removed" in fail_on_kinds else 0,
    }
    ok = sum(failing_changes.values()) == 0
    return {
        "schema": MCP_TOOL_DIFF_SCHEMA,
        "version": MCP_TOOL_DIFF_VERSION,
        "ok": ok,
        "baseline": _snapshot_ref(baseline, baseline_snapshot),
        "current": _snapshot_ref(current, current_snapshot),
        "fail_on": list(fail_on_kinds),
        "failing_changes": failing_changes,
        "summary": {
            "added": len(added),
            "changed": len(changed),
            "removed": len(removed),
            "unchanged": len(unchanged),
            "baseline_tools": len(baseline_tools),
            "current_tools": len(current_tools),
        },
        "added": added,
        "changed": changed,
        "removed": removed,
        "unchanged": unchanged,
    }


def parse_mcp_tool_headers(values: Sequence[str] | None, *, token: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        name, separator, item = str(value).partition(":")
        if not separator or not name.strip():
            raise ValueError("headers must use 'Name: value'")
        headers[name.strip().lower()] = item.strip()
    if token is not None and "authorization" not in headers:
        headers["authorization"] = f"Bearer {token}"
    return headers


def format_mcp_tool_snapshot_report(snapshot: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug mcp tools snapshot",
        "",
        f"Label: {snapshot.get('label') or '-'}",
        f"Tools: {snapshot.get('tool_count', 0)}",
        f"Created: {snapshot.get('created_at') or '-'}",
    ]
    source = snapshot.get("source")
    if isinstance(source, Mapping):
        if source.get("url"):
            lines.append(f"Source: {source.get('url')}")
        elif source.get("path"):
            lines.append(f"Source: {source.get('path')}")
    if snapshot.get("output"):
        lines.append(f"Output: {snapshot['output']}")
    lines.extend(["", "## Tools"])
    for tool in snapshot.get("tools", []):
        if isinstance(tool, Mapping):
            description = str(tool.get("description") or "").strip()
            suffix = f" - {description}" if description else ""
            lines.append(f"- `{tool.get('name')}` `{str(tool.get('hash', ''))[:12]}`{suffix}")
    return "\n".join(lines)


def format_mcp_tool_diff_report(diff: Mapping[str, Any]) -> str:
    summary = diff.get("summary") if isinstance(diff.get("summary"), Mapping) else {}
    lines = [
        "# snulbug mcp tools diff",
        "",
        f"Result: {'ok' if diff.get('ok') else 'changed'}",
        (
            "Summary: "
            f"{summary.get('added', 0)} added, "
            f"{summary.get('changed', 0)} changed, "
            f"{summary.get('removed', 0)} removed, "
            f"{summary.get('unchanged', 0)} unchanged"
        ),
    ]
    fail_on = diff.get("fail_on")
    if fail_on:
        lines.append(f"Fail on: {', '.join(str(item) for item in fail_on)}")
    _append_tool_change_section(lines, "Added", diff.get("added"), hash_key="hash")
    _append_tool_change_section(lines, "Removed", diff.get("removed"), hash_key="hash")
    changed = diff.get("changed")
    if isinstance(changed, Sequence) and not isinstance(changed, str | bytes | bytearray) and changed:
        lines.extend(["", "## Changed"])
        for item in changed:
            if isinstance(item, Mapping):
                fields = ", ".join(str(field) for field in item.get("changed_fields", [])) or "hash"
                lines.append(
                    f"- `{item.get('name')}` `{item.get('before_short_hash')}` -> "
                    f"`{item.get('after_short_hash')}` ({fields})"
                )
    return "\n".join(lines)


def _append_tool_change_section(lines: list[str], title: str, tools: Any, *, hash_key: str) -> None:
    if not isinstance(tools, Sequence) or isinstance(tools, str | bytes | bytearray) or not tools:
        return
    lines.extend(["", f"## {title}"])
    for tool in tools:
        if isinstance(tool, Mapping):
            lines.append(f"- `{tool.get('name')}` `{str(tool.get(hash_key, ''))[:12]}`")


def _normalize_tool(tool: Any) -> dict[str, Any]:
    return _normalize_tools_with_schema_catalog([tool])[0]


def _normalize_tools_with_schema_catalog(tools: Sequence[Any]) -> list[dict[str, Any]]:
    if any(not isinstance(tool, Mapping) for tool in tools):
        raise ValueError("MCP tool entries must be objects")
    catalog = build_mcp_schema_catalog(
        {"tools/list": {"result": {"tools": list(tools)}}},
        methods=("tools/list",),
    )
    normalized = catalog.get("surfaces", {}).get("tools", [])
    return [dict(tool) for tool in normalized if isinstance(tool, Mapping)]


def mcp_tool_digest(tool: Mapping[str, Any]) -> str:
    return _normalize_tool(tool)["hash"]


def _tools_from_payload(payload: Any) -> Sequence[Any]:
    if isinstance(payload, Mapping) and payload.get("schema") == MCP_TOOL_SNAPSHOT_SCHEMA:
        tools = payload.get("tools")
    elif isinstance(payload, Mapping) and payload.get("schema") == MCP_SCHEMA_CATALOG_SCHEMA:
        surfaces = payload.get("surfaces")
        tools = surfaces.get("tools") if isinstance(surfaces, Mapping) else None
    elif isinstance(payload, Mapping) and isinstance(payload.get("result"), Mapping):
        tools = payload["result"].get("tools")
    elif isinstance(payload, Mapping):
        tools = payload.get("tools")
    else:
        tools = payload
    if not isinstance(tools, Sequence) or isinstance(tools, str | bytes | bytearray):
        raise ValueError("MCP tools payload must be a tools/list response, snapshot, or tools array")
    return tools


def _decode_http_tools_payload(body: bytes, content_type: str) -> Any:
    text = body.decode("utf-8")
    if "text/event-stream" in content_type.lower() or text.lstrip().startswith(("event:", "data:")):
        for data in _sse_data_events(text):
            stripped = data.strip()
            if not stripped or stripped == "[DONE]":
                continue
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                continue
        raise ValueError("MCP SSE response did not contain a JSON data event")
    return json.loads(text)


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


def _load_snapshot_like(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    payload = _read_json(Path(value)) if isinstance(value, str | Path) else dict(value)
    if isinstance(payload, Mapping) and payload.get("schema") == MCP_TOOL_SNAPSHOT_SCHEMA:
        return build_mcp_tool_snapshot(
            _tools_from_payload(payload),
            source=payload.get("source") if isinstance(payload.get("source"), Mapping) else None,
            label=payload.get("label") if isinstance(payload.get("label"), str) else None,
            created_at=payload.get("created_at") if isinstance(payload.get("created_at"), str) else None,
        )
    return build_mcp_tool_snapshot(_tools_from_payload(payload), source={"type": "inline"})


def _tools_by_name(snapshot: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    tools = snapshot.get("tools")
    if not isinstance(tools, Sequence) or isinstance(tools, str | bytes | bytearray):
        raise ValueError("MCP tool snapshot is missing tools")
    return {str(tool["name"]): dict(tool) for tool in tools if isinstance(tool, Mapping)}


def _tool_summary(tool: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": tool.get("name"),
        "hash": tool.get("hash"),
        "short_hash": str(tool.get("hash", ""))[:12],
        "description": tool.get("description"),
    }


def _changed_tool_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    fields = []
    for field in sorted(set(before) | set(after)):
        if field != "hash" and before.get(field) != after.get(field):
            fields.append(field)
    return fields or ["hash"]


def _normalize_fail_on(values: Sequence[str]) -> tuple[str, ...]:
    kinds: set[str] = set()
    for value in values:
        item = str(value).lower()
        if item in {"any", "all"}:
            kinds.update(MCP_TOOL_DIFF_KINDS)
        elif item in MCP_TOOL_DIFF_KINDS:
            kinds.add(item)
        else:
            raise ValueError("fail_on values must be added, changed, removed, or any")
    return tuple(kind for kind in MCP_TOOL_DIFF_KINDS if kind in kinds)


def _snapshot_ref(input_value: Any, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    ref: dict[str, Any] = {"tool_count": snapshot.get("tool_count", 0), "label": snapshot.get("label")}
    if isinstance(input_value, str | Path):
        ref["path"] = str(input_value)
    source = snapshot.get("source")
    if isinstance(source, Mapping):
        if source.get("path"):
            ref["source_path"] = source.get("path")
        if source.get("url"):
            ref["source_url"] = source.get("url")
    return ref


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MCP_SCHEMA_CATALOG_SCHEMA = "snulbug.mcp-schema-catalog.v1"
MCP_SCHEMA_CATALOG_VERSION = 1
MCP_SCHEMA_DIFF_SCHEMA = "snulbug.mcp-schema-diff.v1"
MCP_SCHEMA_DIFF_VERSION = 1
DEFAULT_MCP_PROTOCOL_VERSION = "2025-06-18"

MCP_SCHEMA_METHODS = (
    "initialize",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
)
MCP_SCHEMA_METHOD_ALIASES = {
    "tools": "tools/list",
    "resources": "resources/list",
    "resource-templates": "resources/templates/list",
    "resource_templates": "resources/templates/list",
    "prompts": "prompts/list",
}
MCP_SCHEMA_DIFF_KINDS = ("added", "changed", "removed")

SURFACE_METHODS = {
    "tools": "tools/list",
    "resources": "resources/list",
    "resource_templates": "resources/templates/list",
    "prompts": "prompts/list",
}
SURFACE_ID_FIELDS = {
    "tools": "name",
    "resources": "uri",
    "resource_templates": "uriTemplate",
    "prompts": "name",
}


def discover_mcp_schemas(
    *,
    source: str | Path | None = None,
    url: str | None = None,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
    label: str | None = None,
    out: str | Path | None = None,
    report_out: str | Path | None = None,
    methods: Sequence[str] | None = None,
    protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Discover a normalized MCP capability/schema catalog from a file or live endpoint."""

    if source is not None and url is not None:
        raise ValueError("pass only one of source or url")
    if source is None and url is None:
        raise ValueError("one of source or url is required")

    selected_methods = normalize_mcp_schema_methods(methods)
    if source is not None:
        source_path = Path(source)
        payload = _read_json(source_path)
        if isinstance(payload, Mapping) and payload.get("schema") == MCP_SCHEMA_CATALOG_SCHEMA:
            catalog = normalize_mcp_schema_catalog(payload)
            catalog["source"] = {"type": "file", "path": str(source_path)}
        else:
            catalog = build_mcp_schema_catalog(
                _responses_from_payload(payload),
                source={"type": "file", "path": str(source_path)},
                label=label,
                methods=selected_methods,
                protocol_version=protocol_version,
            )
    else:
        if url is None:
            raise ValueError("url is required when source is omitted")
        responses = fetch_mcp_schema_responses(
            url,
            headers=headers,
            token=token,
            timeout=timeout,
            methods=selected_methods,
            protocol_version=protocol_version,
        )
        catalog = build_mcp_schema_catalog(
            responses,
            source={"type": "url", "url": url},
            label=label,
            methods=selected_methods,
            protocol_version=protocol_version,
        )

    if label is not None:
        catalog["label"] = label
    if out is not None:
        output_path = Path(out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        catalog["output"] = str(output_path)
    if report_out is not None:
        report_path = Path(report_out)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(format_mcp_schema_catalog_report(catalog) + "\n", encoding="utf-8")
        catalog["report_out"] = str(report_path)
    return catalog


def fetch_mcp_schema_responses(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
    methods: Sequence[str] | None = None,
    protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
) -> dict[str, Any]:
    responses: dict[str, Any] = {}
    for method in normalize_mcp_schema_methods(methods):
        try:
            responses[method] = fetch_mcp_jsonrpc(
                url,
                method,
                headers=headers,
                token=token,
                timeout=timeout,
                protocol_version=protocol_version,
            )
        except Exception as exc:
            responses[method] = {"error": {"message": str(exc), "source": "snulbug.discovery"}}
    return responses


def fetch_mcp_jsonrpc(
    url: str,
    method: str,
    *,
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 10.0,
    protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
) -> Any:
    parsed_url = urlsplit(url)
    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError("MCP schema discovery URL must use http or https")
    request_headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": protocol_version,
        **{str(name).lower(): str(value) for name, value in (headers or {}).items()},
    }
    if token is not None and "authorization" not in request_headers:
        request_headers["authorization"] = f"Bearer {token}"
    body = json.dumps(_jsonrpc_request(method, protocol_version=protocol_version), separators=(",", ":")).encode(
        "utf-8"
    )
    request = Request(url, data=body, headers=request_headers, method="POST")
    try:
        # URL scheme is restricted to HTTP(S) above.
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            response_body = response.read()
            status = int(response.status)
            content_type = response.headers.get("content-type", "")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MCP {method} failed with HTTP {exc.code}: {detail[:300]}") from exc
    except URLError as exc:
        raise RuntimeError(f"MCP {method} request failed: {exc.reason}") from exc
    if status < 200 or status >= 300:
        raise RuntimeError(f"MCP {method} failed with HTTP {status}")
    return _decode_http_jsonrpc_payload(response_body, content_type)


def build_mcp_schema_catalog(
    responses: Mapping[str, Any],
    *,
    source: Mapping[str, Any] | None = None,
    label: str | None = None,
    methods: Sequence[str] | None = None,
    protocol_version: str = DEFAULT_MCP_PROTOCOL_VERSION,
    created_at: str | None = None,
) -> dict[str, Any]:
    selected_methods = normalize_mcp_schema_methods(methods)
    normalized_responses = {normalize_mcp_schema_method(name): value for name, value in responses.items()}
    initialize_result = _result_from_response(normalized_responses.get("initialize"))
    errors = _method_errors(normalized_responses, selected_methods)
    surfaces = {
        "tools": _normalize_items(
            _result_array(normalized_responses.get("tools/list"), "tools"),
            normalizer=_normalize_tool_schema,
            id_field="name",
        ),
        "resources": _normalize_items(
            _result_array(normalized_responses.get("resources/list"), "resources"),
            normalizer=_normalize_resource_schema,
            id_field="uri",
        ),
        "resource_templates": _normalize_items(
            _result_array(normalized_responses.get("resources/templates/list"), "resourceTemplates"),
            normalizer=_normalize_resource_template_schema,
            id_field="uriTemplate",
        ),
        "prompts": _normalize_items(
            _result_array(normalized_responses.get("prompts/list"), "prompts"),
            normalizer=_normalize_prompt_schema,
            id_field="name",
        ),
    }
    catalog = {
        "schema": MCP_SCHEMA_CATALOG_SCHEMA,
        "version": MCP_SCHEMA_CATALOG_VERSION,
        "ok": not errors,
        "created_at": created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "label": label,
        "source": dict(source or {}),
        "protocol_version": protocol_version,
        "methods": selected_methods,
        "server": _normalize_initialize_result(initialize_result),
        "surfaces": surfaces,
        "summary": {
            "tools": len(surfaces["tools"]),
            "resources": len(surfaces["resources"]),
            "resource_templates": len(surfaces["resource_templates"]),
            "prompts": len(surfaces["prompts"]),
            "errors": len(errors),
        },
        "errors": errors,
    }
    catalog["hash"] = stable_schema_digest(
        {
            "server": catalog["server"],
            "surfaces": catalog["surfaces"],
            "protocol_version": catalog["protocol_version"],
        }
    )
    return catalog


def normalize_mcp_schema_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    if catalog.get("schema") != MCP_SCHEMA_CATALOG_SCHEMA:
        raise ValueError("MCP schema catalog has unsupported schema")
    return build_mcp_schema_catalog(
        {
            "initialize": {"result": catalog.get("server") or {}},
            "tools/list": {"result": {"tools": _surface(catalog, "tools")}},
            "resources/list": {"result": {"resources": _surface(catalog, "resources")}},
            "resources/templates/list": {"result": {"resourceTemplates": _surface(catalog, "resource_templates")}},
            "prompts/list": {"result": {"prompts": _surface(catalog, "prompts")}},
        },
        source=catalog.get("source") if isinstance(catalog.get("source"), Mapping) else None,
        label=catalog.get("label") if isinstance(catalog.get("label"), str) else None,
        methods=(
            catalog.get("methods")
            if isinstance(catalog.get("methods"), Sequence)
            and not isinstance(catalog.get("methods"), str | bytes | bytearray)
            else None
        ),
        protocol_version=str(catalog.get("protocol_version") or DEFAULT_MCP_PROTOCOL_VERSION),
        created_at=catalog.get("created_at") if isinstance(catalog.get("created_at"), str) else None,
    )


def diff_mcp_schema_catalogs(
    baseline: str | Path | Mapping[str, Any],
    current: str | Path | Mapping[str, Any],
    *,
    fail_on: Sequence[str] | None = None,
) -> dict[str, Any]:
    baseline_catalog = _load_catalog_like(baseline)
    current_catalog = _load_catalog_like(current)
    added = []
    changed = []
    removed = []
    unchanged = []
    for surface in SURFACE_METHODS:
        baseline_items = _surface_by_id(baseline_catalog, surface)
        current_items = _surface_by_id(current_catalog, surface)
        baseline_ids = set(baseline_items)
        current_ids = set(current_items)
        added.extend(_schema_summary(surface, current_items[item_id]) for item_id in sorted(current_ids - baseline_ids))
        removed.extend(
            _schema_summary(surface, baseline_items[item_id]) for item_id in sorted(baseline_ids - current_ids)
        )
        for item_id in sorted(baseline_ids & current_ids):
            before = baseline_items[item_id]
            after = current_items[item_id]
            if before["hash"] == after["hash"]:
                unchanged.append(_schema_summary(surface, after))
            else:
                changed.append(
                    {
                        "surface": surface,
                        "id": item_id,
                        "before_hash": before["hash"],
                        "after_hash": after["hash"],
                        "before_short_hash": before["hash"][:12],
                        "after_short_hash": after["hash"][:12],
                        "changed_fields": _changed_fields(before, after),
                    }
                )
    fail_on_kinds = _normalize_fail_on(fail_on or [])
    failing_changes = {
        "added": len(added) if "added" in fail_on_kinds else 0,
        "changed": len(changed) if "changed" in fail_on_kinds else 0,
        "removed": len(removed) if "removed" in fail_on_kinds else 0,
    }
    return {
        "schema": MCP_SCHEMA_DIFF_SCHEMA,
        "version": MCP_SCHEMA_DIFF_VERSION,
        "ok": sum(failing_changes.values()) == 0,
        "baseline": _catalog_ref(baseline, baseline_catalog),
        "current": _catalog_ref(current, current_catalog),
        "fail_on": list(fail_on_kinds),
        "failing_changes": failing_changes,
        "summary": {
            "added": len(added),
            "changed": len(changed),
            "removed": len(removed),
            "unchanged": len(unchanged),
            "baseline_items": _catalog_item_count(baseline_catalog),
            "current_items": _catalog_item_count(current_catalog),
        },
        "added": added,
        "changed": changed,
        "removed": removed,
        "unchanged": unchanged,
    }


def parse_mcp_schema_headers(values: Sequence[str] | None, *, token: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        name, separator, item = str(value).partition(":")
        if not separator or not name.strip():
            raise ValueError("headers must use 'Name: value'")
        headers[name.strip().lower()] = item.strip()
    if token is not None and "authorization" not in headers:
        headers["authorization"] = f"Bearer {token}"
    return headers


def normalize_mcp_schema_method(value: str) -> str:
    method = MCP_SCHEMA_METHOD_ALIASES.get(str(value), str(value))
    if method not in MCP_SCHEMA_METHODS:
        raise ValueError(f"unsupported MCP schema discovery method: {value}")
    return method


def normalize_mcp_schema_methods(values: Sequence[str] | None) -> tuple[str, ...]:
    if not values:
        return MCP_SCHEMA_METHODS
    seen = []
    for value in values:
        method = normalize_mcp_schema_method(str(value))
        if method not in seen:
            seen.append(method)
    return tuple(seen)


def stable_schema_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def format_mcp_schema_catalog_report(catalog: Mapping[str, Any]) -> str:
    summary = catalog.get("summary") if isinstance(catalog.get("summary"), Mapping) else {}
    lines = [
        "# snulbug mcp schemas discover",
        "",
        f"Label: {catalog.get('label') or '-'}",
        f"Result: {'ok' if catalog.get('ok') else 'partial'}",
        f"Protocol: {catalog.get('protocol_version') or '-'}",
        (
            "Summary: "
            f"{summary.get('tools', 0)} tools, "
            f"{summary.get('resources', 0)} resources, "
            f"{summary.get('resource_templates', 0)} resource templates, "
            f"{summary.get('prompts', 0)} prompts, "
            f"{summary.get('errors', 0)} errors"
        ),
        f"Catalog hash: `{str(catalog.get('hash', ''))[:12]}`",
    ]
    source = catalog.get("source")
    if isinstance(source, Mapping):
        if source.get("url"):
            lines.append(f"Source: {source.get('url')}")
        elif source.get("path"):
            lines.append(f"Source: {source.get('path')}")
    server = catalog.get("server") if isinstance(catalog.get("server"), Mapping) else {}
    server_info = server.get("serverInfo") if isinstance(server.get("serverInfo"), Mapping) else {}
    if server_info:
        lines.extend(["", "## Server", f"- name: `{server_info.get('name') or '-'}`"])
        if server_info.get("version"):
            lines.append(f"- version: `{server_info.get('version')}`")
    for surface, title in (
        ("tools", "Tools"),
        ("resources", "Resources"),
        ("resource_templates", "Resource Templates"),
        ("prompts", "Prompts"),
    ):
        _append_surface_section(lines, title, _surface(catalog, surface))
    errors = catalog.get("errors")
    if isinstance(errors, Sequence) and not isinstance(errors, str | bytes | bytearray) and errors:
        lines.extend(["", "## Discovery Errors"])
        for error in errors:
            if isinstance(error, Mapping):
                lines.append(f"- `{error.get('method')}`: {error.get('message')}")
    return "\n".join(lines)


def format_mcp_schema_diff_report(diff: Mapping[str, Any]) -> str:
    summary = diff.get("summary") if isinstance(diff.get("summary"), Mapping) else {}
    lines = [
        "# snulbug mcp schemas diff",
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
    _append_diff_section(lines, "Added", diff.get("added"))
    _append_diff_section(lines, "Removed", diff.get("removed"))
    changed = diff.get("changed")
    if isinstance(changed, Sequence) and not isinstance(changed, str | bytes | bytearray) and changed:
        lines.extend(["", "## Changed"])
        for item in changed:
            if isinstance(item, Mapping):
                fields = ", ".join(str(field) for field in item.get("changed_fields", [])) or "hash"
                lines.append(
                    f"- `{item.get('surface')}` `{item.get('id')}` "
                    f"`{item.get('before_short_hash')}` -> `{item.get('after_short_hash')}` ({fields})"
                )
    return "\n".join(lines)


def _jsonrpc_request(method: str, *, protocol_version: str) -> dict[str, Any]:
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": "snulbug-schemas-initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "snulbug-schema-discovery", "version": "0.1.0"},
            },
        }
    return {"jsonrpc": "2.0", "id": f"snulbug-schemas-{method}", "method": method, "params": {}}


def _responses_from_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("MCP schema discovery source must be an object")
    responses = payload.get("responses")
    if isinstance(responses, Mapping):
        return {normalize_mcp_schema_method(str(method)): response for method, response in responses.items()}
    parsed: dict[str, Any] = {}
    for method in MCP_SCHEMA_METHODS:
        if method in payload:
            parsed[method] = payload[method]
    if parsed:
        return parsed
    if isinstance(payload.get("result"), Mapping):
        result = payload["result"]
        if "tools" in result:
            return {"tools/list": payload}
        if "resources" in result:
            return {"resources/list": payload}
        if "resourceTemplates" in result:
            return {"resources/templates/list": payload}
        if "prompts" in result:
            return {"prompts/list": payload}
    raise ValueError("MCP schema discovery source must contain responses or MCP list responses")


def _method_errors(responses: Mapping[str, Any], methods: Sequence[str]) -> list[dict[str, Any]]:
    errors = []
    for method in methods:
        response = responses.get(method)
        if not isinstance(response, Mapping):
            errors.append({"method": method, "message": "method response missing"})
            continue
        error = response.get("error")
        if isinstance(error, Mapping):
            errors.append({"method": method, "message": str(error.get("message") or error), "error": dict(error)})
    return errors


def _normalize_initialize_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        return {}
    normalized = {
        "protocolVersion": result.get("protocolVersion"),
        "capabilities": dict(result.get("capabilities")) if isinstance(result.get("capabilities"), Mapping) else {},
        "serverInfo": dict(result.get("serverInfo")) if isinstance(result.get("serverInfo"), Mapping) else {},
        "instructions": result.get("instructions") if isinstance(result.get("instructions"), str) else None,
    }
    normalized["hash"] = stable_schema_digest(normalized)
    return normalized


def _normalize_tool_schema(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {
        "name": _required_string(item, "name", "tool"),
        "title": item.get("title") if isinstance(item.get("title"), str) else None,
        "description": item.get("description") if isinstance(item.get("description"), str) else None,
        "inputSchema": dict(item.get("inputSchema")) if isinstance(item.get("inputSchema"), Mapping) else None,
        "outputSchema": dict(item.get("outputSchema")) if isinstance(item.get("outputSchema"), Mapping) else None,
        "annotations": dict(item.get("annotations")) if isinstance(item.get("annotations"), Mapping) else None,
    }
    normalized["hash"] = stable_schema_digest(_without_hash(normalized))
    return normalized


def _normalize_resource_schema(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {
        "uri": _required_string(item, "uri", "resource"),
        "name": item.get("name") if isinstance(item.get("name"), str) else None,
        "title": item.get("title") if isinstance(item.get("title"), str) else None,
        "description": item.get("description") if isinstance(item.get("description"), str) else None,
        "mimeType": item.get("mimeType") if isinstance(item.get("mimeType"), str) else None,
        "annotations": dict(item.get("annotations")) if isinstance(item.get("annotations"), Mapping) else None,
    }
    normalized["hash"] = stable_schema_digest(_without_hash(normalized))
    return normalized


def _normalize_resource_template_schema(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {
        "uriTemplate": _required_string(item, "uriTemplate", "resource template"),
        "name": item.get("name") if isinstance(item.get("name"), str) else None,
        "title": item.get("title") if isinstance(item.get("title"), str) else None,
        "description": item.get("description") if isinstance(item.get("description"), str) else None,
        "mimeType": item.get("mimeType") if isinstance(item.get("mimeType"), str) else None,
        "annotations": dict(item.get("annotations")) if isinstance(item.get("annotations"), Mapping) else None,
    }
    normalized["hash"] = stable_schema_digest(_without_hash(normalized))
    return normalized


def _normalize_prompt_schema(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {
        "name": _required_string(item, "name", "prompt"),
        "title": item.get("title") if isinstance(item.get("title"), str) else None,
        "description": item.get("description") if isinstance(item.get("description"), str) else None,
        "arguments": _normalize_prompt_arguments(item.get("arguments")),
    }
    normalized["hash"] = stable_schema_digest(_without_hash(normalized))
    return normalized


def _normalize_prompt_arguments(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    arguments = []
    for item in value:
        if isinstance(item, Mapping) and isinstance(item.get("name"), str):
            arguments.append(
                {
                    "name": item.get("name"),
                    "title": item.get("title") if isinstance(item.get("title"), str) else None,
                    "description": item.get("description") if isinstance(item.get("description"), str) else None,
                    "required": bool(item.get("required", False)),
                }
            )
    return sorted(arguments, key=lambda item: str(item["name"]))


def _normalize_items(items: Any, *, normalizer: Any, id_field: str) -> list[dict[str, Any]]:
    if not isinstance(items, Sequence) or isinstance(items, str | bytes | bytearray):
        return []
    normalized = []
    for item in items:
        if isinstance(item, Mapping):
            normalized.append(normalizer(item))
    ids = [str(item[id_field]) for item in normalized]
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    if duplicates:
        raise ValueError(f"MCP schema discovery found duplicate {id_field} values: {', '.join(duplicates)}")
    return sorted(normalized, key=lambda item: str(item[id_field]))


def _result_array(response: Any, field: str) -> Any:
    result = _result_from_response(response)
    return result.get(field) if isinstance(result, Mapping) else []


def _result_from_response(response: Any) -> Any:
    if not isinstance(response, Mapping):
        return None
    if isinstance(response.get("result"), Mapping):
        return response["result"]
    if response.get("schema") == MCP_SCHEMA_CATALOG_SCHEMA:
        return response
    return response if "error" not in response else None


def _required_string(item: Mapping[str, Any], field: str, item_type: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"MCP {item_type} entry must include a non-empty {field}")
    return value


def _surface(catalog: Mapping[str, Any], name: str) -> list[Any]:
    surfaces = catalog.get("surfaces")
    if not isinstance(surfaces, Mapping):
        return []
    value = surfaces.get(name)
    return list(value) if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray) else []


def _surface_by_id(catalog: Mapping[str, Any], surface: str) -> dict[str, dict[str, Any]]:
    id_field = SURFACE_ID_FIELDS[surface]
    return {str(item[id_field]): dict(item) for item in _surface(catalog, surface) if isinstance(item, Mapping)}


def _schema_summary(surface: str, item: Mapping[str, Any]) -> dict[str, Any]:
    item_id = str(item.get(SURFACE_ID_FIELDS[surface], ""))
    return {
        "surface": surface,
        "id": item_id,
        "name": item.get("name"),
        "hash": item.get("hash"),
        "short_hash": str(item.get("hash", ""))[:12],
        "description": item.get("description"),
    }


def _changed_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    fields = []
    for field in sorted(set(before) | set(after)):
        if field != "hash" and before.get(field) != after.get(field):
            fields.append(field)
    return fields or ["hash"]


def _catalog_item_count(catalog: Mapping[str, Any]) -> int:
    return sum(len(_surface(catalog, surface)) for surface in SURFACE_METHODS)


def _catalog_ref(input_value: Any, catalog: Mapping[str, Any]) -> dict[str, Any]:
    ref = {
        "label": catalog.get("label"),
        "hash": catalog.get("hash"),
        "summary": dict(catalog.get("summary")) if isinstance(catalog.get("summary"), Mapping) else {},
    }
    if isinstance(input_value, str | Path):
        ref["path"] = str(input_value)
    source = catalog.get("source")
    if isinstance(source, Mapping):
        if source.get("path"):
            ref["source_path"] = source.get("path")
        if source.get("url"):
            ref["source_url"] = source.get("url")
    return ref


def _load_catalog_like(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    payload = _read_json(Path(value)) if isinstance(value, str | Path) else dict(value)
    if isinstance(payload, Mapping) and payload.get("schema") == MCP_SCHEMA_CATALOG_SCHEMA:
        return normalize_mcp_schema_catalog(payload)
    return build_mcp_schema_catalog(_responses_from_payload(payload))


def _normalize_fail_on(values: Sequence[str]) -> tuple[str, ...]:
    kinds: set[str] = set()
    for value in values:
        item = str(value).lower()
        if item in {"any", "all"}:
            kinds.update(MCP_SCHEMA_DIFF_KINDS)
        elif item in MCP_SCHEMA_DIFF_KINDS:
            kinds.add(item)
        else:
            raise ValueError("fail_on values must be added, changed, removed, or any")
    return tuple(kind for kind in MCP_SCHEMA_DIFF_KINDS if kind in kinds)


def _append_surface_section(lines: list[str], title: str, items: Sequence[Any]) -> None:
    if not items:
        return
    lines.extend(["", f"## {title}"])
    for item in items:
        if isinstance(item, Mapping):
            identifier = item.get("name") or item.get("uri") or item.get("uriTemplate")
            description = str(item.get("description") or "").strip()
            suffix = f" - {description}" if description else ""
            lines.append(f"- `{identifier}` `{str(item.get('hash', ''))[:12]}`{suffix}")


def _append_diff_section(lines: list[str], title: str, items: Any) -> None:
    if not isinstance(items, Sequence) or isinstance(items, str | bytes | bytearray) or not items:
        return
    lines.extend(["", f"## {title}"])
    for item in items:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('surface')}` `{item.get('id')}` `{str(item.get('hash', ''))[:12]}`")


def _without_hash(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "hash"}


def _decode_http_jsonrpc_payload(body: bytes, content_type: str) -> Any:
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


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

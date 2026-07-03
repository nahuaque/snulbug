from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

LATEST_MCP_SPEC_VERSION = "2025-11-25"
MCP_SPEC_CONFORMANCE_SCHEMA = "snulbug.mcp-spec-conformance.v1"
PROTECTED_RESOURCE_AUTH_MODES = {"oauth-resource", "enterprise-managed"}


def run_mcp_2025_11_25_conformance(
    *,
    url: str,
    headers: Mapping[str, str] | None = None,
    proxy_config: Mapping[str, Any] | None = None,
    status: Mapping[str, Any] | None = None,
    live_checks: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Run MCP 2025-11-25 share-facing conformance checks.

    These checks intentionally focus on the public share boundary. They do not
    claim a full MCP server certification; they make the spec-sensitive gaps a
    first-class part of `snulbug mcp share doctor`.
    """

    normalized_headers = _normalize_headers(headers)
    config = _mapping(proxy_config)
    auth = _mapping(config.get("auth"))
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []

    _add_check(
        checks,
        "mcp2025.spec.target",
        "pass",
        "share doctor is checking MCP 2025-11-25 readiness",
        details={"spec_version": LATEST_MCP_SPEC_VERSION},
    )
    _check_accept_header(checks, recommendations, normalized_headers)
    _check_protocol_version_header(checks, recommendations, normalized_headers)
    _check_edge_hardening(checks, recommendations, proxy_config=config)
    _check_origin_guard(checks, recommendations, url=url, proxy_config=config)
    _check_streamable_get(
        checks,
        recommendations,
        url=url,
        headers=normalized_headers,
        live_checks=live_checks,
        timeout=timeout,
    )
    _check_oauth_metadata(checks, recommendations, auth=auth)
    _check_client_id_metadata(checks, recommendations, auth=auth)
    _check_schema_catalog_visibility(checks, recommendations, status=_mapping(status))
    _check_mcp_tasks(checks, recommendations, status=_mapping(status))
    _check_server_to_client_mediation(checks, recommendations, proxy_config=config)

    summary = _summary(checks)
    result = {
        "schema": MCP_SPEC_CONFORMANCE_SCHEMA,
        "version": 1,
        "ok": summary["failed"] == 0,
        "status": "failed" if summary["failed"] else "review" if summary["warnings"] else "pass",
        "spec_version": LATEST_MCP_SPEC_VERSION,
        "url": _safe_url(url),
        "live_checks": live_checks,
        "summary": summary,
    }
    return {
        "result": result,
        "checks": checks,
        "recommendations": _unique_strings(recommendations),
    }


def _check_accept_header(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    headers: Mapping[str, str],
) -> None:
    accept = str(headers.get("accept") or "")
    lowered = accept.lower()
    has_json = "application/json" in lowered
    has_sse = "text/event-stream" in lowered
    ok = has_json and has_sse
    _add_check(
        checks,
        "mcp2025.transport.accept_header",
        "pass" if ok else "warn",
        "MCP client headers advertise JSON and SSE responses"
        if ok
        else "MCP Streamable HTTP clients should send Accept: application/json, text/event-stream",
        details={"accept_present": bool(accept), "has_application_json": has_json, "has_text_event_stream": has_sse},
    )
    if not ok:
        recommendations.append(
            "Include `Accept: application/json, text/event-stream` in generated client and smoke-test snippets."
        )


def _check_protocol_version_header(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    headers: Mapping[str, str],
) -> None:
    version = headers.get("mcp-protocol-version")
    if version == LATEST_MCP_SPEC_VERSION:
        status = "pass"
        message = f"MCP-Protocol-Version targets {LATEST_MCP_SPEC_VERSION}"
    elif version:
        status = "warn"
        message = f"MCP-Protocol-Version is {version}, while latest MCP is {LATEST_MCP_SPEC_VERSION}"
    else:
        status = "warn"
        message = "MCP-Protocol-Version is not present in generated client headers"
    _add_check(
        checks,
        "mcp2025.transport.protocol_version_header",
        status,
        message,
        details={"configured": version, "latest": LATEST_MCP_SPEC_VERSION},
    )
    if status != "pass":
        recommendations.append(
            f"Prefer `MCP-Protocol-Version: {LATEST_MCP_SPEC_VERSION}` for clients that support the latest MCP spec."
        )


def _check_origin_guard(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    url: str,
    proxy_config: Mapping[str, Any],
) -> None:
    if not _is_public_url(url):
        _add_check(
            checks,
            "mcp2025.transport.origin_guard",
            "skip",
            "public URL is localhost or missing, so public Origin validation is not evaluated",
            details={"url": _safe_url(url)},
        )
        return

    configured = _origin_guard_configured(proxy_config)
    _add_check(
        checks,
        "mcp2025.transport.origin_guard",
        "pass" if configured else "warn",
        "public Streamable HTTP Origin guard is configured"
        if configured
        else "public Streamable HTTP share does not declare an Origin allowlist",
        details={"url": _safe_url(url), "origin_guard_configured": configured},
    )
    if not configured:
        recommendations.append(
            "Add an explicit Origin allowlist/validation rule before treating a public Streamable HTTP share as "
            "hardened."
        )


def _check_edge_hardening(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    proxy_config: Mapping[str, Any],
) -> None:
    enabled = proxy_config.get("streamable_http_hardening") is True
    require_accept = proxy_config.get("streamable_http_require_accept") is True
    require_content_type = proxy_config.get("streamable_http_require_content_type") is True
    allow_get = proxy_config.get("streamable_http_allow_get") is True
    allow_delete = proxy_config.get("streamable_http_allow_delete") is True
    require_session = proxy_config.get("streamable_http_require_session_id") is True
    protocol = proxy_config.get("streamable_http_protocol_version")
    details = {
        "enabled": enabled,
        "require_accept": require_accept,
        "require_content_type": require_content_type,
        "allow_get": allow_get,
        "allow_delete": allow_delete,
        "require_session_id": require_session,
        "protocol_version": protocol,
    }
    ok = enabled and require_accept and require_content_type and not allow_get
    _add_check(
        checks,
        "mcp2025.transport.edge_hardening",
        "pass" if ok else "warn",
        "snulbug edge hardening enforces Streamable HTTP request shape"
        if ok
        else "snulbug Streamable HTTP edge hardening is incomplete or relaxed",
        details=details,
    )
    if not enabled:
        recommendations.append("Enable `mcp.proxy.streamable_http_hardening` before sharing a public MCP URL.")
    if not require_accept:
        recommendations.append("Require Streamable HTTP POST clients to advertise JSON and SSE response support.")
    if not require_content_type:
        recommendations.append("Require `Content-Type: application/json` on Streamable HTTP POST requests.")
    if allow_get:
        recommendations.append(
            "Only enable Streamable HTTP GET/SSE when the upstream and client support resumable streams."
        )


def _check_streamable_get(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    url: str,
    headers: Mapping[str, str],
    live_checks: bool,
    timeout: float,
) -> None:
    if not live_checks:
        _add_check(
            checks,
            "mcp2025.transport.streamable_get",
            "skip",
            "Streamable HTTP GET/SSE behavior was not probed because live checks are disabled",
        )
        return

    probe = _probe_streamable_get(url, headers=headers, timeout=timeout)
    status = int(probe.get("status") or 0)
    content_type = str(probe.get("content_type") or "").lower()
    ok = status == 405 or (200 <= status < 300 and "text/event-stream" in content_type)
    _add_check(
        checks,
        "mcp2025.transport.streamable_get",
        "pass" if ok else "warn",
        "Streamable HTTP GET returned SSE or a valid 405 unsupported response"
        if ok
        else "Streamable HTTP GET did not return SSE or 405",
        details=probe,
    )
    if not ok:
        recommendations.append(
            "Verify GET /mcp either opens an SSE stream or returns HTTP 405 when resumable streams are unsupported."
        )


def _check_oauth_metadata(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    auth: Mapping[str, Any],
) -> None:
    if auth.get("mode") not in PROTECTED_RESOURCE_AUTH_MODES:
        _add_check(
            checks,
            "mcp2025.auth.protected_resource_metadata",
            "skip",
            "OAuth protected-resource mode is not enabled",
        )
        _add_check(
            checks,
            "mcp2025.auth.incremental_scope_challenge",
            "skip",
            "OAuth scope challenges are not applicable when OAuth mode is disabled",
        )
        return

    resource = auth.get("resource")
    authorization_servers = _string_list(auth.get("authorization_servers"))
    issuer = auth.get("issuer")
    metadata_ok = bool(resource and (authorization_servers or issuer))
    _add_check(
        checks,
        "mcp2025.auth.protected_resource_metadata",
        "pass" if metadata_ok else "warn",
        "OAuth protected-resource metadata has resource and authorization server hints"
        if metadata_ok
        else "OAuth protected-resource metadata is missing resource or authorization server hints",
        details={
            "resource_configured": bool(resource),
            "authorization_server_count": len(authorization_servers) + (1 if issuer else 0),
        },
    )
    if not metadata_ok:
        recommendations.append(
            "Configure `mcp.auth.resource` and issuer/authorization server metadata for OAuth shares."
        )

    scopes = _configured_auth_scopes(auth)
    _add_check(
        checks,
        "mcp2025.auth.incremental_scope_challenge",
        "pass" if scopes else "skip",
        "OAuth scopes are configured for incremental authorization challenges"
        if scopes
        else "OAuth mode has no configured scopes to advertise in authorization challenges",
        details={"scope_count": len(scopes), "scopes": scopes[:20]},
    )


def _check_client_id_metadata(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    auth: Mapping[str, Any],
) -> None:
    if auth.get("mode") not in PROTECTED_RESOURCE_AUTH_MODES:
        _add_check(
            checks,
            "mcp2025.auth.client_id_metadata_documents",
            "skip",
            "OAuth Client ID Metadata Documents are not applicable when OAuth mode is disabled",
        )
        return
    configured = bool(
        auth.get("client_id_metadata_document")
        or auth.get("client_id_metadata_documents")
        or auth.get("client_metadata_url")
    )
    _add_check(
        checks,
        "mcp2025.auth.client_id_metadata_documents",
        "pass" if configured else "warn",
        "OAuth Client ID Metadata Document setup is configured"
        if configured
        else "OAuth Client ID Metadata Document setup is not configured",
    )
    if not configured:
        recommendations.append(
            "Generate provider/client setup that includes OAuth Client ID Metadata Document guidance for MCP clients."
        )


def _check_schema_catalog_visibility(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    status: Mapping[str, Any],
) -> None:
    schemas = _mapping(status.get("schemas"))
    catalog_count = int(schemas.get("catalog_count") or 0)
    tool_count = int(schemas.get("tool_count") or 0)
    if catalog_count <= 0:
        _add_check(
            checks,
            "mcp2025.schemas.catalog_loaded",
            "warn",
            "no MCP schema catalog is loaded, so 2025-11-25 tool/resource/prompt metadata cannot be reviewed",
            details={"catalog_count": catalog_count, "tool_count": tool_count},
        )
        recommendations.append("Run schema discovery before sharing if you want doctor to review tool/schema drift.")
        return
    _add_check(
        checks,
        "mcp2025.schemas.catalog_loaded",
        "pass",
        "MCP schema catalog is loaded for metadata and drift review",
        details={"catalog_count": catalog_count, "tool_count": tool_count},
    )


def _check_mcp_tasks(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    status: Mapping[str, Any],
) -> None:
    schemas = _mapping(status.get("schemas"))
    task_support = _mapping(schemas.get("task_support"))
    counts = _mapping(task_support.get("counts"))
    optional = int(counts.get("optional") or 0)
    required = int(counts.get("required") or 0)
    task_capable = optional + required
    server_capability = schemas.get("server_tasks_capability") is True
    details = {
        "task_capable_tools": task_capable,
        "task_required_tools": required,
        "server_tasks_capability": server_capability,
        "counts": dict(counts),
    }
    if task_capable == 0 and not server_capability:
        _add_check(
            checks,
            "mcp2025.tasks.support",
            "skip",
            "no MCP Tasks capability or task-capable tools were observed in schema catalogs",
            details=details,
        )
        return
    ok = task_capable == 0 or server_capability
    _add_check(
        checks,
        "mcp2025.tasks.support",
        "pass" if ok else "warn",
        "MCP Tasks capability and tool-level execution.taskSupport are consistent"
        if ok
        else "tools advertise execution.taskSupport but server capabilities do not declare Tasks support",
        details=details,
    )
    if not ok:
        recommendations.append(
            "Confirm the upstream declares `capabilities.tasks.requests.tools.call` before relying on "
            "`execution.taskSupport` from tools/list."
        )


def _check_server_to_client_mediation(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    *,
    proxy_config: Mapping[str, Any],
) -> None:
    action = proxy_config.get("server_to_client_request_action")
    legacy_mediation = _mapping(
        proxy_config.get("server_to_client_policy") or proxy_config.get("client_capability_policy")
    )
    configured = action in {"block", "warn", "allow"} or bool(legacy_mediation)
    hardened = action == "block"
    _add_check(
        checks,
        "mcp2025.server_to_client.mediation",
        "pass" if hardened else "warn" if configured else "warn",
        "server-to-client MCP requests are blocked by response policy"
        if hardened
        else "server-to-client MCP request mediation is configured in non-blocking mode"
        if configured
        else "server-to-client sampling, elicitation, and roots requests are not explicitly mediated",
        details={"configured": configured, "action": action},
    )
    if not hardened:
        recommendations.append(
            'Use `mcp.proxy.server_to_client_request_action = "block"` for public shares unless the upstream '
            "and client are explicitly trusted to handle sampling/createMessage, elicitation/create, and roots/list."
        )


def _probe_streamable_get(url: str, *, headers: Mapping[str, str], timeout: float) -> dict[str, Any]:
    request_headers = {
        "accept": "text/event-stream",
        **{name: value for name, value in headers.items() if name not in {"content-type", "content-length"}},
    }
    request = Request(url, headers=request_headers, method="GET")
    try:
        # URL scheme is checked by the caller-facing doctor config.
        with urlopen(request, timeout=timeout) as response:  # nosec B310
            body = response.read(512)
            return {
                "ok": True,
                "status": int(response.status),
                "content_type": response.headers.get("content-type", ""),
                "body_prefix_bytes": len(body),
            }
    except HTTPError as exc:
        return {
            "ok": exc.code == 405,
            "status": int(exc.code),
            "content_type": exc.headers.get("content-type", ""),
            "error": str(exc),
        }
    except URLError as exc:
        return {"ok": False, "status": 0, "error": str(exc.reason)}
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc)}


def _add_check(
    checks: list[dict[str, Any]],
    check_id: str,
    status: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> None:
    check: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "message": message,
        "component": "mcp-spec",
    }
    if details:
        check["details"] = dict(details)
    checks.append(check)


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(name).strip().lower(): str(value) for name, value in (headers or {}).items() if str(name).strip()}


def _origin_guard_configured(proxy_config: Mapping[str, Any]) -> bool:
    candidates: list[Any] = [
        proxy_config.get("streamable_http_allowed_origins"),
        proxy_config.get("origin_allowlist"),
        proxy_config.get("allowed_origins"),
        proxy_config.get("origin_validation"),
        proxy_config.get("validate_origin"),
        proxy_config.get("require_origin"),
    ]
    security = _mapping(proxy_config.get("security"))
    candidates.extend(
        [
            security.get("origin_allowlist"),
            security.get("allowed_origins"),
            security.get("origin_validation"),
            security.get("validate_origin"),
            security.get("require_origin"),
        ]
    )
    return any(_truthy_config(value) for value in candidates)


def _truthy_config(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "on", "enforce", "strict", "required"}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return bool(value)
    if isinstance(value, Mapping):
        return bool(value)
    return False


def _configured_auth_scopes(auth: Mapping[str, Any]) -> list[str]:
    scopes = {
        *map(str, _sequence(auth.get("required_scopes"))),
        *map(str, _sequence(auth.get("scopes_supported"))),
        *(str(scope) for scope in _mapping(auth.get("scope_map"))),
    }
    for profile in _sequence(auth.get("issuers")):
        if not isinstance(profile, Mapping):
            continue
        scopes.update(map(str, _sequence(profile.get("required_scopes"))))
        scopes.update(map(str, _sequence(profile.get("scopes_supported"))))
        scopes.update(str(scope) for scope in _mapping(profile.get("scope_map")))
    return sorted(scope for scope in scopes if scope)


def _is_public_url(url: str | None) -> bool:
    if not url:
        return False
    parsed = urlsplit(str(url))
    host = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"} or not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return False
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    return True


def _safe_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlsplit(str(url))
    if not parsed.username and not parsed.password:
        return str(url)
    host = parsed.hostname or ""
    netloc = host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    if value is None or isinstance(value, str | bytes | bytearray):
        return ()
    if isinstance(value, Sequence):
        return value
    return ()


def _string_list(value: Any) -> list[str]:
    return [str(item) for item in _sequence(value) if str(item)]


def _summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "skipped": sum(1 for check in checks if check.get("status") == "skip"),
    }


def _unique_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

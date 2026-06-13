from __future__ import annotations

import http.client
import json
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .config import DEFAULT_CONFIG_PATH, load_mcp_fabric_config
from .manifests import load_manifest, verify_upstream_manifest

_FABRIC_DOCTOR_REQUEST = {
    "jsonrpc": "2.0",
    "id": "snulbug-fabric-doctor-tools-list",
    "method": "tools/list",
    "params": {},
}


def fabric_status(config: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Summarize the declared MCP fabric without probing network endpoints."""

    fabric = load_mcp_fabric_config(config)
    proxy = _mapping(fabric.get("proxy"))
    upstreams = [_upstream_status(upstream) for upstream in _upstreams(proxy)]
    summary = _fabric_summary(fabric, proxy, upstreams)
    recommendations = _fabric_recommendations(fabric, upstreams)
    return {
        "ok": summary["missing_required_manifests"] == 0,
        "name": fabric["name"],
        "description": fabric.get("description", ""),
        "config": str(config),
        "gateway_url": fabric.get("gateway_url"),
        "require_manifests": fabric["require_manifests"],
        "probe_gateway": fabric["probe_gateway"],
        "probe_upstreams": fabric["probe_upstreams"],
        "timeout": fabric["timeout"],
        "proxy": _proxy_status(proxy),
        "upstreams": upstreams,
        "summary": summary,
        "recommendations": recommendations,
    }


def doctor_fabric(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
    probe_gateway: bool | None = None,
    probe_upstreams: bool | None = None,
) -> dict[str, Any]:
    """Run static and active checks against a declared MCP fabric."""

    checks: list[dict[str, Any]] = []
    probes: dict[str, Any] = {}
    try:
        status = fabric_status(config)
        fabric = load_mcp_fabric_config(config)
    except Exception as exc:
        _add_check(checks, "config.loaded", False, f"failed to load fabric config: {exc}")
        summary = _checks_summary(checks)
        return {
            "ok": False,
            "config": str(config),
            "checks": checks,
            "summary": summary,
            "recommendations": ["Fix the snulbug.toml syntax or [mcp.fabric]/[mcp.proxy] configuration."],
            "probes": probes,
        }

    headers = dict(headers or {})
    timeout_value = float(timeout if timeout is not None else fabric["timeout"])
    if timeout_value <= 0:
        raise ValueError("timeout must be positive")
    do_probe_gateway = fabric["probe_gateway"] if probe_gateway is None else probe_gateway
    do_probe_upstreams = fabric["probe_upstreams"] if probe_upstreams is None else probe_upstreams
    proxy = _mapping(fabric.get("proxy"))
    upstreams = _upstreams(proxy)

    _add_check(checks, "config.loaded", True, f"loaded fabric config {config}", details={"config": str(config)})
    _add_check(
        checks,
        "fabric.gateway_url_present",
        bool(fabric.get("gateway_url")),
        "gateway URL is configured or inferred" if fabric.get("gateway_url") else "gateway URL is missing",
        details={"gateway_url": fabric.get("gateway_url")},
    )
    _add_check(
        checks,
        "proxy.facade_enabled",
        bool(upstreams),
        f"facade declares {len(upstreams)} upstream(s)" if upstreams else "no facade upstreams are declared",
        severity="warning",
    )
    _add_check(
        checks,
        "logs.record_out_configured",
        bool(proxy.get("record_out")),
        "record_out is configured" if proxy.get("record_out") else "record_out is not configured",
        severity="warning",
        details={"record_out": str(proxy.get("record_out")) if proxy.get("record_out") else None},
    )
    _add_check(
        checks,
        "logs.audit_out_configured",
        bool(proxy.get("audit_out")),
        "audit_out is configured" if proxy.get("audit_out") else "audit_out is not configured",
        severity="warning",
        details={"audit_out": str(proxy.get("audit_out")) if proxy.get("audit_out") else None},
    )

    for upstream in upstreams:
        _run_manifest_checks(checks, upstream, require_manifest=bool(fabric["require_manifests"]))

    if do_probe_gateway and fabric.get("gateway_url"):
        _run_mcp_endpoint_checks(
            checks,
            probes,
            check_prefix="gateway",
            url=str(fabric["gateway_url"]),
            headers=headers,
            timeout=timeout_value,
            label="gateway",
        )
    elif not do_probe_gateway:
        _add_check(checks, "gateway.probe_enabled", None, "gateway probing is disabled")

    for upstream in upstreams:
        if not do_probe_upstreams:
            _add_check(checks, f"upstream.{_check_name(upstream)}.probe_enabled", None, "upstream probing is disabled")
            continue
        _run_upstream_probe_checks(checks, probes, upstream, headers=headers, timeout=timeout_value)

    summary = _checks_summary(checks)
    recommendations = _doctor_recommendations(checks, headers=headers)
    return {
        **status,
        "ok": summary["failed"] == 0,
        "checks": checks,
        "summary": {**status["summary"], **summary},
        "recommendations": recommendations or status["recommendations"],
        "probes": probes,
    }


def format_fabric_status_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric status",
        "",
        f"Fabric: {result.get('name')}",
        f"Config: {result.get('config')}",
        f"Gateway: {result.get('gateway_url') or '(missing)'}",
        f"Require manifests: {str(bool(result.get('require_manifests'))).lower()}",
        "",
        "## Proxy",
    ]
    proxy = _mapping(result.get("proxy"))
    for key in ("host", "port", "policy", "state", "tunnel_provider", "lease_required", "facade"):
        lines.append(f"- {key}: `{proxy.get(key)}`")

    lines.extend(["", "## Upstreams"])
    upstreams = list(result.get("upstreams", []))
    if not upstreams:
        lines.append("- none")
    for upstream in upstreams:
        manifest = _mapping(upstream.get("manifest"))
        manifest_text = "none"
        if manifest:
            manifest_text = f"{manifest.get('path')} ({'exists' if manifest.get('exists') else 'missing'})"
        lines.append(
            "- "
            f"{upstream.get('name')} [{upstream.get('transport')}] "
            f"prefix=`{upstream.get('tool_prefix')}` "
            f"url=`{upstream.get('url') or '-'}` "
            f"manifest=`{manifest_text}`"
        )

    summary = _mapping(result.get("summary"))
    lines.extend(
        [
            "",
            "## Summary",
            f"- upstreams: {summary.get('upstream_count', 0)}",
            f"- manifests: {summary.get('manifest_count', 0)}",
            f"- missing required manifests: {summary.get('missing_required_manifests', 0)}",
        ]
    )
    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip()


def format_fabric_doctor_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric doctor",
        "",
        f"Fabric: {result.get('name')}",
        f"Gateway: {result.get('gateway_url') or '(missing)'}",
        "",
        "## Checks",
    ]
    for check in result.get("checks", []):
        lines.append(f"- [{check.get('status')}] {check.get('id')}: {check.get('message')}")

    summary = _mapping(result.get("summary"))
    lines.extend(
        [
            "",
            "## Summary",
            (
                f"Passed: {summary.get('passed', 0)} | Failed: {summary.get('failed', 0)} | "
                f"Warnings: {summary.get('warnings', 0)} | Skipped: {summary.get('skipped', 0)}"
            ),
        ]
    )
    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip()


def _proxy_status(proxy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "host": proxy.get("host"),
        "port": proxy.get("port"),
        "policy": str(proxy.get("policy")) if proxy.get("policy") is not None else None,
        "state": proxy.get("state"),
        "record_out": str(proxy.get("record_out")) if proxy.get("record_out") is not None else None,
        "audit_out": str(proxy.get("audit_out")) if proxy.get("audit_out") is not None else None,
        "tunnel_provider": proxy.get("tunnel_provider"),
        "tunnel_public_url": proxy.get("tunnel_public_url"),
        "lease_required": proxy.get("lease_required"),
        "cloudflare_access": proxy.get("cloudflare_access"),
        "facade": bool(proxy.get("upstreams")),
    }


def _upstream_status(upstream: Mapping[str, Any]) -> dict[str, Any]:
    status: dict[str, Any] = {
        "name": upstream.get("name"),
        "transport": upstream.get("transport"),
        "tool_prefix": upstream.get("tool_prefix"),
        "default": upstream.get("default", False),
    }
    for field in ("url", "command", "cwd", "peer", "local_port", "bridge_command", "bridge_config"):
        if upstream.get(field) is not None:
            status[field] = str(upstream[field])
    if upstream.get("args"):
        status["args"] = list(upstream["args"])
    if upstream.get("bridge_args"):
        status["bridge_args"] = list(upstream["bridge_args"])
    manifest = _manifest_status(upstream)
    if manifest:
        status["manifest"] = manifest
    return status


def _manifest_status(upstream: Mapping[str, Any]) -> dict[str, Any]:
    path = upstream.get("manifest")
    if path is None:
        return {}
    manifest_path = Path(path)
    status: dict[str, Any] = {
        "path": str(manifest_path),
        "required": bool(upstream.get("manifest_required", True)),
        "exists": manifest_path.is_file(),
        "expected_identity": upstream.get("manifest_identity"),
        "configured_key_id": upstream.get("manifest_key_id"),
        "secret_env": upstream.get("manifest_secret_env"),
        "secret_env_set": bool(os.environ.get(str(upstream.get("manifest_secret_env"))))
        if upstream.get("manifest_secret_env")
        else None,
        "inline_secret_configured": bool(upstream.get("manifest_secret")),
    }
    if not manifest_path.is_file():
        return _drop_empty(status)
    try:
        document = load_manifest(manifest_path)
    except Exception as exc:
        status["load_error"] = str(exc)
        return _drop_empty(status)
    signature = document.get("snulbug_signature")
    if isinstance(signature, Mapping):
        status["signed"] = True
        status["signature_key_id"] = signature.get("key_id")
        status["digest"] = signature.get("digest")
        status["algorithm"] = signature.get("algorithm")
    else:
        status["signed"] = False
    for field in ("schema", "identity", "transport", "tool_prefix"):
        if document.get(field) is not None:
            status[f"declared_{field}"] = document[field]
    tools = document.get("tools")
    if isinstance(tools, list):
        status["declared_tool_count"] = len(tools)
    return _drop_empty(status)


def _fabric_summary(
    fabric: Mapping[str, Any],
    proxy: Mapping[str, Any],
    upstreams: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    transports: dict[str, int] = {}
    for upstream in upstreams:
        transport = str(upstream.get("transport", "unknown"))
        transports[transport] = transports.get(transport, 0) + 1
    missing_required_manifests = sum(
        1
        for upstream in upstreams
        if bool(fabric.get("require_manifests")) and not _mapping(upstream.get("manifest")).get("exists")
    )
    default_upstream = next((upstream.get("name") for upstream in upstreams if upstream.get("default")), None)
    return {
        "upstream_count": len(upstreams),
        "transports": transports,
        "manifest_count": sum(1 for upstream in upstreams if upstream.get("manifest")),
        "missing_required_manifests": missing_required_manifests,
        "default_upstream": default_upstream,
        "facade": bool(proxy.get("upstreams")),
        "tunnel_provider": proxy.get("tunnel_provider"),
    }


def _fabric_recommendations(fabric: Mapping[str, Any], upstreams: Sequence[Mapping[str, Any]]) -> list[str]:
    recommendations = []
    if not upstreams:
        recommendations.append("Declare [[mcp.proxy.upstreams]] entries to run snulbug as a fabric facade.")
    if fabric.get("require_manifests") and any(
        not _mapping(upstream.get("manifest")).get("exists") for upstream in upstreams
    ):
        recommendations.append("Add signed manifests for every upstream or set require_manifests = false.")
    if not fabric.get("gateway_url"):
        recommendations.append("Set mcp.fabric.gateway_url or configure mcp.proxy.host and mcp.proxy.port.")
    return recommendations


def _run_manifest_checks(
    checks: list[dict[str, Any]],
    upstream: Mapping[str, Any],
    *,
    require_manifest: bool,
) -> None:
    name = _check_name(upstream)
    manifest = upstream.get("manifest")
    if manifest is None:
        _add_check(
            checks,
            f"upstream.{name}.manifest_present",
            False if require_manifest else None,
            "manifest is required but missing" if require_manifest else "no manifest configured",
        )
        return
    manifest_path = Path(manifest)
    exists = manifest_path.is_file()
    _add_check(
        checks,
        f"upstream.{name}.manifest_present",
        exists,
        f"manifest exists at {manifest_path}" if exists else f"manifest file is missing: {manifest_path}",
        details={"path": str(manifest_path)},
    )
    if not exists:
        return
    try:
        document = load_manifest(manifest_path)
        signature = document.get("snulbug_signature")
        signature_key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
        key_id = upstream.get("manifest_key_id") or signature_key_id
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("manifest key_id is required")
        secret = upstream.get("manifest_secret")
        secret_env = upstream.get("manifest_secret_env")
        if not secret and isinstance(secret_env, str):
            secret = os.environ.get(secret_env)
        if not secret:
            source = f"environment variable {secret_env!r}" if secret_env else "manifest_secret"
            raise ValueError(f"manifest secret is required from {source}")
        expected_identity = upstream.get("manifest_identity")
        verified = verify_upstream_manifest(
            document,
            secrets={key_id: str(secret)},
            expected_identity=expected_identity if isinstance(expected_identity, str) else None,
        )
        _add_check(
            checks,
            f"upstream.{name}.manifest_verified",
            True,
            f"manifest verified for {verified.get('identity', upstream.get('name'))}",
            details=verified,
        )
    except Exception as exc:
        _add_check(checks, f"upstream.{name}.manifest_verified", False, f"manifest verification failed: {exc}")


def _run_upstream_probe_checks(
    checks: list[dict[str, Any]],
    probes: dict[str, Any],
    upstream: Mapping[str, Any],
    *,
    headers: Mapping[str, str],
    timeout: float,
) -> None:
    name = _check_name(upstream)
    transport = upstream.get("transport")
    if transport in {"http", "holepunch"}:
        url = upstream.get("url")
        if not isinstance(url, str) or not url:
            _add_check(checks, f"upstream.{name}.url_present", False, "upstream URL is missing")
            return
        _run_mcp_endpoint_checks(
            checks,
            probes,
            check_prefix=f"upstream.{name}",
            url=url,
            headers=headers,
            timeout=timeout,
            label=f"upstream {upstream.get('name')}",
        )
        return
    if transport == "stdio":
        command = upstream.get("command")
        command_ok = isinstance(command, str) and bool(_resolve_command(command))
        _add_check(
            checks,
            f"upstream.{name}.stdio_command",
            command_ok,
            f"stdio command is available: {command}" if command_ok else f"stdio command is not on PATH: {command}",
            details={"command": command},
        )
        return
    _add_check(checks, f"upstream.{name}.transport_supported", False, f"unsupported transport: {transport!r}")


def _run_mcp_endpoint_checks(
    checks: list[dict[str, Any]],
    probes: dict[str, Any],
    *,
    check_prefix: str,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    label: str,
) -> None:
    probe = _probe_mcp_tools_list(url, headers=headers, timeout=timeout)
    probes[check_prefix] = probe
    reachable = probe.get("error") is None and probe.get("status") is not None
    reachable_message = (
        f"{label} responded with HTTP {probe.get('status')}"
        if reachable
        else f"{label} did not respond: {probe.get('error')}"
    )
    _add_check(
        checks,
        f"{check_prefix}.reachable",
        reachable,
        reachable_message,
        details={"url": url, "status": probe.get("status"), "error": probe.get("error")},
    )
    json_body = probe.get("json")
    tools = json_body.get("result", {}).get("tools") if isinstance(json_body, Mapping) else None
    round_trip = probe.get("status") == 200 and isinstance(tools, list)
    _add_check(
        checks,
        f"{check_prefix}.tools_list",
        round_trip,
        f"{label} returned tools/list with {len(tools)} tool(s)"
        if round_trip
        else f"{label} did not return a valid tools/list response",
        details={"status": probe.get("status"), "body_sample": probe.get("body_sample")},
    )


def _probe_mcp_tools_list(url: str, *, headers: Mapping[str, str], timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _probe_error(url, "invalid URL")
    body = json.dumps(_FABRIC_DOCTOR_REQUEST, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "Host": parsed.netloc,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "User-Agent": "snulbug-fabric-doctor",
        **dict(headers),
    }
    connection = _connection(parsed, timeout)
    try:
        connection.request("POST", _exact_target(parsed), body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        text = response_body.decode("utf-8", errors="replace")
        json_body = None
        try:
            json_body = json.loads(text) if text else None
        except json.JSONDecodeError:
            json_body = None
        return {
            "url": url,
            "status": int(response.status),
            "headers": {name.lower(): value for name, value in response.getheaders()},
            "body_size": len(response_body),
            "body_sample": text[:300],
            "json": json_body,
            "error": None,
        }
    except Exception as exc:
        return _probe_error(url, str(exc))
    finally:
        connection.close()


def _probe_error(url: str, error: str) -> dict[str, Any]:
    return {
        "url": url,
        "status": None,
        "headers": {},
        "body_size": 0,
        "body_sample": "",
        "json": None,
        "error": error,
    }


def _connection(upstream: SplitResult, timeout: float) -> http.client.HTTPConnection:
    host = upstream.hostname
    if host is None:
        raise ValueError("upstream host is required")
    port = upstream.port
    if upstream.scheme == "https":
        return http.client.HTTPSConnection(host, port=port, timeout=timeout)
    return http.client.HTTPConnection(host, port=port, timeout=timeout)


def _exact_target(upstream: SplitResult) -> str:
    path = upstream.path or "/"
    return f"{path}?{upstream.query}" if upstream.query else path


def _resolve_command(command: str) -> str | None:
    if "/" in command or "\\" in command:
        return command if Path(command).exists() else None
    return shutil.which(command)


def _doctor_recommendations(checks: Sequence[Mapping[str, Any]], *, headers: Mapping[str, str]) -> list[str]:
    recommendations = []
    statuses = {str(check.get("id")): str(check.get("status")) for check in checks}
    if statuses.get("gateway.tools_list") == "fail" and not any(name.lower() == "authorization" for name in headers):
        recommendations.append("Pass --token or --header Authorization:Bearer... so doctor can verify the gateway.")
    manifest_failed = any(
        str(check.get("id", "")).endswith(".manifest_verified") and check.get("status") == "fail" for check in checks
    )
    tools_list_failed = any(
        str(check.get("id", "")).endswith(".tools_list") and check.get("status") == "fail" for check in checks
    )
    if manifest_failed:
        recommendations.append(
            "Fix manifest signatures, expected identities, or manifest secret environment variables."
        )
    if tools_list_failed:
        recommendations.append(
            "Start the gateway/upstream servers, or disable the corresponding probe for static checks."
        )
    if statuses.get("proxy.facade_enabled") == "warn":
        recommendations.append("Declare [[mcp.proxy.upstreams]] entries to expose multiple MCP servers as one fabric.")
    return recommendations


def _checks_summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "skipped": sum(1 for check in checks if check.get("status") == "skip"),
    }


def _add_check(
    checks: list[dict[str, Any]],
    check_id: str,
    passed: bool | None,
    message: str,
    *,
    severity: str = "error",
    details: Mapping[str, Any] | None = None,
) -> None:
    if passed is True:
        status = "pass"
    elif passed is None:
        status = "skip"
    elif severity == "warning":
        status = "warn"
    else:
        status = "fail"
    check = {
        "id": check_id,
        "status": status,
        "message": message,
    }
    if details:
        check["details"] = _json_safe(details)
    checks.append(check)


def _upstreams(proxy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    upstreams = proxy.get("upstreams")
    if not isinstance(upstreams, list):
        return []
    return [upstream for upstream in upstreams if isinstance(upstream, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _check_name(upstream: Mapping[str, Any]) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(upstream.get("name", "upstream"))).strip("_") or "upstream"


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


def _json_safe(value: Mapping[str, Any]) -> dict[str, Any]:
    result = {}
    for key, item in value.items():
        if isinstance(item, Path):
            result[str(key)] = str(item)
        elif isinstance(item, Mapping):
            result[str(key)] = _json_safe(item)
        elif isinstance(item, list):
            result[str(key)] = [str(part) if isinstance(part, Path) else part for part in item]
        else:
            result[str(key)] = item
    return result

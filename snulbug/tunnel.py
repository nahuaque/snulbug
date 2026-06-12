from __future__ import annotations

import http.client
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .config import DEFAULT_CONFIG_PATH, load_mcp_proxy_config

TUNNEL_PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale")
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_AUTH_FAILURE_STATUSES = (401, 403)

_DOCTOR_REQUEST = {
    "jsonrpc": "2.0",
    "id": "snulbug-doctor-tools-list",
    "method": "tools/list",
    "params": {},
}


@dataclass(frozen=True)
class HttpProbe:
    url: str
    status: int | None
    headers: Mapping[str, str]
    body_size: int
    body_sample: str
    json_body: Any
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "body_size": self.body_size,
            "body_sample": self.body_sample,
            "json": self.json_body,
            "error": self.error,
        }


def parse_tunnel_headers(values: Sequence[str] | None, *, token: str | None = None) -> dict[str, str]:
    """Parse repeated CLI-style HTTP headers."""

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for value in values or ():
        name, separator, header_value = value.partition(":")
        if not separator:
            name, separator, header_value = value.partition("=")
        if not separator or not name.strip() or not header_value.strip():
            raise ValueError("headers must use 'Name: value' or 'Name=value'")
        name = name.strip()
        header_value = header_value.strip()
        if "\n" in name or "\r" in name or "\n" in header_value or "\r" in header_value:
            raise ValueError("headers must not contain newlines")
        headers[name] = header_value
    return headers


def doctor_tunnel(
    *,
    provider: str = "generic",
    url: str | None = None,
    local_url: str | None = None,
    config: str | Path | None = None,
    headers: Mapping[str, str] | None = None,
    path: str = DEFAULT_MCP_PATH,
    timeout: float = 5.0,
    auth_failure_statuses: Sequence[int] = DEFAULT_AUTH_FAILURE_STATUSES,
) -> dict[str, Any]:
    """Run tunnel-safety probes against a snulbug MCP proxy."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    headers = dict(headers or {})
    auth_failure_statuses = tuple(int(status) for status in auth_failure_statuses)
    checks: list[dict[str, Any]] = []
    probes: dict[str, Any] = {}
    recommendations: list[str] = []

    config_result = _load_config(config)
    proxy_config = config_result.get("proxy_config")
    if config_result["path"] is not None:
        _add_check(
            checks,
            "config.loaded",
            config_result["ok"],
            config_result["message"],
            severity="error" if config_result["explicit"] else "warning",
            details={"config": str(config_result["path"])},
        )

    if local_url is None and isinstance(proxy_config, Mapping):
        local_url = f"http://{proxy_config['host']}:{proxy_config['port']}{_normalize_path(path)}"
    public_url = _normalize_url(url, path) if url else None
    local_url = _normalize_url(local_url, path) if local_url else None

    if public_url is None and local_url is None:
        _add_check(
            checks,
            "target.url_present",
            False,
            "pass --url, --local-url, or run from a directory containing snulbug.toml",
        )

    _config_safety_checks(checks, proxy_config, public_url=public_url)

    log_stats_before = _log_stats(proxy_config)
    if local_url:
        _run_target_checks(
            checks,
            probes,
            target="local",
            url=local_url,
            headers=headers,
            timeout=timeout,
            auth_failure_statuses=auth_failure_statuses,
        )
    else:
        _add_check(checks, "local.url_present", None, "no local URL was provided or inferred")

    if public_url:
        public_auth_probe = _run_target_checks(
            checks,
            probes,
            target="public",
            url=public_url,
            headers=headers,
            timeout=timeout,
            auth_failure_statuses=auth_failure_statuses,
        )
        _provider_hint_check(checks, provider=provider, url=public_url, probe=public_auth_probe)
    else:
        _add_check(checks, "public.url_present", None, "no public tunnel URL was provided")

    _log_checks(checks, proxy_config, before=log_stats_before, after=_log_stats(proxy_config))
    summary = _summary(checks)
    recommendations.extend(_recommendations(checks, headers=headers, public_url=public_url))

    return {
        "ok": summary["failed"] == 0,
        "provider": provider,
        "url": public_url,
        "local_url": local_url,
        "config": str(config_result["path"]) if config_result["path"] is not None else None,
        "checks": checks,
        "summary": summary,
        "recommendations": recommendations,
        "probes": probes,
    }


def format_tunnel_doctor_report(result: Mapping[str, Any]) -> str:
    """Render a tunnel doctor result as readable Markdown."""

    lines = [
        "# snulbug tunnel doctor",
        "",
        f"Provider: {result.get('provider', 'generic')}",
        f"Local URL: {result.get('local_url') or '(not checked)'}",
        f"Public URL: {result.get('url') or '(not checked)'}",
        "",
        "## Checks",
    ]
    for check in result.get("checks", []):
        status = str(check.get("status", "unknown"))
        lines.append(f"- [{status}] {check.get('id')}: {check.get('message')}")

    summary = result.get("summary", {})
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
    return "\n".join(lines)


def _run_target_checks(
    checks: list[dict[str, Any]],
    probes: dict[str, Any],
    *,
    target: str,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    auth_failure_statuses: Sequence[int],
) -> HttpProbe | None:
    unauthenticated = _post_json(url, headers={}, timeout=timeout)
    probes[f"{target}.unauthenticated"] = unauthenticated.to_dict()
    reachable = unauthenticated.error is None
    _add_check(
        checks,
        f"{target}.reachable",
        reachable,
        f"{target} URL accepted an HTTP connection" if reachable else f"{target} URL failed: {unauthenticated.error}",
    )
    blocked = reachable and unauthenticated.status in auth_failure_statuses
    _add_check(
        checks,
        f"{target}.unauthenticated_blocked",
        blocked,
        (
            f"{target} unauthenticated MCP request was blocked with status {unauthenticated.status}"
            if blocked
            else f"{target} unauthenticated MCP request was not blocked by the policy proxy"
        ),
        details={"expected_statuses": list(auth_failure_statuses), "status": unauthenticated.status},
    )

    if not headers:
        _add_check(
            checks,
            f"{target}.authenticated_mcp_round_trip",
            None,
            "no auth headers were supplied; pass --token or --header to test authenticated MCP traffic",
        )
        return None

    authenticated = _post_json(url, headers=headers, timeout=timeout)
    probes[f"{target}.authenticated"] = authenticated.to_dict()
    mcp_ok = _is_successful_mcp_probe(authenticated)
    _add_check(
        checks,
        f"{target}.authenticated_mcp_round_trip",
        mcp_ok,
        (
            f"{target} authenticated tools/list round trip succeeded"
            if mcp_ok
            else f"{target} authenticated tools/list round trip failed"
        ),
        details={"status": authenticated.status, "error": authenticated.error},
    )
    return authenticated


def _post_json(url: str, *, headers: Mapping[str, str], timeout: float) -> HttpProbe:
    parsed = urlsplit(url)
    body = json.dumps(_DOCTOR_REQUEST, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "snulbug-tunnel-doctor",
        **dict(headers),
    }
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    target = _request_target(parsed)
    try:
        connection.request("POST", target, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        decoded = response_body.decode("utf-8", errors="replace")
        return HttpProbe(
            url=url,
            status=int(response.status),
            headers=_response_headers(response.getheaders()),
            body_size=len(response_body),
            body_sample=decoded[:500],
            json_body=_parse_json(decoded),
        )
    except Exception as exc:
        return HttpProbe(url=url, status=None, headers={}, body_size=0, body_sample="", json_body=None, error=str(exc))
    finally:
        connection.close()


def _normalize_url(value: str | None, path: str) -> str:
    if not value:
        raise ValueError("URL must not be empty")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be an absolute http:// or https:// URL")
    if parsed.path in {"", "/"}:
        parsed = parsed._replace(path=_normalize_path(path))
    return urlunsplit(parsed._replace(fragment=""))


def _normalize_path(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"


def _request_target(parsed: SplitResult) -> str:
    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def _response_headers(headers: Sequence[tuple[str, str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in headers:
        result[name.lower()] = value
    return result


def _parse_json(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def _is_successful_mcp_probe(probe: HttpProbe) -> bool:
    if probe.error is not None or probe.status != 200 or not isinstance(probe.json_body, Mapping):
        return False
    if probe.json_body.get("id") == _DOCTOR_REQUEST["id"]:
        return "result" in probe.json_body or "error" in probe.json_body
    return "result" in probe.json_body or "jsonrpc" in probe.json_body


def _load_config(config: str | Path | None) -> dict[str, Any]:
    explicit = config is not None
    path = Path(config) if config is not None else Path(DEFAULT_CONFIG_PATH)
    if not path.exists():
        return {
            "ok": False if explicit else None,
            "explicit": explicit,
            "path": path if explicit else None,
            "proxy_config": None,
            "message": f"config file not found: {path}",
        }
    try:
        proxy_config = load_mcp_proxy_config(path)
    except Exception as exc:
        return {
            "ok": False,
            "explicit": explicit,
            "path": path,
            "proxy_config": None,
            "message": f"could not load config: {exc}",
        }
    return {
        "ok": True,
        "explicit": explicit,
        "path": path,
        "proxy_config": proxy_config,
        "message": f"loaded config: {path}",
    }


def _config_safety_checks(
    checks: list[dict[str, Any]],
    proxy_config: Mapping[str, Any] | None,
    *,
    public_url: str | None,
) -> None:
    if not isinstance(proxy_config, Mapping):
        _add_check(checks, "config.safe_defaults", None, "no snulbug.toml config was loaded")
        return
    severity = "error" if public_url else "warning"
    _add_check(
        checks,
        "config.redact_records",
        bool(proxy_config.get("redact_records")),
        "live replay records are redacted by default",
        severity=severity,
    )
    _add_check(
        checks,
        "config.response_redact_secrets",
        bool(proxy_config.get("response_redact_secrets")),
        "MCP responses redact likely secrets before returning to the client",
        severity=severity,
    )
    _add_check(
        checks,
        "config.tool_pinning",
        bool(proxy_config.get("tool_pinning")),
        "tools/list descriptions and schemas are pinned on first sight",
        severity=severity,
    )
    _add_check(
        checks,
        "config.tool_pinning_action",
        proxy_config.get("tool_pinning_action") == "block",
        "tool pinning action is set to block",
        severity="warning",
        details={"tool_pinning_action": proxy_config.get("tool_pinning_action")},
    )
    _add_check(
        checks,
        "config.schema_validation",
        bool(proxy_config.get("schema_validation")),
        "tools/call arguments are validated against observed inputSchema values",
        severity="warning",
    )


def _provider_hint_check(
    checks: list[dict[str, Any]],
    *,
    provider: str,
    url: str,
    probe: HttpProbe | None,
) -> None:
    if provider == "generic":
        _add_check(checks, "public.provider_hint", None, "provider is generic; no provider header hint expected")
        return
    parsed = urlsplit(url)
    headers = dict(probe.headers) if probe is not None else {}
    hostname = parsed.hostname or ""
    header_blob = " ".join(f"{name}:{value}" for name, value in headers.items()).lower()
    if provider == "ngrok":
        ok = "ngrok" in hostname.lower() or "ngrok" in header_blob
        message = "public URL or response headers look like ngrok"
    elif provider == "cloudflare":
        ok = "cf-ray" in headers or "cloudflare" in header_blob
        message = "public response includes Cloudflare edge hints"
    else:
        ok = hostname.endswith(".ts.net") or ".ts.net" in hostname
        message = "public URL looks like a Tailscale Funnel hostname"
    _add_check(checks, "public.provider_hint", ok, message, severity="warning", details={"hostname": hostname})


def _log_stats(proxy_config: Mapping[str, Any] | None) -> dict[str, int | None]:
    if not isinstance(proxy_config, Mapping):
        return {}
    stats: dict[str, int | None] = {}
    for key in ("record_out", "audit_out"):
        value = proxy_config.get(key)
        if value:
            path = Path(value)
            stats[key] = path.stat().st_size if path.exists() else 0
    return stats


def _log_checks(
    checks: list[dict[str, Any]],
    proxy_config: Mapping[str, Any] | None,
    *,
    before: Mapping[str, int | None],
    after: Mapping[str, int | None],
) -> None:
    if not isinstance(proxy_config, Mapping):
        _add_check(checks, "logs.configured", None, "no config was loaded, so log paths could not be checked")
        return
    for key in ("record_out", "audit_out"):
        value = proxy_config.get(key)
        if not value:
            _add_check(checks, f"logs.{key}_configured", None, f"{key} is not configured")
            continue
        grew = (after.get(key) or 0) > (before.get(key) or 0)
        _add_check(
            checks,
            f"logs.{key}_grew",
            grew,
            f"{key} grew after doctor probes",
            details={"path": str(value), "before_bytes": before.get(key), "after_bytes": after.get(key)},
        )


def _summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "skipped": sum(1 for check in checks if check.get("status") == "skip"),
    }


def _recommendations(
    checks: Sequence[Mapping[str, Any]],
    *,
    headers: Mapping[str, str],
    public_url: str | None,
) -> list[str]:
    check_statuses = {str(check.get("id")): str(check.get("status")) for check in checks}
    recommendations: list[str] = []
    if public_url is None:
        recommendations.append("Pass --url with the public tunnel URL before sharing the MCP endpoint externally.")
    if not headers:
        recommendations.append("Pass --token or --header so doctor can verify authenticated MCP traffic.")
    if check_statuses.get("public.unauthenticated_blocked") == "fail":
        recommendations.append("Point the tunnel at snulbug, not the upstream MCP server, and require bearer auth.")
    if any(check.get("status") == "fail" and str(check.get("id", "")).startswith("logs.") for check in checks):
        recommendations.append("Run the proxy with record_out and audit_out enabled before relying on tunnel traffic.")
    if any(check.get("status") == "fail" and str(check.get("id", "")).startswith("config.") for check in checks):
        recommendations.append(
            "Regenerate with `snulbug mcp quickstart --preset tunnel-safe` or restore safe defaults."
        )
    return recommendations


def _add_check(
    checks: list[dict[str, Any]],
    check_id: str,
    ok: bool | None,
    message: str,
    *,
    severity: str = "error",
    details: Mapping[str, Any] | None = None,
) -> None:
    if ok is True:
        status = "pass"
    elif ok is None:
        status = "skip"
    elif severity == "warning":
        status = "warn"
    else:
        status = "fail"
    checks.append(
        {
            "id": check_id,
            "status": status,
            "ok": ok,
            "severity": severity,
            "message": message,
            "details": dict(details or {}),
        }
    )

from __future__ import annotations

import http.client
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .config import DEFAULT_CONFIG_PATH, DEFAULT_MCP_PROXY_CONFIG, load_mcp_proxy_config

TUNNEL_PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale")
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_AUTH_FAILURE_STATUSES = (401, 403)
DEFAULT_TUNNEL_TOKEN_ENV = "SNULBUG_TOKEN"
DEFAULT_TUNNEL_OUTPUT_DIR = "tunnel.snulbug"

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


@dataclass(frozen=True)
class TunnelAuditConfig:
    provider: str = "auto"
    public_url: str | None = None

    def __post_init__(self) -> None:
        if self.provider not in {"auto", *TUNNEL_PROVIDERS}:
            raise ValueError("tunnel provider must be 'auto', 'generic', 'ngrok', 'cloudflare', or 'tailscale'")


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


def build_tunnel_audit_metadata(
    scope: Mapping[str, Any],
    *,
    config: TunnelAuditConfig | None = None,
) -> dict[str, Any]:
    """Extract provider-aware tunnel audit metadata from an ASGI HTTP scope."""

    config = config or TunnelAuditConfig()
    headers = _scope_headers(scope)
    host = headers.get("host")
    forwarded_host = headers.get("x-forwarded-host") or headers.get("x-original-host")
    public_url = config.public_url or _public_url_from_headers(scope, headers)
    provider = config.provider if config.provider != "auto" else _infer_tunnel_provider(headers, public_url)

    metadata: dict[str, Any] = {
        "provider": provider,
        "inferred": config.provider == "auto",
        "public_url": public_url,
        "public_host": _host_from_url(public_url) or forwarded_host or host,
        "host": host,
        "forwarded_host": forwarded_host,
        "forwarded_proto": headers.get("x-forwarded-proto"),
        "forwarded_for": _forwarded_chain(headers.get("x-forwarded-for")),
        "client": _scope_client(scope),
        "source_ip": _source_ip(headers, scope),
        "edge_request_id": _edge_request_id(provider, headers),
    }
    if provider == "cloudflare":
        metadata["cloudflare"] = _drop_empty(
            {
                "ray": headers.get("cf-ray"),
                "connecting_ip": headers.get("cf-connecting-ip"),
                "ip_country": headers.get("cf-ipcountry"),
                "visitor": _parse_json(headers.get("cf-visitor", "")),
                "access_authenticated_user_email": headers.get("cf-access-authenticated-user-email"),
            }
        )
    elif provider == "ngrok":
        metadata["ngrok"] = _drop_empty(
            {
                "request_id": headers.get("x-ngrok-request-id") or headers.get("ngrok-request-id"),
                "trace_id": headers.get("x-ngrok-trace-id") or headers.get("ngrok-trace-id"),
            }
        )
    elif provider == "tailscale":
        metadata["tailscale"] = _drop_empty(
            {
                "tsnet_host": bool((metadata.get("public_host") or "").endswith(".ts.net")),
            }
        )
    return _drop_empty(metadata)


def init_tunnel_provider(
    *,
    provider: str,
    config: str | Path | None = None,
    local_url: str | None = None,
    public_url: str | None = None,
    hostname: str | None = None,
    token_env: str = DEFAULT_TUNNEL_TOKEN_ENV,
    path: str = DEFAULT_MCP_PATH,
    output_dir: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Generate provider-specific tunnel setup snippets for a snulbug MCP proxy."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if not token_env:
        raise ValueError("token_env must not be empty")

    config_result = _load_config(config)
    if config_result["explicit"] and config_result["ok"] is not True:
        raise ValueError(str(config_result["message"]))

    endpoint = _infer_local_endpoint(local_url, config_result.get("proxy_config"), path)
    origin = _origin_from_endpoint(endpoint, path)
    public_endpoint = _public_endpoint(provider, public_url=public_url, hostname=hostname, path=path)
    plan = _provider_plan(
        provider,
        origin=origin,
        endpoint=endpoint,
        public_endpoint=public_endpoint,
        token_env=token_env,
    )
    files = _tunnel_init_files(
        provider,
        origin=origin,
        endpoint=endpoint,
        public_endpoint=public_endpoint,
        token_env=token_env,
        plan=plan,
    )
    written_files: list[str] = []
    if output_dir is not None:
        written_files = _write_tunnel_init_files(Path(output_dir), files, force=force)

    return {
        "ok": True,
        "provider": provider,
        "config": str(config_result["path"]) if config_result["path"] is not None else None,
        "local_origin": origin,
        "local_url": endpoint,
        "public_url": public_endpoint,
        "token_env": token_env,
        "commands": plan["commands"],
        "client": plan["client"],
        "doctor": plan["doctor"],
        "files": files,
        "written_files": written_files,
        "next_steps": [
            "Start snulbug with `snulbug mcp proxy --config snulbug.toml`.",
            "Run the provider command or config generated by this init plan.",
            "Run the generated `snulbug tunnel doctor` command before sharing the public MCP URL.",
        ],
    }


def format_tunnel_init_report(result: Mapping[str, Any]) -> str:
    """Render a tunnel init plan as copy-pasteable Markdown."""

    lines = [
        "# snulbug tunnel init",
        "",
        f"Provider: {result.get('provider')}",
        f"Local origin: {result.get('local_origin')}",
        f"Local MCP URL: {result.get('local_url')}",
        f"Public MCP URL: {result.get('public_url')}",
        "",
        "## Commands",
    ]
    for command in result.get("commands", []):
        lines.extend(
            [
                f"### {command['title']}",
                "",
                str(command.get("description", "")),
                "",
                "```bash",
                str(command["command"]),
                "```",
                "",
            ]
        )

    doctor = result.get("doctor", {})
    if doctor:
        lines.extend(["## Verify", "", "```bash", str(doctor.get("command", "")), "```", ""])

    client = result.get("client", {})
    if client:
        lines.extend(
            [
                "## MCP client",
                "",
                f"URL: `{client.get('url')}`",
                "",
                "Headers:",
            ]
        )
        for name, value in dict(client.get("headers", {})).items():
            lines.append(f"- `{name}: {value}`")
        lines.append("")

    written_files = result.get("written_files", [])
    if written_files:
        lines.extend(["## Written files"])
        for path in written_files:
            lines.append(f"- `{path}`")
        lines.append("")

    next_steps = result.get("next_steps", [])
    if next_steps:
        lines.extend(["## Next steps"])
        for step in next_steps:
            lines.append(f"- {step}")

    return "\n".join(lines).rstrip()


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


def _infer_local_endpoint(
    local_url: str | None,
    proxy_config: Any,
    path: str,
) -> str:
    if local_url:
        return _normalize_url(local_url, path)
    if isinstance(proxy_config, Mapping):
        return _normalize_url(f"http://{proxy_config['host']}:{proxy_config['port']}{_normalize_path(path)}", path)
    defaults = DEFAULT_MCP_PROXY_CONFIG
    return _normalize_url(f"http://{defaults['host']}:{defaults['port']}{_normalize_path(path)}", path)


def _origin_from_endpoint(endpoint: str, path: str) -> str:
    parsed = urlsplit(endpoint)
    normalized_path = _normalize_path(path)
    endpoint_path = parsed.path or "/"
    if endpoint_path == normalized_path:
        origin_path = ""
    elif endpoint_path.endswith(normalized_path):
        origin_path = endpoint_path[: -len(normalized_path)] or ""
    else:
        origin_path = endpoint_path.rstrip("/")
    return urlunsplit(parsed._replace(path=origin_path, query="", fragment="")).rstrip("/")


def _public_endpoint(
    provider: str,
    *,
    public_url: str | None,
    hostname: str | None,
    path: str,
) -> str:
    if public_url:
        return _normalize_url(public_url, path)
    normalized_path = _normalize_path(path)
    if provider == "ngrok":
        host = hostname or "YOUR-TUNNEL.ngrok.app"
    elif provider == "cloudflare":
        host = hostname or "mcp.example.com"
    elif provider == "tailscale":
        host = hostname or "YOUR-HOST.YOUR-TAILNET.ts.net"
    else:
        host = hostname or "YOUR-TUNNEL.example"
    return f"https://{host}{normalized_path}"


def _provider_plan(
    provider: str,
    *,
    origin: str,
    endpoint: str,
    public_endpoint: str,
    token_env: str,
) -> dict[str, Any]:
    token = f"${{{token_env}}}"
    if provider == "ngrok":
        tunnel_target = _ngrok_target(origin)
        public_host = urlsplit(public_endpoint).hostname or "YOUR-TUNNEL.ngrok.app"
        domain_arg = "" if public_host == "YOUR-TUNNEL.ngrok.app" else f" --domain {public_host}"
        commands = [
            {
                "id": "run-ngrok",
                "title": "Expose snulbug with ngrok",
                "description": "Point ngrok at the snulbug proxy origin, not the upstream MCP server.",
                "command": f"ngrok http{domain_arg} {tunnel_target}",
            }
        ]
    elif provider == "cloudflare":
        public_host = urlsplit(public_endpoint).hostname or "mcp.example.com"
        commands = [
            {
                "id": "create-cloudflare-tunnel",
                "title": "Create and route a Cloudflare Tunnel",
                "description": "Create a named tunnel and route the public hostname to it.",
                "command": "\n".join(
                    [
                        "cloudflared tunnel create snulbug-mcp",
                        f"cloudflared tunnel route dns snulbug-mcp {public_host}",
                    ]
                ),
            },
            {
                "id": "run-cloudflare-tunnel",
                "title": "Run cloudflared with generated ingress config",
                "description": "The generated config routes only the public MCP hostname to snulbug.",
                "command": "cloudflared tunnel --config cloudflared.yml run snulbug-mcp",
            },
        ]
    elif provider == "tailscale":
        funnel_target = _tailscale_target(origin)
        commands = [
            {
                "id": "run-tailscale-funnel",
                "title": "Expose snulbug with Tailscale Funnel",
                "description": "Funnel exposes the snulbug proxy URL publicly; snulbug still enforces MCP policy.",
                "command": f"sudo tailscale funnel {funnel_target}",
            }
        ]
    else:
        commands = [
            {
                "id": "run-provider-tunnel",
                "title": "Expose snulbug with your tunnel provider",
                "description": "Point the tunnel at the snulbug proxy origin, not the upstream MCP server.",
                "command": f"# Configure your tunnel provider to forward public HTTPS traffic to {origin}",
            }
        ]

    doctor_command = _doctor_command(provider, public_endpoint=public_endpoint, token_env=token_env)
    return {
        "commands": commands,
        "client": {
            "url": public_endpoint,
            "headers": {"Authorization": f"Bearer {token}"},
        },
        "doctor": {
            "command": doctor_command,
            "local_url": endpoint,
            "public_url": public_endpoint,
        },
    }


def _ngrok_target(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and not parsed.path:
        return str(parsed.port or 80)
    return origin


def _tailscale_target(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and not parsed.path:
        return str(parsed.port or 80)
    return origin


def _doctor_command(provider: str, *, public_endpoint: str, token_env: str) -> str:
    lines = ["snulbug tunnel doctor \\"]
    if provider != "generic":
        lines.append(f"  --provider {provider} \\")
    lines.extend(
        [
            f"  --url {public_endpoint} \\",
            "  --config snulbug.toml \\",
            f"  --token ${{{token_env}}}",
        ]
    )
    return "\n".join(lines)


def _tunnel_init_files(
    provider: str,
    *,
    origin: str,
    endpoint: str,
    public_endpoint: str,
    token_env: str,
    plan: Mapping[str, Any],
) -> list[dict[str, str]]:
    files = [
        {
            "path": "README.md",
            "kind": "markdown",
            "contents": _tunnel_readme(
                provider,
                origin=origin,
                endpoint=endpoint,
                public_endpoint=public_endpoint,
                token_env=token_env,
                plan=plan,
            ),
        }
    ]
    if provider == "cloudflare":
        files.append(
            {
                "path": "cloudflared.yml",
                "kind": "cloudflared-config",
                "contents": _cloudflared_config(origin, public_endpoint),
            }
        )
    elif provider == "ngrok":
        files.append(
            {
                "path": "ngrok-traffic-policy.yml",
                "kind": "ngrok-traffic-policy",
                "contents": _ngrok_traffic_policy(),
            }
        )
    return files


def _write_tunnel_init_files(output_dir: Path, files: Sequence[Mapping[str, str]], *, force: bool) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for file_spec in files:
        relative = Path(file_spec["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid tunnel init file path: {relative}")
        target = output_dir / relative
        if target.exists() and not force:
            raise FileExistsError(f"tunnel init output already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(file_spec["contents"], encoding="utf-8")
        written.append(str(target))
    return written


def _tunnel_readme(
    provider: str,
    *,
    origin: str,
    endpoint: str,
    public_endpoint: str,
    token_env: str,
    plan: Mapping[str, Any],
) -> str:
    command_sections = []
    for command in plan.get("commands", []):
        command_sections.append(
            "\n".join(
                [
                    f"## {command['title']}",
                    "",
                    str(command.get("description", "")),
                    "",
                    "```bash",
                    str(command["command"]),
                    "```",
                ]
            )
        )
    doctor = plan["doctor"]["command"]
    commands = "\n\n".join(command_sections)
    return (
        f"# snulbug {provider} tunnel setup\n\n"
        f"Local snulbug origin: `{origin}`\n\n"
        f"Local MCP URL: `{endpoint}`\n\n"
        f"Public MCP URL: `{public_endpoint}`\n\n"
        "Set the bearer token before running doctor or configuring an MCP client:\n\n"
        "```bash\n"
        f"export {token_env}=local-dev-secret\n"
        "```\n\n"
        f"{commands}\n\n"
        "## Verify before sharing\n\n"
        "```bash\n"
        f"{doctor}\n"
        "```\n\n"
        "Point MCP clients at the public MCP URL only after `snulbug tunnel doctor` passes.\n"
    )


def _cloudflared_config(origin: str, public_endpoint: str) -> str:
    hostname = urlsplit(public_endpoint).hostname or "mcp.example.com"
    return (
        "tunnel: snulbug-mcp\n"
        "credentials-file: /path/to/snulbug-mcp-credentials.json\n"
        "\n"
        "ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: {origin}\n"
        "  - service: http_status:404\n"
    )


def _ngrok_traffic_policy() -> str:
    return (
        "on_http_request:\n"
        "  - expressions:\n"
        "      - \"!hasReqHeader('Authorization')\"\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 401\n"
        '          body: "Authorization required"\n'
    )


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


def _scope_headers(scope: Mapping[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = _decode_header(raw_name).lower()
        value = _decode_header(raw_value)
        if name in headers:
            headers[name] = f"{headers[name]}, {value}"
        else:
            headers[name] = value
    return headers


def _decode_header(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _public_url_from_headers(scope: Mapping[str, Any], headers: Mapping[str, str]) -> str | None:
    host = headers.get("x-forwarded-host") or headers.get("host")
    if not host:
        return None
    proto = headers.get("x-forwarded-proto") or str(scope.get("scheme", "http"))
    path = str(scope.get("path", "/"))
    return f"{proto}://{host}{path}"


def _host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    return parsed.hostname


def _infer_tunnel_provider(headers: Mapping[str, str], public_url: str | None) -> str:
    host = (_host_from_url(public_url) or headers.get("x-forwarded-host") or headers.get("host") or "").lower()
    header_blob = " ".join(f"{name}:{value}" for name, value in headers.items()).lower()
    if "cf-ray" in headers or "cf-connecting-ip" in headers or "cloudflare" in header_blob:
        return "cloudflare"
    if "ngrok" in host or "ngrok" in header_blob:
        return "ngrok"
    if host.endswith(".ts.net") or ".ts.net" in host:
        return "tailscale"
    return "generic"


def _forwarded_chain(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _scope_client(scope: Mapping[str, Any]) -> dict[str, Any] | None:
    client = scope.get("client")
    if not isinstance(client, Sequence) or isinstance(client, str | bytes | bytearray) or not client:
        return None
    result: dict[str, Any] = {"host": client[0]}
    if len(client) > 1:
        result["port"] = client[1]
    return result


def _source_ip(headers: Mapping[str, str], scope: Mapping[str, Any]) -> str | None:
    for header in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
        if headers.get(header):
            return headers[header]
    forwarded = _forwarded_chain(headers.get("x-forwarded-for"))
    if forwarded:
        return forwarded[0]
    client = _scope_client(scope)
    if client and client.get("host"):
        return str(client["host"])
    return None


def _edge_request_id(provider: str, headers: Mapping[str, str]) -> str | None:
    if provider == "cloudflare":
        return headers.get("cf-ray")
    if provider == "ngrok":
        return headers.get("x-ngrok-request-id") or headers.get("ngrok-request-id")
    return (
        headers.get("x-request-id")
        or headers.get("x-correlation-id")
        or headers.get("traceparent")
        or headers.get("cf-ray")
    )


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


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


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

from __future__ import annotations

import http.client
import json
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .config import DEFAULT_CONFIG_PATH, DEFAULT_MCP_PROXY_CONFIG, load_mcp_proxy_config
from .quickstart import create_mcp_quickstart

TUNNEL_PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch")
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_AUTH_FAILURE_STATUSES = (401, 403)
DEFAULT_TUNNEL_TOKEN_ENV = "SNULBUG_TOKEN"
DEFAULT_TUNNEL_OUTPUT_DIR = ".snulbug/configs"
DEFAULT_GENERIC_TUNNEL_HOST = "YOUR-TUNNEL-FORWARDING-DOMAIN"
DEFAULT_NGROK_FORWARDING_HOST = "YOUR-NGROK-FORWARDING-DOMAIN"
DEFAULT_NGROK_INTERNAL_URL = "https://snulbug-mcp.internal"
DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME = "snulbug-mcp-internal"
DEFAULT_CLOUDFLARE_TUNNEL_HOST = "YOUR-CLOUDFLARE-TUNNEL-HOSTNAME"
DEFAULT_TAILSCALE_FUNNEL_HOST = "YOUR-HOST.YOUR-TAILNET.ts.net"
DEFAULT_LOCALXPOSE_FORWARDING_HOST = "YOUR-LOCALXPOSE-FORWARDING-DOMAIN"
DEFAULT_PINGGY_FORWARDING_HOST = "YOUR-PINGGY-FORWARDING-DOMAIN"
DEFAULT_HOLEPUNCH_CLIENT_ORIGIN = "http://127.0.0.1:18080"
DEFAULT_PUBLIC_URL_ENVS = {
    "generic": "TUNNEL_URL",
    "ngrok": "NGROK_URL",
    "cloudflare": "CLOUDFLARE_TUNNEL_URL",
    "tailscale": "TAILSCALE_FUNNEL_URL",
    "localxpose": "LOCALXPOSE_URL",
    "pinggy": "PINGGY_URL",
}
DEFAULT_PUBLIC_HOSTS = {
    "generic": DEFAULT_GENERIC_TUNNEL_HOST,
    "ngrok": DEFAULT_NGROK_FORWARDING_HOST,
    "cloudflare": DEFAULT_CLOUDFLARE_TUNNEL_HOST,
    "tailscale": DEFAULT_TAILSCALE_FUNNEL_HOST,
    "localxpose": DEFAULT_LOCALXPOSE_FORWARDING_HOST,
    "pinggy": DEFAULT_PINGGY_FORWARDING_HOST,
}

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
            raise ValueError(
                "tunnel provider must be 'auto', 'generic', 'ngrok', 'cloudflare', "
                "'tailscale', 'localxpose', 'pinggy', or 'holepunch'"
            )


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
    elif provider == "localxpose":
        metadata["localxpose"] = _drop_empty(
            {
                "real_ip": headers.get("x-real-ip"),
                "request_id": headers.get("x-request-id") or headers.get("x-correlation-id"),
            }
        )
    elif provider == "pinggy":
        metadata["pinggy"] = _drop_empty(
            {
                "request_id": headers.get("x-request-id") or headers.get("x-correlation-id"),
            }
        )
    elif provider == "holepunch":
        metadata["holepunch"] = _drop_empty(
            {
                "transport": headers.get("x-snulbug-holepunch-transport")
                or headers.get("x-snulbug-peer-transport")
                or "hypertele",
                "peer": headers.get("x-snulbug-holepunch-peer") or headers.get("x-snulbug-peer-key"),
                "bridge": headers.get("x-snulbug-bridge-id"),
                "client_bridge": _is_loopback_host(host),
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
    ngrok_internal_url: str | None = None,
    ngrok_endpoint_name: str = DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME,
    token_env: str = DEFAULT_TUNNEL_TOKEN_ENV,
    path: str = DEFAULT_MCP_PATH,
    output_dir: str | Path | None = None,
    doctor_command: str | None = None,
    force: bool = False,
    write: bool = True,
) -> dict[str, Any]:
    """Generate provider-specific tunnel setup snippets for a snulbug MCP proxy."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if not token_env:
        raise ValueError("token_env must not be empty")
    if provider != "ngrok" and (
        ngrok_internal_url is not None or ngrok_endpoint_name != DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME
    ):
        raise ValueError("ngrok_internal_url and ngrok_endpoint_name are only valid for provider='ngrok'")
    if provider == "ngrok" and not ngrok_endpoint_name.strip():
        raise ValueError("ngrok_endpoint_name must not be empty")

    config_result = _load_config(config)
    if config_result["explicit"] and config_result["ok"] is not True:
        raise ValueError(str(config_result["message"]))

    effective_output_dir = Path(output_dir) if output_dir is not None else Path(DEFAULT_TUNNEL_OUTPUT_DIR)
    endpoint = _infer_local_endpoint(local_url, config_result.get("proxy_config"), path)
    origin = _origin_from_endpoint(endpoint, path)
    public_endpoint = _public_endpoint(provider, public_url=public_url, hostname=hostname, path=path)
    generated_quickstart = None
    config_path = config_result["path"]
    if write and config_result["ok"] is not True:
        generated_quickstart = create_mcp_quickstart(
            effective_output_dir,
            preset="tunnel-safe",
            upstream=DEFAULT_MCP_PROXY_CONFIG["upstream"],
            token="local-dev-secret",
            host=urlsplit(endpoint).hostname or str(DEFAULT_MCP_PROXY_CONFIG["host"]),
            port=urlsplit(endpoint).port or int(DEFAULT_MCP_PROXY_CONFIG["port"]),
            tunnel_provider=provider,
            tunnel_public_url=public_endpoint,
            force=force,
        )
        config_path = Path(generated_quickstart["config"])
    plan = _provider_plan(
        provider,
        origin=origin,
        endpoint=endpoint,
        public_endpoint=public_endpoint,
        token_env=token_env,
        config_path=config_path or Path(DEFAULT_CONFIG_PATH),
        output_dir=effective_output_dir,
        doctor_command=doctor_command or _share_doctor_command(None),
        ngrok_internal_url=ngrok_internal_url,
        ngrok_endpoint_name=ngrok_endpoint_name,
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
    if generated_quickstart:
        written_files.extend(
            [
                str(generated_quickstart["config"]),
                str(generated_quickstart["policy"]),
                str(generated_quickstart["traces"]),
            ]
        )
    if write:
        written_files.extend(_write_tunnel_init_files(effective_output_dir, files, force=force))

    share_target = "peer bridge details" if provider == "holepunch" else "public MCP URL"
    initial_config_missing = config_result["ok"] is not True
    next_steps = []
    if generated_quickstart:
        next_steps.append(f"Review or edit the generated upstream in `{generated_quickstart['config']}`.")
    next_steps.extend(
        [
            f"Start snulbug with `snulbug mcp share run --config {config_path}`.",
            "Run the provider command or config generated by this init plan.",
            f"Run `{plan['doctor']['command']}` before sharing the {share_target}.",
        ]
    )
    return {
        "ok": True,
        "provider": provider,
        "config": str(config_path) if config_path is not None else None,
        "config_generated": bool(generated_quickstart),
        "initial_config_missing": initial_config_missing,
        "local_origin": origin,
        "local_url": endpoint,
        "public_url": public_endpoint,
        "token_env": token_env,
        "output_dir": str(effective_output_dir),
        "quickstart": generated_quickstart,
        "commands": plan["commands"],
        "traffic_policy": plan.get("traffic_policy"),
        "bridge": plan.get("bridge"),
        "client": plan["client"],
        "doctor": plan["doctor"],
        "files": files,
        "written_files": written_files,
        "next_steps": next_steps,
    }


def format_tunnel_init_report(result: Mapping[str, Any]) -> str:
    """Render provider setup as copy-pasteable Markdown."""

    provider = str(result.get("provider"))
    remote_label = "Client bridge MCP URL" if provider == "holepunch" else "Public MCP URL"
    public_url = str(result.get("public_url") or "")
    displayed_public_url = _display_public_endpoint(provider, public_url)
    lines = [
        "# snulbug MCP share provider setup",
        "",
        f"Provider: {provider}",
        f"Local origin: {result.get('local_origin')}",
        f"Local MCP URL: {result.get('local_url')}",
        f"{remote_label}: {displayed_public_url}",
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

    token_env = str(result.get("token_env") or DEFAULT_TUNNEL_TOKEN_ENV)
    lines.extend(
        [
            "## Token",
            "",
            "The generated starter policy uses `local-dev-secret` by default.",
            "",
            "```bash",
            f"export {token_env}=local-dev-secret",
            "```",
            "",
        ]
    )

    if _is_default_public_endpoint(provider, public_url):
        lines.extend(_default_public_url_report_lines(provider))

    quickstart = result.get("quickstart")
    if isinstance(quickstart, Mapping):
        lines.extend(
            [
                "## Generated snulbug config",
                "",
                f"Config: `{quickstart.get('config')}`",
                f"Policy: `{quickstart.get('policy')}`",
                f"Traces: `{quickstart.get('traces')}`",
                "",
                "The generated proxy config points at `http://127.0.0.1:9000` by default. "
                "Edit the `upstream` value if your local MCP server listens somewhere else.",
                "",
            ]
        )

    doctor = result.get("doctor", {})
    if doctor:
        lines.extend(["## Verify", "", "```bash", str(doctor.get("command", "")), "```", ""])

    client = result.get("client", {})
    if client:
        client_url = _display_public_endpoint(provider, str(client.get("url") or ""))
        lines.extend(
            [
                "## MCP client",
                "",
                f"URL: `{client_url}`",
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
    """Render share exposure check results as readable Markdown."""

    provider = str(result.get("provider", "generic"))
    remote_label = "Client bridge URL" if provider == "holepunch" else "Public URL"
    lines = [
        "# snulbug mcp share doctor",
        "",
        f"Provider: {provider}",
        f"Local URL: {result.get('local_url') or '(not checked)'}",
        f"{remote_label}: {result.get('url') or '(not checked)'}",
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
        host = hostname or DEFAULT_NGROK_FORWARDING_HOST
    elif provider == "cloudflare":
        host = hostname or DEFAULT_CLOUDFLARE_TUNNEL_HOST
    elif provider == "tailscale":
        host = hostname or DEFAULT_TAILSCALE_FUNNEL_HOST
    elif provider == "localxpose":
        host = hostname or DEFAULT_LOCALXPOSE_FORWARDING_HOST
    elif provider == "pinggy":
        host = hostname or DEFAULT_PINGGY_FORWARDING_HOST
    elif provider == "holepunch":
        origin = f"http://{hostname}" if hostname else DEFAULT_HOLEPUNCH_CLIENT_ORIGIN
        return _normalize_url(origin, path)
    else:
        host = hostname or DEFAULT_GENERIC_TUNNEL_HOST
    return f"https://{host}{normalized_path}"


def _url_origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit(parsed._replace(path="", query="", fragment="")).rstrip("/")


def _provider_plan(
    provider: str,
    *,
    origin: str,
    endpoint: str,
    public_endpoint: str,
    token_env: str,
    config_path: str | Path,
    output_dir: str | Path,
    doctor_command: str,
    ngrok_internal_url: str | None = None,
    ngrok_endpoint_name: str = DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME,
) -> dict[str, Any]:
    token = f"${{{token_env}}}"
    bridge = None
    output = Path(output_dir)
    if provider == "ngrok":
        internal_url = _ngrok_internal_endpoint_url(ngrok_internal_url)
        public_origin = _display_public_endpoint("ngrok", _url_origin(public_endpoint))
        agent_config_file = _shell_path(output / "ngrok-agent.yml")
        traffic_policy_file = _shell_path(output / "ngrok-traffic-policy.yml")
        commands = [
            {
                "id": "run-ngrok-agent",
                "title": "Run the ngrok internal Agent Endpoint",
                "description": (
                    "Start the ngrok agent endpoint that privately forwards the ngrok Cloud Endpoint "
                    "to the local snulbug proxy origin."
                ),
                "command": f"ngrok start --config {agent_config_file} --all",
            },
            {
                "id": "attach-ngrok-cloud-policy",
                "title": "Attach the Traffic Policy to your ngrok Cloud Endpoint",
                "description": (
                    "Create or choose the public Cloud Endpoint, then attach the generated Traffic Policy. "
                    "The policy performs coarse MCP checks and forwards allowed traffic to the internal endpoint."
                ),
                "command": _shell_print_command(
                    [
                        f"In the ngrok dashboard, create or choose {public_origin}.",
                        f"Attach {traffic_policy_file} as the endpoint Traffic Policy.",
                    ]
                ),
            },
        ]
        traffic_policy = {
            "path": traffic_policy_file,
            "mode": "cloud-endpoint",
            "internal_endpoint": internal_url,
            "agent_config": agent_config_file,
            "checks": [
                "deny non-MCP paths",
                "require Authorization header",
                "require Bearer token shape",
                "restrict HTTP methods",
                "require JSON content type on POST",
                "add snulbug/ngrok audit headers",
                "forward allowed traffic to the ngrok internal Agent Endpoint",
            ],
        }
        bridge = {
            "transport": "ngrok-internal",
            "mode": "cloud-endpoint",
            "internal_url": internal_url,
            "endpoint_name": ngrok_endpoint_name,
            "agent_config": "ngrok-agent.yml",
        }
    elif provider == "cloudflare":
        public_host = urlsplit(public_endpoint).hostname or DEFAULT_CLOUDFLARE_TUNNEL_HOST
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
                "command": f"cloudflared tunnel --config {_shell_path(output / 'cloudflared.yml')} run snulbug-mcp",
            },
        ]
        traffic_policy = None
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
        traffic_policy = None
    elif provider == "localxpose":
        public_host = urlsplit(public_endpoint).hostname or DEFAULT_LOCALXPOSE_FORWARDING_HOST
        reserved_domain_arg = (
            "" if _is_default_public_endpoint("localxpose", public_endpoint) else f" --reserved-domain {public_host}"
        )
        commands = [
            {
                "id": "run-localxpose",
                "title": "Expose snulbug with LocalXpose",
                "description": (
                    "Point a LocalXpose HTTP tunnel at the snulbug proxy origin. "
                    "The basic LocalXpose HTTP tunnel defaults to localhost:8080."
                ),
                "command": f"loclx tunnel http{reserved_domain_arg}",
            }
        ]
        traffic_policy = None
    elif provider == "pinggy":
        pinggy_target = _pinggy_target(origin)
        commands = [
            {
                "id": "run-pinggy",
                "title": "Expose snulbug with Pinggy",
                "description": (
                    "Point a Pinggy SSH HTTP tunnel at the snulbug proxy origin. "
                    "Copy the HTTPS forwarding URL printed by Pinggy before running doctor."
                ),
                "command": f"ssh -p 443 -R0:{pinggy_target} free.pinggy.io",
            }
        ]
        traffic_policy = None
    elif provider == "holepunch":
        origin_target = _host_port_from_origin(origin)
        client_target = _host_port_from_origin(_url_origin(public_endpoint))
        commands = [
            {
                "id": "run-hypertele-server",
                "title": "Run the Hypertele server bridge on the snulbug machine",
                "description": (
                    "Expose only the local snulbug origin to allowed Holepunch peers. "
                    "The command prints the server peer key for the client side."
                ),
                "command": (
                    f"hypertele-server -l {origin_target['port']} --address {origin_target['host']} "
                    f"-c {_shell_path(output / 'hypertele-server.json')} --private"
                ),
            },
            {
                "id": "run-hypertele-client",
                "title": "Run the Hypertele client bridge on the MCP client machine",
                "description": "Bind a local client-side MCP port and forward it over the private peer bridge.",
                "command": (
                    f"hypertele -p {client_target['port']} -c {_shell_path(output / 'hypertele-client.json')} --private"
                ),
            },
        ]
        traffic_policy = None
        bridge = {
            "transport": "hypertele",
            "mode": "private",
            "server_config": "hypertele-server.json",
            "client_config": "hypertele-client.json",
            "server_address": origin_target["host"],
            "server_port": origin_target["port"],
            "client_url": public_endpoint,
            "client_host": client_target["host"],
            "client_port": client_target["port"],
        }
    else:
        commands = [
            {
                "id": "run-provider-tunnel",
                "title": "Expose snulbug with your tunnel provider",
                "description": "Point the tunnel at the snulbug proxy origin, not the upstream MCP server.",
                "command": f"# Configure your tunnel provider to forward public HTTPS traffic to {origin}",
            }
        ]
        traffic_policy = None
        bridge = None

    return {
        "commands": commands,
        "traffic_policy": traffic_policy,
        "bridge": bridge if provider in {"holepunch", "ngrok"} else None,
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


def _ngrok_internal_endpoint_url(value: str | None) -> str:
    endpoint = value or DEFAULT_NGROK_INTERNAL_URL
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("ngrok internal endpoint URL must be an absolute https:// URL")
    if not parsed.hostname.endswith(".internal"):
        raise ValueError("ngrok internal endpoint hostname must end with .internal")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("ngrok internal endpoint URL must not include a path, query, or fragment")
    return _url_origin(endpoint)


def _tailscale_target(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and not parsed.path:
        return str(parsed.port or 80)
    return origin


def _shell_print_command(lines: Sequence[str]) -> str:
    quoted = " ".join(shlex.quote(line) for line in lines)
    return f"printf '%s\\n' {quoted}"


def _pinggy_target(origin: str) -> str:
    target = _host_port_from_origin(origin)
    host = "localhost" if target["host"] in {"127.0.0.1", "::1"} else str(target["host"])
    return f"{host}:{target['port']}"


def _host_port_from_origin(origin: str) -> dict[str, Any]:
    parsed = urlsplit(origin)
    return {
        "host": parsed.hostname or "127.0.0.1",
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
    }


def _share_doctor_command(share_dir: str | Path | None) -> str:
    if share_dir is None:
        return "snulbug mcp share doctor <share-directory>"
    return f"snulbug mcp share doctor {_shell_path(share_dir)}"


def _is_default_public_endpoint(provider: str, value: str) -> bool:
    default_origin = _default_public_origin(provider)
    return bool(default_origin and _url_origin(value) == default_origin)


def _default_public_origin(provider: str) -> str | None:
    host = DEFAULT_PUBLIC_HOSTS.get(provider)
    if host is None:
        return None
    return f"https://{host}"


def _default_public_url_display(provider: str, public_endpoint: str) -> str:
    env = DEFAULT_PUBLIC_URL_ENVS[provider]
    parsed = urlsplit(public_endpoint)
    suffix = parsed.path or DEFAULT_MCP_PATH
    if parsed.query:
        suffix = f"{suffix}?{parsed.query}"
    return f"${{{env}}}{suffix}"


def _display_public_endpoint(provider: str, public_endpoint: str) -> str:
    if _is_default_public_endpoint(provider, public_endpoint):
        return _default_public_url_display(provider, public_endpoint)
    return public_endpoint


def display_tunnel_public_endpoint(provider: str, public_endpoint: str) -> str:
    """Return the copy-paste display URL for a tunnel endpoint."""

    return _display_public_endpoint(provider, public_endpoint)


def _default_public_url_report_lines(provider: str) -> list[str]:
    env = DEFAULT_PUBLIC_URL_ENVS[provider]
    origin = _default_public_origin(provider) or ""
    title = {
        "generic": "Public tunnel URL",
        "ngrok": "Ngrok forwarding URL",
        "cloudflare": "Cloudflare Tunnel URL",
        "tailscale": "Tailscale Funnel URL",
        "localxpose": "LocalXpose forwarding URL",
        "pinggy": "Pinggy forwarding URL",
    }[provider]
    note = {
        "generic": "Set this to the exact public HTTPS origin printed or assigned by your tunnel provider.",
        "ngrok": (
            "Set this to the exact `Forwarding` HTTPS origin printed by the ngrok CLI. "
            "Do not assume an `ngrok.app` domain; random free URLs may use `ngrok-free.dev`, "
            "`ngrok-free.app`, or another ngrok-owned domain."
        ),
        "cloudflare": (
            "Set this to the actual Cloudflare Tunnel HTTPS origin that routes to snulbug. "
            "For named tunnels, pass `--hostname` or replace the generated placeholder in "
            "`cloudflared.yml` before running cloudflared."
        ),
        "tailscale": (
            "Set this to the public Funnel HTTPS origin for this machine, usually `https://HOST.TAILNET.ts.net`."
        ),
        "localxpose": (
            "Set this to the exact LocalXpose HTTPS URL printed by `loclx tunnel http`. "
            "Pass `--hostname` when you want the generated command to use a reserved LocalXpose domain."
        ),
        "pinggy": (
            "Set this to the exact Pinggy HTTPS URL printed by the SSH tunnel command. "
            "Free Pinggy URLs commonly use a `pinggy-free.link` domain."
        ),
    }[provider]
    return [
        f"## {title}",
        "",
        note,
        "",
        "```bash",
        f"export {env}={origin}",
        "```",
        "",
    ]


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
        bridge = plan.get("bridge") if isinstance(plan.get("bridge"), Mapping) else {}
        internal_url = str(bridge.get("internal_url") or DEFAULT_NGROK_INTERNAL_URL)
        endpoint_name = str(bridge.get("endpoint_name") or DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME)
        files.append(
            {
                "path": "ngrok-traffic-policy.yml",
                "kind": "ngrok-traffic-policy",
                "contents": _ngrok_traffic_policy(public_endpoint, internal_url=internal_url),
            }
        )
        files.append(
            {
                "path": "ngrok-agent.yml",
                "kind": "ngrok-agent-config",
                "contents": _ngrok_agent_config(origin, internal_url=internal_url, endpoint_name=endpoint_name),
            }
        )
    elif provider == "holepunch":
        files.extend(
            [
                {
                    "path": "hypertele-server.json",
                    "kind": "hypertele-server-config",
                    "contents": _hypertele_server_config(),
                },
                {
                    "path": "hypertele-client.json",
                    "kind": "hypertele-client-config",
                    "contents": _hypertele_client_config(),
                },
            ]
        )
    return files


def _shell_path(path: str | Path) -> str:
    return shlex.quote(str(path))


def _write_tunnel_init_files(output_dir: Path, files: Sequence[Mapping[str, str]], *, force: bool) -> list[str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for file_spec in files:
        relative = Path(file_spec["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid provider setup file path: {relative}")
        target = output_dir / relative
        if target.exists() and not force:
            raise FileExistsError(f"provider setup output already exists: {target}")
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
    provider_notes = _provider_readme_notes(provider, plan)
    commands = "\n\n".join(command_sections)
    remote_label = "Client bridge MCP URL" if provider == "holepunch" else "Public MCP URL"
    displayed_public_endpoint = _display_public_endpoint(provider, public_endpoint)
    public_url_notes = (
        "\n".join(_default_public_url_report_lines(provider))
        if _is_default_public_endpoint(provider, public_endpoint)
        else ""
    )
    verify_title = "Verify before sharing bridge details" if provider == "holepunch" else "Verify before sharing"
    final_instruction = (
        "Point MCP clients at the client bridge MCP URL only after `snulbug mcp share doctor` passes.\n"
        if provider == "holepunch"
        else "Point MCP clients at the public MCP URL only after `snulbug mcp share doctor` passes.\n"
    )
    return (
        f"# snulbug {provider} share provider setup\n\n"
        f"Local snulbug origin: `{origin}`\n\n"
        f"Local MCP URL: `{endpoint}`\n\n"
        f"{remote_label}: `{displayed_public_endpoint}`\n\n"
        "Set the bearer token before running doctor or configuring an MCP client:\n\n"
        "```bash\n"
        f"export {token_env}=local-dev-secret\n"
        "```\n\n"
        f"{public_url_notes}"
        f"{commands}\n\n"
        f"{provider_notes}"
        f"## {verify_title}\n\n"
        "```bash\n"
        f"{doctor}\n"
        "```\n\n"
        f"{final_instruction}"
    )


def _provider_readme_notes(provider: str, plan: Mapping[str, Any]) -> str:
    if provider == "holepunch":
        return _holepunch_readme_notes(plan)
    if provider == "tailscale":
        return _tailscale_readme_notes(plan)
    if provider != "ngrok":
        return ""
    traffic_policy = plan.get("traffic_policy")
    if not isinstance(traffic_policy, Mapping):
        return ""
    checks = "\n".join(f"- {check}" for check in traffic_policy.get("checks", []))
    bridge = plan.get("bridge") if isinstance(plan.get("bridge"), Mapping) else {}
    internal_url = bridge.get("internal_url") or traffic_policy.get("internal_endpoint") or DEFAULT_NGROK_INTERNAL_URL
    endpoint_name = bridge.get("endpoint_name") or DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME
    agent_config = bridge.get("agent_config") or "ngrok-agent.yml"
    return (
        "## Ngrok MCP gateway\n\n"
        "The generated ngrok setup follows the Cloud Endpoint plus private internal "
        "Agent Endpoint pattern from ngrok's MCP gateway guidance:\n\n"
        f"- Internal Agent Endpoint: `{internal_url}`\n"
        f"- Agent endpoint name: `{endpoint_name}`\n"
        f"- Agent config: `{agent_config}`\n"
        f"- Cloud Endpoint Traffic Policy: `{traffic_policy.get('path')}`\n\n"
        "Replace `YOUR_NGROK_AUTHTOKEN` in the generated agent config or merge the "
        "endpoint block into your existing ngrok v3 config. Create or choose the "
        "public ngrok Cloud Endpoint for your MCP URL, then attach the generated "
        "Traffic Policy to that Cloud Endpoint.\n\n"
        "The policy is a coarse edge guard for local-dev MCP traffic:\n\n"
        f"{checks}\n\n"
        "Snulbug remains the MCP-aware authorization, lease, recording, audit, and "
        "response-policy boundary behind ngrok.\n\n"
    )


def _holepunch_readme_notes(plan: Mapping[str, Any]) -> str:
    bridge = plan.get("bridge", {})
    client = plan.get("client", {})
    headers = dict(client.get("headers", {})) if isinstance(client, Mapping) else {}
    authorization = headers.get("Authorization", "Bearer ${SNULBUG_TOKEN}")
    client_url = client.get("url", "http://127.0.0.1:18080/mcp") if isinstance(client, Mapping) else ""
    client_port = bridge.get("client_port", 18080) if isinstance(bridge, Mapping) else 18080
    server_config = bridge.get("server_config", "hypertele-server.json") if isinstance(bridge, Mapping) else ""
    client_config = bridge.get("client_config", "hypertele-client.json") if isinstance(bridge, Mapping) else ""
    return (
        "## Holepunch peer bridge\n\n"
        "This provider is experimental. It uses Hypertele as a private Holepunch peer "
        "bridge, not as a public HTTPS tunnel. The MCP client talks to a local port on "
        "the client machine, and snulbug still enforces bearer auth, policy, audit, "
        "response controls, and optional leases.\n\n"
        f"- Server-side config: `{server_config}`\n"
        f"- Client-side config: `{client_config}`\n"
        f"- Client MCP URL: `{client_url}`\n\n"
        "Install Hypertele on both machines, then replace the placeholder seed and "
        "peer keys in the generated JSON files before running the bridge. If your "
        "Hypertele version expects the private server seed through `-s`, keep the "
        "generated config as documentation and pass that seed on the client command "
        "line.\n\n"
        "Point MCP clients at the client-side local bridge and keep the snulbug bearer "
        "header:\n\n"
        "```text\n"
        f"{client_url}\n"
        f"Authorization: {authorization}\n"
        "```\n\n"
        "The recommended quickstart defaults keep leases optional for bearer-only "
        "clients:\n\n"
        "```toml\n"
        'tunnel_provider = "holepunch"\n'
        f'tunnel_public_url = "{client_url}"\n'
        'lease_file = "leases.json"\n'
        "lease_required = false\n"
        'lease_header = "x-snulbug-lease"\n'
        "```\n\n"
        "Create a short-lived lease when an agent needs one bounded task:\n\n"
        "```bash\n"
        "snulbug mcp share lease create \\\n"
        "  --file leases.json \\\n"
        '  --task "Holepunch MCP peer session" \\\n'
        "  --allow-tool safe_read_file \\\n"
        "  --allow-tool list_project_files \\\n"
        "  --ttl 30m\n"
        "```\n\n"
        "Then send the returned lease token with tool-call requests:\n\n"
        "```text\n"
        "x-snulbug-lease: <lease token>\n"
        "```\n\n"
        "Run `snulbug mcp share doctor` from a machine where the client-side Hypertele "
        f"bridge is listening on port `{client_port}`.\n\n"
    )


def _tailscale_readme_notes(plan: Mapping[str, Any]) -> str:
    client = plan.get("client", {})
    headers = dict(client.get("headers", {})) if isinstance(client, Mapping) else {}
    authorization = headers.get("Authorization", "Bearer ${SNULBUG_TOKEN}")
    return (
        "## Tailscale Funnel bearer + lease recipe\n\n"
        "Tailscale Funnel gets public HTTPS traffic to this machine; snulbug is still "
        "the MCP authorization boundary. Keep the `tunnel-safe` preset for public "
        "Funnel URLs and require clients to send the bearer header:\n\n"
        "```text\n"
        f"Authorization: {authorization}\n"
        "```\n\n"
        "The generated quickstart defaults keep leases optional so existing clients "
        "can connect with bearer auth only:\n\n"
        "```toml\n"
        'lease_file = "leases.json"\n'
        "lease_required = false\n"
        'lease_header = "x-snulbug-lease"\n'
        "```\n\n"
        "Create a short-lived lease when an agent needs one bounded task:\n\n"
        "```bash\n"
        "snulbug mcp share lease create \\\n"
        "  --file leases.json \\\n"
        '  --task "Tailscale Funnel MCP session" \\\n'
        "  --allow-tool safe_read_file \\\n"
        "  --allow-tool list_project_files \\\n"
        "  --ttl 30m\n"
        "```\n\n"
        "Send the returned lease token with tool-call requests:\n\n"
        "```text\n"
        "x-snulbug-lease: <lease token>\n"
        "```\n\n"
        "To require leases for every MCP `tools/call`, set `lease_required = true` "
        "and keep the same `x-snulbug-lease` header.\n\n"
    )


def _hypertele_server_config() -> str:
    return (
        json.dumps(
            {
                "seed": "REPLACE_WITH_32_BYTE_SERVER_SEED",
                "allow": ["REPLACE_WITH_CLIENT_PEER_KEY"],
            },
            indent=2,
        )
        + "\n"
    )


def _hypertele_client_config() -> str:
    return json.dumps({"peer": "REPLACE_WITH_SERVER_PEER_KEY_OR_PRIVATE_SEED"}, indent=2) + "\n"


def _cloudflared_config(origin: str, public_endpoint: str) -> str:
    hostname = urlsplit(public_endpoint).hostname or DEFAULT_CLOUDFLARE_TUNNEL_HOST
    return (
        "tunnel: snulbug-mcp\n"
        "credentials-file: /path/to/snulbug-mcp-credentials.json\n"
        "\n"
        "ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: {origin}\n"
        "  - service: http_status:404\n"
    )


def _ngrok_agent_config(origin: str, *, internal_url: str, endpoint_name: str) -> str:
    return (
        "# Generated by snulbug for ngrok's MCP gateway pattern.\n"
        "# Replace YOUR_NGROK_AUTHTOKEN or merge this endpoint into your existing ngrok v3 config.\n"
        "version: 3\n"
        "agent:\n"
        "  authtoken: YOUR_NGROK_AUTHTOKEN\n"
        "endpoints:\n"
        f"  - name: {_yaml_string(endpoint_name)}\n"
        f"    url: {_yaml_string(internal_url)}\n"
        "    description: Private internal Agent Endpoint for the local snulbug MCP gateway.\n"
        "    upstream:\n"
        f"      url: {_yaml_string(origin)}\n"
    )


def _ngrok_traffic_policy(public_endpoint: str, *, internal_url: str) -> str:
    mcp_path = urlsplit(public_endpoint).path or DEFAULT_MCP_PATH
    public_url = _normalize_url(public_endpoint, mcp_path)
    expressions = {
        "non_mcp_path": f"req.url.path != {json.dumps(mcp_path)}",
        "missing_authorization": "!hasReqHeader('Authorization')",
        "invalid_bearer": "!getReqHeader('Authorization').exists(v, v.matches('^Bearer .+'))",
        "disallowed_method": "!(req.method in ['GET', 'POST', 'OPTIONS', 'DELETE'])",
        "invalid_post_content_type": (
            "req.method == 'POST' && "
            "!getReqHeader('Content-Type').exists(v, v.matches('(?i)^application/json($|[; ])'))"
        ),
    }
    return (
        "# Generated by snulbug for an ngrok public Cloud Endpoint.\n"
        "# This is a coarse ngrok edge guard; snulbug still performs MCP-aware\n"
        "# authorization, replay recording, auditing, and response policy behind it.\n"
        "on_http_request:\n"
        "  - name: Add snulbug tunnel audit headers\n"
        "    actions:\n"
        "      - type: add-headers\n"
        "        config:\n"
        "          headers:\n"
        '            x-snulbug-tunnel-provider: "ngrok"\n'
        '            x-snulbug-traffic-policy: "ngrok-mcp-v1"\n'
        f"            x-snulbug-public-url: {_yaml_string(public_url)}\n"
        '            x-snulbug-edge-client-ip: "${conn.client_ip}"\n'
        "  - name: Hide non-MCP paths\n"
        "    expressions:\n"
        f"      - {_yaml_string(expressions['non_mcp_path'])}\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 404\n"
        "  - name: Require Authorization header\n"
        "    expressions:\n"
        f"      - {_yaml_string(expressions['missing_authorization'])}\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 401\n"
        "  - name: Require Bearer Authorization value\n"
        "    expressions:\n"
        f"      - {_yaml_string(expressions['invalid_bearer'])}\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 401\n"
        "  - name: Restrict MCP HTTP methods\n"
        "    expressions:\n"
        f"      - {_yaml_string(expressions['disallowed_method'])}\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 405\n"
        "  - name: Require JSON POST bodies\n"
        "    expressions:\n"
        f"      - {_yaml_string(expressions['invalid_post_content_type'])}\n"
        "    actions:\n"
        "      - type: deny\n"
        "        config:\n"
        "          status_code: 415\n"
        "  - name: Forward allowed MCP traffic to the private snulbug Agent Endpoint\n"
        "    actions:\n"
        "      - type: forward-internal\n"
        "        config:\n"
        f"          url: {_yaml_string(internal_url)}\n"
    )


def _yaml_string(value: str) -> str:
    return json.dumps(value)


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
    explicit_provider = headers.get("x-snulbug-tunnel-provider", "").lower()
    if explicit_provider in TUNNEL_PROVIDERS:
        return explicit_provider
    if "cf-ray" in headers or "cf-connecting-ip" in headers or "cloudflare" in header_blob:
        return "cloudflare"
    if "ngrok" in host or "ngrok" in header_blob:
        return "ngrok"
    if host.endswith(".ts.net") or ".ts.net" in host:
        return "tailscale"
    if host.endswith(".loclx.io") or "localxpose" in header_blob or "loclx" in header_blob:
        return "localxpose"
    if "pinggy" in host or "pinggy" in header_blob:
        return "pinggy"
    if "holepunch" in header_blob or "hypertele" in header_blob:
        return "holepunch"
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
    for header in ("cf-connecting-ip", "true-client-ip", "x-real-ip", "x-snulbug-edge-client-ip"):
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
    if provider == "localxpose":
        return headers.get("x-request-id") or headers.get("x-correlation-id")
    if provider == "pinggy":
        return headers.get("x-request-id") or headers.get("x-correlation-id")
    if provider == "holepunch":
        return headers.get("x-snulbug-bridge-id")
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


def _is_loopback_host(value: str | None) -> bool:
    if not value:
        return False
    parsed = urlsplit(f"//{value}")
    host = parsed.hostname or value
    return host in {"127.0.0.1", "localhost", "::1"}


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
    if provider == "holepunch":
        _add_check(
            checks,
            "public.provider_hint",
            None,
            "Holepunch peer bridges do not expose public hostname or edge-header hints",
            details={"transport": "hypertele"},
        )
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
    elif provider == "localxpose":
        ok = hostname.endswith(".loclx.io") or "localxpose" in header_blob or "loclx" in header_blob
        message = "public URL or response headers look like LocalXpose"
    elif provider == "pinggy":
        ok = "pinggy" in hostname or "pinggy" in header_blob
        message = "public URL or response headers look like Pinggy"
    else:
        ok = hostname.endswith(".ts.net") or ".ts.net" in hostname
        message = "public URL looks like a Tailscale Funnel hostname"
    _add_check(checks, "public.provider_hint", ok, message, severity="warning", details={"hostname": hostname})


def _log_stats(proxy_config: Mapping[str, Any] | None) -> dict[str, int | None]:
    if not isinstance(proxy_config, Mapping):
        return {}
    stats: dict[str, int | None] = {}
    record_out = proxy_config.get("record_out")
    if record_out:
        path = Path(record_out)
        stats["record_out"] = path.stat().st_size if path.exists() else 0
    audit_path = _audit_event_sink_path(proxy_config)
    if audit_path is not None:
        stats["audit_jsonl"] = audit_path.stat().st_size if audit_path.exists() else 0
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
    log_paths = {
        "record_out": Path(proxy_config["record_out"]) if proxy_config.get("record_out") else None,
        "audit_jsonl": _audit_event_sink_path(proxy_config),
    }
    for key, path in log_paths.items():
        if path is None:
            _add_check(checks, f"logs.{key}_configured", None, f"{key} is not configured")
            continue
        grew = (after.get(key) or 0) > (before.get(key) or 0)
        _add_check(
            checks,
            f"logs.{key}_grew",
            grew,
            f"{key} grew after doctor probes",
            details={"path": str(path), "before_bytes": before.get(key), "after_bytes": after.get(key)},
        )


def _audit_event_sink_path(proxy_config: Mapping[str, Any]) -> Path | None:
    event_sinks = proxy_config.get("event_sinks", [])
    if not isinstance(event_sinks, Sequence) or isinstance(event_sinks, str | bytes | bytearray):
        return None
    for sink in event_sinks:
        if isinstance(sink, Mapping) and sink.get("type") == "audit_jsonl" and sink.get("path"):
            return Path(str(sink["path"]))
    return None


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
        recommendations.append(
            "Run the proxy with record_out and an audit_jsonl event sink before relying on tunnel traffic."
        )
    if any(check.get("status") == "fail" and str(check.get("id", "")).startswith("config.") for check in checks):
        recommendations.append(
            "Regenerate with `snulbug mcp share quickstart --preset tunnel-safe` or restore safe defaults."
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

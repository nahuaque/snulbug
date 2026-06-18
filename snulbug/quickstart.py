from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .bundle import test_bundle, validate_bundle
from .config import default_event_sink_configs
from .gateway_templates import GatewayTemplate, render_gateway_toml
from .presets import (
    DEFAULT_ALLOWED_PATHS,
    DEFAULT_ALLOWED_TOOLS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RATE_WINDOW,
    DEFAULT_TOKEN,
    McpPolicyOptions,
    generate_mcp_preset,
)
from .scaffolds import (
    GeneratedArtifact,
    GeneratedClient,
    GeneratedCommand,
    GeneratedLog,
    GeneratedSession,
    ScaffoldFile,
    ScaffoldPlan,
    session_result,
    write_scaffold,
)

CLOUDFLARE_ACCESS_PROFILES = ("access-gate", "service-token", "oauth-resource", "audit")
DEFAULT_CLOUDFLARE_ACCESS_PROFILE = "access-gate"
DEFAULT_CLOUDFLARE_SERVICE_TOKEN_CLIENT_ID_ENV = "CLOUDFLARE_ACCESS_CLIENT_ID"
DEFAULT_CLOUDFLARE_SERVICE_TOKEN_CLIENT_SECRET_ENV = "CLOUDFLARE_ACCESS_CLIENT_SECRET"
TAILSCALE_PROFILES = ("funnel-public", "serve-tailnet", "oauth-resource")
DEFAULT_TAILSCALE_PROFILE = "funnel-public"


def create_mcp_quickstart(
    directory: str | Path = ".",
    *,
    preset: str = "local-dev-safe",
    policy_output: str | Path = "policy.snulbug",
    config_output: str | Path = "snulbug.toml",
    traces_dir: str | Path = "traces",
    upstream: str = "http://127.0.0.1:9000",
    token: str | None = None,
    token_env: str | None = None,
    allowed_tools: Sequence[str] | None = None,
    allowed_paths: Sequence[str] | None = None,
    rate_limit: int | None = None,
    rate_window: int | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    trace: bool = True,
    record_out: str | Path = "traces/session.jsonl",
    redact_records: bool = True,
    confirm: bool = False,
    max_body_bytes: int = 65536,
    response_max_bytes: int = 262144,
    response_redact_secrets: bool = True,
    response_block_instructions: bool = False,
    tool_pinning: bool = True,
    tool_pinning_action: str = "block",
    schema_validation: bool = True,
    schema_validation_action: str = "block",
    lease_file: str | Path = "leases.json",
    lease_required: bool = True,
    lease_header: str = "x-snulbug-lease",
    tunnel_provider: str = "auto",
    tunnel_public_url: str | None = None,
    cloudflare_profile: str | None = None,
    tailscale_profile: str | None = None,
    cloudflare_access: str = "off",
    cloudflare_access_require_jwt: bool = True,
    cloudflare_access_require_email: bool = False,
    cloudflare_access_require_cf_ray: bool = True,
    cloudflare_access_allowed_emails: Sequence[str] | None = None,
    cloudflare_access_allowed_domains: Sequence[str] | None = None,
    cloudflare_access_validate_jwt: bool = False,
    cloudflare_access_team_domain: str | None = None,
    cloudflare_access_issuer: str | None = None,
    cloudflare_access_audience: str | None = None,
    cloudflare_access_certs_url: str | None = None,
    cloudflare_access_jwks_cache_seconds: float = 300.0,
    cloudflare_access_jwks_fetch_timeout: float = 5.0,
    cloudflare_access_leeway_seconds: float = 60.0,
    auth_issuer: str | None = None,
    auth_resource: str | None = None,
    auth_audience: str | None = None,
    auth_required_scopes: Sequence[str] | None = None,
    auth_jwks_url: str | None = None,
    auth_token_validation: str = "jwt",
    timeout: float = 30.0,
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Create a local MCP policy proxy starter project."""

    resolved_cloudflare_profile, tunnel_provider = _resolve_cloudflare_profile(
        tunnel_provider,
        cloudflare_profile,
    )
    resolved_tailscale_profile, tunnel_provider = _resolve_tailscale_profile(
        tunnel_provider,
        tailscale_profile,
    )
    cloudflare_client_headers = _cloudflare_profile_client_headers(resolved_cloudflare_profile)
    auth_config = _tunnel_profile_auth_config(
        resolved_cloudflare_profile,
        resolved_tailscale_profile,
        tunnel_public_url=tunnel_public_url,
        local_url=f"http://{host}:{port}/mcp",
        issuer=auth_issuer,
        resource=auth_resource,
        audience=auth_audience,
        required_scopes=auth_required_scopes,
        jwks_url=auth_jwks_url,
        token_validation=auth_token_validation,
    )

    root = Path(directory)
    policy_dir = _resolve_output(root, policy_output)
    config_path = _resolve_output(root, config_output)
    traces_path = _resolve_output(root, traces_dir)
    _preflight_quickstart(policy_dir, config_path, traces_path, force=force)

    write_scaffold(
        ScaffoldPlan(
            name="mcp share quickstart",
            root=root,
            directories=[Path("."), _scaffold_child_path(root, traces_path)],
        ),
        force=force,
    )
    policy_result = generate_mcp_preset(
        preset,
        policy_dir,
        options=McpPolicyOptions(
            token=token,
            token_env=token_env,
            allowed_tools=list(allowed_tools) if allowed_tools else None,
            allowed_paths=list(allowed_paths) if allowed_paths else None,
            rate_limit=rate_limit,
            rate_window=rate_window,
        ),
        force=force,
    )
    audit_event_out = traces_path / "audit.jsonl"

    effective_token = token or DEFAULT_TOKEN
    effective_tools = list(allowed_tools) if allowed_tools else list(DEFAULT_ALLOWED_TOOLS)
    effective_paths = list(allowed_paths) if allowed_paths else list(DEFAULT_ALLOWED_PATHS)
    effective_rate_limit = rate_limit or DEFAULT_RATE_LIMIT
    effective_rate_window = rate_window or DEFAULT_RATE_WINDOW
    policy_file = policy_dir / "policy.lua"
    config_values = {
        "upstream": upstream,
        "policy": _config_path(policy_file, config_path.parent),
        "host": host,
        "port": port,
        "state": state,
        "trace": trace,
        "record_out": _config_path(_resolve_output(root, record_out), config_path.parent),
        "redact_records": redact_records,
        "confirm": confirm,
        "max_body_bytes": max_body_bytes,
        "response_max_bytes": response_max_bytes,
        "response_redact_secrets": response_redact_secrets,
        "response_block_instructions": response_block_instructions,
        "tool_pinning": tool_pinning,
        "tool_pinning_action": tool_pinning_action,
        "schema_validation": schema_validation,
        "schema_validation_action": schema_validation_action,
        "lease_file": _config_path(_resolve_output(root, lease_file), config_path.parent),
        "lease_required": lease_required,
        "lease_header": lease_header,
        "tunnel_provider": tunnel_provider,
        "tunnel_public_url": tunnel_public_url or "",
        "cloudflare_access_profile": resolved_cloudflare_profile or "",
        "tailscale_profile": resolved_tailscale_profile or "",
        "cloudflare_access": cloudflare_access,
        "cloudflare_access_require_jwt": cloudflare_access_require_jwt,
        "cloudflare_access_require_email": cloudflare_access_require_email,
        "cloudflare_access_require_cf_ray": cloudflare_access_require_cf_ray,
        "cloudflare_access_allowed_emails": list(cloudflare_access_allowed_emails or []),
        "cloudflare_access_allowed_domains": list(cloudflare_access_allowed_domains or []),
        "cloudflare_access_validate_jwt": cloudflare_access_validate_jwt,
        "cloudflare_access_team_domain": cloudflare_access_team_domain or "",
        "cloudflare_access_issuer": cloudflare_access_issuer or "",
        "cloudflare_access_audience": cloudflare_access_audience or "",
        "cloudflare_access_certs_url": cloudflare_access_certs_url or "",
        "cloudflare_access_jwks_cache_seconds": cloudflare_access_jwks_cache_seconds,
        "cloudflare_access_jwks_fetch_timeout": cloudflare_access_jwks_fetch_timeout,
        "cloudflare_access_leeway_seconds": cloudflare_access_leeway_seconds,
        "timeout": timeout,
    }
    config_values.update(
        _cloudflare_profile_proxy_values(
            resolved_cloudflare_profile,
            allowed_emails=cloudflare_access_allowed_emails,
            allowed_domains=cloudflare_access_allowed_domains,
            team_domain=cloudflare_access_team_domain,
            issuer=cloudflare_access_issuer,
            audience=cloudflare_access_audience,
            certs_url=cloudflare_access_certs_url,
            jwks_cache_seconds=cloudflare_access_jwks_cache_seconds,
            jwks_fetch_timeout=cloudflare_access_jwks_fetch_timeout,
            leeway_seconds=cloudflare_access_leeway_seconds,
        )
    )
    event_sinks = default_event_sink_configs(audit_path=_config_path(audit_event_out, config_path.parent))
    _write_mcp_proxy_config(
        config_path,
        config_values,
        auth=auth_config,
        event_sinks=event_sinks,
        force=force,
    )

    validation = validate_bundle(policy_dir) if validate else None
    bundle_tests = test_bundle(policy_dir) if validate else None
    ok = bool(policy_result.get("ok", False))
    if validation is not None:
        ok = ok and bool(validation["ok"])
    if bundle_tests is not None:
        ok = ok and bool(bundle_tests["ok"])

    client_url = f"http://{host}:{port}/mcp"
    record_path = _resolve_output(root, record_out)
    lease_path = _resolve_output(root, lease_file)
    client_headers = {"Authorization": f"Bearer {effective_token}", **cloudflare_client_headers}
    next_steps = [
        f"uv run snulbug mcp share run --config {config_path}",
        (
            "uv run snulbug mcp share lease create "
            f"--file {lease_path} "
            "--task 'Inspect docs' --allow-tool safe_read_file --ttl 30m"
        ),
        f"configure your MCP client URL as {client_url}",
        f"send Authorization: Bearer {effective_token}",
        f"uv run snulbug mcp evidence inspect {record_path}",
        f"uv run snulbug mcp evidence inspect {audit_event_out} --kind audit",
    ]
    if not validate:
        next_steps.insert(0, f"uv run snulbug bundle test {policy_dir}")
        next_steps.insert(0, f"uv run snulbug bundle validate {policy_dir}")
    generated_session = session_result(
        GeneratedSession(
            name="mcp share quickstart",
            root=root,
            generated_by="snulbug mcp share quickstart",
            artifacts=[
                GeneratedArtifact("policy", policy_dir, "policy_bundle"),
                GeneratedArtifact("policy_file", policy_file, "policy"),
                GeneratedArtifact("config", config_path, "config"),
                GeneratedArtifact("traces", traces_path, "directory"),
                GeneratedArtifact("lease_file", lease_path, "lease_store"),
            ],
            commands=[
                GeneratedCommand("proxy", next_steps[0 if validate else 2], "Start the MCP policy proxy"),
                GeneratedCommand(
                    "lease_create",
                    (
                        "uv run snulbug mcp share lease create "
                        f"--file {lease_path} "
                        "--task 'Inspect docs' --allow-tool safe_read_file --ttl 30m"
                    ),
                    "Create a task-scoped lease",
                ),
                GeneratedCommand("inspect_session", f"uv run snulbug mcp evidence inspect {record_path}"),
                GeneratedCommand(
                    "inspect_audit",
                    f"uv run snulbug mcp evidence inspect {audit_event_out} --kind audit",
                ),
            ],
            clients=[GeneratedClient("default", client_url, client_headers)],
            logs=[
                GeneratedLog("record_out", record_path, "record_jsonl"),
                GeneratedLog("audit_events", audit_event_out, "audit_jsonl"),
            ],
            next_steps=next_steps,
            metadata={
                "preset": preset,
                "upstream": upstream,
                "cloudflare_access_profile": resolved_cloudflare_profile,
                "tailscale_profile": resolved_tailscale_profile,
            },
        ),
        ok=ok,
    )
    primary_client = generated_session["primary_client"] or {}
    result: dict[str, Any] = {
        "ok": ok,
        "directory": str(root),
        "preset": preset,
        "policy": generated_session["file_map"]["policy"],
        "policy_file": generated_session["file_map"]["policy_file"],
        "config": generated_session["file_map"]["config"],
        "traces": generated_session["file_map"]["traces"],
        "upstream": upstream,
        "client": {
            "url": primary_client.get("url"),
            "headers": primary_client.get("headers", {}),
        },
        "policy_options": {
            "token": effective_token,
            "token_env": token_env,
            "allowed_tools": effective_tools,
            "allowed_paths": effective_paths,
            "rate_limit": effective_rate_limit,
            "rate_window": effective_rate_window,
        },
        "proxy": {
            "host": host,
            "port": port,
            "state": state,
            "record_out": generated_session["log_map"]["record_out"],
            "redact_records": redact_records,
            "confirm": confirm,
            "event_sinks": event_sinks,
            "response_max_bytes": response_max_bytes,
            "response_redact_secrets": response_redact_secrets,
            "response_block_instructions": response_block_instructions,
            "tool_pinning": tool_pinning,
            "tool_pinning_action": tool_pinning_action,
            "schema_validation": schema_validation,
            "schema_validation_action": schema_validation_action,
            "lease_file": generated_session["file_map"]["lease_file"],
            "lease_required": lease_required,
            "lease_header": lease_header,
            "tunnel_provider": tunnel_provider,
            "tunnel_public_url": tunnel_public_url,
            "cloudflare_access_profile": resolved_cloudflare_profile,
            "tailscale_profile": resolved_tailscale_profile,
            "cloudflare_access": config_values["cloudflare_access"],
            "cloudflare_access_require_jwt": config_values["cloudflare_access_require_jwt"],
            "cloudflare_access_require_email": config_values["cloudflare_access_require_email"],
            "cloudflare_access_require_cf_ray": config_values["cloudflare_access_require_cf_ray"],
            "cloudflare_access_allowed_emails": list(config_values["cloudflare_access_allowed_emails"]),
            "cloudflare_access_allowed_domains": list(config_values["cloudflare_access_allowed_domains"]),
            "cloudflare_access_validate_jwt": config_values["cloudflare_access_validate_jwt"],
            "cloudflare_access_team_domain": config_values["cloudflare_access_team_domain"] or None,
            "cloudflare_access_issuer": config_values["cloudflare_access_issuer"] or None,
            "cloudflare_access_audience": config_values["cloudflare_access_audience"] or None,
            "cloudflare_access_certs_url": config_values["cloudflare_access_certs_url"] or None,
            "cloudflare_access_jwks_cache_seconds": config_values["cloudflare_access_jwks_cache_seconds"],
            "cloudflare_access_jwks_fetch_timeout": config_values["cloudflare_access_jwks_fetch_timeout"],
            "cloudflare_access_leeway_seconds": config_values["cloudflare_access_leeway_seconds"],
            "auth": auth_config,
        },
        "cloudflare": {
            "profile": resolved_cloudflare_profile,
            "client_headers": cloudflare_client_headers,
            "auth": auth_config if resolved_cloudflare_profile == "oauth-resource" else None,
        },
        "tailscale": {
            "profile": resolved_tailscale_profile,
            "auth": auth_config if resolved_tailscale_profile == "oauth-resource" else None,
        },
        "validation": validation,
        "tests": bundle_tests,
        "generated_session": generated_session,
        "next_steps": generated_session["next_steps"],
    }
    return result


def _preflight_quickstart(policy_dir: Path, config_path: Path, traces_path: Path, *, force: bool) -> None:
    if policy_dir.exists() and not force:
        raise FileExistsError(f"policy output already exists: {policy_dir}")
    if config_path.exists() and not force:
        raise FileExistsError(f"config file already exists: {config_path}")
    if traces_path.exists() and not traces_path.is_dir():
        raise FileExistsError(f"traces path exists and is not a directory: {traces_path}")


def _resolve_output(root: Path, output: str | Path) -> Path:
    path = Path(output)
    return path if path.is_absolute() else root / path


def _config_path(path: Path, base: Path) -> str:
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return str(path)


def _write_mcp_proxy_config(
    path: Path,
    values: dict[str, Any],
    *,
    auth: Mapping[str, Any] | None = None,
    event_sinks: Sequence[Mapping[str, Any]] = (),
    force: bool = False,
) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"config file already exists: {path}")
    template = GatewayTemplate(proxy=values, auth=auth, event_sinks=event_sinks)
    write_scaffold(
        ScaffoldPlan(
            name="mcp share quickstart config",
            root=path.parent,
            files=[
                ScaffoldFile(
                    path=path.name,
                    content=render_gateway_toml(template),
                    kind="config",
                )
            ],
        ),
        force=force,
    )


def _scaffold_child_path(root: Path, path: Path) -> Path | str:
    if path.is_absolute():
        return path
    return _config_path(path, root)


def _resolve_cloudflare_profile(
    tunnel_provider: str,
    cloudflare_profile: str | None,
) -> tuple[str | None, str]:
    if cloudflare_profile is not None and cloudflare_profile not in CLOUDFLARE_ACCESS_PROFILES:
        raise ValueError(f"cloudflare_profile must be one of: {', '.join(CLOUDFLARE_ACCESS_PROFILES)}")
    if cloudflare_profile is not None and tunnel_provider == "auto":
        tunnel_provider = "cloudflare"
    if tunnel_provider == "cloudflare":
        return cloudflare_profile or DEFAULT_CLOUDFLARE_ACCESS_PROFILE, tunnel_provider
    if cloudflare_profile is not None:
        raise ValueError("cloudflare_profile requires tunnel_provider='cloudflare' or tunnel_provider='auto'")
    return None, tunnel_provider


def _resolve_tailscale_profile(
    tunnel_provider: str,
    tailscale_profile: str | None,
) -> tuple[str | None, str]:
    if tailscale_profile is not None and tailscale_profile not in TAILSCALE_PROFILES:
        raise ValueError(f"tailscale_profile must be one of: {', '.join(TAILSCALE_PROFILES)}")
    if tailscale_profile is not None and tunnel_provider == "auto":
        tunnel_provider = "tailscale"
    if tunnel_provider == "tailscale":
        return tailscale_profile or DEFAULT_TAILSCALE_PROFILE, tunnel_provider
    if tailscale_profile is not None:
        raise ValueError("tailscale_profile requires tunnel_provider='tailscale' or tunnel_provider='auto'")
    return None, tunnel_provider


def _cloudflare_profile_proxy_values(
    profile: str | None,
    *,
    allowed_emails: Sequence[str] | None,
    allowed_domains: Sequence[str] | None,
    team_domain: str | None,
    issuer: str | None,
    audience: str | None,
    certs_url: str | None,
    jwks_cache_seconds: float,
    jwks_fetch_timeout: float,
    leeway_seconds: float,
) -> dict[str, Any]:
    if profile is None:
        return {}
    if profile == "oauth-resource":
        access_mode = "audit"
        validate_jwt = False
    elif profile == "audit":
        access_mode = "audit"
        validate_jwt = bool(team_domain and audience)
    else:
        access_mode = "enforce"
        validate_jwt = True
    domains = list(allowed_domains or [])
    emails = list(allowed_emails or [])
    return {
        "cloudflare_access_profile": profile,
        "cloudflare_access": access_mode,
        "cloudflare_access_require_jwt": True,
        "cloudflare_access_require_email": bool(emails or domains),
        "cloudflare_access_require_cf_ray": True,
        "cloudflare_access_allowed_emails": emails,
        "cloudflare_access_allowed_domains": domains,
        "cloudflare_access_validate_jwt": validate_jwt,
        "cloudflare_access_team_domain": team_domain or "",
        "cloudflare_access_issuer": issuer or "",
        "cloudflare_access_audience": audience or "",
        "cloudflare_access_certs_url": certs_url or "",
        "cloudflare_access_jwks_cache_seconds": jwks_cache_seconds,
        "cloudflare_access_jwks_fetch_timeout": jwks_fetch_timeout,
        "cloudflare_access_leeway_seconds": leeway_seconds,
    }


def _cloudflare_profile_client_headers(profile: str | None) -> dict[str, str]:
    if profile != "service-token":
        return {}
    return {
        "CF-Access-Client-Id": f"${{{DEFAULT_CLOUDFLARE_SERVICE_TOKEN_CLIENT_ID_ENV}}}",
        "CF-Access-Client-Secret": f"${{{DEFAULT_CLOUDFLARE_SERVICE_TOKEN_CLIENT_SECRET_ENV}}}",
    }


def _tunnel_profile_auth_config(
    cloudflare_profile: str | None,
    tailscale_profile: str | None,
    *,
    tunnel_public_url: str | None,
    local_url: str,
    issuer: str | None,
    resource: str | None,
    audience: str | None,
    required_scopes: Sequence[str] | None,
    jwks_url: str | None,
    token_validation: str,
) -> dict[str, Any] | None:
    oauth_resource_enabled = cloudflare_profile == "oauth-resource" or tailscale_profile == "oauth-resource"
    if not oauth_resource_enabled:
        return None
    if not issuer:
        raise ValueError("oauth-resource tunnel profiles require auth_issuer")
    effective_resource = resource or tunnel_public_url or local_url
    effective_scopes = list(required_scopes or ["mcp:connect"])
    return {
        "mode": "oauth-resource",
        "resource": effective_resource,
        "issuer": issuer,
        "authorization_servers": [issuer],
        "audience": audience or effective_resource,
        "required_scopes": effective_scopes,
        "scopes_supported": effective_scopes,
        "jwks_url": jwks_url or "",
        "issuer_discovery": True,
        "token_validation": token_validation,
        "strip_authorization_upstream": True,
    }

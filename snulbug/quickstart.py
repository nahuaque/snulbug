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
from .scaffolds import ScaffoldFile, ScaffoldPlan, write_scaffold


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
    lease_required: bool = False,
    lease_header: str = "x-snulbug-lease",
    tunnel_provider: str = "auto",
    tunnel_public_url: str | None = None,
    cloudflare_access: str = "off",
    cloudflare_access_require_jwt: bool = True,
    cloudflare_access_require_email: bool = False,
    cloudflare_access_require_cf_ray: bool = True,
    cloudflare_access_allowed_emails: Sequence[str] | None = None,
    cloudflare_access_allowed_domains: Sequence[str] | None = None,
    timeout: float = 30.0,
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Create a local MCP policy proxy starter project."""

    root = Path(directory)
    policy_dir = _resolve_output(root, policy_output)
    config_path = _resolve_output(root, config_output)
    traces_path = _resolve_output(root, traces_dir)
    _preflight_quickstart(policy_dir, config_path, traces_path, force=force)

    write_scaffold(
        ScaffoldPlan(
            name="mcp quickstart",
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
        "cloudflare_access": cloudflare_access,
        "cloudflare_access_require_jwt": cloudflare_access_require_jwt,
        "cloudflare_access_require_email": cloudflare_access_require_email,
        "cloudflare_access_require_cf_ray": cloudflare_access_require_cf_ray,
        "cloudflare_access_allowed_emails": list(cloudflare_access_allowed_emails or []),
        "cloudflare_access_allowed_domains": list(cloudflare_access_allowed_domains or []),
        "timeout": timeout,
    }
    event_sinks = default_event_sink_configs(audit_path=_config_path(audit_event_out, config_path.parent))
    _write_mcp_proxy_config(config_path, config_values, event_sinks=event_sinks, force=force)

    validation = validate_bundle(policy_dir) if validate else None
    bundle_tests = test_bundle(policy_dir) if validate else None
    ok = bool(policy_result.get("ok", False))
    if validation is not None:
        ok = ok and bool(validation["ok"])
    if bundle_tests is not None:
        ok = ok and bool(bundle_tests["ok"])

    client_url = f"http://{host}:{port}/mcp"
    result: dict[str, Any] = {
        "ok": ok,
        "directory": str(root),
        "preset": preset,
        "policy": str(policy_dir),
        "policy_file": str(policy_file),
        "config": str(config_path),
        "traces": str(traces_path),
        "upstream": upstream,
        "client": {
            "url": client_url,
            "headers": {"Authorization": f"Bearer {effective_token}"},
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
            "record_out": str(_resolve_output(root, record_out)),
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
            "lease_file": str(_resolve_output(root, lease_file)),
            "lease_required": lease_required,
            "lease_header": lease_header,
            "tunnel_provider": tunnel_provider,
            "tunnel_public_url": tunnel_public_url,
            "cloudflare_access": cloudflare_access,
            "cloudflare_access_require_jwt": cloudflare_access_require_jwt,
            "cloudflare_access_require_email": cloudflare_access_require_email,
            "cloudflare_access_require_cf_ray": cloudflare_access_require_cf_ray,
            "cloudflare_access_allowed_emails": list(cloudflare_access_allowed_emails or []),
            "cloudflare_access_allowed_domains": list(cloudflare_access_allowed_domains or []),
        },
        "validation": validation,
        "tests": bundle_tests,
        "next_steps": [
            f"uv run snulbug mcp proxy --config {config_path}",
            (
                "uv run snulbug mcp lease create "
                f"--file {_resolve_output(root, lease_file)} "
                "--task 'Inspect docs' --allow-tool safe_read_file --ttl 30m"
            ),
            f"configure your MCP client URL as {client_url}",
            f"send Authorization: Bearer {effective_token}",
            f"uv run snulbug mcp evidence inspect {_resolve_output(root, record_out)}",
            f"uv run snulbug mcp evidence inspect {audit_event_out} --kind audit",
        ],
    }
    if not validate:
        result["next_steps"].insert(0, f"uv run snulbug bundle test {policy_dir}")
        result["next_steps"].insert(0, f"uv run snulbug bundle validate {policy_dir}")
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
    event_sinks: Sequence[Mapping[str, Any]] = (),
    force: bool = False,
) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"config file already exists: {path}")
    template = GatewayTemplate(proxy=values, event_sinks=event_sinks)
    write_scaffold(
        ScaffoldPlan(
            name="mcp quickstart config",
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

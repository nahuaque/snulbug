from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .bundle import test_bundle, validate_bundle
from .presets import (
    DEFAULT_ALLOWED_TOOLS,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RATE_WINDOW,
    DEFAULT_TOKEN,
    McpPolicyOptions,
    generate_mcp_preset,
)


def create_mcp_quickstart(
    directory: str | Path = ".",
    *,
    preset: str = "local-dev-safe",
    policy_output: str | Path = "policy.asgi-lua",
    config_output: str | Path = "asgi-lua.toml",
    traces_dir: str | Path = "traces",
    upstream: str = "http://127.0.0.1:9000",
    token: str | None = None,
    token_env: str | None = None,
    allowed_tools: Sequence[str] | None = None,
    rate_limit: int | None = None,
    rate_window: int | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    trace: bool = True,
    record_out: str | Path = "traces/session.jsonl",
    audit_out: str | Path = "traces/audit.jsonl",
    redact_records: bool = True,
    decision_console: bool = True,
    decision_console_format: str = "text",
    max_body_bytes: int = 65536,
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

    root.mkdir(parents=True, exist_ok=True)
    policy_result = generate_mcp_preset(
        preset,
        policy_dir,
        options=McpPolicyOptions(
            token=token,
            token_env=token_env,
            allowed_tools=list(allowed_tools) if allowed_tools else None,
            rate_limit=rate_limit,
            rate_window=rate_window,
        ),
        force=force,
    )
    traces_path.mkdir(parents=True, exist_ok=True)

    effective_token = token or DEFAULT_TOKEN
    effective_tools = list(allowed_tools) if allowed_tools else list(DEFAULT_ALLOWED_TOOLS)
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
        "audit_out": _config_path(_resolve_output(root, audit_out), config_path.parent),
        "redact_records": redact_records,
        "decision_console": decision_console,
        "decision_console_format": decision_console_format,
        "max_body_bytes": max_body_bytes,
        "timeout": timeout,
    }
    _write_mcp_proxy_config(config_path, config_values, force=force)

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
            "rate_limit": effective_rate_limit,
            "rate_window": effective_rate_window,
        },
        "proxy": {
            "host": host,
            "port": port,
            "state": state,
            "record_out": str(_resolve_output(root, record_out)),
            "audit_out": str(_resolve_output(root, audit_out)),
            "redact_records": redact_records,
            "decision_console": decision_console,
            "decision_console_format": decision_console_format,
        },
        "validation": validation,
        "tests": bundle_tests,
        "next_steps": [
            f"uv run asgi-lua mcp proxy --config {config_path}",
            f"configure your MCP client URL as {client_url}",
            f"send Authorization: Bearer {effective_token}",
            f"uv run asgi-lua mcp inspect {_resolve_output(root, record_out)}",
            f"uv run asgi-lua mcp inspect {_resolve_output(root, audit_out)} --kind audit",
        ],
    }
    if not validate:
        result["next_steps"].insert(0, f"uv run asgi-lua bundle test {policy_dir}")
        result["next_steps"].insert(0, f"uv run asgi-lua bundle validate {policy_dir}")
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


def _write_mcp_proxy_config(path: Path, values: dict[str, Any], *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"config file already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["[mcp.proxy]"]
    for key, value in values.items():
        lines.append(f"{key} = {_toml_value(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(str(value))

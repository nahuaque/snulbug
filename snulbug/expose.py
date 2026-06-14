from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import load_mcp_proxy_config
from .tunnel import (
    DEFAULT_TUNNEL_OUTPUT_DIR,
    DEFAULT_TUNNEL_TOKEN_ENV,
    TUNNEL_PROVIDERS,
    display_tunnel_public_endpoint,
    init_tunnel_provider,
)

DEFAULT_EXPOSE_REPORT = "session-report.md"


def plan_exposure_session(
    *,
    provider: str,
    config: str | Path | None = None,
    local_url: str | None = None,
    public_url: str | None = None,
    hostname: str | None = None,
    token_env: str = DEFAULT_TUNNEL_TOKEN_ENV,
    path: str = "/mcp",
    output_dir: str | Path | None = None,
    report_out: str | Path | None = None,
    decision_console: bool = True,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Plan a tunnel-safe MCP exposure session without supervising processes."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if not token_env:
        raise ValueError("token_env must not be empty")

    effective_output_dir = Path(output_dir) if output_dir is not None else Path(DEFAULT_TUNNEL_OUTPUT_DIR)
    tunnel = init_tunnel_provider(
        provider=provider,
        config=config,
        local_url=local_url,
        public_url=public_url,
        hostname=hostname,
        token_env=token_env,
        path=path,
        output_dir=effective_output_dir,
        force=force,
        write=not dry_run,
    )
    planned_config = _planned_config_path(
        config=config,
        tunnel=tunnel,
        output_dir=effective_output_dir,
    )
    tunnel = _normalize_tunnel_plan_for_expose(tunnel, config_path=planned_config, dry_run=dry_run)
    audit_log = _audit_log_path(planned_config, tunnel=tunnel, output_dir=effective_output_dir)
    report_path = str(Path(report_out) if report_out is not None else effective_output_dir / DEFAULT_EXPOSE_REPORT)
    public_url = str(tunnel.get("public_url") or "")
    client = _client_summary(provider, tunnel.get("client", {}))
    commands = {
        "export_token": f"export {token_env}=local-dev-secret",
        "proxy": _proxy_command(planned_config, decision_console=decision_console),
        "provider": [str(command["command"]) for command in tunnel.get("commands", [])],
        "doctor": str(tunnel.get("doctor", {}).get("command", "")),
        "inspect_audit": _inspect_command(audit_log, report_path),
    }
    steps = _steps(commands, report_path=report_path)
    return {
        "ok": bool(tunnel.get("ok", False)),
        "dry_run": dry_run,
        "provider": provider,
        "config": planned_config,
        "config_generated": bool(tunnel.get("config_generated", False)),
        "would_generate_config": bool(dry_run and tunnel.get("initial_config_missing")),
        "output_dir": str(effective_output_dir),
        "local_origin": tunnel.get("local_origin"),
        "local_url": tunnel.get("local_url"),
        "public_url": public_url,
        "public_url_display": display_tunnel_public_endpoint(provider, public_url),
        "token_env": token_env,
        "decision_console": decision_console,
        "client": client,
        "tunnel": _tunnel_summary(tunnel),
        "commands": commands,
        "steps": steps,
        "files": {
            "config": planned_config,
            "written": list(tunnel.get("written_files", [])),
            "audit_log": audit_log,
            "report": report_path,
        },
        "next_steps": [step["command"] for step in steps if step.get("command")],
    }


def format_exposure_session_report(result: Mapping[str, Any]) -> str:
    """Render an exposure session plan as copy-pasteable Markdown."""

    mode = "dry run; no files written" if result.get("dry_run") else "generated plan"
    lines = [
        "# snulbug expose",
        "",
        f"Provider: {result.get('provider')}",
        f"Mode: {mode}",
        f"Config: `{result.get('config')}`",
        f"Local MCP URL: {result.get('local_url')}",
        f"Public MCP URL: {result.get('public_url_display') or result.get('public_url')}",
        "",
    ]
    if result.get("would_generate_config"):
        lines.extend(
            [
                "This dry run would generate a tunnel-safe starter config and policy under "
                f"`{result.get('output_dir')}`.",
                "",
            ]
        )
    written = result.get("files", {}).get("written", []) if isinstance(result.get("files"), Mapping) else []
    if written:
        lines.extend(["## Written files"])
        for path in written:
            lines.append(f"- `{path}`")
        lines.append("")

    commands = result.get("commands", {})
    if isinstance(commands, Mapping):
        _append_command(lines, "Export token", commands.get("export_token"))
        _append_command(lines, "Start proxy", commands.get("proxy"))
        for index, command in enumerate(commands.get("provider", []) or [], start=1):
            _append_command(lines, f"Start provider {index}", command)
        _append_command(lines, "Run doctor", commands.get("doctor"))

    client = result.get("client", {})
    if isinstance(client, Mapping):
        lines.extend(["## MCP client", "", f"URL: `{client.get('display_url') or client.get('url')}`", "", "Headers:"])
        for name, value in dict(client.get("headers", {})).items():
            lines.append(f"- `{name}: {value}`")
        lines.append("")

    if isinstance(commands, Mapping):
        _append_command(lines, "Session report", commands.get("inspect_audit"))
    return "\n".join(lines).rstrip()


def _planned_config_path(*, config: str | Path | None, tunnel: Mapping[str, Any], output_dir: Path) -> str:
    if tunnel.get("config"):
        return str(tunnel["config"])
    if config is not None:
        return str(config)
    return str(output_dir / "snulbug.toml")


def _client_summary(provider: str, client: Any) -> dict[str, Any]:
    if not isinstance(client, Mapping):
        return {}
    summary = dict(client)
    public_url = str(summary.get("url") or "")
    summary["display_url"] = display_tunnel_public_endpoint(provider, public_url)
    return summary


def _normalize_tunnel_plan_for_expose(
    tunnel: Mapping[str, Any],
    *,
    config_path: str,
    dry_run: bool,
) -> dict[str, Any]:
    normalized = dict(tunnel)
    normalized["config"] = config_path
    doctor = dict(normalized.get("doctor", {}))
    if doctor.get("command"):
        doctor["command"] = _replace_config_argument(str(doctor["command"]), config_path)
    normalized["doctor"] = doctor
    if dry_run and normalized.get("initial_config_missing"):
        normalized["config_generated"] = False
        next_steps = list(normalized.get("next_steps", []))
        normalized["next_steps"] = [
            step.replace("`snulbug mcp proxy --config None`", f"`snulbug mcp proxy --config {config_path}`")
            for step in next_steps
        ]
    return normalized


def _replace_config_argument(command: str, config_path: str) -> str:
    lines = []
    for line in command.splitlines():
        stripped = line.strip()
        if stripped.startswith("--config "):
            suffix = " \\" if line.rstrip().endswith("\\") else ""
            lines.append(f"  --config {shlex.quote(config_path)}{suffix}")
        else:
            lines.append(line)
    return "\n".join(lines)


def _audit_log_path(config_path: str, *, tunnel: Mapping[str, Any], output_dir: Path) -> str:
    quickstart = tunnel.get("quickstart")
    if isinstance(quickstart, Mapping):
        proxy = quickstart.get("proxy")
        if isinstance(proxy, Mapping) and proxy.get("audit_out"):
            return str(proxy["audit_out"])
    path = Path(config_path)
    if path.exists():
        try:
            return str(load_mcp_proxy_config(path)["audit_out"])
        except Exception:
            pass
    return str(output_dir / "traces" / "audit.jsonl")


def _proxy_command(config_path: str, *, decision_console: bool) -> str:
    flag = "--decision-console" if decision_console else "--no-decision-console"
    return f"snulbug mcp proxy --config {shlex.quote(config_path)} {flag}"


def _inspect_command(audit_log: str, report_path: str) -> str:
    return f"snulbug mcp evidence inspect {shlex.quote(audit_log)} --kind audit --report-out {shlex.quote(report_path)}"


def _steps(commands: Mapping[str, Any], *, report_path: str) -> list[dict[str, Any]]:
    steps = [
        {
            "id": "export-token",
            "title": "Export bearer token",
            "command": commands["export_token"],
            "success": "provider doctor and MCP clients can send the bearer token",
        },
        {
            "id": "start-proxy",
            "title": "Start snulbug proxy",
            "command": commands["proxy"],
            "success": "snulbug listens on the local MCP URL",
        },
    ]
    for index, command in enumerate(commands.get("provider", []) or [], start=1):
        steps.append(
            {
                "id": f"start-provider-{index}",
                "title": "Start tunnel provider",
                "command": command,
                "success": "provider prints or serves the public forwarding URL",
            }
        )
    steps.extend(
        [
            {
                "id": "doctor",
                "title": "Verify exposure boundary",
                "command": commands["doctor"],
                "success": "unauthenticated public MCP traffic is blocked and authenticated tools/list works",
            },
            {
                "id": "session-report",
                "title": "Write session report",
                "command": commands["inspect_audit"],
                "success": f"session report is written to {report_path}",
            },
        ]
    )
    return steps


def _tunnel_summary(tunnel: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "provider": tunnel.get("provider"),
        "public_url": tunnel.get("public_url"),
        "local_url": tunnel.get("local_url"),
        "commands": tunnel.get("commands", []),
        "doctor": tunnel.get("doctor", {}),
        "traffic_policy": tunnel.get("traffic_policy"),
        "bridge": tunnel.get("bridge"),
    }


def _append_command(lines: list[str], title: str, command: Any) -> None:
    if not command:
        return
    lines.extend([f"## {title}", "", "```bash", str(command), "```", ""])

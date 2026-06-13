from __future__ import annotations

import json
import secrets
import shlex
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .leases import create_lease
from .presets import DEFAULT_ALLOWED_PATHS, DEFAULT_ALLOWED_TOOLS
from .quickstart import create_mcp_quickstart
from .tunnel import TUNNEL_PROVIDERS, init_tunnel_provider

DEFAULT_SHARE_PROVIDER = "holepunch"
DEFAULT_SHARE_PRESET = "tunnel-safe"
DEFAULT_SHARE_TTL = "30m"
DEFAULT_SHARE_DIR = Path(".snulbug") / "shares"
DEFAULT_SHARE_CLIENT_NAME = "snulbug-share"
DEFAULT_SHARE_TOKEN_ENV = "SNULBUG_SHARE_TOKEN"


def create_mcp_share(
    directory: str | Path | None = None,
    *,
    provider: str = DEFAULT_SHARE_PROVIDER,
    preset: str = DEFAULT_SHARE_PRESET,
    upstream: str = "http://127.0.0.1:9000",
    hostname: str | None = None,
    public_url: str | None = None,
    token: str | None = None,
    ttl: str = DEFAULT_SHARE_TTL,
    task: str = "Ephemeral MCP share session",
    allowed_tools: Sequence[str] | None = None,
    allowed_paths: Sequence[str] | None = None,
    allowed_hosts: Sequence[str] | None = None,
    allowed_commands: Sequence[str] | None = None,
    max_calls: int | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    lease_required: bool = True,
    lease_header: str = "x-snulbug-lease",
    client_name: str = DEFAULT_SHARE_CLIENT_NAME,
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Create a bounded, ready-to-run MCP share session directory."""

    if provider not in TUNNEL_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(TUNNEL_PROVIDERS)}")
    if not ttl.strip():
        raise ValueError("ttl must be non-empty")
    if not task.strip():
        raise ValueError("task must be non-empty")
    if not client_name.strip():
        raise ValueError("client_name must be non-empty")

    share_dir = _share_directory(directory)
    _preflight_share(share_dir, force=force)
    share_dir.mkdir(parents=True, exist_ok=True)

    bearer_token = token or _new_bearer_token()
    tools = list(allowed_tools) if allowed_tools else list(DEFAULT_ALLOWED_TOOLS)
    paths = list(allowed_paths) if allowed_paths else list(DEFAULT_ALLOWED_PATHS)
    hosts = list(allowed_hosts or [])
    commands = list(allowed_commands or [])

    local_url = f"http://{host}:{port}/mcp"
    tunnel_preview = init_tunnel_provider(
        provider=provider,
        local_url=local_url,
        public_url=public_url,
        hostname=hostname,
        token_env=DEFAULT_SHARE_TOKEN_ENV,
    )

    quickstart = create_mcp_quickstart(
        share_dir,
        preset=preset,
        upstream=upstream,
        token=bearer_token,
        allowed_tools=tools,
        allowed_paths=paths,
        host=host,
        port=port,
        state=state,
        lease_required=lease_required,
        lease_header=lease_header,
        tunnel_provider=provider,
        tunnel_public_url=tunnel_preview["public_url"],
        force=force,
        validate=validate,
    )
    lease = create_lease(
        share_dir / "leases.json",
        task=task,
        allow_tools=tools,
        allow_paths=paths,
        allow_hosts=hosts,
        allow_commands=commands,
        ttl=ttl,
        max_calls=max_calls,
    )
    tunnel = init_tunnel_provider(
        provider=provider,
        config=quickstart["config"],
        local_url=local_url,
        public_url=tunnel_preview["public_url"],
        token_env=DEFAULT_SHARE_TOKEN_ENV,
        output_dir=share_dir / "tunnel",
        force=force,
    )

    client_headers = {
        "Authorization": f"Bearer {bearer_token}",
        lease_header: lease["token"],
    }
    client_config = _client_config(client_name, tunnel["client"]["url"], client_headers)
    client_config_path = share_dir / "mcp-client.json"
    _write_json(client_config_path, client_config, force=force)

    session_id = share_dir.name
    command_plan = _command_plan(
        share_dir=share_dir,
        provider=provider,
        client_url=tunnel["client"]["url"],
        provider_commands=tunnel["commands"],
        token=bearer_token,
        lease_id=lease["lease"]["id"],
    )
    report_path = share_dir / "SHARE.md"
    report = _share_report(
        session_id=session_id,
        provider=provider,
        preset=preset,
        ttl=ttl,
        task=task,
        quickstart=quickstart,
        tunnel=tunnel,
        lease=lease,
        client_config_path=client_config_path,
        command_plan=command_plan,
    )
    _write_text(report_path, report, force=force)

    return {
        "ok": bool(quickstart["ok"]) and bool(tunnel["ok"]) and bool(lease["ok"]),
        "session": {
            "id": session_id,
            "directory": str(share_dir),
            "provider": provider,
            "preset": preset,
            "ttl": ttl,
            "task": task,
            "lease_required": lease_required,
            "lease_header": lease_header,
        },
        "quickstart": _quickstart_summary(quickstart),
        "tunnel": _tunnel_summary(tunnel),
        "lease": {
            "file": lease["file"],
            "lease": lease["lease"],
            "headers": {lease_header: lease["token"]},
        },
        "client": {
            "name": client_name,
            "url": tunnel["client"]["url"],
            "headers": client_headers,
            "config": str(client_config_path),
        },
        "commands": command_plan,
        "files": {
            "config": quickstart["config"],
            "policy": quickstart["policy"],
            "lease_file": lease["file"],
            "client_config": str(client_config_path),
            "report": str(report_path),
            "tunnel_dir": str(share_dir / "tunnel"),
        },
        "next_steps": [
            command_plan["proxy"],
            *command_plan["provider"],
            command_plan["doctor"],
            f"configure your MCP client from {client_config_path}",
            command_plan["inspect_audit"],
        ],
    }


def _share_directory(directory: str | Path | None) -> Path:
    if directory is not None:
        return Path(directory)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return DEFAULT_SHARE_DIR / f"share-{stamp}-{secrets.token_hex(3)}"


def _preflight_share(directory: Path, *, force: bool) -> None:
    if force:
        return
    for relative in (
        "policy.snulbug",
        "snulbug.toml",
        "leases.json",
        "mcp-client.json",
        "SHARE.md",
        "tunnel",
    ):
        path = directory / relative
        if path.exists():
            raise FileExistsError(f"share output already exists: {path}")


def _new_bearer_token() -> str:
    return f"sbt_{secrets.token_urlsafe(24)}"


def _client_config(name: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
    return {
        "mcpServers": {
            name: {
                "url": url,
                "headers": headers,
            }
        }
    }


def _command_plan(
    *,
    share_dir: Path,
    provider: str,
    client_url: str,
    provider_commands: Sequence[dict[str, Any]],
    token: str,
    lease_id: str,
) -> dict[str, Any]:
    config = share_dir / "snulbug.toml"
    audit = share_dir / "traces" / "audit.jsonl"
    session = share_dir / "traces" / "session.jsonl"
    lease_file = share_dir / "leases.json"
    tunnel_dir = share_dir / "tunnel"
    doctor_lines = ["uv run snulbug tunnel doctor \\"]
    if provider != "generic":
        doctor_lines.append(f"  --provider {provider} \\")
    doctor_lines.extend(
        [
            f"  --url {client_url} \\",
            f"  --config {shlex.quote(str(config))} \\",
            f"  --token ${{{DEFAULT_SHARE_TOKEN_ENV}}}",
        ]
    )
    return {
        "export_token": f"export {DEFAULT_SHARE_TOKEN_ENV}={shlex.quote(token)}",
        "proxy": f"uv run snulbug mcp proxy --config {shlex.quote(str(config))} --decision-console",
        "provider": [
            f"(cd {shlex.quote(str(tunnel_dir))} && {str(command['command'])})" for command in provider_commands
        ],
        "doctor": "\n".join(doctor_lines),
        "inspect_session": f"uv run snulbug mcp inspect {shlex.quote(str(session))}",
        "inspect_audit": (
            f"uv run snulbug mcp inspect {shlex.quote(str(audit))} "
            f"--kind audit --report-out {shlex.quote(str(share_dir / 'session-report.md'))}"
        ),
        "revoke_lease": (
            f"uv run snulbug mcp lease revoke {shlex.quote(lease_id)} --file {shlex.quote(str(lease_file))}"
        ),
    }


def _share_report(
    *,
    session_id: str,
    provider: str,
    preset: str,
    ttl: str,
    task: str,
    quickstart: dict[str, Any],
    tunnel: dict[str, Any],
    lease: dict[str, Any],
    client_config_path: Path,
    command_plan: dict[str, Any],
) -> str:
    provider_commands = "\n".join(command_plan["provider"])
    return (
        "# snulbug MCP share session\n\n"
        f"Session: `{session_id}`\n\n"
        f"Provider: `{provider}`\n\n"
        f"Preset: `{preset}`\n\n"
        f"Task: `{task}`\n\n"
        f"TTL: `{ttl}`\n\n"
        f"Client URL: `{tunnel['client']['url']}`\n\n"
        f"Lease: `{lease['lease']['id']}` expires at `{lease['lease']['expires_at']}`\n\n"
        "## MCP client config\n\n"
        f"Use `{client_config_path}`. It contains the bearer token and task lease token for this session.\n\n"
        "## Start the share\n\n"
        "```bash\n"
        f"{command_plan['export_token']}\n"
        f"{command_plan['proxy']}\n"
        "```\n\n"
        "In another shell, run the provider bridge/tunnel command:\n\n"
        "```bash\n"
        f"{provider_commands}\n"
        "```\n\n"
        "## Verify\n\n"
        "```bash\n"
        f"{command_plan['doctor']}\n"
        "```\n\n"
        "## Close out\n\n"
        "```bash\n"
        f"{command_plan['inspect_audit']}\n"
        f"{command_plan['revoke_lease']}\n"
        "```\n\n"
        "The bearer token is embedded in the generated policy. Stop the proxy and delete this share "
        "directory when the session is over.\n\n"
        "## Artifacts\n\n"
        f"- Config: `{quickstart['config']}`\n"
        f"- Policy: `{quickstart['policy']}`\n"
        f"- Lease file: `{lease['file']}`\n"
        f"- Tunnel setup: `{Path(tunnel['written_files'][0]).parent if tunnel.get('written_files') else ''}`\n"
    )


def _quickstart_summary(quickstart: dict[str, Any]) -> dict[str, Any]:
    validation = quickstart.get("validation")
    tests = quickstart.get("tests")
    return {
        "ok": quickstart.get("ok"),
        "directory": quickstart.get("directory"),
        "preset": quickstart.get("preset"),
        "config": quickstart.get("config"),
        "policy": quickstart.get("policy"),
        "policy_file": quickstart.get("policy_file"),
        "traces": quickstart.get("traces"),
        "upstream": quickstart.get("upstream"),
        "proxy": quickstart.get("proxy"),
        "validation": _ok_summary(validation),
        "tests": _ok_summary(tests),
    }


def _tunnel_summary(tunnel: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": tunnel.get("ok"),
        "provider": tunnel.get("provider"),
        "local_url": tunnel.get("local_url"),
        "public_url": tunnel.get("public_url"),
        "commands": tunnel.get("commands", []),
        "bridge": tunnel.get("bridge"),
        "client": tunnel.get("client"),
        "doctor": tunnel.get("doctor"),
        "traffic_policy": tunnel.get("traffic_policy"),
        "written_files": tunnel.get("written_files", []),
    }


def _ok_summary(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    return {key: value[key] for key in ("ok", "name", "version", "fixture_count", "passed", "failed") if key in value}


def _write_json(path: Path, value: Any, *, force: bool) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n", force=force)


def _write_text(path: Path, value: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"share output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")

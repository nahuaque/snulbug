from __future__ import annotations

import json
import secrets
import shlex
import shutil
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import default_event_sink_configs
from .gateway_templates import GatewayTemplate, render_gateway_toml
from .inspection import format_mcp_inspection_report, inspect_mcp_log
from .leases import create_lease
from .presets import DEFAULT_ALLOWED_PATHS, DEFAULT_ALLOWED_TOOLS, McpPolicyOptions, generate_mcp_preset
from .quickstart import create_mcp_quickstart
from .scaffolds import (
    GeneratedArtifact,
    GeneratedClient,
    GeneratedCommand,
    GeneratedLog,
    GeneratedSession,
    ScaffoldFile,
    ScaffoldPlan,
    format_session_report,
    json_scaffold_file,
    session_result,
    write_scaffold,
)
from .share_session import (
    SHARE_SESSION_MODEL_PATH,
    build_share_session_model,
    load_share_session_model,
    share_session_model_path,
    update_share_session_model,
    write_share_session_model,
)
from .tunnel import TUNNEL_PROVIDERS, init_tunnel_provider

DEFAULT_SHARE_PROVIDER = "holepunch"
DEFAULT_SHARE_PRESET = "tunnel-safe"
DEFAULT_SHARE_TTL = "30m"
DEFAULT_SHARE_DIR = Path(".snulbug") / "shares"
DEFAULT_SHARE_CLIENT_NAME = "snulbug-share"
DEFAULT_SHARE_TOKEN_ENV = "SNULBUG_SHARE_TOKEN"
DEFAULT_CONTAINER_RECIPE_DIR = "containers"
SHARE_MANIFEST = "share.json"
CONTAINER_BIND_HOST = ".".join(("0", "0", "0", "0"))
CONTAINER_REMOTE_BRIDGE_PORT = 19100


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
        write=False,
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
        doctor_command=f"uv run snulbug mcp share doctor {shlex.quote(str(share_dir))}",
        force=force,
    )

    client_headers = {
        "Authorization": f"Bearer {bearer_token}",
        lease_header: lease["token"],
    }
    client_config = _client_config(client_name, tunnel["client"]["url"], client_headers)
    client_config_path = share_dir / "mcp-client.json"
    _write_json(client_config_path, client_config, force=force)

    container_recipe = _write_container_upstream_recipe(
        share_dir=share_dir,
        provider=provider,
        preset=preset,
        token=bearer_token,
        ttl=ttl,
        task=task,
        allowed_tools=tools,
        allowed_paths=paths,
        allowed_hosts=hosts,
        allowed_commands=commands,
        max_calls=max_calls,
        client_url=tunnel["client"]["url"],
        port=port,
        state=state,
        lease_required=lease_required,
        lease_header=lease_header,
        client_name=client_name,
        force=force,
    )

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
    ok = bool(quickstart["ok"]) and bool(tunnel["ok"]) and bool(lease["ok"])
    generated_session = session_result(
        GeneratedSession(
            name="mcp share",
            root=share_dir,
            generated_by="snulbug mcp share create",
            artifacts=[
                GeneratedArtifact("manifest", share_dir / SHARE_MANIFEST, "manifest"),
                GeneratedArtifact("session_model", share_session_model_path(share_dir), "session_model"),
                GeneratedArtifact("config", quickstart["config"], "config"),
                GeneratedArtifact("policy", quickstart["policy"], "policy_bundle"),
                GeneratedArtifact("policy_file", quickstart["policy_file"], "policy"),
                GeneratedArtifact("lease_file", lease["file"], "lease_store"),
                GeneratedArtifact("client_config", client_config_path, "client_config"),
                GeneratedArtifact("report", report_path, "report"),
                GeneratedArtifact("tunnel_dir", share_dir / "tunnel", "directory"),
                GeneratedArtifact("container_recipes", container_recipe["directory"], "directory"),
            ],
            commands=[GeneratedCommand(name, command) for name, command in command_plan.items()],
            clients=[
                GeneratedClient(client_name, tunnel["client"]["url"], client_headers, config=client_config_path),
            ],
            logs=[
                GeneratedLog("session_log", share_dir / "traces" / "session.jsonl", "record_jsonl"),
                GeneratedLog("audit_log", share_dir / "traces" / "audit.jsonl", "audit_jsonl"),
            ],
            next_steps=[
                command_plan["proxy"],
                *command_plan["provider"],
                command_plan["doctor"],
                f"configure your MCP client from {client_config_path}",
                command_plan["inspect_audit"],
            ],
            scaffolds=[container_recipe["scaffold"]],
            metadata={
                "session_id": session_id,
                "provider": provider,
                "preset": preset,
                "ttl": ttl,
                "task": task,
                "upstream": upstream,
                "lease": {
                    "id": lease["lease"]["id"],
                    "expires_at": lease["lease"]["expires_at"],
                    "header": lease_header,
                },
            },
        ),
        ok=ok,
    )
    report = _share_report(
        generated_session=generated_session,
        lease=lease,
        container_recipe=container_recipe,
        client_config_path=client_config_path,
    )
    _write_text(report_path, report, force=force)
    manifest = _share_manifest(
        session_id=session_id,
        share_dir=share_dir,
        provider=provider,
        preset=preset,
        ttl=ttl,
        task=task,
        upstream=upstream,
        host=host,
        port=port,
        state=state,
        lease_required=lease_required,
        lease_header=lease_header,
        quickstart=quickstart,
        tunnel=tunnel,
        lease=lease,
        client_config_path=client_config_path,
        container_recipe=container_recipe,
        command_plan=command_plan,
    )
    _write_share_manifest(share_dir, manifest, force=force)
    session_model = build_share_session_model(manifest, directory=share_dir)
    write_share_session_model(share_dir, session_model, force=force)
    primary_client = generated_session["primary_client"] or {}
    file_map = generated_session["file_map"]

    return {
        "ok": ok,
        "session": {
            "id": session_id,
            "directory": str(share_dir),
            "model": str(share_session_model_path(share_dir)),
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
            "url": primary_client.get("url"),
            "headers": primary_client.get("headers", {}),
            "config": primary_client.get("config"),
        },
        "recipes": {
            "remote_container_upstream": container_recipe,
        },
        "commands": generated_session["command_map"],
        "files": {
            "manifest": file_map["manifest"],
            "session_model": file_map["session_model"],
            "config": file_map["config"],
            "policy": file_map["policy"],
            "lease_file": file_map["lease_file"],
            "client_config": file_map["client_config"],
            "report": file_map["report"],
            "tunnel_dir": file_map["tunnel_dir"],
            "container_recipes": file_map["container_recipes"],
        },
        "generated_session": generated_session,
        "next_steps": generated_session["next_steps"],
    }


def load_mcp_share(directory: str | Path) -> dict[str, Any]:
    """Load a generated MCP share session manifest."""

    share_dir = Path(directory)
    manifest_path = share_dir / SHARE_MANIFEST
    with manifest_path.open("r", encoding="utf-8") as file:
        manifest = json.load(file)
    if not isinstance(manifest, Mapping):
        raise ValueError(f"share manifest must contain a JSON object: {manifest_path}")
    return dict(manifest)


def share_status(directory: str | Path) -> dict[str, Any]:
    """Summarize a generated MCP share session without starting processes."""

    share_dir = Path(directory)
    manifest = load_mcp_share(share_dir)
    session_model: dict[str, Any] | None = None
    model_path = share_session_model_path(share_dir)
    if model_path.exists():
        session_model = load_share_session_model(share_dir)
    files = manifest.get("files") if isinstance(manifest.get("files"), Mapping) else {}
    lease = manifest.get("lease") if isinstance(manifest.get("lease"), Mapping) else {}
    lease_file = files.get("lease_file") or lease.get("file")
    lease_status: dict[str, Any] = {"ok": False, "file": lease_file}
    if isinstance(lease_file, str) and lease_file:
        from .leases import list_leases

        listed = list_leases(_resolve_share_path(share_dir, lease_file))
        lease_id = lease.get("id")
        leases = listed.get("leases", [])
        matched = next(
            (item for item in leases if isinstance(item, Mapping) and item.get("id") == lease_id),
            None,
        )
        lease_status = {
            "ok": True,
            "file": lease_file,
            "id": lease_id,
            "active": bool(matched.get("active")) if isinstance(matched, Mapping) else False,
            "matched": matched,
        }

    file_status = {
        key: _resolve_share_path(share_dir, value).exists()
        for key, value in files.items()
        if isinstance(value, str) and key != "manifest"
    }
    return {
        "ok": True,
        "session": manifest.get("session", {}),
        "state": manifest.get("state", "unknown"),
        "directory": str(share_dir),
        "client": manifest.get("client", {}),
        "lease": lease_status,
        "files": file_status,
        "commands": manifest.get("commands", {}),
        "session_model": session_model,
        "session_model_path": str(model_path),
    }


def doctor_mcp_share(
    directory: str | Path,
    *,
    timeout: float = 5.0,
    public_url: str | None = None,
) -> dict[str, Any]:
    """Run exposure checks against a generated share session."""

    from .tunnel import doctor_tunnel, parse_tunnel_headers

    share_dir = Path(directory)
    manifest = load_mcp_share(share_dir)
    session = manifest.get("session") if isinstance(manifest.get("session"), Mapping) else {}
    client = manifest.get("client") if isinstance(manifest.get("client"), Mapping) else {}
    files = manifest.get("files") if isinstance(manifest.get("files"), Mapping) else {}
    config = files.get("config")
    provider = session.get("provider") or "generic"
    url = public_url or client.get("url")
    headers = client.get("headers") if isinstance(client.get("headers"), Mapping) else {}
    if not isinstance(url, str) or not url:
        raise ValueError("share manifest does not contain a client URL")
    if not isinstance(config, str) or not config:
        raise ValueError("share manifest does not contain a config path")
    if public_url:
        _update_share_client_url(share_dir, str(public_url))
    result = doctor_tunnel(
        provider=str(provider),
        url=url,
        config=_resolve_share_path(share_dir, config),
        headers=parse_tunnel_headers([f"{key}: {value}" for key, value in headers.items()]),
        timeout=timeout,
    )
    _update_share_manifest(share_dir, state="verified" if result.get("ok") else "doctor_failed")
    result["share"] = str(share_dir)
    return result


def share_client_config(
    directory: str | Path,
    *,
    output_format: str = "json",
) -> dict[str, Any]:
    """Return the generated MCP client config for a share session."""

    share_dir = Path(directory)
    manifest = load_mcp_share(share_dir)
    client = manifest.get("client") if isinstance(manifest.get("client"), Mapping) else {}
    config_path = client.get("config")
    if not isinstance(config_path, str) or not config_path:
        raise ValueError("share manifest does not contain a client config path")
    resolved = _resolve_share_path(share_dir, config_path)
    with resolved.open("r", encoding="utf-8") as file:
        config = json.load(file)
    if output_format == "path":
        return {"ok": True, "share": str(share_dir), "format": output_format, "path": str(resolved)}
    if output_format in {"json", "claude-desktop", "cursor"}:
        return {"ok": True, "share": str(share_dir), "format": output_format, "config": config}
    raise ValueError("output_format must be one of: json, claude-desktop, cursor, path")


def close_mcp_share(
    directory: str | Path,
    *,
    revoke: bool = True,
    report: bool = True,
    learn: bool = False,
    learn_out: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Close a generated share by revoking its lease and writing a report."""

    from .leases import revoke_lease

    share_dir = Path(directory)
    manifest = load_mcp_share(share_dir)
    files = manifest.get("files") if isinstance(manifest.get("files"), Mapping) else {}
    lease = manifest.get("lease") if isinstance(manifest.get("lease"), Mapping) else {}
    result: dict[str, Any] = {
        "ok": True,
        "share": str(share_dir),
        "state": "closed",
        "revoked": None,
        "report": None,
        "learned_policy": None,
    }
    if revoke:
        lease_file = files.get("lease_file") or lease.get("file")
        lease_id = lease.get("id")
        if isinstance(lease_file, str) and isinstance(lease_id, str):
            result["revoked"] = revoke_lease(_resolve_share_path(share_dir, lease_file), lease_id)
            result["ok"] = bool(result["revoked"]["ok"])
        else:
            result["revoked"] = {"ok": False, "error": "share manifest does not contain lease file/id"}
            result["ok"] = False

    audit_path = _resolve_share_path(share_dir, files.get("audit_log", "traces/audit.jsonl"))
    inspection: dict[str, Any] | None = None
    if audit_path.exists():
        inspection = inspect_mcp_log(audit_path, kind="audit")

    if report:
        report_path = share_dir / "session-report.md"
        if inspection is not None:
            report_text = format_mcp_inspection_report(inspection)
        else:
            report_text = "# snulbug MCP share closeout\n\nNo audit log was found for this share session.\n"
        _write_text(report_path, report_text, force=force)
        result["report"] = str(report_path)

    if learn:
        session_path = _resolve_share_path(share_dir, files.get("session_log", "traces/session.jsonl"))
        if not session_path.exists():
            result["learned_policy"] = {"ok": False, "error": f"session log not found: {session_path}"}
            result["ok"] = False
        else:
            from .learn import learn_mcp_policy

            output = Path(learn_out) if learn_out is not None else share_dir / "learned-policy.snulbug"
            learned = learn_mcp_policy(session_path, output, force=force)
            result["learned_policy"] = learned
            result["ok"] = bool(result["ok"] and learned["ok"])

    _update_share_manifest(
        share_dir,
        state="closed" if result["ok"] else "close_failed",
        closeout={
            "closed_at": _now_iso(),
            "revoked": result["revoked"],
            "report": result["report"],
            "learned_policy": result["learned_policy"],
        },
    )
    return result


def run_mcp_share(
    directory: str | Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Run the proxy for a generated MCP share session."""

    share_dir = Path(directory)
    manifest = load_mcp_share(share_dir)
    commands = manifest.get("commands") if isinstance(manifest.get("commands"), Mapping) else {}
    files = manifest.get("files") if isinstance(manifest.get("files"), Mapping) else {}
    config = files.get("config")
    if not isinstance(config, str) or not config:
        raise ValueError("share manifest does not contain a config path")
    if dry_run:
        return {
            "ok": True,
            "share": str(share_dir),
            "state": manifest.get("state", "created"),
            "commands": commands,
        }

    from .config import load_mcp_fabric_config, load_mcp_proxy_config
    from .proxy import run_mcp_proxy_config

    config_path = _resolve_share_path(share_dir, config)
    proxy_config = load_mcp_proxy_config(config_path)
    fabric_config = load_mcp_fabric_config(config_path)
    fabric_config["proxy"] = proxy_config
    _update_share_manifest(
        share_dir,
        state="running",
        runtime={
            "started_at": _now_iso(),
            "config": str(config_path),
        },
    )
    run_mcp_proxy_config(proxy_config, fabric_config)
    return None


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
        SHARE_MANIFEST,
        SHARE_SESSION_MODEL_PATH,
        "SHARE.md",
        "tunnel",
        DEFAULT_CONTAINER_RECIPE_DIR,
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
    share_doctor = f"uv run snulbug mcp share doctor {shlex.quote(str(share_dir))}"
    return {
        "export_token": f"export {DEFAULT_SHARE_TOKEN_ENV}={shlex.quote(token)}",
        "run": f"uv run snulbug mcp share run {shlex.quote(str(share_dir))}",
        "proxy": f"uv run snulbug mcp share run --config {shlex.quote(str(config))}",
        "provider": [
            f"(cd {shlex.quote(str(tunnel_dir))} && {str(command['command'])})" for command in provider_commands
        ],
        "doctor": share_doctor,
        "share_doctor": share_doctor,
        "client": f"uv run snulbug mcp share client {shlex.quote(str(share_dir))}",
        "close": f"uv run snulbug mcp share close {shlex.quote(str(share_dir))} --report --revoke",
        "inspect_session": f"uv run snulbug mcp evidence inspect {shlex.quote(str(session))}",
        "inspect_audit": (
            f"uv run snulbug mcp evidence inspect {shlex.quote(str(audit))} "
            f"--kind audit --report-out {shlex.quote(str(share_dir / 'session-report.md'))}"
        ),
        "revoke_lease": (
            f"uv run snulbug mcp share lease revoke {shlex.quote(lease_id)} --file {shlex.quote(str(lease_file))}"
        ),
    }


def _share_report(
    *,
    generated_session: Mapping[str, Any],
    lease: dict[str, Any],
    container_recipe: dict[str, Any],
    client_config_path: Path,
) -> str:
    command_map = (
        generated_session.get("command_map") if isinstance(generated_session.get("command_map"), Mapping) else {}
    )
    return format_session_report(
        generated_session,
        title="snulbug MCP share session",
        sections=("overview", "metadata", "client", "files", "logs", "commands", "next_steps"),
        extra_sections=[
            (
                "MCP client config",
                f"Use `{client_config_path}`. It contains the bearer token and task lease token for this session.",
            ),
            (
                "Remote container as upstream",
                (
                    f"Optional Docker Compose recipe: `{container_recipe['readme']}`\n\n"
                    "This recipe runs a snulbug facade gateway, a local MCP container, and a "
                    "remote-by-peer MCP container reached through a managed Hypertele bridge. "
                    f"Use `{container_recipe['client_config']}` for this facade recipe because it "
                    "contains a lease scoped to prefixed facade tools."
                ),
            ),
            (
                "Close out",
                [
                    f"- `{command_map.get('close')}`",
                    "- Stop the proxy and delete this share directory when the session is over.",
                    f"- Lease `{lease['lease']['id']}` expires at `{lease['lease']['expires_at']}`.",
                ],
            ),
        ],
    )


def _share_manifest(
    *,
    session_id: str,
    share_dir: Path,
    provider: str,
    preset: str,
    ttl: str,
    task: str,
    upstream: str,
    host: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
    quickstart: dict[str, Any],
    tunnel: dict[str, Any],
    lease: dict[str, Any],
    client_config_path: Path,
    container_recipe: dict[str, Any],
    command_plan: dict[str, Any],
) -> dict[str, Any]:
    audit_log = share_dir / "traces" / "audit.jsonl"
    session_log = share_dir / "traces" / "session.jsonl"
    client_headers = {
        "Authorization": f"Bearer {quickstart.get('token', '')}",
        lease_header: lease["token"],
    }
    # quickstart does not expose the bearer token in older result shapes; the
    # client config is the source of truth for secret-bearing headers.
    try:
        with client_config_path.open("r", encoding="utf-8") as file:
            client_config = json.load(file)
        server_config = next(iter(client_config.get("mcpServers", {}).values()))
        headers = server_config.get("headers")
        if isinstance(headers, Mapping):
            client_headers = {str(key): str(value) for key, value in headers.items()}
    except Exception:
        pass

    return {
        "type": "snulbug.share",
        "version": 1,
        "state": "created",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "session": {
            "id": session_id,
            "directory": str(share_dir),
            "provider": provider,
            "preset": preset,
            "ttl": ttl,
            "task": task,
            "upstream": upstream,
            "host": host,
            "port": port,
            "state": state,
            "lease_required": lease_required,
            "lease_header": lease_header,
        },
        "client": {
            "name": next(iter(_client_config_names(client_config_path)), DEFAULT_SHARE_CLIENT_NAME),
            "url": tunnel["client"]["url"],
            "headers": client_headers,
            "config": str(client_config_path),
        },
        "lease": {
            "file": lease["file"],
            "id": lease["lease"]["id"],
            "expires_at": lease["lease"]["expires_at"],
            "header": lease_header,
        },
        "files": {
            "manifest": str(share_dir / SHARE_MANIFEST),
            "session_model": str(share_session_model_path(share_dir)),
            "config": quickstart["config"],
            "policy": quickstart["policy"],
            "policy_file": quickstart["policy_file"],
            "lease_file": lease["file"],
            "client_config": str(client_config_path),
            "report": str(share_dir / "SHARE.md"),
            "session_log": str(session_log),
            "audit_log": str(audit_log),
            "tunnel_dir": str(share_dir / "tunnel"),
            "container_recipes": container_recipe["directory"],
        },
        "tunnel": _tunnel_summary(tunnel),
        "recipes": {
            "remote_container_upstream": container_recipe,
        },
        "commands": command_plan,
    }


def _client_config_names(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8") as file:
        config = json.load(file)
    servers = config.get("mcpServers") if isinstance(config, Mapping) else None
    if not isinstance(servers, Mapping):
        return []
    return [str(name) for name in servers]


def _write_share_manifest(share_dir: Path, manifest: Mapping[str, Any], *, force: bool) -> None:
    _write_json(share_dir / SHARE_MANIFEST, dict(manifest), force=force)


def _update_share_manifest(
    share_dir: Path,
    *,
    state: str | None = None,
    runtime: Mapping[str, Any] | None = None,
    closeout: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = load_mcp_share(share_dir)
    if state is not None:
        manifest["state"] = state
    manifest["updated_at"] = _now_iso()
    if runtime is not None:
        manifest["runtime"] = dict(runtime)
    if closeout is not None:
        manifest["closeout"] = dict(closeout)
    (share_dir / SHARE_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    update_share_session_model(share_dir, manifest=manifest)
    return manifest


def _update_share_client_url(share_dir: Path, url: str) -> None:
    manifest = load_mcp_share(share_dir)
    client = manifest.get("client")
    if isinstance(client, dict):
        client["url"] = url
    tunnel = manifest.get("tunnel")
    if isinstance(tunnel, dict):
        tunnel["public_url"] = url
        tunnel_client = tunnel.get("client")
        if isinstance(tunnel_client, dict):
            tunnel_client["url"] = url
    manifest["updated_at"] = _now_iso()
    (share_dir / SHARE_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    update_share_session_model(share_dir, manifest=manifest)

    config_path = client.get("config") if isinstance(client, Mapping) else None
    if isinstance(config_path, str) and config_path:
        resolved = _resolve_share_path(share_dir, config_path)
        if resolved.exists():
            with resolved.open("r", encoding="utf-8") as file:
                config = json.load(file)
            servers = config.get("mcpServers") if isinstance(config, Mapping) else None
            if isinstance(servers, dict):
                for server in servers.values():
                    if isinstance(server, dict):
                        server["url"] = url
                resolved.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_share_path(share_dir: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else share_dir / path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_container_upstream_recipe(
    *,
    share_dir: Path,
    provider: str,
    preset: str,
    token: str,
    ttl: str,
    task: str,
    allowed_tools: Sequence[str],
    allowed_paths: Sequence[str],
    allowed_hosts: Sequence[str],
    allowed_commands: Sequence[str],
    max_calls: int | None,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
    client_name: str,
    force: bool,
) -> dict[str, Any]:
    recipe_dir = share_dir / DEFAULT_CONTAINER_RECIPE_DIR
    recipe_dir.mkdir(parents=True, exist_ok=True)
    facade_tools = _facade_allowed_tools(allowed_tools)

    policy_dir = recipe_dir / "policy.snulbug"
    generate_mcp_preset(
        preset,
        policy_dir,
        options=McpPolicyOptions(
            token=token,
            allowed_tools=facade_tools,
            allowed_paths=list(allowed_paths),
        ),
        force=force,
    )
    lease = create_lease(
        recipe_dir / "leases.json",
        task=f"{task} (container facade)",
        allow_tools=facade_tools,
        allow_paths=allowed_paths,
        allow_hosts=allowed_hosts,
        allow_commands=allowed_commands,
        ttl=ttl,
        max_calls=max_calls,
    )

    client_headers = {
        "Authorization": f"Bearer {token}",
        lease_header: lease["token"],
    }
    client_config_path = recipe_dir / "mcp-client.facade.json"
    facade_config_path = recipe_dir / "snulbug.facade.toml"
    local_config_path = recipe_dir / "snulbug.local.toml"
    files = {
        "compose": recipe_dir / "docker-compose.yml",
        "gateway_dockerfile": recipe_dir / "Dockerfile.gateway",
        "remote_peer_dockerfile": recipe_dir / "Dockerfile.remote-peer",
        "mock_server": recipe_dir / "mock_mcp_server.py",
        "mock_server_js": recipe_dir / "mock_mcp_server.js",
        "hypertele_server": recipe_dir / "hypertele-server.json",
        "hypertele_client": recipe_dir / "hypertele-client.json",
        "source": recipe_dir / "snulbug-src",
        "readme": recipe_dir / "README.md",
    }
    if files["source"].exists() and not force:
        raise FileExistsError(f"share output already exists: {files['source']}")
    scaffold = write_scaffold(
        ScaffoldPlan(
            name="share container recipe",
            root=recipe_dir,
            files=[
                json_scaffold_file(
                    client_config_path.name,
                    _client_config(f"{client_name}-facade", client_url, client_headers),
                    kind="client_config",
                ),
                ScaffoldFile(
                    path=facade_config_path.name,
                    content=_container_facade_config(
                        provider=provider,
                        client_url=client_url,
                        port=port,
                        state=state,
                        lease_required=lease_required,
                        lease_header=lease_header,
                    ),
                    kind="config",
                ),
                ScaffoldFile(
                    path=local_config_path.name,
                    content=_container_local_config(
                        provider=provider,
                        client_url=client_url,
                        port=port,
                        state=state,
                        lease_required=lease_required,
                        lease_header=lease_header,
                    ),
                    kind="config",
                ),
                ScaffoldFile(path=files["compose"].name, content=_container_compose(), kind="compose"),
                ScaffoldFile(path=files["gateway_dockerfile"].name, content=_gateway_dockerfile(), kind="dockerfile"),
                ScaffoldFile(
                    path=files["remote_peer_dockerfile"].name,
                    content=_remote_peer_dockerfile(),
                    kind="dockerfile",
                ),
                ScaffoldFile(path=files["mock_server"].name, content=_mock_mcp_server(), kind="server"),
                ScaffoldFile(path=files["mock_server_js"].name, content=_mock_mcp_server_js(), kind="server"),
                ScaffoldFile(
                    path=files["hypertele_server"].name,
                    content=_hypertele_server_config(),
                    kind="bridge_config",
                ),
                ScaffoldFile(
                    path=files["hypertele_client"].name,
                    content=_hypertele_client_config(),
                    kind="bridge_config",
                ),
                ScaffoldFile(
                    path=files["readme"].name,
                    content=_container_recipe_readme(
                        client_config_path=client_config_path,
                        facade_config_path=facade_config_path,
                        facade_tools=facade_tools,
                    ),
                    kind="docs",
                ),
            ],
        ),
        force=force,
    )
    _copy_gateway_source(files["source"], force=force)
    return {
        "ok": True,
        "directory": str(recipe_dir),
        "kind": "remote-container-upstream",
        "compose": str(files["compose"]),
        "facade_config": str(facade_config_path),
        "local_config": str(local_config_path),
        "policy": str(policy_dir),
        "lease_file": lease["file"],
        "lease": lease["lease"],
        "client_config": str(client_config_path),
        "client": {
            "url": client_url,
            "headers": client_headers,
        },
        "readme": str(files["readme"]),
        "allowed_tools": facade_tools,
        "files": {name: str(path) for name, path in files.items()},
        "scaffold": scaffold,
        "written_files": scaffold["written_files"],
    }


def _facade_allowed_tools(allowed_tools: Sequence[str]) -> list[str]:
    tools: list[str] = []
    for tool in allowed_tools:
        if tool.startswith(("local.", "remote.")):
            _append_unique(tools, tool)
        else:
            _append_unique(tools, f"local.{tool}")
            _append_unique(tools, f"remote.{tool}")
    return tools


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _container_facade_config(
    *,
    provider: str,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
) -> str:
    return render_gateway_toml(
        GatewayTemplate(
            proxy=_container_proxy_values(
                provider=provider,
                client_url=client_url,
                port=port,
                state=state,
                lease_required=lease_required,
                lease_header=lease_header,
            ),
            upstreams=[
                _container_local_upstream(),
                {
                    "name": "remote",
                    "transport": "holepunch",
                    "url": f"http://127.0.0.1:{CONTAINER_REMOTE_BRIDGE_PORT}/mcp",
                    "local_port": CONTAINER_REMOTE_BRIDGE_PORT,
                    "bridge_config": "hypertele-client.json",
                    "bridge_cwd": "/share/containers",
                    "bridge_command": "hypertele",
                    "bridge_private": True,
                    "bridge_ready_timeout": 15.0,
                    "tool_prefix": "remote.",
                },
            ],
            event_sinks=default_event_sink_configs(audit_path="../traces/container-audit.jsonl"),
        )
    )


def _container_local_config(
    *,
    provider: str,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
) -> str:
    return render_gateway_toml(
        GatewayTemplate(
            proxy=_container_proxy_values(
                provider=provider,
                client_url=client_url,
                port=port,
                state=state,
                lease_required=lease_required,
                lease_header=lease_header,
            ),
            upstreams=[_container_local_upstream()],
            event_sinks=default_event_sink_configs(audit_path="../traces/container-audit.jsonl"),
        )
    )


def _container_proxy_values(
    *,
    provider: str,
    client_url: str,
    port: int,
    state: str,
    lease_required: bool,
    lease_header: str,
) -> dict[str, Any]:
    return {
        "policy": "policy.snulbug/policy.lua",
        "host": CONTAINER_BIND_HOST,
        "port": port,
        "state": state,
        "trace": True,
        "record_out": "../traces/container-session.jsonl",
        "redact_records": True,
        "confirm": False,
        "max_body_bytes": 65536,
        "response_max_bytes": 262144,
        "response_redact_secrets": True,
        "response_block_instructions": False,
        "tool_pinning": True,
        "tool_pinning_action": "block",
        "schema_validation": True,
        "schema_validation_action": "block",
        "lease_file": "leases.json",
        "lease_required": lease_required,
        "lease_header": lease_header,
        "tunnel_provider": provider,
        "tunnel_public_url": client_url,
        "cloudflare_access": "off",
        "timeout": 30.0,
    }


def _container_local_upstream() -> dict[str, Any]:
    return {
        "name": "local",
        "transport": "http",
        "url": "http://local-mcp:9000/mcp",
        "tool_prefix": "local.",
        "default": True,
    }


def _container_compose() -> str:
    return f"""name: snulbug-mcp-container-share

services:
  snulbug-gateway:
    build:
      context: .
      dockerfile: Dockerfile.gateway
    ports:
      - "8080:8080"
    volumes:
      - ..:/share
    depends_on:
      local-mcp:
        condition: service_started
    command:
      - snulbug
      - mcp
      - proxy
      - --config
      - /share/containers/snulbug.local.toml

  local-mcp:
    image: python:3.13-slim
    working_dir: /app
    volumes:
      - ./mock_mcp_server.py:/app/mock_mcp_server.py:ro
    command:
      - python
      - /app/mock_mcp_server.py
      - --host
      - {CONTAINER_BIND_HOST}
      - --port
      - "9000"
      - --name
      - local

  remote-by-peer-mcp:
    profiles:
      - remote-peer
    build:
      context: .
      dockerfile: Dockerfile.remote-peer
    volumes:
      - ./hypertele-server.json:/peer/hypertele-server.json:ro
    command:
      - sh
      - -lc
      - >-
        node /app/mock_mcp_server.js --host 127.0.0.1 --port 9000 --name remote &
        exec hypertele-server -l 9000 --address 127.0.0.1 -c /peer/hypertele-server.json --private
"""


def _gateway_dockerfile() -> str:
    return """FROM python:3.13-slim

WORKDIR /src

COPY snulbug-src/ /src/

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv pip install --system --no-cache "."

WORKDIR /share
"""


def _remote_peer_dockerfile() -> str:
    return """FROM node:22-bookworm-slim

RUN npm install -g hypertele

WORKDIR /app
COPY mock_mcp_server.js /app/mock_mcp_server.js
"""


def _copy_gateway_source(destination: Path, *, force: bool) -> None:
    source_root = Path(__file__).resolve().parents[1]
    package_source = source_root / "snulbug"
    required_files = ("pyproject.toml", "README.md", "LICENSE")
    missing = [name for name in required_files if not (source_root / name).is_file()]
    if missing or not package_source.is_dir():
        raise FileNotFoundError(
            "cannot create container gateway source snapshot; run `snulbug mcp share` from a source checkout "
            "until snulbug is published as a container-installable package"
        )
    if destination.exists():
        if not force:
            raise FileExistsError(f"share output already exists: {destination}")
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name in required_files:
        shutil.copy2(source_root / name, destination / name)
    shutil.copytree(package_source, destination / "snulbug", ignore=_ignore_source_artifacts)


def _ignore_source_artifacts(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name == "__pycache__" or name.endswith((".pyc", ".pyo")) or name in {".DS_Store", ".pytest_cache"}
    }


def _mock_mcp_server() -> str:
    return """from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "snulbug-mock-mcp/1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return

        method = request.get("method")
        if self.path != "/mcp":
            self.send_error(404)
            return
        if method == "tools/list":
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "safe_read_file",
                                "description": f"Read a demo file from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                            {
                                "name": "list_project_files",
                                "description": f"List demo files from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                            },
                        ]
                    },
                }
            )
            return
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            tool = params.get("name")
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"{self.server.server_name_label} handled {tool}",
                            }
                        ]
                    },
                }
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": {}})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--name", default="local")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.server_name_label = args.name
    server.serve_forever()


if __name__ == "__main__":
    main()
"""


def _mock_mcp_server_js() -> str:
    return """const http = require('node:http')

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

const host = arg('host', '127.0.0.1')
const port = Number(arg('port', '9000'))
const serverName = arg('name', 'remote')

function writeJson(response, payload) {
  const body = Buffer.from(JSON.stringify(payload))
  response.writeHead(200, {
    'content-type': 'application/json',
    'content-length': String(body.length)
  })
  response.end(body)
}

const server = http.createServer((request, response) => {
  if (request.method !== 'POST' || request.url !== '/mcp') {
    response.writeHead(404)
    response.end()
    return
  }

  const chunks = []
  request.on('data', chunk => chunks.push(chunk))
  request.on('end', () => {
    let message = {}
    try {
      const body = Buffer.concat(chunks).toString('utf8')
      message = body ? JSON.parse(body) : {}
    } catch {
      writeJson(response, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } })
      return
    }

    if (message.method === 'tools/list') {
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'safe_read_file',
              description: `Read a demo file from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: { path: { type: 'string' } },
                required: ['path'],
                additionalProperties: false
              }
            },
            {
              name: 'list_project_files',
              description: `List demo files from ${serverName}`,
              inputSchema: {
                type: 'object',
                properties: {},
                additionalProperties: false
              }
            }
          ]
        }
      })
      return
    }

    if (message.method === 'tools/call') {
      const params = message.params && typeof message.params === 'object' ? message.params : {}
      writeJson(response, {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          content: [
            {
              type: 'text',
              text: `${serverName} handled ${params.name || ''}`
            }
          ]
        }
      })
      return
    }

    writeJson(response, { jsonrpc: '2.0', id: message.id, result: {} })
  })
})

server.listen(port, host)
"""


def _hypertele_server_config() -> str:
    return (
        json.dumps(
            {
                "seed": "REPLACE_WITH_32_BYTE_REMOTE_SERVER_SEED",
                "allow": ["REPLACE_WITH_GATEWAY_PEER_KEY"],
            },
            indent=2,
        )
        + "\n"
    )


def _hypertele_client_config() -> str:
    return json.dumps({"peer": "REPLACE_WITH_REMOTE_CONTAINER_PEER_KEY_OR_PRIVATE_SEED"}, indent=2) + "\n"


def _container_recipe_readme(
    *,
    client_config_path: Path,
    facade_config_path: Path,
    facade_tools: Sequence[str],
) -> str:
    tools = "\n".join(f"- `{tool}`" for tool in facade_tools)
    return (
        "# Remote container as upstream\n\n"
        "This optional recipe shows one snulbug facade gateway container, one local "
        "MCP container, and one remote-by-peer MCP container. The gateway exposes one "
        "client-facing MCP URL and routes prefixed tools to either the local container "
        "or the remote container reached through a managed Hypertele bridge.\n\n"
        "## Files\n\n"
        "- `docker-compose.yml`: gateway, local MCP, and remote-by-peer MCP services.\n"
        "- `snulbug.local.toml`: default compose config with only the `local.` upstream.\n"
        "- `snulbug.facade.toml`: peer facade config with both `local.` and `remote.` upstreams.\n"
        "- `policy.snulbug/`: policy generated for prefixed facade tools.\n"
        "- `leases.json`: task lease generated for prefixed facade tools.\n"
        "- `mcp-client.facade.json`: MCP client config for this container facade.\n"
        "- `mock_mcp_server.py` / `mock_mcp_server.js`: local and remote demo MCP servers.\n"
        "- `snulbug-src/`: local source snapshot installed into the gateway image.\n"
        "- `hypertele-server.json` / `hypertele-client.json`: placeholder peer bridge configs.\n\n"
        "## Run\n\n"
        "Start the local MCP container and snulbug gateway first. This default path "
        "does not install Node, npm, or Hypertele in the gateway image:\n\n"
        "```bash\n"
        "docker compose up --build local-mcp snulbug-gateway\n"
        "```\n\n"
        "For the remote peer path, edit `hypertele-server.json` and "
        "`hypertele-client.json` with real Hypertele peer material, make Hypertele "
        "available to the gateway or run it as a sidecar, then switch the gateway "
        "command to `snulbug.facade.toml`.\n\n"
        "`Dockerfile.gateway` installs from the generated `snulbug-src/` snapshot "
        "instead of PyPI, so this recipe works before snulbug has a published package "
        "release.\n\n"
        f"Point the MCP client at `{client_config_path}`. The facade config is "
        f"`{facade_config_path}`.\n\n"
        "## Facade tool names\n\n"
        f"{tools}\n\n"
        "The normal share config remains available at `../snulbug.toml`; this recipe "
        "uses a separate facade config, policy, lease, and client file so the "
        "container experiment does not change the default share session.\n"
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
    write_scaffold(
        ScaffoldPlan(
            name="share",
            root=path.parent,
            files=[json_scaffold_file(path.name, value)],
        ),
        force=force,
    )


def _write_text(path: Path, value: str, *, force: bool) -> None:
    write_scaffold(
        ScaffoldPlan(
            name="share",
            root=path.parent,
            files=[ScaffoldFile(path=path.name, content=value)],
        ),
        force=force,
    )

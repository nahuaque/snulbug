from __future__ import annotations

import http.client
import json
import os
import secrets
import shlex
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlencode, urlsplit

from .bundle import validate_bundle
from .config import default_event_sink_configs
from .fabric_members import DEFAULT_FABRIC_MEMBER_REGISTRY_KEY, register_fabric_member
from .gateway_templates import GatewayTemplate, render_gateway_toml
from .inspection import format_mcp_inspection_report, inspect_mcp_log
from .leases import create_lease
from .presets import DEFAULT_ALLOWED_PATHS, DEFAULT_ALLOWED_TOOLS, McpPolicyOptions, generate_mcp_preset
from .quickstart import create_mcp_quickstart
from .redaction import SECRET_REPLACEMENT, build_audit_event
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
DEFAULT_SHARE_MEMBER_REGISTRY = Path(".snulbug") / "fabric-members.json"
DEFAULT_SHARE_MEMBER_DISCOVERY_PROVIDER = "share-members"
SHARE_MEMBER_KINDS = ("codespaces", "devcontainer", "holepunch", "container", "generic")


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


def share_status(
    directory: str | Path,
    *,
    timeout: float = 1.0,
    live_checks: bool = True,
) -> dict[str, Any]:
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
            "leases": leases,
        }

    file_status = {
        key: _resolve_share_path(share_dir, value).exists()
        for key, value in files.items()
        if isinstance(value, str) and key != "manifest"
    }
    session_model = session_model or build_share_session_model(manifest, directory=share_dir)
    gateway = _share_gateway_status(share_dir, manifest, session_model, timeout=timeout, live_checks=live_checks)
    upstreams = _share_upstream_statuses(share_dir, manifest, timeout=timeout, live_checks=live_checks)
    traffic = _share_traffic_summary(share_dir, session_model)
    recordings = _share_recordings_status(share_dir, session_model)
    policy = _mapping(session_model.get("policy"))
    members = _mapping(session_model.get("members"))
    amendments = _share_amendment_status(session_model)
    tunnel = _share_tunnel_status(manifest, session_model)
    findings = _share_findings(gateway=gateway, upstreams=upstreams, traffic=traffic, tunnel=tunnel, policy=policy)
    return {
        "ok": True,
        "session": manifest.get("session", {}),
        "state": manifest.get("state", "unknown"),
        "directory": str(share_dir),
        "client": manifest.get("client", {}),
        "lease": lease_status,
        "leases": _share_leases_summary(lease_status),
        "files": file_status,
        "commands": manifest.get("commands", {}),
        "session_model": session_model,
        "session_model_path": str(model_path),
        "gateway": gateway,
        "upstreams": upstreams,
        "tunnel_doctor": tunnel,
        "policy": policy,
        "members": members,
        "amendments": amendments,
        "traffic": traffic,
        "recordings": recordings,
        "findings": findings,
    }


def share_report(
    directory: str | Path,
    *,
    output: str | Path | None = None,
    timeout: float = 1.0,
    live_checks: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Generate a human-readable report for a share session."""

    status = share_status(directory, timeout=timeout, live_checks=live_checks)
    report = format_share_report(status)
    output_path = Path(output) if output is not None else None
    if output_path is not None:
        if output_path.exists() and not force:
            raise FileExistsError(f"share report already exists: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
    return {
        "ok": status["ok"],
        "share": str(directory),
        "path": str(output_path) if output_path is not None else None,
        "report": report,
        "status": status,
    }


def promote_mcp_share_policy(
    directory: str | Path = ".",
    *,
    to_state: str,
    secret: str,
    key_id: str,
    actor: str | None = None,
    note: str | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
    lifecycle_action: str = "promote",
) -> dict[str, Any]:
    """Promote the active share policy bundle and refresh the session model."""

    from .bundle import inspect_bundle_lifecycle, promote_bundle_lifecycle

    share_dir, manifest, session_model = _load_share_model_context(directory)
    bundle = _share_policy_bundle_path(share_dir, session_model, manifest)
    before = inspect_bundle_lifecycle(bundle)
    promotion = promote_bundle_lifecycle(
        bundle,
        to_state=to_state,
        secret=secret,
        key_id=key_id,
        actor=actor,
        note=note,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    after = inspect_bundle_lifecycle(bundle)
    lifecycle = {
        "action": lifecycle_action,
        "requested_state": to_state,
        "from_state": before.get("state"),
        "to_state": promotion.get("to_state") or after.get("state"),
        "state": after.get("state"),
        "signed": after.get("signed"),
        "signature": after.get("signature"),
        "result": promotion,
        "updated_at": _now_iso(),
    }
    updated_model = _record_share_policy_lifecycle(share_dir, manifest, session_model, lifecycle=lifecycle)
    return {
        "ok": bool(promotion.get("ok")),
        "share": str(share_dir),
        "bundle": str(bundle),
        "action": lifecycle_action,
        "requested_state": to_state,
        "from_state": before.get("state"),
        "to_state": promotion.get("to_state"),
        "state": after.get("state"),
        "promotion": promotion,
        "lifecycle": after,
        "session_model": str(share_session_model_path(share_dir)),
        "policy": _mapping(updated_model.get("policy")),
    }


def activate_mcp_share_policy(
    directory: str | Path = ".",
    *,
    secret: str,
    key_id: str,
    actor: str | None = None,
    note: str | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Promote the active share policy bundle to active."""

    result = promote_mcp_share_policy(
        directory,
        to_state="active",
        secret=secret,
        key_id=key_id,
        actor=actor,
        note=note,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
        lifecycle_action="activate",
    )
    result["activation"] = result.get("promotion")
    return result


def attach_mcp_share_member(
    directory: str | Path = ".",
    *,
    member_id: str | None = None,
    kind: str = "container",
    upstreams: Sequence[Mapping[str, Any]] = (),
    metadata_file: str | Path | None = None,
    registry: str | Path | None = None,
    registry_key: str = DEFAULT_FABRIC_MEMBER_REGISTRY_KEY,
    role: str = "data_plane",
    status: str = "active",
    ttl_seconds: float = 60.0,
    labels: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    metadata_output: str | Path | None = None,
    discovery_name: str = DEFAULT_SHARE_MEMBER_DISCOVERY_PROVIDER,
    update_config: bool = True,
) -> dict[str, Any]:
    """Attach a remote data-plane member to a share session."""

    share_dir, manifest, session_model = _load_share_model_context(directory)
    config_path = _share_config_path(share_dir, manifest, session_model)
    document = _load_share_member_metadata(metadata_file) if metadata_file is not None else {}
    payload = _share_member_attach_payload(
        document,
        member_id=member_id,
        kind=kind,
        upstreams=upstreams,
        role=role,
        status=status,
        ttl_seconds=ttl_seconds,
        labels=labels,
        metadata=metadata,
    )
    metadata_document = _share_member_metadata_document(payload)
    metadata_output_path = None
    if metadata_output is not None:
        metadata_output_path = _resolve_share_path(share_dir, metadata_output)
        _write_json(metadata_output_path, metadata_document, force=False)
    registry_spec = _share_member_registry(share_dir, registry)
    registered = register_fabric_member(
        registry_spec,
        key=registry_key,
        member_id=payload["member_id"],
        role=payload["role"],
        upstreams=payload["upstreams"],
        ttl_seconds=payload["ttl_seconds"],
        status=payload["status"],
        labels=payload["labels"],
        metadata=payload["metadata"],
    )
    discovery = _ensure_share_member_discovery_provider(
        config_path,
        registry=registry_spec,
        registry_key=registry_key,
        discovery_name=discovery_name,
        enabled=update_config,
    )
    attachment = _share_member_attachment(
        payload=payload,
        registered=registered,
        registry=registry_spec,
        registry_key=registry_key,
        discovery_name=discovery_name,
        config_path=config_path,
        discovery=discovery,
    )
    updated_model = _record_share_member_attachment(
        share_dir,
        manifest,
        session_model,
        attachment=attachment,
        registry=registry_spec,
        registry_key=registry_key,
        discovery_name=discovery_name,
    )
    return {
        "ok": bool(registered.get("ok")),
        "share": str(share_dir),
        "member_id": registered.get("member", {}).get("id", payload["member_id"]),
        "kind": payload["kind"],
        "registry": str(registry_spec),
        "registry_key": registry_key,
        "config": str(config_path),
        "discovery": discovery,
        "member": registered.get("member"),
        "summary": registered.get("summary"),
        "attachment": attachment,
        "metadata_document": metadata_document,
        "metadata_output": str(metadata_output_path) if metadata_output_path is not None else None,
        "session_model": str(share_session_model_path(share_dir)),
        "members": _mapping(updated_model.get("members")),
        "next_steps": [
            f"uv run snulbug mcp share status {shlex.quote(str(share_dir))}",
            f"uv run snulbug mcp share run {shlex.quote(str(share_dir))}",
        ],
    }


def format_share_status_report(result: Mapping[str, Any]) -> str:
    """Render share status as Markdown."""

    lines = _share_report_lines(result, title="# snulbug mcp share status")
    return "\n".join(lines).rstrip() + "\n"


def format_share_report(result: Mapping[str, Any]) -> str:
    """Render a full human-readable share report."""

    lines = _share_report_lines(result, title="# snulbug MCP share report")
    traffic = _mapping(result.get("traffic"))
    if traffic.get("inspection_report"):
        lines.extend(["", "## Evidence Detail", "", str(traffic["inspection_report"]).rstrip()])
    return "\n".join(lines).rstrip() + "\n"


def doctor_mcp_share(
    directory: str | Path,
    *,
    timeout: float = 5.0,
    public_url: str | None = None,
    live_checks: bool = True,
    conformance_pack: str | Path | None = None,
    require_conformance: bool = False,
) -> dict[str, Any]:
    """Run a unified readiness gate against a generated share session."""

    from .config import load_mcp_fabric_config, load_mcp_proxy_config
    from .fabric import doctor_fabric
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
        manifest = load_mcp_share(share_dir)
        client = _mapping(manifest.get("client"))
        url = public_url or client.get("url")
    config_path = _resolve_share_path(share_dir, config)
    doctor_headers = parse_tunnel_headers([f"{key}: {value}" for key, value in headers.items()])
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []

    status = share_status(share_dir, timeout=timeout, live_checks=live_checks)
    _add_share_status_checks(checks, status, live_checks=live_checks)

    proxy_config: dict[str, Any] | None = None
    fabric_config: dict[str, Any] | None = None
    try:
        proxy_config = load_mcp_proxy_config(config_path)
        _add_share_doctor_check(
            checks,
            "config.proxy_loaded",
            True,
            f"loaded proxy config {config_path}",
            component="config",
            details={"config": str(config_path)},
        )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "config.proxy_loaded",
            False,
            f"failed to load proxy config: {exc}",
            component="config",
            details={"config": str(config_path)},
        )
        recommendations.append("Fix the generated snulbug.toml before sharing this MCP endpoint.")
    try:
        fabric_config = load_mcp_fabric_config(config_path)
        _add_share_doctor_check(
            checks,
            "config.fabric_loaded",
            True,
            f"loaded fabric config {config_path}",
            component="config",
            details={"config": str(config_path)},
        )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "config.fabric_loaded",
            False,
            f"failed to load fabric config: {exc}",
            component="config",
            details={"config": str(config_path)},
        )

    policy = _share_policy_doctor_checks(share_dir, proxy_config, status)
    checks.extend(policy["checks"])
    recommendations.extend(policy["recommendations"])

    fabric = None
    if fabric_config is not None:
        fabric = doctor_fabric(
            config_path,
            headers=doctor_headers,
            timeout=timeout,
            probe_gateway=False,
            probe_upstreams=False,
        )
        _extend_component_checks(checks, fabric.get("checks", []), component="fabric", prefix="fabric")
        recommendations.extend(str(item) for item in _sequence(fabric.get("recommendations")))
    else:
        _add_share_doctor_check(
            checks,
            "fabric.doctor",
            None,
            "fabric doctor skipped because fabric config did not load",
            component="fabric",
        )

    conformance = _run_share_conformance_doctor(
        conformance_pack,
        headers=doctor_headers,
        timeout=timeout,
        require_conformance=require_conformance,
    )
    checks.extend(conformance["checks"])
    recommendations.extend(conformance["recommendations"])

    tunnel = doctor_tunnel(
        provider=str(provider),
        url=url,
        config=config_path,
        headers=doctor_headers,
        timeout=timeout,
    )
    _extend_component_checks(checks, tunnel.get("checks", []), component="tunnel", prefix="tunnel")
    recommendations.extend(str(item) for item in _sequence(tunnel.get("recommendations")))

    summary = _share_doctor_summary(checks)
    result = {
        "ok": summary["failed"] == 0,
        "share": str(share_dir),
        "provider": provider,
        "url": tunnel.get("url"),
        "local_url": tunnel.get("local_url"),
        "config": str(config_path),
        "checks": checks,
        "summary": summary,
        "recommendations": _unique_strings(recommendations),
        "status": status,
        "policy": policy["result"],
        "fabric": fabric,
        "conformance": conformance["result"],
        "tunnel": tunnel,
        "tunnel_doctor": tunnel,
    }
    _update_share_manifest(
        share_dir,
        state="verified" if result.get("ok") else "doctor_failed",
        health={
            "last_checked_at": _now_iso(),
            "last_summary": result.get("summary"),
            "share_doctor": {
                "ok": result.get("ok"),
                "summary": result.get("summary"),
                "url": result.get("url"),
                "local_url": result.get("local_url"),
            },
            "tunnel_doctor": {
                "ok": tunnel.get("ok"),
                "provider": tunnel.get("provider"),
                "url": tunnel.get("url"),
                "local_url": tunnel.get("local_url"),
                "summary": tunnel.get("summary"),
                "recommendations": tunnel.get("recommendations", []),
            },
        },
    )
    return result


def doctor_mcp_share_auth(
    directory: str | Path | None = None,
    *,
    config: str | Path | None = None,
    public_url: str | None = None,
    headers: Sequence[str] | Mapping[str, str] | None = None,
    token: str | None = None,
    timeout: float = 5.0,
    live_checks: bool = True,
) -> dict[str, Any]:
    """Verify OAuth protected-resource auth readiness for a share session or config."""

    from .config import load_mcp_proxy_config
    from .mcp_auth import OAuthResourceConfig, oauth_resource_metadata_url
    from .mcp_tools import fetch_mcp_tools_list, parse_mcp_tool_headers

    share_dir = Path(directory) if directory is not None else None
    manifest: dict[str, Any] = {}
    session_model: dict[str, Any] = {}
    if share_dir is not None:
        manifest_path = share_dir / SHARE_MANIFEST
        if manifest_path.is_file():
            manifest = load_mcp_share(share_dir)
        model_path = share_session_model_path(share_dir)
        if model_path.is_file():
            session_model = load_share_session_model(share_dir)

    config_path = _resolve_auth_doctor_config_path(share_dir, manifest, session_model, config)
    proxy_config = load_mcp_proxy_config(config_path)
    auth = _mapping(proxy_config.get("auth"))
    client_headers = _share_auth_client_headers(manifest, session_model)
    supplied_headers = (
        parse_mcp_tool_headers(headers, token=token)
        if not isinstance(headers, Mapping)
        else parse_mcp_tool_headers([f"{key}: {value}" for key, value in headers.items()], token=token)
    )
    probe_headers = {**client_headers, **supplied_headers}
    public_url_candidates = _auth_public_url_candidates(
        manifest=manifest,
        session_model=session_model,
        proxy_config=proxy_config,
        public_url=public_url,
    )
    url = _resolve_auth_doctor_public_url(public_url_candidates=public_url_candidates, auth=auth)
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    live: dict[str, Any] = {}

    enabled = auth.get("mode") == "oauth-resource"
    _add_share_doctor_check(
        checks,
        "auth.mode",
        enabled,
        "OAuth protected-resource mode is enabled" if enabled else "OAuth protected-resource mode is not enabled",
        component="auth",
        details={"mode": auth.get("mode")},
    )
    if not enabled:
        recommendations.append('Enable [mcp.auth] mode = "oauth-resource" before using auth doctor.')
        summary = _share_doctor_summary(checks)
        return {
            "ok": False,
            "share": str(share_dir) if share_dir is not None else None,
            "config": str(config_path),
            "url": url,
            "auth": _auth_doctor_summary(auth),
            "checks": checks,
            "summary": summary,
            "recommendations": _unique_strings(recommendations),
            "live": live,
        }

    oauth_config = OAuthResourceConfig(
        mode=str(auth.get("mode") or "off"),
        resource=auth.get("resource") if isinstance(auth.get("resource"), str) else None,
        resource_aliases=tuple(str(item) for item in _sequence(auth.get("resource_aliases"))),
        issuer=auth.get("issuer") if isinstance(auth.get("issuer"), str) else None,
        authorization_servers=tuple(str(item) for item in _sequence(auth.get("authorization_servers"))),
        audience=auth.get("audience") if isinstance(auth.get("audience"), str) else None,
        audiences=tuple(str(item) for item in _sequence(auth.get("audiences"))),
        required_scopes=tuple(str(item) for item in _sequence(auth.get("required_scopes"))),
        scopes_supported=tuple(str(item) for item in _sequence(auth.get("scopes_supported"))),
        jwks_path=auth.get("jwks_path") if isinstance(auth.get("jwks_path"), Path) else None,
        jwks_url=auth.get("jwks_url") if isinstance(auth.get("jwks_url"), str) else None,
        jwks_cache_seconds=float(auth.get("jwks_cache_seconds") or 300.0),
        jwks_fetch_timeout=float(auth.get("jwks_fetch_timeout") or 5.0),
        issuer_metadata_url=auth.get("issuer_metadata_url")
        if isinstance(auth.get("issuer_metadata_url"), str)
        else None,
        issuer_discovery=bool(auth.get("issuer_discovery", True)),
        token_validation=str(auth.get("token_validation") or "jwt"),
        introspection_endpoint=auth.get("introspection_endpoint")
        if isinstance(auth.get("introspection_endpoint"), str)
        else None,
        introspection_client_id=auth.get("introspection_client_id")
        if isinstance(auth.get("introspection_client_id"), str)
        else None,
        introspection_client_secret_env=auth.get("introspection_client_secret_env")
        if isinstance(auth.get("introspection_client_secret_env"), str)
        else None,
        introspection_cache_seconds=float(auth.get("introspection_cache_seconds") or 30.0),
        introspection_fetch_timeout=float(auth.get("introspection_fetch_timeout") or 5.0),
        resource_metadata_url=auth.get("resource_metadata_url")
        if isinstance(auth.get("resource_metadata_url"), str)
        else None,
        realm=str(auth.get("realm") or "mcp"),
        leeway_seconds=float(auth.get("leeway_seconds") or 60.0),
        strip_authorization_upstream=bool(auth.get("strip_authorization_upstream", True)),
        scope_map={
            str(scope): tuple(str(selector) for selector in _sequence(selectors))
            for scope, selectors in _mapping(auth.get("scope_map")).items()
        },
        claim_policy=_mapping(auth.get("claim_policy")),
    )
    metadata_url = oauth_resource_metadata_url(oauth_config)

    _add_auth_url_checks(checks, auth, url, public_url_candidates, recommendations)
    _add_auth_safety_checks(checks, proxy_config, auth, manifest, recommendations)

    jwks = _inspect_local_jwks(
        auth.get("jwks_path"),
        remote_url=auth.get("jwks_url"),
        issuer_discovery=bool(auth.get("issuer_discovery", True) and auth.get("issuer")),
        token_validation=str(auth.get("token_validation") or "jwt"),
    )
    _add_share_doctor_check(
        checks,
        "auth.jwks.local",
        jwks["ok"] if jwks.get("status") != "skip" else None,
        f"local JWKS contains {jwks.get('key_count', 0)} key(s)" if jwks["ok"] else str(jwks["message"]),
        component="auth",
        details={key: value for key, value in jwks.items() if key not in {"ok", "message"}},
    )
    if not jwks["ok"] and jwks.get("status") != "skip":
        recommendations.append("Configure mcp.auth.jwks_path with a readable JWKS containing at least one key.")

    protected_metadata: Mapping[str, Any] | None = None
    issuer_metadata: Mapping[str, Any] | None = None
    issuer_metadata_url: str | None = None
    if live_checks:
        metadata_probe = _fetch_auth_json_document(
            metadata_url,
            headers=_metadata_probe_headers(probe_headers),
            timeout=timeout,
        )
        live["protected_resource_metadata"] = metadata_probe
        protected_metadata = _mapping(metadata_probe.get("json"))
        metadata_ok = metadata_probe.get("ok") is True and bool(protected_metadata)
        _add_share_doctor_check(
            checks,
            "auth.protected_resource_metadata.reachable",
            metadata_ok,
            f"protected resource metadata is reachable at {metadata_url}"
            if metadata_ok
            else f"protected resource metadata is not reachable at {metadata_url}: {metadata_probe.get('error')}",
            component="auth",
            details=_http_probe_details(metadata_probe),
        )
        if metadata_ok:
            resource_match = _urls_match(protected_metadata.get("resource"), auth.get("resource"))
            _add_share_doctor_check(
                checks,
                "auth.protected_resource_metadata.resource",
                resource_match,
                "protected resource metadata advertises the configured resource"
                if resource_match
                else "protected resource metadata resource does not match mcp.auth.resource",
                component="auth",
                details={
                    "metadata_resource": protected_metadata.get("resource"),
                    "configured_resource": auth.get("resource"),
                },
            )
            advertised_servers = [str(item) for item in _sequence(protected_metadata.get("authorization_servers"))]
            expected_servers = _auth_issuer_candidates(auth)
            server_match = not expected_servers or any(server in advertised_servers for server in expected_servers)
            _add_share_doctor_check(
                checks,
                "auth.protected_resource_metadata.authorization_server",
                server_match,
                "protected resource metadata advertises the configured issuer"
                if server_match
                else "protected resource metadata does not advertise the configured issuer",
                component="auth",
                details={"advertised": advertised_servers, "expected": expected_servers},
            )
        else:
            recommendations.append("Start snulbug and verify GET /.well-known/oauth-protected-resource before sharing.")
    else:
        _add_share_doctor_check(
            checks,
            "auth.protected_resource_metadata.reachable",
            None,
            "protected resource metadata reachability skipped",
            component="auth",
            details={"url": metadata_url},
        )

    issuer_urls = _issuer_metadata_urls(auth)
    if live_checks and issuer_urls:
        issuer_probe = _first_successful_auth_json_document(issuer_urls, headers={}, timeout=timeout)
        live["issuer_metadata"] = issuer_probe
        issuer_metadata = _mapping(issuer_probe.get("json"))
        issuer_metadata_url = issuer_probe.get("url") if isinstance(issuer_probe.get("url"), str) else None
        issuer_ok = issuer_probe.get("ok") is True and bool(issuer_metadata)
        _add_share_doctor_check(
            checks,
            "auth.issuer_metadata.reachable",
            issuer_ok,
            f"issuer metadata is reachable at {issuer_metadata_url}"
            if issuer_ok
            else f"issuer metadata is not reachable: {issuer_probe.get('error')}",
            component="auth",
            details={**_http_probe_details(issuer_probe), "attempted_urls": issuer_urls},
        )
        if not issuer_ok:
            recommendations.append("Expose OAuth authorization-server metadata from the configured issuer.")
    elif live_checks:
        _add_share_doctor_check(
            checks,
            "auth.issuer_metadata.reachable",
            False,
            "issuer metadata cannot be checked because no issuer or authorization server is configured",
            component="auth",
        )
    else:
        _add_share_doctor_check(
            checks,
            "auth.issuer_metadata.reachable",
            None,
            "issuer metadata reachability skipped",
            component="auth",
            details={"attempted_urls": issuer_urls},
        )

    _add_jwks_or_introspection_check(
        checks,
        issuer_metadata,
        local_jwks_ok=bool(jwks["ok"]),
        configured_jwks_url=auth.get("jwks_url") if isinstance(auth.get("jwks_url"), str) else None,
        configured_introspection_endpoint=auth.get("introspection_endpoint")
        if isinstance(auth.get("introspection_endpoint"), str)
        else None,
        token_validation=str(auth.get("token_validation") or "jwt"),
        issuer_discovery=bool(auth.get("issuer_discovery", True) and auth.get("issuer")),
        token=token,
        headers={},
        timeout=timeout,
        live_checks=live_checks,
        live=live,
        recommendations=recommendations,
    )
    _add_scope_map_tool_checks(
        checks,
        auth,
        url,
        probe_headers=probe_headers,
        token=token,
        timeout=timeout,
        live_checks=live_checks,
        live=live,
        recommendations=recommendations,
        fetch_tools=fetch_mcp_tools_list,
    )
    _add_claim_policy_tool_checks(
        checks,
        auth,
        url,
        probe_headers=probe_headers,
        token=token,
        timeout=timeout,
        live_checks=live_checks,
        live=live,
        recommendations=recommendations,
        fetch_tools=fetch_mcp_tools_list,
    )

    summary = _share_doctor_summary(checks)
    return {
        "ok": summary["failed"] == 0,
        "share": str(share_dir) if share_dir is not None else None,
        "config": str(config_path),
        "url": url,
        "auth": _auth_doctor_summary(auth),
        "checks": checks,
        "summary": summary,
        "recommendations": _unique_strings(recommendations),
        "live": live,
    }


def format_share_auth_doctor_report(result: Mapping[str, Any]) -> str:
    """Render OAuth protected-resource auth readiness checks as Markdown."""

    summary = _mapping(result.get("summary"))
    auth = _mapping(result.get("auth"))
    lines = [
        "# snulbug mcp share auth doctor",
        "",
        f"Share: {result.get('share') or '(none)'}",
        f"Config: {result.get('config')}",
        f"Public/client URL: {result.get('url') or '(not configured)'}",
        f"Mode: {auth.get('mode')}",
        f"Resource: {auth.get('resource') or '(not configured)'}",
        f"Issuer: {auth.get('issuer') or '(not configured)'}",
        f"Result: {'pass' if result.get('ok') else 'fail'}",
        "",
        "## Summary",
        (
            f"Passed: {summary.get('passed', 0)} | Failed: {summary.get('failed', 0)} | "
            f"Warnings: {summary.get('warnings', 0)} | Skipped: {summary.get('skipped', 0)}"
        ),
        "",
        "## Checks",
    ]
    for check in result.get("checks", []):
        if isinstance(check, Mapping):
            lines.append(f"- [{check.get('status')}] {check.get('id')}: {check.get('message')}")

    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip() + "\n"


def format_share_doctor_report(result: Mapping[str, Any]) -> str:
    """Render unified share readiness checks as Markdown."""

    summary = _mapping(result.get("summary"))
    lines = [
        "# snulbug mcp share doctor",
        "",
        f"Share: {result.get('share')}",
        f"Provider: {result.get('provider')}",
        f"Local URL: {result.get('local_url') or '(not checked)'}",
        f"Public/client URL: {result.get('url') or '(not checked)'}",
        f"Result: {'pass' if result.get('ok') else 'fail'}",
        "",
        "## Summary",
        (
            f"Passed: {summary.get('passed', 0)} | Failed: {summary.get('failed', 0)} | "
            f"Warnings: {summary.get('warnings', 0)} | Skipped: {summary.get('skipped', 0)}"
        ),
        "",
        "## Checks",
    ]
    for check in result.get("checks", []):
        if isinstance(check, Mapping):
            lines.append(f"- [{check.get('status')}] {check.get('id')}: {check.get('message')}")

    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip() + "\n"


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


def _resolve_auth_doctor_config_path(
    share_dir: Path | None,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
    config: str | Path | None,
) -> Path:
    if config is not None:
        return Path(config)
    if share_dir is None:
        raise ValueError("auth doctor requires a share directory or --config")
    gateway = _mapping(session_model.get("gateway"))
    paths = _mapping(session_model.get("paths"))
    files = _mapping(manifest.get("files"))
    config_value = gateway.get("config") or paths.get("config") or files.get("config")
    if not isinstance(config_value, str) or not config_value:
        raise ValueError("share session does not contain a snulbug.toml config path")
    return _resolve_share_path(share_dir, config_value)


def _share_auth_client_headers(
    manifest: Mapping[str, Any],
    _session_model: Mapping[str, Any],
) -> dict[str, str]:
    client = _mapping(manifest.get("client"))
    headers = _mapping(client.get("headers"))
    return {str(name).lower(): str(value) for name, value in headers.items() if value is not None}


def _auth_public_url_candidates(
    *,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
    proxy_config: Mapping[str, Any],
    public_url: str | None,
) -> list[dict[str, str]]:
    tunnel_model = _mapping(session_model.get("tunnel"))
    client_model = _mapping(session_model.get("client"))
    client = _mapping(manifest.get("client"))
    tunnel = _mapping(manifest.get("tunnel"))
    candidates = []
    for source, value in (
        ("cli.url", public_url),
        ("session.tunnel.public_url", tunnel_model.get("public_url")),
        ("session.tunnel.client_url", tunnel_model.get("client_url")),
        ("session.client.url", client_model.get("url")),
        ("manifest.client.url", client.get("url")),
        ("manifest.tunnel.public_url", tunnel.get("public_url")),
        ("config.proxy.tunnel_public_url", proxy_config.get("tunnel_public_url")),
    ):
        if isinstance(value, str) and value:
            candidates.append({"source": source, "url": value, "normalized": _normalize_auth_url(value)})
    return candidates


def _resolve_auth_doctor_public_url(
    *,
    public_url_candidates: Sequence[Mapping[str, str]],
    auth: Mapping[str, Any],
) -> str | None:
    for candidate in public_url_candidates:
        value = candidate.get("url")
        if isinstance(value, str) and value:
            return value
    resource = auth.get("resource")
    if isinstance(resource, str) and resource:
        return resource
    return None


def _auth_doctor_summary(auth: Mapping[str, Any]) -> dict[str, Any]:
    jwks_path = auth.get("jwks_path")
    scope_map = _mapping(auth.get("scope_map"))
    claim_policy = _mapping(auth.get("claim_policy"))
    return {
        "mode": auth.get("mode"),
        "resource": auth.get("resource"),
        "resource_aliases": [str(item) for item in _sequence(auth.get("resource_aliases"))],
        "issuer": auth.get("issuer"),
        "authorization_servers": [str(item) for item in _sequence(auth.get("authorization_servers"))],
        "audience": auth.get("audience"),
        "audiences": [str(item) for item in _sequence(auth.get("audiences"))],
        "required_scopes": [str(item) for item in _sequence(auth.get("required_scopes"))],
        "scopes_supported": [str(item) for item in _sequence(auth.get("scopes_supported"))],
        "jwks_path": str(jwks_path) if jwks_path else None,
        "jwks_url": auth.get("jwks_url"),
        "jwks_cache_seconds": auth.get("jwks_cache_seconds"),
        "jwks_fetch_timeout": auth.get("jwks_fetch_timeout"),
        "issuer_metadata_url": auth.get("issuer_metadata_url"),
        "issuer_discovery": auth.get("issuer_discovery"),
        "token_validation": auth.get("token_validation"),
        "introspection_endpoint": auth.get("introspection_endpoint"),
        "introspection_client_id": auth.get("introspection_client_id"),
        "introspection_client_secret_env": auth.get("introspection_client_secret_env"),
        "introspection_cache_seconds": auth.get("introspection_cache_seconds"),
        "introspection_fetch_timeout": auth.get("introspection_fetch_timeout"),
        "resource_metadata_url": auth.get("resource_metadata_url"),
        "strip_authorization_upstream": auth.get("strip_authorization_upstream"),
        "scope_map": {
            str(scope): [str(selector) for selector in _sequence(selectors)] for scope, selectors in scope_map.items()
        },
        "claim_policy": {
            "enabled": claim_policy.get("enabled") is True,
            "default_action": claim_policy.get("default_action"),
            "rules": [_auth_claim_policy_rule_summary(rule) for rule in _sequence(claim_policy.get("rules"))],
        },
        "issuers": [_auth_issuer_profile_summary(profile) for profile in _sequence(auth.get("issuers"))],
    }


def _add_auth_url_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    url: str | None,
    public_url_candidates: Sequence[Mapping[str, str]],
    recommendations: list[str],
) -> None:
    _add_share_doctor_check(
        checks,
        "auth.public_url.configured",
        bool(url),
        f"public/client URL is {url}" if url else "public/client URL is not configured",
        component="auth",
        details={"url": url},
    )
    if not url:
        recommendations.append("Pass --url with the exact public MCP URL before sharing an OAuth-protected endpoint.")
        return

    _add_auth_public_url_drift_check(checks, public_url_candidates, recommendations)

    https_ok = _auth_url_is_https_or_local(url)
    _add_share_doctor_check(
        checks,
        "auth.https_or_localhost",
        https_ok,
        "public/client URL uses HTTPS or localhost HTTP"
        if https_ok
        else "public/client URL must use HTTPS except for localhost",
        component="auth",
        details={"url": url},
    )
    if not https_ok:
        recommendations.append("Use HTTPS for public MCP OAuth resource URLs; reserve HTTP for localhost only.")

    resource_urls = _auth_resource_urls(auth)
    accepted_audiences = _auth_accepted_audiences(auth)
    invalid_resource_urls = _invalid_auth_resource_urls(resource_urls)
    _add_share_doctor_check(
        checks,
        "auth.resource.indicators_valid",
        not invalid_resource_urls,
        "configured OAuth resource indicators are absolute HTTPS/local MCP URLs"
        if not invalid_resource_urls
        else "configured OAuth resource indicators are not valid public MCP URLs",
        component="auth",
        details={"resource_urls": resource_urls, "invalid": invalid_resource_urls},
    )
    if invalid_resource_urls:
        recommendations.append(
            "Use absolute HTTPS public MCP URLs for mcp.auth.resource and mcp.auth.resource_aliases; "
            "HTTP is only acceptable for localhost."
        )

    audience_configured = bool(accepted_audiences)
    _add_share_doctor_check(
        checks,
        "auth.audience.configured",
        audience_configured,
        "OAuth audience validation is configured"
        if audience_configured
        else "OAuth audience validation is not configured",
        component="auth",
        details={"audience": auth.get("audience"), "audiences": _sequence(auth.get("audiences"))},
    )
    if not audience_configured:
        recommendations.append("Set mcp.auth.audience to the exact public MCP URL, or mcp.auth.audiences for aliases.")

    resource_match = _url_in_values(url, resource_urls)
    canonical_resource_match = _urls_match(auth.get("resource"), url)
    _add_share_doctor_check(
        checks,
        "auth.resource.matches_public_url",
        resource_match,
        "mcp.auth.resource or resource_aliases include the public/client URL"
        if resource_match
        else "mcp.auth.resource/resource_aliases do not include the public/client URL",
        component="auth",
        details={
            "resource": auth.get("resource"),
            "resource_aliases": _sequence(auth.get("resource_aliases")),
            "url": url,
        },
    )
    if not resource_match:
        recommendations.append(
            "Set mcp.auth.resource to the exact public MCP URL clients connect to, or add an explicit "
            "mcp.auth.resource_aliases entry for intentional multi-URL shares."
        )
    elif not canonical_resource_match:
        _add_share_doctor_check(
            checks,
            "auth.resource.public_url_uses_alias",
            False,
            "public/client URL is accepted through mcp.auth.resource_aliases rather than canonical mcp.auth.resource",
            component="auth",
            severity="warning",
            details={"resource": auth.get("resource"), "url": url},
        )

    audience_match = _url_in_values(url, accepted_audiences)
    _add_share_doctor_check(
        checks,
        "auth.audience.matches_public_url",
        audience_match,
        "mcp.auth.audience/audiences include the public/client URL"
        if audience_match
        else "mcp.auth.audience/audiences do not include the public/client URL",
        component="auth",
        details={"audience": auth.get("audience"), "audiences": _sequence(auth.get("audiences")), "url": url},
    )
    if not audience_match:
        recommendations.append(
            "Set mcp.auth.audience to the exact public MCP URL, or add mcp.auth.audiences entries for "
            "intentional multi-URL shares."
        )

    overlap = sorted({value for value in resource_urls if _url_in_values(value, accepted_audiences)})
    _add_share_doctor_check(
        checks,
        "auth.resource.audience_overlap",
        bool(overlap),
        "at least one accepted audience matches a configured resource indicator"
        if overlap
        else "accepted audiences do not match any configured resource indicator",
        component="auth",
        details={"resource_urls": resource_urls, "accepted_audiences": accepted_audiences, "overlap": overlap},
    )
    if not overlap:
        recommendations.append("Keep OAuth resource indicators and accepted audiences aligned exactly.")

    multi_url_explicit = len(resource_urls) > 1 or len(accepted_audiences) > 1
    if multi_url_explicit:
        _add_share_doctor_check(
            checks,
            "auth.multi_url.explicit",
            False,
            "multiple public resource/audience URLs are configured explicitly",
            component="auth",
            severity="warning",
            details={"resource_urls": resource_urls, "accepted_audiences": accepted_audiences},
        )


def _add_auth_public_url_drift_check(
    checks: list[dict[str, Any]],
    public_url_candidates: Sequence[Mapping[str, str]],
    recommendations: list[str],
) -> None:
    if not public_url_candidates:
        _add_share_doctor_check(
            checks,
            "auth.public_url.sources_consistent",
            None,
            "no share/tunnel public URL sources are configured",
            component="auth",
        )
        return
    distinct: dict[str, list[dict[str, str]]] = {}
    for candidate in public_url_candidates:
        normalized = candidate.get("normalized") or _normalize_auth_url(str(candidate.get("url", "")))
        distinct.setdefault(normalized, []).append(
            {"source": str(candidate.get("source")), "url": str(candidate.get("url"))}
        )
    ok = len(distinct) == 1
    _add_share_doctor_check(
        checks,
        "auth.public_url.sources_consistent",
        ok,
        "share, tunnel, client, and proxy public URL sources agree"
        if ok
        else "share, tunnel, client, and proxy public URL sources disagree",
        component="auth",
        details={"sources": list(public_url_candidates), "distinct": distinct},
    )
    if not ok:
        recommendations.append(
            "Update stale share/client/config URLs or pass the exact current --url, then align "
            "mcp.proxy.tunnel_public_url, mcp.auth.resource, and mcp.auth.audience."
        )


def _auth_resource_urls(auth: Mapping[str, Any]) -> list[str]:
    return _unique_strings(
        [
            *([str(auth["resource"])] if isinstance(auth.get("resource"), str) and auth.get("resource") else []),
            *(str(item) for item in _sequence(auth.get("resource_aliases"))),
        ]
    )


def _auth_accepted_audiences(auth: Mapping[str, Any]) -> list[str]:
    return _unique_strings(
        [
            *([str(auth["audience"])] if isinstance(auth.get("audience"), str) and auth.get("audience") else []),
            *(str(item) for item in _sequence(auth.get("audiences"))),
        ]
    )


def _invalid_auth_resource_urls(urls: Sequence[str]) -> list[dict[str, Any]]:
    invalid = []
    for url in urls:
        parsed = urlsplit(url)
        reason = None
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            reason = "not_absolute_http_url"
        elif not _auth_url_is_https_or_local(url):
            reason = "not_https_or_localhost"
        elif parsed.fragment:
            reason = "fragment_not_allowed"
        elif parsed.query:
            reason = "query_not_allowed"
        if reason:
            invalid.append({"url": url, "reason": reason})
    return invalid


def _url_in_values(url: str, values: Sequence[str]) -> bool:
    return any(_urls_match(value, url) for value in values)


def _add_auth_safety_checks(
    checks: list[dict[str, Any]],
    proxy_config: Mapping[str, Any],
    auth: Mapping[str, Any],
    manifest: Mapping[str, Any],
    recommendations: list[str],
) -> None:
    redact_records = proxy_config.get("redact_records") is True
    unsafe_sinks = _unsafe_auth_event_sinks(proxy_config.get("event_sinks"))
    token_logging_ok = redact_records and not unsafe_sinks
    _add_share_doctor_check(
        checks,
        "auth.raw_token_logging",
        token_logging_ok,
        "recording and event sinks are configured to avoid raw token logging"
        if token_logging_ok
        else "raw token logging safeguards are not fully enabled",
        component="auth",
        details={"redact_records": redact_records, "unsafe_event_sinks": unsafe_sinks},
    )
    if not token_logging_ok:
        recommendations.append(
            'Keep mcp.proxy.redact_records = true and webhook redaction = "strict" for OAuth shares.'
        )

    strip_upstream = auth.get("strip_authorization_upstream") is True
    _add_share_doctor_check(
        checks,
        "auth.anti_passthrough",
        strip_upstream,
        "caller Authorization headers are stripped before upstream forwarding"
        if strip_upstream
        else "caller Authorization headers may be forwarded upstream",
        component="auth",
        details={"strip_authorization_upstream": auth.get("strip_authorization_upstream")},
    )
    if not strip_upstream:
        recommendations.append(
            "Set mcp.auth.strip_authorization_upstream = true and broker upstream credentials separately."
        )

    client_headers = _share_auth_client_headers(manifest, {})
    cloudflare_access = str(proxy_config.get("cloudflare_access") or "off")
    cf_header_names = sorted(name for name in client_headers if name in _CLOUDFLARE_ACCESS_HEADER_NAMES)
    cloudflare_ok = cloudflare_access != "enforce" and not cf_header_names
    if cloudflare_access == "audit" and not cf_header_names:
        message = "Cloudflare Access audit mode does not block OAuth metadata"
    elif cloudflare_ok:
        message = "Cloudflare Access headers do not conflict with OAuth mode"
    elif cloudflare_access == "enforce":
        message = "Cloudflare Access enforcement can block OAuth protected-resource discovery"
    else:
        message = "Cloudflare Access client headers are embedded in the share client config"
    _add_share_doctor_check(
        checks,
        "auth.cloudflare_access.conflict",
        cloudflare_ok,
        message,
        component="auth",
        details={"cloudflare_access": cloudflare_access, "cloudflare_header_names": cf_header_names},
    )
    if not cloudflare_ok:
        recommendations.append(
            "Do not require Cloudflare Access service-token headers for OAuth discovery endpoints; "
            "use OAuth as the public resource boundary or keep Cloudflare Access in audit mode."
        )


_CLOUDFLARE_ACCESS_HEADER_NAMES = {
    "cf-access-client-id",
    "cf-access-client-secret",
    "cf-access-jwt-assertion",
}


def _unsafe_auth_event_sinks(value: Any) -> list[dict[str, Any]]:
    unsafe: list[dict[str, Any]] = []
    for index, sink in enumerate(_sequence(value)):
        sink_map = _mapping(sink)
        if sink_map.get("type") != "webhook":
            continue
        webhook = sink_map.get("webhook")
        redaction = getattr(webhook, "redaction", None)
        body_mode = getattr(webhook, "body_mode", None)
        name = getattr(webhook, "name", f"webhook-{index + 1}")
        if redaction == "none":
            unsafe.append({"index": index, "name": str(name), "redaction": redaction, "body_mode": body_mode})
    return unsafe


def _inspect_local_jwks(
    path_value: Any,
    *,
    remote_url: Any = None,
    issuer_discovery: bool = False,
    token_validation: str = "jwt",
) -> dict[str, Any]:
    if not isinstance(path_value, str | Path):
        if token_validation == "introspection":
            return {
                "ok": False,
                "status": "skip",
                "message": "local JWKS is not configured; runtime will use token introspection",
                "path": None,
                "key_count": 0,
            }
        if isinstance(remote_url, str) and remote_url:
            return {
                "ok": False,
                "status": "skip",
                "message": "local JWKS is not configured; runtime will use remote JWKS URL",
                "path": None,
                "jwks_url": remote_url,
                "key_count": 0,
            }
        if issuer_discovery:
            return {
                "ok": False,
                "status": "skip",
                "message": "local JWKS is not configured; runtime will discover issuer JWKS",
                "path": None,
                "key_count": 0,
            }
        return {"ok": False, "message": "mcp.auth.jwks_path is not configured", "path": None, "key_count": 0}
    path = Path(path_value)
    if not path.is_file():
        return {"ok": False, "message": f"JWKS file is missing: {path}", "path": str(path), "key_count": 0}
    try:
        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except Exception as exc:
        return {"ok": False, "message": f"JWKS file could not be read: {exc}", "path": str(path), "key_count": 0}
    keys = payload.get("keys") if isinstance(payload, Mapping) else None
    key_count = len(keys) if isinstance(keys, list) else 0
    ok = key_count > 0
    return {
        "ok": ok,
        "message": "JWKS is usable" if ok else "JWKS must contain a non-empty keys array",
        "path": str(path),
        "key_count": key_count,
    }


def _fetch_auth_json_document(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"ok": False, "url": url, "status": None, "error": f"unsupported URL: {url}"}
    request_headers = {
        "accept": "application/json",
        "user-agent": "snulbug-auth-doctor/0.1",
        **{str(name): str(value) for name, value in headers.items()},
    }
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request("GET", _request_target(parsed), headers=request_headers)
        response = connection.getresponse()
        body = response.read(1_048_577)
        status = int(response.status)
        content_type = response.headers.get("content-type", "")
        if len(body) > 1_048_576:
            return {
                "ok": False,
                "url": url,
                "status": status,
                "content_type": content_type,
                "error": "response body exceeds 1 MiB",
            }
        text = body.decode("utf-8", errors="replace")
        try:
            payload = json.loads(text) if text.strip() else None
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "url": url,
                "status": status,
                "content_type": content_type,
                "error": f"response is not JSON: {exc}",
            }
        return {
            "ok": 200 <= status < 300 and isinstance(payload, Mapping),
            "url": url,
            "status": status,
            "content_type": content_type,
            "json": dict(payload) if isinstance(payload, Mapping) else payload,
            "error": None if 200 <= status < 300 else f"HTTP {status}",
        }
    except Exception as exc:
        return {"ok": False, "url": url, "status": None, "error": str(exc)}
    finally:
        connection.close()


def _first_successful_auth_json_document(
    urls: Sequence[str],
    *,
    headers: Mapping[str, str],
    timeout: float,
) -> dict[str, Any]:
    last_probe: dict[str, Any] = {"ok": False, "error": "no URLs attempted", "attempted_urls": list(urls)}
    for url in urls:
        probe = _fetch_auth_json_document(url, headers=headers, timeout=timeout)
        if probe.get("ok") is True:
            probe["attempted_urls"] = list(urls)
            return probe
        last_probe = probe
    last_probe["attempted_urls"] = list(urls)
    return last_probe


def _metadata_probe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(name): str(value) for name, value in headers.items() if str(name).lower() != "authorization"}


def _http_probe_details(probe: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: probe.get(key)
        for key in ("url", "status", "content_type", "error", "attempted_urls")
        if probe.get(key) is not None
    }


def _auth_issuer_candidates(auth: Mapping[str, Any]) -> list[str]:
    candidates = []
    issuer = auth.get("issuer")
    if isinstance(issuer, str) and issuer:
        candidates.append(issuer)
    for server in _sequence(auth.get("authorization_servers")):
        if isinstance(server, str) and server:
            candidates.append(server)
    return _unique_strings(candidates)


def _issuer_metadata_urls(auth: Mapping[str, Any]) -> list[str]:
    configured = auth.get("issuer_metadata_url")
    if isinstance(configured, str) and configured:
        return [configured]
    if auth.get("issuer_discovery") is False:
        return []
    urls = []
    for issuer in _auth_issuer_candidates(auth):
        base = issuer.rstrip("/")
        if base.startswith(("http://", "https://")):
            urls.append(f"{base}/.well-known/oauth-authorization-server")
            urls.append(f"{base}/.well-known/openid-configuration")
    return _unique_strings(urls)


def _add_jwks_or_introspection_check(
    checks: list[dict[str, Any]],
    issuer_metadata: Mapping[str, Any] | None,
    *,
    local_jwks_ok: bool,
    configured_jwks_url: str | None,
    configured_introspection_endpoint: str | None,
    token_validation: str,
    issuer_discovery: bool,
    token: str | None,
    headers: Mapping[str, str],
    timeout: float,
    live_checks: bool,
    live: dict[str, Any],
    recommendations: list[str],
) -> None:
    uses_jwt = token_validation in {"jwt", "jwt_or_introspection", "jwt_and_introspection"}
    uses_introspection = token_validation in {"introspection", "jwt_or_introspection", "jwt_and_introspection"}
    if not live_checks:
        if uses_introspection and configured_introspection_endpoint:
            _add_share_doctor_check(
                checks,
                "auth.jwks_or_introspection",
                None,
                "token introspection live check skipped",
                component="auth",
                details={
                    "introspection_endpoint": configured_introspection_endpoint,
                    "token_validation": token_validation,
                },
            )
            return
        if configured_jwks_url or issuer_discovery:
            _add_share_doctor_check(
                checks,
                "auth.jwks_or_introspection",
                None,
                "remote JWKS runtime fetch skipped",
                component="auth",
                details={
                    "jwks_url": configured_jwks_url,
                    "issuer_discovery": issuer_discovery,
                    "token_validation": token_validation,
                },
            )
            return
        _add_share_doctor_check(
            checks,
            "auth.jwks_or_introspection",
            local_jwks_ok,
            "local JWKS is usable" if local_jwks_ok else "local JWKS is not usable",
            component="auth",
        )
        return

    metadata = _mapping(issuer_metadata)
    jwt_ok = True
    jwt_message = "JWT validation is not enabled"
    jwt_details: dict[str, Any] = {}
    if uses_jwt and configured_jwks_url:
        probe = _fetch_auth_json_document(configured_jwks_url, headers=headers, timeout=timeout)
        live["jwks"] = probe
        jwks_keys = _sequence(_mapping(probe.get("json")).get("keys"))
        jwt_ok = probe.get("ok") is True and bool(jwks_keys)
        jwt_message = (
            f"configured remote JWKS contains {len(jwks_keys)} key(s)"
            if jwt_ok
            else f"configured remote JWKS is not usable at {configured_jwks_url}: {probe.get('error')}"
        )
        jwt_details = _http_probe_details(probe)
        if not jwt_ok:
            recommendations.append("Fix mcp.auth.jwks_url or configure a local mcp.auth.jwks_path fallback.")
    elif uses_jwt and isinstance(metadata.get("jwks_uri"), str) and metadata.get("jwks_uri"):
        jwks_uri = str(metadata["jwks_uri"])
        probe = _fetch_auth_json_document(jwks_uri, headers=headers, timeout=timeout)
        live["jwks"] = probe
        jwks_keys = _sequence(_mapping(probe.get("json")).get("keys"))
        jwt_ok = probe.get("ok") is True and bool(jwks_keys)
        jwt_message = (
            f"issuer JWKS contains {len(jwks_keys)} key(s)"
            if jwt_ok
            else f"issuer JWKS is not usable at {jwks_uri}: {probe.get('error')}"
        )
        jwt_details = _http_probe_details(probe)
        if not jwt_ok:
            recommendations.append("Fix the issuer jwks_uri or configure a reachable JWKS endpoint.")
    elif uses_jwt:
        jwt_ok = local_jwks_ok
        jwt_message = (
            "local JWKS is usable and issuer metadata does not advertise JWKS"
            if local_jwks_ok
            else "no usable JWKS is available"
        )
        if not jwt_ok:
            recommendations.append("Publish issuer JWKS metadata or configure mcp.auth.jwks_path with local keys.")

    introspection_ok = True
    introspection_status: bool | None = True
    introspection_message = "token introspection is not enabled"
    introspection_details: dict[str, Any] = {}
    if uses_introspection:
        introspection = configured_introspection_endpoint or metadata.get("introspection_endpoint")
        if not isinstance(introspection, str) or not introspection:
            introspection_ok = False
            introspection_status = False
            introspection_message = "no token introspection endpoint is configured or advertised by issuer metadata"
            recommendations.append(
                "Configure mcp.auth.introspection_endpoint or advertise introspection_endpoint in issuer metadata."
            )
        elif not token:
            introspection_status = None
            introspection_message = "token introspection POST skipped because no token was supplied"
            introspection_details = {"introspection_endpoint": introspection}
            recommendations.append("Pass --token with an active OAuth token to fully verify token introspection.")
        else:
            probe = _post_auth_introspection(introspection, token=token, headers=headers, timeout=timeout)
            live["introspection"] = probe
            payload = _mapping(probe.get("json"))
            introspection_ok = probe.get("ok") is True and payload.get("active") is True
            introspection_status = introspection_ok
            introspection_message = (
                "token introspection endpoint accepts the supplied token"
                if introspection_ok
                else f"token introspection is not usable at {introspection}: {probe.get('error') or 'inactive token'}"
            )
            introspection_details = _http_probe_details(probe)

    if introspection_status is None and (not uses_jwt or jwt_ok):
        combined_status: bool | None = None
    else:
        combined_status = jwt_ok and introspection_ok
    if combined_status is True:
        if uses_jwt and uses_introspection:
            message = f"{jwt_message}; {introspection_message}"
        elif uses_introspection:
            message = introspection_message
        else:
            message = jwt_message
    elif combined_status is None:
        message = introspection_message
    else:
        message = (
            "; ".join(
                item
                for item in (
                    jwt_message if uses_jwt and not jwt_ok else None,
                    introspection_message if uses_introspection and not introspection_ok else None,
                )
                if item
            )
            or "auth token validation is not usable"
        )

    _add_share_doctor_check(
        checks,
        "auth.jwks_or_introspection",
        combined_status,
        message,
        component="auth",
        details={
            "token_validation": token_validation,
            "jwks": jwt_details,
            "introspection": introspection_details,
        },
    )


def _post_auth_introspection(
    url: str,
    *,
    token: str,
    headers: Mapping[str, str],
    timeout: float,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"ok": False, "url": url, "status": None, "error": f"unsupported URL: {url}"}
    request_headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "snulbug-auth-doctor/0.1",
        **{str(name): str(value) for name, value in headers.items()},
    }
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request(
            "POST",
            _request_target(parsed),
            body=urlencode({"token": token}).encode("utf-8"),
            headers=request_headers,
        )
        response = connection.getresponse()
        body = response.read(1_048_577)
        status = int(response.status)
        content_type = response.headers.get("content-type", "")
        if len(body) > 1_048_576:
            return {
                "ok": False,
                "url": url,
                "status": status,
                "content_type": content_type,
                "error": "response body exceeds 1 MiB",
            }
        text = body.decode("utf-8", errors="replace")
        try:
            payload = json.loads(text) if text.strip() else None
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "url": url,
                "status": status,
                "content_type": content_type,
                "error": f"response is not JSON: {exc}",
            }
        return {
            "ok": 200 <= status < 300 and isinstance(payload, Mapping),
            "url": url,
            "status": status,
            "content_type": content_type,
            "json": dict(payload) if isinstance(payload, Mapping) else payload,
            "error": None if 200 <= status < 300 else f"HTTP {status}",
        }
    except Exception as exc:
        return {"ok": False, "url": url, "status": None, "error": str(exc)}
    finally:
        connection.close()


def _add_scope_map_tool_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    url: str | None,
    *,
    probe_headers: Mapping[str, str],
    token: str | None,
    timeout: float,
    live_checks: bool,
    live: dict[str, Any],
    recommendations: list[str],
    fetch_tools: Any,
) -> None:
    scope_map = _mapping(auth.get("scope_map"))
    _add_share_doctor_check(
        checks,
        "auth.scope_map.configured",
        bool(scope_map),
        "OAuth scopes are mapped to MCP methods/tools" if scope_map else "OAuth scope-to-MCP mapping is not configured",
        component="auth",
        severity="warning",
        details={"scope_count": len(scope_map)},
    )
    if not scope_map:
        recommendations.append("Add [mcp.auth.scope_map] entries so OAuth scopes authorize concrete MCP actions.")
        return

    tool_patterns = _scope_map_tool_patterns(scope_map)
    if not tool_patterns:
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            None,
            "scope map does not contain tool-specific selectors",
            component="auth",
            details={"scope_count": len(scope_map)},
        )
        return
    if not live_checks:
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            None,
            "live tool discovery skipped",
            component="auth",
            details={"tool_selectors": tool_patterns},
        )
        return
    if not url:
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            False,
            "live tool discovery requires a public/client URL",
            component="auth",
        )
        return
    if not token and not _has_authorization_header(probe_headers):
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            None,
            "live tool discovery requires --token or an Authorization header",
            component="auth",
            details={"tool_selectors": tool_patterns},
        )
        recommendations.append(
            "Pass --token or --header 'Authorization: Bearer ...' to validate scope-map tool selectors."
        )
        return

    try:
        payload, fetch_metadata = fetch_tools(url, headers=probe_headers, token=None, timeout=timeout)
        tool_names = _tool_names_from_tools_payload(payload)
        missing = _missing_scope_map_tool_patterns(tool_patterns, tool_names)
        live["tools_list"] = {
            "url": fetch_metadata.get("url"),
            "status": fetch_metadata.get("status"),
            "content_type": fetch_metadata.get("content_type"),
            "tool_count": len(tool_names),
            "tools": sorted(tool_names),
        }
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            not missing,
            "scope-map tool selectors match discovered MCP tools"
            if not missing
            else "scope-map tool selectors do not match discovered MCP tools",
            component="auth",
            details={"missing_selectors": missing, "tool_count": len(tool_names)},
        )
        if missing:
            recommendations.append(
                "Update [mcp.auth.scope_map] selectors or refresh schema discovery from the live MCP server."
            )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "auth.scope_map.tools_discovered",
            False,
            f"live tools/list discovery failed: {exc}",
            component="auth",
            details={"url": url},
        )
        recommendations.append("Verify the public MCP URL and token before relying on scope-to-tool checks.")


def _add_claim_policy_tool_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    url: str | None,
    *,
    probe_headers: Mapping[str, str],
    token: str | None,
    timeout: float,
    live_checks: bool,
    live: dict[str, Any],
    recommendations: list[str],
    fetch_tools: Any,
) -> None:
    policy = _mapping(auth.get("claim_policy"))
    if policy.get("enabled") is not True:
        return

    rules = [rule for rule in _sequence(policy.get("rules")) if isinstance(rule, Mapping)]
    _add_share_doctor_check(
        checks,
        "auth.claim_policy.configured",
        bool(rules),
        "OAuth claims are mapped to MCP tools" if rules else "OAuth claim-to-tool policy has no rules",
        component="auth",
        details={
            "default_action": policy.get("default_action"),
            "rule_count": len(rules),
            "rules": [_auth_claim_policy_rule_summary(rule) for rule in rules],
        },
    )
    if not rules:
        recommendations.append("Add [[mcp.auth.claim_policy.rules]] entries or disable mcp.auth.claim_policy.enabled.")
        return

    tool_patterns = _claim_policy_tool_patterns(policy)
    if not tool_patterns:
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            None,
            "claim policy does not contain tool-specific allow entries",
            component="auth",
            details={"rule_count": len(rules)},
        )
        return
    if not live_checks:
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            None,
            "live tool discovery skipped",
            component="auth",
            details={"tool_patterns": tool_patterns},
        )
        return
    if not url:
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            False,
            "live tool discovery requires a public/client URL",
            component="auth",
        )
        return
    if not token and not _has_authorization_header(probe_headers):
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            None,
            "live tool discovery requires --token or an Authorization header",
            component="auth",
            details={"tool_patterns": tool_patterns},
        )
        recommendations.append(
            "Pass --token or --header 'Authorization: Bearer ...' to validate claim-policy tool entries."
        )
        return

    try:
        live_tools = _live_tool_names(live)
        if not live_tools:
            payload, fetch_metadata = fetch_tools(url, headers=probe_headers, token=None, timeout=timeout)
            live_tools = _tool_names_from_tools_payload(payload)
            live["tools_list"] = {
                "url": fetch_metadata.get("url"),
                "status": fetch_metadata.get("status"),
                "content_type": fetch_metadata.get("content_type"),
                "tool_count": len(live_tools),
                "tools": sorted(live_tools),
            }
        missing = _missing_scope_map_tool_patterns(tool_patterns, live_tools)
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            not missing,
            "claim-policy tool entries match discovered MCP tools"
            if not missing
            else "claim-policy tool entries do not match discovered MCP tools",
            component="auth",
            details={"missing_patterns": missing, "tool_count": len(live_tools)},
        )
        if missing:
            recommendations.append(
                "Update [[mcp.auth.claim_policy.rules]] allow entries or refresh schema discovery "
                "from the live MCP server."
            )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "auth.claim_policy.tools_discovered",
            False,
            f"live tools/list discovery failed: {exc}",
            component="auth",
            details={"url": url},
        )
        recommendations.append("Verify the public MCP URL and token before relying on claim-to-tool checks.")


def _scope_map_tool_patterns(scope_map: Mapping[str, Any]) -> list[str]:
    patterns: list[str] = []
    for selectors in scope_map.values():
        for selector in _sequence(selectors):
            text = str(selector)
            prefix = "tools/call:"
            if text.startswith(prefix) and len(text) > len(prefix):
                patterns.append(text[len(prefix) :])
    return sorted(set(patterns))


def _claim_policy_tool_patterns(policy: Mapping[str, Any]) -> list[str]:
    patterns: list[str] = []
    for rule in _sequence(policy.get("rules")):
        if not isinstance(rule, Mapping):
            continue
        for tool in _sequence(rule.get("allow_tools")):
            text = str(tool)
            if text:
                patterns.append(text)
        for prefix in _sequence(rule.get("allow_tool_prefixes")):
            text = str(prefix)
            if text:
                patterns.append(f"{text}*")
        for selector in _sequence(rule.get("allow_selectors")):
            text = str(selector)
            prefix = "tools/call:"
            if text.startswith(prefix) and len(text) > len(prefix):
                patterns.append(text[len(prefix) :])
    return sorted(set(patterns))


def _auth_claim_policy_rule_summary(rule: Any) -> dict[str, Any]:
    item = _mapping(rule)
    return {
        "id": item.get("id"),
        "claim": item.get("claim"),
        "values": [str(value) for value in _sequence(item.get("values"))],
        "allow_tools": [str(value) for value in _sequence(item.get("allow_tools"))],
        "allow_tool_prefixes": [str(value) for value in _sequence(item.get("allow_tool_prefixes"))],
        "allow_selectors": [str(value) for value in _sequence(item.get("allow_selectors"))],
    }


def _auth_issuer_profile_summary(profile: Any) -> dict[str, Any]:
    item = _mapping(profile)
    jwks_path = item.get("jwks_path")
    scope_map = _mapping(item.get("scope_map"))
    claim_policy = _mapping(item.get("claim_policy"))
    return {
        "id": item.get("id"),
        "issuer": item.get("issuer"),
        "authorization_servers": [str(value) for value in _sequence(item.get("authorization_servers"))],
        "audience": item.get("audience"),
        "audiences": [str(value) for value in _sequence(item.get("audiences"))],
        "required_scopes": [str(value) for value in _sequence(item.get("required_scopes"))],
        "required_claims": {
            str(claim): [str(value) for value in _sequence(values)]
            for claim, values in _mapping(item.get("required_claims")).items()
        },
        "jwks_path": str(jwks_path) if jwks_path else None,
        "jwks_url": item.get("jwks_url"),
        "token_validation": item.get("token_validation"),
        "scope_map": {
            str(scope): [str(selector) for selector in _sequence(selectors)] for scope, selectors in scope_map.items()
        },
        "claim_policy": {
            "enabled": claim_policy.get("enabled") is True,
            "default_action": claim_policy.get("default_action"),
            "rules": [_auth_claim_policy_rule_summary(rule) for rule in _sequence(claim_policy.get("rules"))],
        },
    }


def _live_tool_names(live: Mapping[str, Any]) -> set[str]:
    return {str(item) for item in _sequence(_mapping(live.get("tools_list")).get("tools")) if item}


def _tool_names_from_tools_payload(payload: Any) -> set[str]:
    source = payload
    if isinstance(payload, Mapping) and isinstance(payload.get("result"), Mapping):
        source = payload["result"]
    tools = _mapping(source).get("tools")
    names = set()
    for tool in _sequence(tools):
        if isinstance(tool, Mapping) and isinstance(tool.get("name"), str):
            names.add(tool["name"])
    return names


def _missing_scope_map_tool_patterns(patterns: Sequence[str], tool_names: set[str]) -> list[str]:
    missing = []
    for pattern in patterns:
        if pattern == "*":
            if not tool_names:
                missing.append(pattern)
            continue
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if not any(name.startswith(prefix) for name in tool_names):
                missing.append(pattern)
            continue
        if pattern not in tool_names:
            missing.append(pattern)
    return missing


def _has_authorization_header(headers: Mapping[str, str]) -> bool:
    return any(str(name).lower() == "authorization" and bool(value) for name, value in headers.items())


def _auth_url_is_https_or_local(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http":
        return False
    hostname = parsed.hostname or ""
    return hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost")


def _urls_match(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str) or not left or not right:
        return False
    return _normalize_auth_url(left) == _normalize_auth_url(right)


def _normalize_auth_url(value: str) -> str:
    return value.rstrip("/")


def _add_share_status_checks(
    checks: list[dict[str, Any]],
    status: Mapping[str, Any],
    *,
    live_checks: bool,
) -> None:
    gateway = _mapping(status.get("gateway"))
    if live_checks and gateway.get("checked"):
        _add_share_doctor_check(
            checks,
            "status.gateway_reachable",
            gateway.get("reachable") is True,
            "gateway is reachable" if gateway.get("reachable") is True else "gateway is not reachable",
            component="status",
            details={"url": gateway.get("url"), "error": gateway.get("error"), "status": gateway.get("status")},
        )
    else:
        _add_share_doctor_check(
            checks,
            "status.gateway_reachable",
            None,
            "gateway reachability check skipped",
            component="status",
        )

    for upstream in _sequence(status.get("upstreams")):
        if not isinstance(upstream, Mapping):
            continue
        name = str(upstream.get("name") or upstream.get("url") or "upstream")
        check_id = f"status.upstream.{_check_slug(name)}.reachable"
        if live_checks and upstream.get("checked"):
            _add_share_doctor_check(
                checks,
                check_id,
                upstream.get("reachable") is True,
                f"upstream {name} is reachable"
                if upstream.get("reachable") is True
                else f"upstream {name} is not reachable",
                component="status",
                details={
                    "url": upstream.get("url"),
                    "transport": upstream.get("transport"),
                    "error": upstream.get("error"),
                    "status": upstream.get("status"),
                },
            )
        else:
            _add_share_doctor_check(
                checks,
                check_id,
                None,
                f"upstream {name} reachability check skipped",
                component="status",
                details={"url": upstream.get("url"), "transport": upstream.get("transport")},
            )

    lease = _mapping(status.get("lease"))
    session_model = _mapping(status.get("session_model"))
    lease_model = _mapping(session_model.get("lease"))
    if lease_model.get("required") is True:
        _add_share_doctor_check(
            checks,
            "status.lease_active",
            lease.get("active") is True,
            "current share lease is active" if lease.get("active") is True else "current share lease is not active",
            component="status",
            details={"lease_file": lease.get("file"), "lease_id": lease.get("id")},
        )
    else:
        _add_share_doctor_check(
            checks,
            "status.lease_active",
            None,
            "share lease is not required",
            component="status",
        )


def _share_policy_doctor_checks(
    share_dir: Path,
    proxy_config: Mapping[str, Any] | None,
    status: Mapping[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    session_model = _mapping(status.get("session_model"))
    policy_model = _mapping(session_model.get("policy"))
    policy_path = proxy_config.get("policy") if isinstance(proxy_config, Mapping) else policy_model.get("active_policy")
    active_policy = Path(policy_path) if isinstance(policy_path, str | Path) else None
    bundle_value = policy_model.get("bundle")
    bundle_path = _resolve_share_path(share_dir, bundle_value) if isinstance(bundle_value, str) else None

    if active_policy is None:
        _add_share_doctor_check(
            checks,
            "policy.configured",
            False,
            "no active policy is configured",
            component="policy",
        )
        recommendations.append("Configure mcp.proxy.policy before sharing.")
        return {
            "result": {"ok": False, "policy": None, "bundle": str(bundle_path) if bundle_path else None},
            "checks": checks,
            "recommendations": recommendations,
        }

    if active_policy.is_file():
        entrypoint_message = f"active policy exists at {active_policy}"
    else:
        entrypoint_message = f"active policy is missing: {active_policy}"
    _add_share_doctor_check(
        checks,
        "policy.entrypoint_present",
        active_policy.is_file(),
        entrypoint_message,
        component="policy",
        details={"policy": str(active_policy)},
    )

    validation: dict[str, Any] | None = None
    if bundle_path is not None and (bundle_path / "manifest.json").is_file():
        validation = validate_bundle(bundle_path)
        _add_share_doctor_check(
            checks,
            "policy.bundle_valid",
            bool(validation.get("ok")),
            "policy bundle validates" if validation.get("ok") else "policy bundle validation failed",
            component="policy",
            details={"bundle": str(bundle_path), "errors": validation.get("errors", [])},
        )
    elif active_policy.is_file():
        try:
            from .runtime import compile_lua_file

            compile_lua_file(active_policy)
            _add_share_doctor_check(
                checks,
                "policy.entrypoint_compiles",
                True,
                "active policy compiles",
                component="policy",
                details={"policy": str(active_policy)},
            )
        except Exception as exc:
            _add_share_doctor_check(
                checks,
                "policy.entrypoint_compiles",
                False,
                f"active policy does not compile: {exc}",
                component="policy",
                details={"policy": str(active_policy)},
            )

    lifecycle_state = policy_model.get("lifecycle_state")
    lifecycle_message = (
        "policy lifecycle is active"
        if lifecycle_state == "active"
        else f"policy lifecycle is {lifecycle_state or 'unspecified'}"
    )
    _add_share_doctor_check(
        checks,
        "policy.lifecycle_active",
        lifecycle_state in {None, "active"},
        lifecycle_message,
        component="policy",
        severity="warning",
        details={"state": lifecycle_state},
    )
    _add_share_doctor_check(
        checks,
        "policy.lifecycle_signed",
        policy_model.get("lifecycle_signed") is True,
        "policy lifecycle is signed"
        if policy_model.get("lifecycle_signed") is True
        else "policy lifecycle is not signed",
        component="policy",
        severity="warning",
    )
    if any(check.get("status") == "fail" for check in checks):
        recommendations.append("Regenerate or repair the policy bundle before sharing this endpoint.")
    return {
        "result": {
            "ok": not any(check.get("status") == "fail" for check in checks),
            "policy": str(active_policy),
            "bundle": str(bundle_path) if bundle_path else None,
            "validation": validation,
            "lifecycle_state": lifecycle_state,
            "lifecycle_signed": policy_model.get("lifecycle_signed"),
        },
        "checks": checks,
        "recommendations": recommendations,
    }


def _run_share_conformance_doctor(
    pack: str | Path | None,
    *,
    headers: Mapping[str, str],
    timeout: float,
    require_conformance: bool,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    if pack is None:
        _add_share_doctor_check(
            checks,
            "conformance.pack_configured",
            False if require_conformance else None,
            "conformance pack is required but was not provided"
            if require_conformance
            else "no fabric conformance pack was provided",
            component="conformance",
        )
        if require_conformance:
            recommendations.append("Pass --conformance-pack with a generated fabric conformance pack.")
        return {
            "result": {"ok": not require_conformance, "status": "not_configured", "required": require_conformance},
            "checks": checks,
            "recommendations": recommendations,
        }

    from .fabric import run_fabric_conformance_pack

    result = run_fabric_conformance_pack(
        pack,
        headers=headers,
        timeout=timeout,
        probe_gateway=False,
        probe_upstreams=False,
    )
    _extend_component_checks(checks, result.get("checks", []), component="conformance", prefix="conformance")
    _add_share_doctor_check(
        checks,
        "conformance.pack_passed",
        result.get("ok") is True,
        "fabric conformance pack passed" if result.get("ok") is True else "fabric conformance pack failed",
        component="conformance",
        details={"pack": str(pack)},
    )
    if result.get("ok") is not True:
        recommendations.extend(str(item) for item in _sequence(result.get("recommendations")))
    result = {**result, "required": require_conformance}
    return {"result": result, "checks": checks, "recommendations": recommendations}


def _extend_component_checks(
    target: list[dict[str, Any]],
    checks: Any,
    *,
    component: str,
    prefix: str,
) -> None:
    for check in _sequence(checks):
        if not isinstance(check, Mapping):
            continue
        item = dict(check)
        check_id = str(item.get("id", "check"))
        if not check_id.startswith(f"{prefix}."):
            item["id"] = f"{prefix}.{check_id}"
        item["component"] = component
        target.append(item)


def _add_share_doctor_check(
    checks: list[dict[str, Any]],
    check_id: str,
    ok: bool | None,
    message: str,
    *,
    component: str,
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
    check: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "message": message,
        "component": component,
    }
    if details:
        check["details"] = dict(details)
    checks.append(check)


def _share_doctor_summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "skipped": sum(1 for check in checks if check.get("status") == "skip"),
    }


def _unique_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _check_slug(value: str) -> str:
    result = []
    for char in value.lower():
        result.append(char if char.isalnum() else "_")
    return "".join(result).strip("_") or "item"


def _share_gateway_status(
    share_dir: Path,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
    *,
    timeout: float,
    live_checks: bool,
) -> dict[str, Any]:
    gateway = _mapping(session_model.get("gateway"))
    url = gateway.get("local_url")
    result: dict[str, Any] = {
        "url": url,
        "checked": bool(live_checks and isinstance(url, str) and url),
        "reachable": None,
    }
    if not result["checked"]:
        return result
    client = _mapping(manifest.get("client"))
    headers = _mapping(client.get("headers"))
    probe = _probe_mcp_url(str(url), headers=headers, timeout=timeout)
    result.update(probe)
    return result


def _share_upstream_statuses(
    share_dir: Path,
    manifest: Mapping[str, Any],
    *,
    timeout: float,
    live_checks: bool,
) -> list[dict[str, Any]]:
    upstreams = _share_upstream_configs(share_dir, manifest)
    statuses = []
    for upstream in upstreams:
        status = dict(upstream)
        url = status.get("url")
        if live_checks and isinstance(url, str) and url.startswith(("http://", "https://")):
            status.update(_probe_mcp_url(url, headers={}, timeout=timeout))
            status["checked"] = True
        else:
            status["checked"] = False
            status["reachable"] = None
        statuses.append(status)
    return statuses


def _share_upstream_configs(share_dir: Path, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    files = _mapping(manifest.get("files"))
    config = files.get("config")
    if isinstance(config, str) and config:
        try:
            from .config import load_mcp_proxy_config

            proxy_config = load_mcp_proxy_config(_resolve_share_path(share_dir, config))
        except Exception:
            proxy_config = {}
        upstreams = proxy_config.get("upstreams") if isinstance(proxy_config, Mapping) else None
        if isinstance(upstreams, Sequence) and not isinstance(upstreams, str | bytes | bytearray) and upstreams:
            result = []
            for upstream in upstreams:
                if isinstance(upstream, Mapping):
                    result.append(
                        {
                            "name": upstream.get("name"),
                            "transport": upstream.get("transport", "http"),
                            "url": upstream.get("url"),
                            "tool_prefix": upstream.get("tool_prefix"),
                        }
                    )
            return result
        upstream = proxy_config.get("upstream") if isinstance(proxy_config, Mapping) else None
        if isinstance(upstream, str) and upstream:
            return [{"name": "default", "transport": "http", "url": upstream}]
    session = _mapping(manifest.get("session"))
    upstream = session.get("upstream")
    return [{"name": "default", "transport": "http", "url": upstream}] if isinstance(upstream, str) else []


def _share_tunnel_status(manifest: Mapping[str, Any], session_model: Mapping[str, Any]) -> dict[str, Any]:
    tunnel = _mapping(session_model.get("tunnel"))
    health = _mapping(manifest.get("health"))
    doctor = _mapping(health.get("tunnel_doctor"))
    configured = bool(tunnel.get("public_url"))
    return {
        "configured": configured,
        "provider": tunnel.get("provider"),
        "public_url": tunnel.get("public_url"),
        "checked": bool(doctor),
        "last_checked_at": health.get("last_checked_at"),
        "ok": doctor.get("ok"),
        "summary": doctor.get("summary"),
        "recommendations": doctor.get("recommendations", []),
    }


def _share_traffic_summary(share_dir: Path, session_model: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _mapping(session_model.get("evidence"))
    audit_path = _resolve_share_path(share_dir, evidence.get("audit_log", "traces/audit.jsonl"))
    record_path = _resolve_share_path(share_dir, evidence.get("record_log", "traces/session.jsonl"))
    source_path = audit_path if audit_path.exists() else record_path
    source_kind = "audit" if source_path == audit_path else "auto"
    summary: dict[str, Any] = {
        "source": str(source_path),
        "source_kind": source_kind,
        "exists": source_path.exists(),
        "event_count": 0,
        "allowed": 0,
        "blocked": 0,
        "confirmed": 0,
        "confirmation_approved": 0,
        "confirmation_denied": 0,
        "redacted_events": 0,
        "response_redacted": 0,
        "record_redacted": 0,
        "methods": [],
        "tools": [],
        "clients": [],
        "source_ips": [],
        "inspection": None,
        "inspection_report": None,
    }
    if not source_path.exists():
        return summary

    methods: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    clients: Counter[str] = Counter()
    source_ips: Counter[str] = Counter()
    for event in _load_share_events(source_path):
        summary["event_count"] += 1
        decision = _mapping(event.get("decision"))
        mcp = _mapping(event.get("mcp"))
        tunnel = _mapping(event.get("tunnel"))
        metadata = _mapping(event.get("metadata"))
        response_policy = _mapping(metadata.get("response_policy"))
        if decision.get("allowed") is False:
            summary["blocked"] += 1
        else:
            summary["allowed"] += 1
        if event.get("redacted") is True:
            summary["record_redacted"] += 1
        if response_policy.get("redacted") is True:
            summary["response_redacted"] += 1
        if _event_has_redaction_marker(event):
            summary["redacted_events"] += 1
        confirmation = _mapping(decision.get("confirmation"))
        if confirmation:
            summary["confirmed"] += 1
            if confirmation.get("approved") is True:
                summary["confirmation_approved"] += 1
            else:
                summary["confirmation_denied"] += 1
        _count_if(methods, mcp.get("method"))
        _count_if(tools, mcp.get("tool") or mcp.get("target"))
        client = _mapping(mcp.get("client"))
        client_name = client.get("name")
        if client_name:
            _count_if(clients, client_name)
        _count_if(source_ips, tunnel.get("source_ip"))

    summary["methods"] = _counter_entries(methods)
    summary["tools"] = _counter_entries(tools)
    summary["clients"] = _counter_entries(clients)
    summary["source_ips"] = _counter_entries(source_ips)
    try:
        inspection = inspect_mcp_log(source_path, kind=source_kind)
        summary["inspection"] = inspection
        summary["inspection_report"] = format_mcp_inspection_report(inspection)
    except Exception as exc:
        summary["inspection_error"] = str(exc)
    return summary


def _share_recordings_status(share_dir: Path, session_model: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _mapping(session_model.get("evidence"))
    result = {}
    for name, fallback in (("record_log", "traces/session.jsonl"), ("audit_log", "traces/audit.jsonl")):
        path = _resolve_share_path(share_dir, evidence.get(name, fallback))
        result[name] = {
            "path": str(path),
            "exists": path.exists(),
            "bytes": path.stat().st_size if path.exists() else 0,
        }
    return result


def _share_amendment_status(session_model: Mapping[str, Any]) -> dict[str, Any]:
    amendments = _mapping(session_model.get("amendments"))
    candidates = [item for item in _sequence(amendments.get("candidates")) if isinstance(item, Mapping)]
    return {
        "last": amendments.get("last"),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def _share_leases_summary(lease_status: Mapping[str, Any]) -> dict[str, Any]:
    all_leases = [lease for lease in _sequence(lease_status.get("leases")) if isinstance(lease, Mapping)]
    return {
        "file": lease_status.get("file"),
        "active_count": sum(1 for lease in all_leases if lease.get("active")),
        "current": lease_status.get("matched"),
        "leases": all_leases,
    }


def _share_findings(
    *,
    gateway: Mapping[str, Any],
    upstreams: Sequence[Mapping[str, Any]],
    traffic: Mapping[str, Any],
    tunnel: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if gateway.get("checked") and gateway.get("reachable") is not True:
        findings.append(
            {
                "severity": "warning",
                "type": "gateway_unreachable",
                "message": "local gateway is not reachable",
            }
        )
    for upstream in upstreams:
        if upstream.get("checked") and upstream.get("reachable") is not True:
            findings.append(
                {
                    "severity": "warning",
                    "type": "upstream_unreachable",
                    "message": f"upstream {upstream.get('name') or upstream.get('url')} is not reachable",
                }
            )
    if tunnel.get("configured") and tunnel.get("checked") and tunnel.get("ok") is False:
        findings.append({"severity": "error", "type": "tunnel_doctor_failed", "message": "last tunnel doctor failed"})
    if traffic.get("blocked", 0):
        findings.append(
            {
                "severity": "warning",
                "type": "blocked_requests",
                "message": f"{traffic.get('blocked')} blocked requests observed",
            }
        )
    risky_tools = [item for item in _sequence(traffic.get("tools")) if _risky_tool_name(str(item.get("value", "")))]
    if risky_tools:
        findings.append(
            {
                "severity": "warning",
                "type": "risky_tools_observed",
                "message": "risky tool-like names observed: "
                + ", ".join(str(item.get("value")) for item in risky_tools[:5]),
            }
        )
    if policy.get("lifecycle_state") not in {None, "active"}:
        findings.append(
            {
                "severity": "info",
                "type": "policy_not_active",
                "message": f"policy lifecycle state is {policy.get('lifecycle_state')}",
            }
        )
    inspection = _mapping(traffic.get("inspection"))
    for finding in _sequence(inspection.get("findings")):
        if isinstance(finding, Mapping):
            findings.append(dict(finding))
    return findings


def _share_report_lines(result: Mapping[str, Any], *, title: str) -> list[str]:
    session = _mapping(result.get("session"))
    gateway = _mapping(result.get("gateway"))
    tunnel = _mapping(result.get("tunnel_doctor"))
    policy = _mapping(result.get("policy"))
    members = _mapping(result.get("members"))
    amendments = _mapping(result.get("amendments"))
    traffic = _mapping(result.get("traffic"))
    recordings = _mapping(result.get("recordings"))
    leases = _mapping(result.get("leases"))
    lines = [
        title,
        "",
        "## Overview",
        "",
        f"- Share: `{result.get('directory')}`",
        f"- State: `{result.get('state')}`",
        f"- Provider: `{session.get('provider')}`",
        f"- Public URL: `{tunnel.get('public_url') or _mapping(result.get('client')).get('url') or '-'}`",
        f"- Local gateway: `{gateway.get('url') or '-'}`",
        f"- Gateway reachable: `{_yes_no_unknown(gateway.get('reachable'))}`",
        "",
        "## Upstreams",
        "",
    ]
    upstreams = _sequence(result.get("upstreams"))
    if upstreams:
        for upstream in upstreams:
            if isinstance(upstream, Mapping):
                lines.append(
                    f"- `{upstream.get('name') or 'upstream'}` {upstream.get('transport') or 'http'} "
                    f"`{upstream.get('url') or '-'}` reachable=`{_yes_no_unknown(upstream.get('reachable'))}`"
                )
    else:
        lines.append("- None configured")
    lines.extend(["", "## Members", ""])
    attachments = [item for item in _sequence(members.get("attachments")) if isinstance(item, Mapping)]
    if attachments:
        lines.append(f"- Registry: `{members.get('registry') or '-'}`")
        lines.append(f"- Discovery provider: `{members.get('discovery_provider') or '-'}`")
        for attachment in attachments:
            lines.append(
                "- "
                f"`{attachment.get('member_id')}` kind=`{attachment.get('kind') or '-'}` "
                f"status=`{attachment.get('status') or '-'}` "
                f"upstreams=`{len(_sequence(attachment.get('upstreams')))}`"
            )
    else:
        lines.append("- None attached")
    lines.extend(
        [
            "",
            "## Tunnel",
            "",
            f"- Configured: `{_yes_no_unknown(tunnel.get('configured'))}`",
            f"- Last doctor checked: `{tunnel.get('last_checked_at') or '-'}`",
            f"- Last doctor ok: `{_yes_no_unknown(tunnel.get('ok'))}`",
            "",
            "## Policy",
            "",
            f"- Bundle: `{policy.get('bundle') or '-'}`",
            f"- Active policy: `{policy.get('active_policy') or '-'}`",
            f"- Lifecycle: `{policy.get('lifecycle_state') or 'observed'}`",
            f"- Signed: `{_yes_no_unknown(policy.get('lifecycle_signed'))}`",
            f"- Last lifecycle action: `{_share_last_lifecycle_label(policy)}`",
            "",
            "## Policy Amendments",
            "",
            f"- Last amendment: `{amendments.get('last') or '-'}`",
            f"- Proposed candidates: `{amendments.get('candidate_count', 0)}`",
            "",
            "## Traffic",
            "",
            f"- Events: `{traffic.get('event_count', 0)}`",
            f"- Allowed: `{traffic.get('allowed', 0)}`",
            f"- Blocked: `{traffic.get('blocked', 0)}`",
            f"- Confirmed: `{traffic.get('confirmed', 0)}`",
            f"- Confirmed approved: `{traffic.get('confirmation_approved', 0)}`",
            f"- Confirmed denied: `{traffic.get('confirmation_denied', 0)}`",
            f"- Secrets redacted events: `{traffic.get('redacted_events', 0)}`",
            f"- Response redactions: `{traffic.get('response_redacted', 0)}`",
            "",
            "### Tools",
            "",
            *_count_lines(traffic.get("tools")),
            "",
            "### Clients / Sources",
            "",
            *_count_lines(traffic.get("clients")),
            *_count_lines(traffic.get("source_ips"), label="source ip"),
            "",
            "## Leases",
            "",
            f"- File: `{leases.get('file') or '-'}`",
            f"- Active leases: `{leases.get('active_count', 0)}`",
            "",
            "## Recordings",
            "",
            f"- Replay log: `{_mapping(recordings.get('record_log')).get('path') or '-'}` "
            f"exists=`{_yes_no_unknown(_mapping(recordings.get('record_log')).get('exists'))}`",
            f"- Audit log: `{_mapping(recordings.get('audit_log')).get('path') or '-'}` "
            f"exists=`{_yes_no_unknown(_mapping(recordings.get('audit_log')).get('exists'))}`",
            "",
            "## Findings",
            "",
        ]
    )
    findings = _sequence(result.get("findings"))
    if findings:
        for finding in findings:
            if isinstance(finding, Mapping):
                message = finding.get("message", finding.get("count", ""))
                lines.append(f"- `{finding.get('severity', 'info')}` {finding.get('type')}: {message}")
    else:
        lines.append("- None")
    commands = _mapping(result.get("commands"))
    if commands:
        lines.extend(["", "## Next Commands", ""])
        for name in ("run", "doctor", "client", "close", "inspect_audit", "inspect_session"):
            command = commands.get(name)
            if isinstance(command, str):
                lines.append(f"- `{name}`: `{command}`")
    return lines


def _probe_mcp_url(url: str, *, headers: Mapping[str, Any], timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"reachable": False, "status": None, "error": f"unsupported URL: {url}"}
    body = json.dumps({"jsonrpc": "2.0", "id": "snulbug-share-status", "method": "tools/list", "params": {}})
    request_headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "snulbug-share-status",
        **{str(key): str(value) for key, value in headers.items()},
    }
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request("POST", _request_target(parsed), body=body, headers=request_headers)
        response = connection.getresponse()
        response.read()
        return {
            "reachable": True,
            "status": int(response.status),
            "error": None,
            "mcp_ok": 200 <= int(response.status) < 300,
        }
    except Exception as exc:
        return {"reachable": False, "status": None, "error": str(exc), "mcp_ok": False}
    finally:
        connection.close()


def _request_target(parsed: SplitResult) -> str:
    path = parsed.path or "/"
    return f"{path}?{parsed.query}" if parsed.query else path


def _load_share_events(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, Mapping):
                continue
            if value.get("type") == "snulbug.request_record":
                events.append(build_audit_event(value))
            else:
                events.append(dict(value))
    return events


def _count_if(counter: Counter[str], value: Any) -> None:
    if value is not None and value != "":
        counter[str(value)] += 1


def _counter_entries(counter: Counter[str]) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(10)]


def _event_has_redaction_marker(event: Mapping[str, Any]) -> bool:
    try:
        return SECRET_REPLACEMENT in json.dumps(event, sort_keys=True, default=str)
    except TypeError:
        return False


def _count_lines(values: Any, *, label: str = "item") -> list[str]:
    entries = _sequence(values)
    if not entries:
        return ["- None"]
    lines = []
    for item in entries:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('value') or label}`: `{item.get('count', 0)}`")
    return lines or ["- None"]


def _risky_tool_name(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    return any(term in normalized for term in ("shell", "exec", "command", "terminal", "subprocess", "spawn"))


def _yes_no_unknown(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _share_last_lifecycle_label(policy: Mapping[str, Any]) -> str:
    lifecycle = _mapping(policy.get("last_lifecycle"))
    if not lifecycle:
        return "-"
    action = lifecycle.get("action") or "lifecycle"
    from_state = lifecycle.get("from_state") or "?"
    to_state = lifecycle.get("to_state") or lifecycle.get("state") or "?"
    return f"{action} {from_state}->{to_state}"


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
    directory: str | Path = ".",
    *,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Run the proxy for a generated MCP share session."""

    context = _share_run_context(directory)
    share_dir = context["share_dir"]
    manifest = context["manifest"]
    session_model = context["session_model"]
    commands = context["commands"]
    resolved_paths = context["resolved_paths"]
    config_path = resolved_paths.get("config")
    if not isinstance(config_path, Path):
        raise ValueError("share session does not contain an active config path")
    if not config_path.is_file():
        raise FileNotFoundError(f"share config not found: {config_path}")
    if dry_run:
        return {
            "ok": True,
            "share": str(share_dir),
            "state": context["state"],
            "source": context["source"],
            "session_model_path": str(context["session_model_path"]),
            "resolved_paths": {key: str(value) for key, value in resolved_paths.items() if isinstance(value, Path)},
            "commands": commands,
        }

    from .config import load_mcp_fabric_config, load_mcp_proxy_config
    from .proxy import run_mcp_proxy_config

    proxy_config = load_mcp_proxy_config(config_path)
    proxy_config = _reconcile_proxy_config_with_share_session(proxy_config, resolved_paths)
    fabric_config = load_mcp_fabric_config(config_path)
    fabric_config["proxy"] = proxy_config
    runtime = {
        "started_at": _now_iso(),
        "config": str(config_path),
        "source": context["source"],
        "resolved_paths": {key: str(value) for key, value in resolved_paths.items() if isinstance(value, Path)},
    }
    if manifest is not None:
        _update_share_manifest(share_dir, state="running", runtime=runtime)
        _update_share_session_runtime(share_dir, session_model, runtime=runtime)
    else:
        _update_share_session_runtime(share_dir, session_model, runtime=runtime)
    run_mcp_proxy_config(proxy_config, fabric_config)
    return None


def _share_run_context(directory: str | Path) -> dict[str, Any]:
    share_dir = Path(directory)
    manifest_path = share_dir / SHARE_MANIFEST
    model_path = share_session_model_path(share_dir)
    manifest = load_mcp_share(share_dir) if manifest_path.is_file() else None
    session_model = load_share_session_model(share_dir) if model_path.is_file() else None
    if session_model is None and manifest is not None:
        session_model = build_share_session_model(manifest, directory=share_dir)
    if session_model is None:
        raise FileNotFoundError(f"share session model not found: {model_path}")
    source = "session_model" if model_path.is_file() else "manifest"
    commands = _mapping(manifest.get("commands")) if manifest is not None else {}
    state = _mapping(session_model.get("status")).get("state") or (
        manifest.get("state", "created") if manifest is not None else "created"
    )
    return {
        "share_dir": share_dir,
        "manifest": manifest,
        "session_model": session_model,
        "session_model_path": model_path,
        "source": source,
        "state": state,
        "commands": commands,
        "resolved_paths": _share_run_resolved_paths(share_dir, session_model, manifest),
    }


def _load_share_model_context(directory: str | Path) -> tuple[Path, dict[str, Any] | None, dict[str, Any]]:
    share_dir = Path(directory)
    manifest_path = share_dir / SHARE_MANIFEST
    model_path = share_session_model_path(share_dir)
    manifest = load_mcp_share(share_dir) if manifest_path.is_file() else None
    if model_path.is_file():
        session_model = load_share_session_model(share_dir)
    elif manifest is not None:
        session_model = build_share_session_model(manifest, directory=share_dir)
    else:
        raise FileNotFoundError(f"share session model not found: {model_path}")
    return share_dir, manifest, session_model


def _share_policy_bundle_path(
    share_dir: Path,
    session_model: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> Path:
    files = _mapping(manifest.get("files")) if manifest is not None else {}
    policy = _mapping(session_model.get("policy"))
    paths = _mapping(session_model.get("paths"))
    value = policy.get("bundle") or paths.get("policy_bundle") or files.get("policy")
    if not isinstance(value, str) or not value:
        raise ValueError("share session does not contain an active policy bundle")
    bundle = _resolve_share_path(share_dir, value)
    if not bundle.is_dir():
        raise FileNotFoundError(f"share policy bundle not found: {bundle}")
    return bundle


def _record_share_policy_lifecycle(
    share_dir: Path,
    manifest: Mapping[str, Any] | None,
    session_model: Mapping[str, Any],
    *,
    lifecycle: Mapping[str, Any],
) -> dict[str, Any]:
    if manifest is not None:
        updated_manifest = dict(manifest)
        policy = dict(_mapping(updated_manifest.get("policy")))
        policy["last_lifecycle"] = dict(lifecycle)
        updated_manifest["policy"] = policy
        updated_manifest["updated_at"] = _now_iso()
        (share_dir / SHARE_MANIFEST).write_text(
            json.dumps(updated_manifest, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        return update_share_session_model(share_dir, manifest=updated_manifest)

    model = json.loads(json.dumps(dict(session_model), default=str))
    status = dict(_mapping(model.get("status")))
    status["updated_at"] = _now_iso()
    model["status"] = status
    policy = dict(_mapping(model.get("policy")))
    policy["lifecycle_state"] = lifecycle.get("state")
    policy["lifecycle_signed"] = lifecycle.get("signed")
    policy["lifecycle_signature"] = lifecycle.get("signature")
    policy["last_lifecycle"] = dict(lifecycle)
    model["policy"] = policy
    write_share_session_model(share_dir, model, force=True)
    return model


def _share_config_path(
    share_dir: Path,
    manifest: Mapping[str, Any] | None,
    session_model: Mapping[str, Any],
) -> Path:
    files = _mapping(manifest.get("files")) if manifest is not None else {}
    gateway = _mapping(session_model.get("gateway"))
    paths = _mapping(session_model.get("paths"))
    value = gateway.get("config") or paths.get("config") or paths.get("fabric_config") or files.get("config")
    if not isinstance(value, str) or not value:
        raise ValueError("share session does not contain an active config path")
    config = _resolve_share_path(share_dir, value)
    if not config.is_file():
        raise FileNotFoundError(f"share config not found: {config}")
    return config


def _load_share_member_metadata(path: str | Path) -> dict[str, Any]:
    metadata_path = Path(path)
    with metadata_path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    if not isinstance(loaded, Mapping):
        raise ValueError(f"share member metadata must contain a JSON object: {metadata_path}")
    return dict(loaded)


def _share_member_attach_payload(
    document: Mapping[str, Any],
    *,
    member_id: str | None,
    kind: str,
    upstreams: Sequence[Mapping[str, Any]],
    role: str,
    status: str,
    ttl_seconds: float,
    labels: Mapping[str, str] | None,
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    resolved_kind = str(document.get("kind") or kind).replace("_", "-")
    if resolved_kind not in SHARE_MEMBER_KINDS:
        raise ValueError(f"share member kind must be one of: {', '.join(SHARE_MEMBER_KINDS)}")
    resolved_member_id = member_id or document.get("member_id") or document.get("id")
    if not isinstance(resolved_member_id, str) or not resolved_member_id.strip():
        raise ValueError("share attach requires --member-id or metadata member_id")
    resolved_role = str(document.get("role") or role).replace("-", "_")
    resolved_status = str(document.get("status") or status).replace("-", "_")
    resolved_ttl = float(document.get("ttl_seconds") or ttl_seconds)
    resolved_upstreams = _normalize_share_member_upstreams(upstreams or _sequence(document.get("upstreams")))
    resolved_labels = {
        **_string_mapping(_mapping(document.get("labels"))),
        **_string_mapping(labels or {}),
        "snulbug.member.kind": resolved_kind,
    }
    resolved_metadata = {
        **dict(_mapping(document.get("metadata"))),
        **dict(metadata or {}),
        "kind": resolved_kind,
        "attached_by": "snulbug mcp share attach",
        "attached_at": _now_iso(),
    }
    for field in ("codespace", "devcontainer", "container", "holepunch"):
        if field in document and field not in resolved_metadata:
            resolved_metadata[field] = document[field]
    return {
        "member_id": resolved_member_id,
        "kind": resolved_kind,
        "role": resolved_role,
        "status": resolved_status,
        "ttl_seconds": resolved_ttl,
        "upstreams": resolved_upstreams,
        "labels": resolved_labels,
        "metadata": resolved_metadata,
    }


def _normalize_share_member_upstreams(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    upstreams = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise ValueError(f"share member upstreams[{index}] must be a table")
        item = {str(key): _jsonish_copy(item_value) for key, item_value in value.items() if item_value is not None}
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"share member upstreams[{index}].name must be a non-empty string")
        if not any(key in item for key in ("url", "command", "local_port", "peer", "bridge_config")):
            raise ValueError(
                f"share member upstreams[{index}] must define url, command, local_port, peer, or bridge_config"
            )
        item.setdefault("tool_prefix", f"{name}.")
        upstreams.append(item)
    return upstreams


def _share_member_metadata_document(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty_json(
        {
            "member_id": payload.get("member_id"),
            "kind": payload.get("kind"),
            "role": payload.get("role"),
            "status": payload.get("status"),
            "ttl_seconds": payload.get("ttl_seconds"),
            "labels": payload.get("labels"),
            "metadata": payload.get("metadata"),
            "upstreams": payload.get("upstreams"),
        }
    )


def _share_member_registry(share_dir: Path, registry: str | Path | None) -> str | Path:
    if registry is None:
        return share_dir / DEFAULT_SHARE_MEMBER_REGISTRY
    if _looks_like_state_registry(registry):
        return str(registry)
    return _resolve_share_path(share_dir, registry)


def _ensure_share_member_discovery_provider(
    config_path: Path,
    *,
    registry: str | Path,
    registry_key: str,
    discovery_name: str,
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"ok": True, "updated": False, "reason": "config_update_disabled", "provider": discovery_name}
    text = config_path.read_text(encoding="utf-8")
    if _toml_provider_name_exists(text, discovery_name):
        return {"ok": True, "updated": False, "reason": "provider_exists", "provider": discovery_name}
    block = _share_member_discovery_provider_toml(
        config_path,
        registry=registry,
        registry_key=registry_key,
        discovery_name=discovery_name,
        include_table="[mcp.fabric.discovery]" not in text,
    )
    suffix = "" if text.endswith("\n") else "\n"
    config_path.write_text(text + suffix + block, encoding="utf-8")
    return {
        "ok": True,
        "updated": True,
        "provider": discovery_name,
        "config": str(config_path),
        "registry": str(registry),
        "registry_key": registry_key,
    }


def _share_member_discovery_provider_toml(
    config_path: Path,
    *,
    registry: str | Path,
    registry_key: str,
    discovery_name: str,
    include_table: bool,
) -> str:
    registry_field, registry_value, key_field = _share_member_registry_provider_fields(
        config_path.parent,
        registry,
    )
    lines = ["# Remote members attached by `snulbug mcp share attach`."]
    if include_table:
        lines.extend(["[mcp.fabric.discovery]", "enabled = true", ""])
    lines.extend(
        [
            "[[mcp.fabric.discovery.providers]]",
            f"name = {_toml_string(discovery_name)}",
            'type = "members"',
            "enabled = true",
            f"{registry_field} = {_toml_string(registry_value)}",
            f"{key_field} = {_toml_string(registry_key)}",
            "",
        ]
    )
    return "\n".join(lines)


def _share_member_registry_provider_fields(config_dir: Path, registry: str | Path) -> tuple[str, str, str]:
    if _looks_like_state_registry(registry):
        return "state", str(registry), "state_key"
    path = Path(registry)
    return "path", _display_path_relative_to(config_dir, path), "registry_key"


def _share_member_attachment(
    *,
    payload: Mapping[str, Any],
    registered: Mapping[str, Any],
    registry: str | Path,
    registry_key: str,
    discovery_name: str,
    config_path: Path,
    discovery: Mapping[str, Any],
) -> dict[str, Any]:
    member = _mapping(registered.get("member"))
    return _drop_empty_json(
        {
            "member_id": member.get("id") or payload.get("member_id"),
            "kind": payload.get("kind"),
            "role": member.get("role") or payload.get("role"),
            "status": member.get("status") or payload.get("status"),
            "registry": str(registry),
            "registry_key": registry_key,
            "discovery_provider": discovery_name,
            "config": str(config_path),
            "config_updated": discovery.get("updated"),
            "attached_at": _now_iso(),
            "labels": payload.get("labels"),
            "metadata": payload.get("metadata"),
            "upstreams": member.get("upstreams") or payload.get("upstreams"),
            "expires_at": member.get("expires_at"),
        }
    )


def _record_share_member_attachment(
    share_dir: Path,
    manifest: Mapping[str, Any] | None,
    session_model: Mapping[str, Any],
    *,
    attachment: Mapping[str, Any],
    registry: str | Path,
    registry_key: str,
    discovery_name: str,
) -> dict[str, Any]:
    if manifest is not None:
        updated_manifest = json.loads(json.dumps(dict(manifest), default=str))
        files = dict(_mapping(updated_manifest.get("files")))
        if not _looks_like_state_registry(registry):
            files["member_registry"] = str(registry)
        updated_manifest["files"] = files
        updated_manifest["members"] = _updated_share_members(
            _mapping(updated_manifest.get("members")),
            attachment=attachment,
            registry=registry,
            registry_key=registry_key,
            discovery_name=discovery_name,
        )
        updated_manifest["updated_at"] = _now_iso()
        (share_dir / SHARE_MANIFEST).write_text(
            json.dumps(updated_manifest, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        return update_share_session_model(share_dir, manifest=updated_manifest)

    model = json.loads(json.dumps(dict(session_model), default=str))
    status = dict(_mapping(model.get("status")))
    status["updated_at"] = _now_iso()
    model["status"] = status
    paths = dict(_mapping(model.get("paths")))
    if not _looks_like_state_registry(registry):
        paths["member_registry"] = str(registry)
    model["paths"] = paths
    model["members"] = _updated_share_members(
        _mapping(model.get("members")),
        attachment=attachment,
        registry=registry,
        registry_key=registry_key,
        discovery_name=discovery_name,
    )
    write_share_session_model(share_dir, model, force=True)
    return model


def _updated_share_members(
    current: Mapping[str, Any],
    *,
    attachment: Mapping[str, Any],
    registry: str | Path,
    registry_key: str,
    discovery_name: str,
) -> dict[str, Any]:
    member_id = str(attachment.get("member_id"))
    attachments = [
        dict(item)
        for item in _sequence(current.get("attachments"))
        if isinstance(item, Mapping) and str(item.get("member_id")) != member_id
    ]
    attachments.append(dict(attachment))
    return {
        "registry": str(registry),
        "registry_key": registry_key,
        "discovery_provider": discovery_name,
        "attachments": sorted(attachments, key=lambda item: str(item.get("member_id", ""))),
    }


def _share_run_resolved_paths(
    share_dir: Path,
    session_model: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> dict[str, Path | None]:
    files = _mapping(manifest.get("files")) if manifest is not None else {}
    gateway = _mapping(session_model.get("gateway"))
    policy = _mapping(session_model.get("policy"))
    lease = _mapping(session_model.get("lease"))
    evidence = _mapping(session_model.get("evidence"))
    paths = _mapping(session_model.get("paths"))
    return {
        "config": _resolve_optional_share_path(
            share_dir,
            gateway.get("config") or paths.get("config") or paths.get("fabric_config") or files.get("config"),
        ),
        "policy": _resolve_optional_share_path(
            share_dir,
            policy.get("active_policy") or paths.get("active_policy") or files.get("policy_file"),
        ),
        "policy_bundle": _resolve_optional_share_path(
            share_dir,
            policy.get("bundle") or paths.get("policy_bundle") or files.get("policy"),
        ),
        "lease_file": _resolve_optional_share_path(
            share_dir,
            lease.get("file") or paths.get("lease_file") or files.get("lease_file"),
        ),
        "record_log": _resolve_optional_share_path(
            share_dir,
            evidence.get("record_log") or paths.get("record_log") or files.get("session_log"),
        ),
        "audit_log": _resolve_optional_share_path(
            share_dir,
            evidence.get("audit_log") or paths.get("audit_log") or files.get("audit_log"),
        ),
    }


def _reconcile_proxy_config_with_share_session(
    proxy_config: Mapping[str, Any],
    resolved_paths: Mapping[str, Path | None],
) -> dict[str, Any]:
    reconciled = dict(proxy_config)
    if resolved_paths.get("policy") is not None:
        reconciled["policy"] = resolved_paths["policy"]
    if resolved_paths.get("lease_file") is not None:
        reconciled["lease_file"] = resolved_paths["lease_file"]
    if resolved_paths.get("record_log") is not None:
        reconciled["record_out"] = resolved_paths["record_log"]
    if resolved_paths.get("audit_log") is not None:
        reconciled["event_sinks"] = _reconcile_audit_event_sink(
            _sequence(reconciled.get("event_sinks")),
            resolved_paths["audit_log"],
        )
    return reconciled


def _reconcile_audit_event_sink(event_sinks: Sequence[Any], audit_log: Path | None) -> list[dict[str, Any]]:
    if audit_log is None:
        return [dict(sink) for sink in event_sinks if isinstance(sink, Mapping)]
    reconciled = []
    replaced = False
    for sink in event_sinks:
        if not isinstance(sink, Mapping):
            continue
        item = dict(sink)
        if item.get("type") == "audit_jsonl":
            item["path"] = audit_log
            replaced = True
        reconciled.append(item)
    if not replaced:
        reconciled.append({"type": "audit_jsonl", "path": audit_log})
    return reconciled


def _update_share_session_runtime(
    share_dir: Path,
    session_model: Mapping[str, Any],
    *,
    runtime: Mapping[str, Any],
) -> None:
    model = json.loads(json.dumps(dict(session_model), default=str))
    status = dict(_mapping(model.get("status")))
    status["state"] = "running"
    status["updated_at"] = _now_iso()
    model["status"] = status
    model["runtime"] = dict(runtime)
    write_share_session_model(share_dir, model, force=True)


def _resolve_optional_share_path(share_dir: Path, value: Any) -> Path | None:
    if value in (None, ""):
        return None
    return _resolve_share_path(share_dir, value)


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
    health: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = load_mcp_share(share_dir)
    if state is not None:
        manifest["state"] = state
    manifest["updated_at"] = _now_iso()
    if runtime is not None:
        manifest["runtime"] = dict(runtime)
    if closeout is not None:
        manifest["closeout"] = dict(closeout)
    if health is not None:
        manifest["health"] = dict(health)
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


def _display_path_relative_to(base: Path, path: Path) -> str:
    if not path.is_absolute():
        return str(path)
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return str(path)


def _looks_like_state_registry(value: str | Path) -> bool:
    if isinstance(value, Path):
        return False
    text = str(value)
    return text == "memory" or text.startswith(("sqlite:", "redis:", "redis://", "rediss://"))


def _toml_provider_name_exists(text: str, name: str) -> bool:
    quoted = _toml_string(name)
    return f"name = {quoted}" in text and 'type = "members"' in text


def _toml_string(value: Any) -> str:
    return json.dumps(str(value))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    return []


def _string_mapping(value: Mapping[str, Any] | None) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}


def _jsonish_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except TypeError:
        return str(value)


def _drop_empty_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {str(key): _drop_empty_json(item) for key, item in value.items()}
        return {key: item for key, item in result.items() if item not in ({}, [], None)}
    if isinstance(value, list):
        return [_drop_empty_json(item) for item in value]
    return value


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

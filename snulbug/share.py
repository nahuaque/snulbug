from __future__ import annotations

import base64
import hashlib
import hmac
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
from .runtime import compile_lua_file
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
from .share_doctor import (
    ShareDoctorCheck,
    ShareDoctorCheckResult,
    ShareDoctorContext,
    register_share_doctor_check,
    run_share_doctor_checks,
)
from .share_session import (
    SHARE_SESSION_MODEL_PATH,
    build_share_session_model,
    load_share_session_model,
    share_session_model_path,
    update_share_session_model,
    write_share_session_model,
)
from .simulator import normalize_request
from .tool_risk import classify_mcp_tool_risks
from .tunnel import (
    DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME,
    get_tunnel_provider,
    init_tunnel_provider,
    list_tunnel_providers,
)

DEFAULT_SHARE_PROVIDER = "holepunch"
DEFAULT_SHARE_PRESET = "tunnel-safe"
DEFAULT_SHARE_TTL = "30m"
DEFAULT_SHARE_DIR = Path(".snulbug") / "shares"
DEFAULT_SHARE_CLIENT_NAME = "snulbug-share"
DEFAULT_SHARE_TOKEN_ENV = "SNULBUG_SHARE_TOKEN"
DEFAULT_SHARE_INVITE_CAPABILITIES = ("project_readonly",)
DEFAULT_CONTAINER_RECIPE_DIR = "containers"
SHARE_MANIFEST = "share.json"
CONTAINER_BIND_HOST = ".".join(("0", "0", "0", "0"))
CONTAINER_REMOTE_BRIDGE_PORT = 19100
DEFAULT_SHARE_MEMBER_REGISTRY = Path(".snulbug") / "fabric-members.json"
DEFAULT_SHARE_MEMBER_DISCOVERY_PROVIDER = "share-members"
SHARE_MEMBER_KINDS = ("codespaces", "devcontainer", "holepunch", "container", "generic")
MCP_INSPECTOR_PACKAGE = "@modelcontextprotocol/inspector"
SHARE_INVITE_SCHEMA = "snulbug.share.invite.v1"
AUTH_CONFORMANCE_SCHEMA = "snulbug.auth-conformance-pack.v1"
AUTH_CONFORMANCE_VERSION = 1
SHARE_CONTRACT_SCHEMA = "snulbug.share-contract.v1"
SHARE_CONTRACT_VERSION = 1
SHARE_CONTRACT_SIGNATURE_FIELD = "snulbug_signature"
SHARE_CONTRACT_ALGORITHM = "hmac-sha256"
CAPABILITY_REQUEST_REVIEW_PATH = Path(".snulbug") / "share" / "capability-requests.json"
SHARE_INVITE_SECRET_STORE_PATH = Path(".snulbug") / "share" / "invite-secrets.json"
CAPABILITY_MATCH_ALLOWED_ACTIONS = {"continue", "set_context", "rewrite", "respond", "rate_limit"}


def create_mcp_share(
    directory: str | Path | None = None,
    *,
    provider: str = DEFAULT_SHARE_PROVIDER,
    preset: str = DEFAULT_SHARE_PRESET,
    upstream: str = "http://127.0.0.1:9000",
    hostname: str | None = None,
    public_url: str | None = None,
    ngrok_internal_url: str | None = None,
    ngrok_endpoint_name: str = DEFAULT_NGROK_INTERNAL_ENDPOINT_NAME,
    cloudflare_profile: str | None = None,
    tailscale_profile: str | None = None,
    auth_issuer: str | None = None,
    auth_resource: str | None = None,
    auth_audience: str | None = None,
    auth_required_scopes: Sequence[str] | None = None,
    auth_jwks_url: str | None = None,
    auth_token_validation: str = "jwt",
    cloudflare_access_allowed_emails: Sequence[str] | None = None,
    cloudflare_access_allowed_domains: Sequence[str] | None = None,
    cloudflare_access_team_domain: str | None = None,
    cloudflare_access_issuer: str | None = None,
    cloudflare_access_audience: str | None = None,
    cloudflare_access_certs_url: str | None = None,
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

    try:
        provider = get_tunnel_provider(provider).name
    except ValueError as exc:
        raise ValueError(f"provider must be one of: {', '.join(list_tunnel_providers())}") from exc
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
        ngrok_internal_url=ngrok_internal_url,
        ngrok_endpoint_name=ngrok_endpoint_name,
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
        cloudflare_profile=cloudflare_profile,
        tailscale_profile=tailscale_profile,
        auth_issuer=auth_issuer,
        auth_resource=auth_resource,
        auth_audience=auth_audience,
        auth_required_scopes=auth_required_scopes,
        auth_jwks_url=auth_jwks_url,
        auth_token_validation=auth_token_validation,
        cloudflare_access_allowed_emails=cloudflare_access_allowed_emails,
        cloudflare_access_allowed_domains=cloudflare_access_allowed_domains,
        cloudflare_access_team_domain=cloudflare_access_team_domain,
        cloudflare_access_issuer=cloudflare_access_issuer,
        cloudflare_access_audience=cloudflare_access_audience,
        cloudflare_access_certs_url=cloudflare_access_certs_url,
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
        hostname=hostname,
        ngrok_internal_url=ngrok_internal_url,
        ngrok_endpoint_name=ngrok_endpoint_name,
        token_env=DEFAULT_SHARE_TOKEN_ENV,
        output_dir=share_dir / "tunnel",
        doctor_command=f"uv run snulbug mcp share doctor {shlex.quote(str(share_dir))}",
        force=force,
    )

    client_headers = {
        "Authorization": f"Bearer {bearer_token}",
        lease_header: lease["token"],
    }
    cloudflare_headers = _mapping(quickstart.get("cloudflare")).get("client_headers")
    if isinstance(cloudflare_headers, Mapping):
        client_headers.update({str(key): str(value) for key, value in cloudflare_headers.items()})
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
        client_extra_headers={key: value for key, value in client_headers.items() if key.startswith("CF-Access-")},
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
                "cloudflare_access_profile": _mapping(quickstart.get("cloudflare")).get("profile"),
                "tailscale_profile": _mapping(quickstart.get("tailscale")).get("profile"),
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
            "cloudflare_access_profile": _mapping(quickstart.get("cloudflare")).get("profile"),
            "tailscale_profile": _mapping(quickstart.get("tailscale")).get("profile"),
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
    include_contract: bool = True,
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
    public_gateway = _share_public_gateway_status(manifest, session_model, timeout=timeout, live_checks=live_checks)
    gateway = _share_gateway_status(share_dir, manifest, session_model, timeout=timeout, live_checks=live_checks)
    upstreams = _share_upstream_statuses(share_dir, manifest, timeout=timeout, live_checks=live_checks)
    traffic = _share_traffic_summary(share_dir, session_model)
    capability_requests = share_capability_requests(share_dir, status="all")
    schema_catalogs = _share_schema_catalog_context(share_dir, manifest, session_model)
    tool_risks = classify_mcp_tool_risks(_share_tool_risk_inputs(traffic.get("tools"), schema_catalogs))
    tool_risks["schema_catalogs"] = _share_schema_catalog_status(schema_catalogs)
    recordings = _share_recordings_status(share_dir, session_model)
    policy = _mapping(session_model.get("policy"))
    members = _mapping(session_model.get("members"))
    invitations = _share_invitation_connection_statuses(
        share_dir,
        session_model,
        _mapping(session_model.get("invitations")),
        lease_status,
    )
    amendments = _share_amendment_status(session_model)
    tunnel = _share_tunnel_status(manifest, session_model)
    contract = _share_contract_status(share_dir, manifest, session_model) if include_contract else {}
    findings = _share_findings(
        gateway=gateway,
        upstreams=upstreams,
        traffic=traffic,
        tool_risks=tool_risks,
        tunnel=tunnel,
        policy=policy,
        contract=contract,
    )
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
        "public_gateway": public_gateway,
        "gateway": gateway,
        "upstreams": upstreams,
        "tunnel_doctor": tunnel,
        "policy": policy,
        "members": members,
        "invitations": invitations,
        "amendments": amendments,
        "contract": contract,
        "traffic": traffic,
        "capability_requests": capability_requests["summary"],
        "tool_risks": tool_risks,
        "schemas": _share_schema_catalog_status(schema_catalogs),
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


def share_contract(
    directory: str | Path,
    *,
    output: str | Path | None = None,
    timeout: float = 1.0,
    live_checks: bool = False,
    include_doctor: bool = False,
    public_url: str | None = None,
    conformance_pack: str | Path | None = None,
    require_conformance: bool = False,
    sign: bool = False,
    secret: str | None = None,
    key_id: str = "local-share",
    force: bool = False,
) -> dict[str, Any]:
    """Generate a secret-light contract describing what a share exposes."""

    share_dir = Path(directory)
    doctor: dict[str, Any] | None = None
    if include_doctor:
        doctor = doctor_mcp_share(
            share_dir,
            timeout=timeout,
            public_url=public_url,
            live_checks=live_checks,
            conformance_pack=conformance_pack,
            require_conformance=require_conformance,
        )
    elif public_url:
        _update_share_client_url(share_dir, public_url)

    manifest = load_mcp_share(share_dir)
    status = share_status(share_dir, timeout=timeout, live_checks=live_checks, include_contract=False)
    proxy_summary = _share_contract_proxy_summary(share_dir, manifest)
    contract = _finalize_share_contract(
        _share_contract_payload(
            share_dir=share_dir,
            manifest=manifest,
            status=status,
            proxy_summary=proxy_summary,
            doctor=doctor,
        ),
        sign=sign,
        secret=secret,
        key_id=key_id,
    )

    output_path = Path(output) if output is not None else None
    if output_path is not None:
        if output_path.exists() and not force:
            raise FileExistsError(f"share contract already exists: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if (share_dir / SHARE_MANIFEST).is_file():
            _record_share_contract(share_dir, contract, path=output_path, required=False)

    ok = bool(status.get("ok", False)) and (doctor is None or bool(doctor.get("ok", False)))
    return {
        "ok": ok,
        "share": str(share_dir),
        "path": str(output_path) if output_path is not None else None,
        "digest": contract.get("digest"),
        "signed": SHARE_CONTRACT_SIGNATURE_FIELD in contract,
        "contract": contract,
    }


def load_share_contract(path: str | Path) -> dict[str, Any]:
    """Load and validate a generated share contract JSON file."""

    contract_path = Path(path)
    with contract_path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, Mapping):
        raise ValueError(f"share contract must contain a JSON object: {contract_path}")
    contract = dict(value)
    if contract.get("schema") != SHARE_CONTRACT_SCHEMA:
        raise ValueError(f"unsupported share contract schema: {contract.get('schema')!r}")
    expected_binding_digest = _share_contract_binding_digest(contract)
    binding_digest = contract.get("binding_digest")
    if binding_digest is None:
        contract["binding_digest"] = expected_binding_digest
    elif binding_digest != expected_binding_digest:
        raise ValueError(
            f"share contract binding digest mismatch: expected {expected_binding_digest}, found {binding_digest}"
        )
    expected_digest = _share_contract_digest(contract)
    digest = contract.get("digest")
    if digest != expected_digest:
        raise ValueError(f"share contract digest mismatch: expected {expected_digest}, found {digest}")
    return contract


def share_contract_runtime_metadata(
    contract: Mapping[str, Any],
    *,
    path: str | Path | None = None,
    required: bool = True,
    verified: bool = True,
) -> dict[str, Any]:
    """Return audit/status-safe metadata for a contract-bound runtime."""

    signature = _mapping(contract.get(SHARE_CONTRACT_SIGNATURE_FIELD))
    return _drop_empty_json(
        {
            "contract_digest": contract.get("binding_digest") or contract.get("digest"),
            "contract_binding_digest": contract.get("binding_digest"),
            "contract_document_digest": contract.get("digest"),
            "contract_key_id": signature.get("key_id"),
            "contract_signed": bool(signature),
            "contract_verified": verified,
            "contract_required": required,
            "contract_path": str(path) if path is not None else None,
        }
    )


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


def amend_mcp_share_policy(
    directory: str | Path = ".",
    *,
    log: str | Path | None = None,
    output: str | Path | None = None,
    kind: str = "auto",
    source: str = "blocked",
    force: bool = False,
    validate: bool = True,
    allow_risky: bool = False,
) -> dict[str, Any]:
    """Propose a policy amendment from a share session and record it on the session model."""

    from .learn import amend_mcp_policy

    share_dir, manifest, session_model = _load_share_model_context(directory)
    bundle = _share_policy_bundle_path(share_dir, session_model, manifest)
    log_path = _share_policy_amend_log_path(share_dir, session_model, log)
    output_path = _share_policy_amend_output_path(share_dir, bundle, output)
    amendment = amend_mcp_policy(
        bundle,
        log_path,
        output_path,
        kind=kind,
        source=source,
        force=force or output is None,
        validate=validate,
        allow_risky=allow_risky,
    )
    record = _drop_empty_json(
        {
            "ok": amendment.get("ok"),
            "source": source,
            "bundle": str(bundle),
            "log": str(log_path),
            "output": str(output_path),
            "policy": amendment.get("policy"),
            "manifest": amendment.get("manifest"),
            "report": amendment.get("report"),
            "event_count": amendment.get("event_count"),
            "candidate_event_count": amendment.get("candidate_event_count"),
            "additions": amendment.get("additions"),
            "capability_delta": amendment.get("capability_delta"),
            "in_place": output is None,
            "created_at": _now_iso(),
        }
    )
    updated_model = _record_share_policy_amendment(share_dir, manifest, session_model, amendment=record)
    return {
        "ok": bool(amendment.get("ok")),
        "share": str(share_dir),
        "bundle": str(bundle),
        "log": str(log_path),
        "output": str(output_path),
        "amendment": amendment,
        "candidate": record,
        "session_model": str(share_session_model_path(share_dir)),
        "policy": _mapping(updated_model.get("policy")),
        "amendments": _mapping(updated_model.get("amendments")),
    }


def preview_mcp_share_policy_amendment(
    directory: str | Path = ".",
    *,
    log: str | Path | None = None,
    output: str | Path | None = None,
    kind: str = "auto",
    source: str = "blocked",
    force: bool = True,
    validate: bool = True,
    allow_risky: bool = False,
) -> dict[str, Any]:
    """Generate a reviewable share policy amendment preview without recording it."""

    from .learn import amend_mcp_policy

    share_dir, manifest, session_model = _load_share_model_context(directory)
    bundle = _share_policy_bundle_path(share_dir, session_model, manifest)
    log_path = _share_policy_amend_log_path(share_dir, session_model, log)
    output_path = _share_policy_amend_preview_output_path(share_dir, output)
    amendment = amend_mcp_policy(
        bundle,
        log_path,
        output_path,
        kind=kind,
        source=source,
        force=force,
        validate=validate,
        allow_risky=allow_risky,
    )
    preview = _drop_empty_json(
        {
            "ok": amendment.get("ok"),
            "source": source,
            "bundle": str(bundle),
            "log": str(log_path),
            "output": str(output_path),
            "policy": amendment.get("policy"),
            "manifest": amendment.get("manifest"),
            "report": amendment.get("report"),
            "event_count": amendment.get("event_count"),
            "candidate_event_count": amendment.get("candidate_event_count"),
            "additions": amendment.get("additions"),
            "rejected": amendment.get("rejected"),
            "ignored": amendment.get("ignored"),
            "capability_delta": amendment.get("capability_delta"),
            "created_at": _now_iso(),
            "preview": True,
        }
    )
    report_path = Path(str(amendment.get("report") or ""))
    return {
        "ok": bool(amendment.get("ok")),
        "share": str(share_dir),
        "bundle": str(bundle),
        "log": str(log_path),
        "output": str(output_path),
        "amendment": amendment,
        "preview": preview,
        "report_text": report_path.read_text(encoding="utf-8") if report_path.is_file() else "",
        "session_model": str(share_session_model_path(share_dir)),
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


def share_capability_requests(
    directory: str | Path = ".",
    *,
    status: str = "pending",
    log: str | Path | None = None,
) -> dict[str, Any]:
    """List MCP-native just-in-time capability requests observed in share evidence."""

    if status not in {"pending", "approved", "denied", "all"}:
        raise ValueError("status must be one of pending, approved, denied, all")
    share_dir, _manifest, session_model = _load_share_model_context(directory)
    reviews = _load_capability_request_reviews(share_dir)
    requests = _observed_capability_requests(share_dir, session_model, log=log)
    reviewed_requests = _mapping(reviews.get("requests"))
    for request_id, review in reviewed_requests.items():
        if request_id not in requests and isinstance(review, Mapping):
            stored_request = _mapping(review.get("request"))
            if stored_request:
                requests[str(request_id)] = dict(stored_request)
    _enrich_capability_requests_with_policy_labels(share_dir, _manifest, session_model, requests)
    merged = []
    for request_id, request in sorted(requests.items(), key=lambda item: str(item[1].get("last_seen_at") or "")):
        review = _mapping(reviewed_requests.get(request_id))
        request_status = str(review.get("status") or "pending")
        if status != "all" and request_status != status:
            continue
        merged.append(_drop_empty_json({**request, "status": request_status, "review": review or None}))

    summary = _capability_request_summary(
        [request for request in requests.values()],
        reviews=reviewed_requests,
        store_path=_capability_request_review_path(share_dir),
    )
    return {
        "ok": True,
        "share": str(share_dir),
        "status": status,
        "summary": summary,
        "requests": merged,
        "store": str(_capability_request_review_path(share_dir)),
        "session_model": str(share_session_model_path(share_dir)),
    }


def approve_share_capability_request(
    directory: str | Path = ".",
    *,
    request_id: str,
    ttl: str | None = None,
    max_calls: int | None = None,
    task: str | None = None,
    allow_tools: Sequence[str] = (),
    allow_paths: Sequence[str] = (),
    allow_hosts: Sequence[str] = (),
    allow_commands: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    bind_auth: bool = True,
    reviewer: str | None = None,
    log: str | Path | None = None,
) -> dict[str, Any]:
    """Approve a JIT capability request by creating a normal task-scoped lease."""

    share_dir, manifest, session_model = _load_share_model_context(directory)
    requests = share_capability_requests(share_dir, status="all", log=log)
    request = next((item for item in requests["requests"] if item.get("id") == request_id), None)
    if not isinstance(request, Mapping):
        raise ValueError(f"capability request not found: {request_id}")
    suggested = _mapping(request.get("suggested_lease"))
    suggested_capabilities = _string_list(suggested.get("capabilities"))
    effective_capabilities = _merge_string_lists(suggested_capabilities, capabilities)
    if effective_capabilities:
        effective_allow_tools = _merge_string_lists(["*"], allow_tools)
    else:
        effective_allow_tools = _merge_string_lists(
            _string_list(suggested.get("allow_tools")) or _string_list(request.get("tool")),
            allow_tools,
        )
    lease_file = _share_capability_lease_file(share_dir, session_model, manifest)
    lease_header = _share_capability_lease_header(session_model, manifest)
    auth = _mapping(request.get("auth"))
    lease = create_lease(
        lease_file,
        task=task or str(suggested.get("task") or request.get("task") or "Temporary MCP access"),
        allow_tools=effective_allow_tools,
        capabilities=effective_capabilities,
        allow_paths=()
        if effective_capabilities
        else _merge_string_lists(_string_list(suggested.get("allow_paths")), allow_paths),
        allow_hosts=()
        if effective_capabilities
        else _merge_string_lists(_string_list(suggested.get("allow_hosts")), allow_hosts),
        allow_commands=()
        if effective_capabilities
        else _merge_string_lists(_string_list(suggested.get("allow_commands")), allow_commands),
        allow_subjects=_string_list(auth.get("subject")) if bind_auth else (),
        allow_issuers=_string_list(auth.get("issuer")) if bind_auth else (),
        allow_tenants=_string_list(auth.get("tenant")) if bind_auth else (),
        allow_client_ids=_string_list(auth.get("client_id")) if bind_auth else (),
        allow_groups=_string_list(auth.get("groups")) if bind_auth else (),
        allow_auth_profiles=_string_list(auth.get("profile_id")) if bind_auth else (),
        ttl=ttl or str(suggested.get("ttl") or "30m"),
        max_calls=max_calls if max_calls is not None else _positive_int(suggested.get("max_calls")),
    )
    review = _drop_empty_json(
        {
            "status": "approved",
            "request_id": request_id,
            "reviewed_at": _now_iso(),
            "reviewer": reviewer,
            "lease_id": _mapping(lease.get("lease")).get("id"),
            "lease_file": str(lease_file),
            "lease_header": lease_header,
            "bind_auth": bind_auth,
            "auth_bound": bool(bind_auth and auth),
            "capabilities": effective_capabilities,
            "request": _capability_request_review_snapshot(request),
        }
    )
    reviews = _record_capability_request_review(share_dir, request_id, review)
    session_model = _record_share_capability_request_review(
        share_dir,
        session_model,
        review=review,
        reviews=reviews,
    )
    token = str(lease.get("token"))
    return {
        "ok": True,
        "share": str(share_dir),
        "request": request,
        "review": review,
        "lease": lease,
        "headers": {lease_header: token},
        "retry_header": f'-H "{lease_header}: {token}"',
        "store": str(_capability_request_review_path(share_dir)),
        "session_model": str(share_session_model_path(share_dir)),
        "capability_requests": _mapping(session_model.get("capability_requests")),
    }


def revoke_mcp_share_lease(
    directory: str | Path = ".",
    *,
    lease_id: str,
) -> dict[str, Any]:
    """Revoke a task lease using the lease store configured for a share session."""

    from .leases import revoke_lease

    share_dir, manifest, session_model = _load_share_model_context(directory)
    lease_file = _share_capability_lease_file(share_dir, session_model, manifest)
    result = revoke_lease(lease_file, lease_id)
    return {
        **result,
        "share": str(share_dir),
        "lease_file": str(lease_file),
    }


def create_mcp_share_lease(
    directory: str | Path = ".",
    *,
    task: str,
    allow_tools: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    allow_paths: Sequence[str] = (),
    allow_hosts: Sequence[str] = (),
    allow_commands: Sequence[str] = (),
    ttl: str = "30m",
    max_calls: int | None = None,
    invite: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a task-scoped lease in the share's configured lease store."""

    from .leases import create_lease

    share_dir, manifest, session_model = _load_share_model_context(directory)
    lease_file = _share_capability_lease_file(share_dir, session_model, manifest)
    lease_header = _share_capability_lease_header(session_model, manifest)
    capability_labels = _string_list(capabilities)
    lease_allow_tools = _string_list(allow_tools)
    if capability_labels and not lease_allow_tools:
        lease_allow_tools = ["*"]
    lease = create_lease(
        lease_file,
        task=task,
        allow_tools=lease_allow_tools,
        capabilities=capability_labels,
        allow_paths=allow_paths,
        allow_hosts=allow_hosts,
        allow_commands=allow_commands,
        ttl=ttl,
        max_calls=max_calls,
        invite=invite,
    )
    token = str(lease.get("token"))
    return {
        "ok": bool(lease.get("ok")),
        "share": str(share_dir),
        "lease": lease.get("lease"),
        "lease_file": str(lease_file),
        "lease_header": lease_header,
        "headers": {lease_header: token},
        "retry_header": f'-H "{lease_header}: {token}"',
        "session_model": str(share_session_model_path(share_dir)),
    }


def cleanup_mcp_share_leases(directory: str | Path = ".") -> dict[str, Any]:
    """Remove revoked or expired leases from the share's configured lease store."""

    from .leases import cleanup_inactive_leases, list_leases

    share_dir, manifest, session_model = _load_share_model_context(directory)
    lease_file = _share_capability_lease_file(share_dir, session_model, manifest)
    result = cleanup_inactive_leases(lease_file)
    listed = list_leases(lease_file)
    return {
        "ok": bool(result.get("ok")),
        "share": str(share_dir),
        "removed_count": int(result.get("removed_count") or 0),
        "lease_file": str(lease_file),
        "leases": _share_leases_summary({"file": str(lease_file), "leases": listed.get("leases", [])}),
        "session_model": str(share_session_model_path(share_dir)),
    }


def create_mcp_share_invite(
    directory: str | Path = ".",
    *,
    recipient: str,
    task: str,
    allow_tools: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    allow_paths: Sequence[str] = (),
    allow_hosts: Sequence[str] = (),
    allow_commands: Sequence[str] = (),
    ttl: str = "30m",
    max_calls: int | None = None,
    client_name: str | None = None,
) -> dict[str, Any]:
    """Create a task-scoped share invitation with console-gated client setup snippets."""

    if not recipient.strip():
        raise ValueError("recipient must be non-empty")
    share_dir, manifest, session_model = _load_share_model_context(directory)
    client = _mapping(manifest.get("client"))
    client_url = str(client.get("url") or "")
    if not client_url:
        raise ValueError("share manifest does not contain a client URL")
    auth_header, auth_value, bearer_token = _share_client_bearer_token(manifest)
    invite_id = _new_share_invite_id()
    effective_client_name = client_name or str(client.get("name") or DEFAULT_SHARE_CLIENT_NAME)
    capability_labels = _string_list(capabilities)
    requested_allow_tools = _string_list(allow_tools)
    if not capability_labels and not requested_allow_tools:
        capability_labels = list(DEFAULT_SHARE_INVITE_CAPABILITIES)
    lease_allow_tools = requested_allow_tools or (["*"] if capability_labels else [])
    lease_result = create_mcp_share_lease(
        share_dir,
        task=task,
        allow_tools=lease_allow_tools,
        capabilities=capability_labels,
        allow_paths=allow_paths,
        allow_hosts=allow_hosts,
        allow_commands=allow_commands,
        ttl=ttl,
        max_calls=max_calls,
        invite={
            "id": invite_id,
            "recipient": recipient,
            "client_name": effective_client_name,
            "capabilities": capability_labels,
        },
    )
    lease = _mapping(lease_result.get("lease"))
    lease_header = str(lease_result.get("lease_header") or _share_capability_lease_header(session_model, manifest))
    lease_token = str(_mapping(lease_result.get("headers")).get(lease_header) or "")
    headers = {auth_header: auth_value, lease_header: lease_token}
    snippets = _share_invite_setup_snippets(
        client_name=effective_client_name,
        client_url=client_url,
        headers=headers,
        bearer_token=bearer_token,
        lease_header=lease_header,
        lease_token=lease_token,
    )
    redacted_snippets = _share_invite_setup_snippets(
        client_name=effective_client_name,
        client_url=client_url,
        headers=_redacted_invite_headers(headers),
        bearer_token=SECRET_REPLACEMENT,
        lease_header=lease_header,
        lease_token=SECRET_REPLACEMENT,
    )
    now = _now_iso()
    invite = _drop_empty_json(
        {
            "schema": SHARE_INVITE_SCHEMA,
            "id": invite_id,
            "recipient": recipient,
            "task": task,
            "created_at": now,
            "expires_at": lease.get("expires_at"),
            "revoked_at": None,
            "client_name": effective_client_name,
            "client_url": client_url,
            "auth_mode": "bearer",
            "lease_id": lease.get("id"),
            "lease_header": lease_header,
            "capabilities": capability_labels,
            "allow_tools": requested_allow_tools,
            "allow_paths": list(allow_paths),
            "allow_hosts": list(allow_hosts),
            "allow_commands": list(allow_commands),
            "max_calls": max_calls,
            "setup_snippets": redacted_snippets,
        }
    )
    session_model = _record_share_invite(share_dir, session_model, invite)
    _record_share_invite_secret(
        share_dir,
        invite_id,
        {
            "schema": "snulbug.share.invite-secret.v1",
            "invite_id": invite_id,
            "created_at": now,
            "recipient": recipient,
            "headers": headers,
            "bearer_token": bearer_token,
            "lease_token": lease_token,
            "setup_snippets": snippets,
        },
    )
    return {
        "ok": True,
        "share": str(share_dir),
        "invite": invite,
        "headers": headers,
        "bearer_token": bearer_token,
        "lease_token": lease_token,
        "setup_snippets": snippets,
        "lease": lease_result.get("lease"),
        "session_model": str(share_session_model_path(share_dir)),
        "invitations": _mapping(session_model.get("invitations")),
    }


def list_mcp_share_invites(
    directory: str | Path = ".",
    *,
    include_revoked: bool = True,
    include_setup: bool = False,
) -> dict[str, Any]:
    """List share invitations without revealing bearer or lease tokens."""

    share_dir, manifest, session_model = _load_share_model_context(directory)
    files = manifest.get("files") if isinstance(manifest.get("files"), Mapping) else {}
    lease = manifest.get("lease") if isinstance(manifest.get("lease"), Mapping) else {}
    lease_file = files.get("lease_file") or lease.get("file")
    lease_status: dict[str, Any] = {"ok": False, "file": lease_file}
    if isinstance(lease_file, str) and lease_file:
        from .leases import list_leases

        listed = list_leases(_resolve_share_path(share_dir, lease_file))
        lease_status = {
            "ok": True,
            "file": lease_file,
            "id": lease.get("id"),
            "leases": listed.get("leases", []),
        }
    invitations = _share_invitation_connection_statuses(
        share_dir,
        session_model,
        _mapping(session_model.get("invitations")),
        lease_status,
    )
    items = [_mapping(item) for item in _sequence(invitations.get("items")) if isinstance(item, Mapping)]
    if not include_revoked:
        items = [item for item in items if not item.get("revoked_at")]
    if include_setup:
        items = _attach_share_invite_secrets(share_dir, items)
    return {
        "ok": True,
        "share": str(share_dir),
        "invitations": items,
        "summary": _share_invite_summary(items),
        "connection_summary": _share_invitation_connection_summary(items),
        "session_model": str(share_session_model_path(share_dir)),
    }


def share_inspector_setup(
    directory: str | Path = ".",
    *,
    invite_id: str | None = None,
    include_secrets: bool = False,
    output: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Generate MCP Inspector setup snippets for a share or invite."""

    share_dir, manifest, session_model = _load_share_model_context(directory)
    client = _mapping(manifest.get("client"))
    client_name = str(client.get("name") or DEFAULT_SHARE_CLIENT_NAME)
    client_url = str(client.get("url") or "")
    if not client_url:
        raise ValueError("share manifest does not contain a client URL")
    headers = _string_mapping(_mapping(client.get("headers")))
    selected_invite: Mapping[str, Any] | None = None
    if invite_id:
        invitations = list_mcp_share_invites(share_dir, include_setup=include_secrets)
        for item in _sequence(invitations.get("invitations")):
            if isinstance(item, Mapping) and item.get("id") == invite_id:
                selected_invite = item
                break
        if selected_invite is None:
            raise ValueError(f"invite not found: {invite_id}")
        client_name = str(selected_invite.get("client_name") or client_name)
        client_url = str(selected_invite.get("client_url") or client_url)
        headers = _share_inspector_invite_headers(
            share_dir,
            selected_invite,
            include_secrets=include_secrets,
        )
    elif not include_secrets:
        headers = _share_inspector_placeholder_headers(headers, session_model=session_model)

    snippets = _mcp_inspector_setup_snippets(
        client_name=client_name,
        client_url=client_url,
        headers=headers,
    )
    written: str | None = None
    if output is not None:
        output_path = Path(output)
        _write_json(output_path, snippets["config"]["json"], force=force)
        written = str(output_path)
        snippets["config"]["path"] = written
        snippets["config"]["command"] = (
            f"npx {MCP_INSPECTOR_PACKAGE} --config {shlex.quote(str(output_path))} --server {shlex.quote(client_name)}"
        )
    return _drop_empty_json(
        {
            "ok": True,
            "share": str(share_dir),
            "invite": dict(selected_invite) if selected_invite is not None else None,
            "include_secrets": include_secrets,
            "written": written,
            "mcp_inspector": snippets,
        }
    )


def _share_acceptance_doctor_checks(
    directory: str | Path = ".",
    *,
    status: Mapping[str, Any] | None = None,
    invite_id: str | None = None,
    live_checks: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Run behavioral handoff checks for share doctor."""

    share_dir = Path(directory)
    status = status if status is not None else share_status(share_dir, live_checks=False)
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    target = _share_acceptance_target(status, invite_id=invite_id)
    tools = _share_acceptance_tools(status)
    policy_path = _share_acceptance_policy_path(share_dir, status)
    script = _share_acceptance_compile_policy(policy_path, checks)
    _share_acceptance_invite_checks(checks, status, target=target, invite_id=invite_id)
    _share_acceptance_inspector_check(checks, share_dir, invite_id=invite_id)
    if script is not None:
        _share_acceptance_policy_checks(
            checks,
            script=script,
            status=status,
            target=target,
            tools=tools,
        )
    _share_acceptance_schema_checks(checks, status)
    _share_acceptance_redaction_checks(checks, status)
    if live_checks:
        _share_acceptance_live_check(checks, status, timeout=timeout)
    else:
        _add_share_doctor_check(
            checks,
            "acceptance.live_tools_list",
            None,
            "live tools/list probe skipped; pass --live-checks to exercise the running gateway",
            component="acceptance",
        )
    summary = _share_doctor_summary(checks)
    if summary["failed"]:
        recommendations.append("Fix failing share acceptance checks before handing out the MCP URL.")
    if summary["warnings"]:
        recommendations.append("Review share acceptance warnings before broadening access.")
    return {
        "ok": summary["failed"] == 0,
        "mode": {"live_checks": live_checks, "timeout": timeout},
        "checks": checks,
        "summary": summary,
        "recommendations": _unique_strings(recommendations),
        "target": target,
        "tools": tools[:10],
    }


def revoke_mcp_share_invite(
    directory: str | Path = ".",
    *,
    invite_id: str,
    revoke_lease: bool = True,
) -> dict[str, Any]:
    """Revoke a share invitation and optionally revoke its backing lease."""

    share_dir, _manifest, session_model = _load_share_model_context(directory)
    invitations = dict(_mapping(session_model.get("invitations")))
    items = [dict(_mapping(item)) for item in _sequence(invitations.get("items")) if isinstance(item, Mapping)]
    now = _now_iso()
    invite: dict[str, Any] | None = None
    for item in items:
        if item.get("id") == invite_id:
            item["revoked_at"] = item.get("revoked_at") or now
            invite = item
            break
    if invite is None:
        return {
            "ok": False,
            "share": str(share_dir),
            "error": f"invite not found: {invite_id}",
            "session_model": str(share_session_model_path(share_dir)),
        }
    invitations["items"] = items
    invitations["summary"] = _share_invite_summary(items)
    model = json.loads(json.dumps(dict(session_model), default=str))
    model["invitations"] = invitations
    write_share_session_model(share_dir, model, force=True)
    _remove_share_invite_secret(share_dir, invite_id)
    lease_result = None
    lease_id = invite.get("lease_id")
    if revoke_lease and isinstance(lease_id, str) and lease_id:
        lease_result = revoke_mcp_share_lease(share_dir, lease_id=lease_id)
    return {
        "ok": True,
        "share": str(share_dir),
        "invite": invite,
        "lease_revoked": _mapping(lease_result).get("ok") if lease_result is not None else None,
        "lease": lease_result,
        "session_model": str(share_session_model_path(share_dir)),
        "invitations": invitations,
    }


def cleanup_mcp_share_invites(
    directory: str | Path = ".",
    *,
    stale_active: bool = False,
    revoke_stale_leases: bool = True,
) -> dict[str, Any]:
    """Remove revoked share invite records from the session model."""

    share_dir, manifest, session_model = _load_share_model_context(directory)
    invitations = dict(_mapping(session_model.get("invitations")))
    items = [dict(_mapping(item)) for item in _sequence(invitations.get("items")) if isinstance(item, Mapping)]
    stale_removed: list[dict[str, Any]] = []
    active_secret_ids: set[str] = set()
    active_lease_ids: set[str] = set()
    if stale_active:
        active_secret_ids = set(_mapping(_load_share_invite_secret_store(share_dir).get("invitations")).keys())
        active_lease_ids = _share_active_lease_ids(share_dir, session_model, manifest)

    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for item in items:
        if item.get("revoked_at"):
            removed.append(item)
            continue
        if stale_active and _share_invite_is_stale(
            item,
            active_secret_ids=active_secret_ids,
            active_lease_ids=active_lease_ids,
        ):
            stale_removed.append(item)
            continue
        kept.append(item)
    invitations["items"] = kept
    invitations["summary"] = _share_invite_summary(kept)
    last_created = _mapping(invitations.get("last_created"))
    removed_ids = {str(item.get("id")) for item in [*removed, *stale_removed] if item.get("id")}
    if str(last_created.get("id")) in removed_ids:
        invitations.pop("last_created", None)

    model = json.loads(json.dumps(dict(session_model), default=str))
    model["invitations"] = invitations
    write_share_session_model(share_dir, model, force=True)
    _prune_share_invite_secrets(
        share_dir,
        active_ids={str(item.get("id")) for item in kept if item.get("id") and not item.get("revoked_at")},
    )
    stale_lease_revocations = []
    if revoke_stale_leases:
        stale_lease_ids = {
            str(item.get("lease_id"))
            for item in stale_removed
            if isinstance(item.get("lease_id"), str) and item.get("lease_id")
        }
        for lease_id in sorted(stale_lease_ids):
            stale_lease_revocations.append(revoke_mcp_share_lease(share_dir, lease_id=lease_id))
    return {
        "ok": True,
        "share": str(share_dir),
        "removed_count": len(removed) + len(stale_removed),
        "removed_revoked_count": len(removed),
        "removed_stale_active_count": len(stale_removed),
        "stale_lease_revocations": stale_lease_revocations,
        "invitations": invitations,
        "session_model": str(share_session_model_path(share_dir)),
    }


def reactivate_mcp_share_lease(
    directory: str | Path = ".",
    *,
    lease_id: str,
    ttl: str = "30m",
    max_calls: int | None = None,
) -> dict[str, Any]:
    """Reactivate a share lease with a fresh token and expiry."""

    from .leases import reactivate_lease

    share_dir, manifest, session_model = _load_share_model_context(directory)
    lease_file = _share_capability_lease_file(share_dir, session_model, manifest)
    lease_header = _share_capability_lease_header(session_model, manifest)
    lease = reactivate_lease(lease_file, lease_id, ttl=ttl, max_calls=max_calls)
    if not lease.get("ok"):
        return {
            **lease,
            "share": str(share_dir),
            "lease_file": str(lease_file),
            "lease_header": lease_header,
        }
    token = str(lease.get("token"))
    return {
        "ok": True,
        "share": str(share_dir),
        "lease": lease.get("lease"),
        "lease_file": str(lease_file),
        "lease_header": lease_header,
        "headers": {lease_header: token},
        "retry_header": f'-H "{lease_header}: {token}"',
        "session_model": str(share_session_model_path(share_dir)),
    }


def deny_share_capability_request(
    directory: str | Path = ".",
    *,
    request_id: str,
    reason: str | None = None,
    reviewer: str | None = None,
    log: str | Path | None = None,
) -> dict[str, Any]:
    """Deny a JIT capability request and persist the review state."""

    share_dir, _manifest, session_model = _load_share_model_context(directory)
    requests = share_capability_requests(share_dir, status="all", log=log)
    request = next((item for item in requests["requests"] if item.get("id") == request_id), None)
    if not isinstance(request, Mapping):
        raise ValueError(f"capability request not found: {request_id}")
    review = _drop_empty_json(
        {
            "status": "denied",
            "request_id": request_id,
            "reviewed_at": _now_iso(),
            "reviewer": reviewer,
            "reason": reason,
            "request": _capability_request_review_snapshot(request),
        }
    )
    reviews = _record_capability_request_review(share_dir, request_id, review)
    session_model = _record_share_capability_request_review(
        share_dir,
        session_model,
        review=review,
        reviews=reviews,
    )
    return {
        "ok": True,
        "share": str(share_dir),
        "request": request,
        "review": review,
        "store": str(_capability_request_review_path(share_dir)),
        "session_model": str(share_session_model_path(share_dir)),
        "capability_requests": _mapping(session_model.get("capability_requests")),
    }


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

    lines = _share_review_lines(result)
    lines.extend(["", "---", ""])
    lines.extend(_share_report_lines(result, title="## Detailed Status"))
    traffic = _mapping(result.get("traffic"))
    if traffic.get("inspection_report"):
        lines.extend(["", "## Evidence Detail", "", str(traffic["inspection_report"]).rstrip()])
    return "\n".join(lines).rstrip() + "\n"


class ShareStatusDoctorCheck(ShareDoctorCheck):
    name = "status"
    component = "status"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        checks: list[dict[str, Any]] = []
        _add_share_status_checks(checks, context.status, live_checks=context.live_checks)
        return ShareDoctorCheckResult(checks=checks)


class ShareConfigDoctorCheck(ShareDoctorCheck):
    name = "config"
    component = "config"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        from .config import load_mcp_fabric_config, load_mcp_proxy_config

        checks: list[dict[str, Any]] = []
        recommendations: list[str] = []
        try:
            context.proxy_config = load_mcp_proxy_config(context.config_path)
            _add_share_doctor_check(
                checks,
                "config.proxy_loaded",
                True,
                f"loaded proxy config {context.config_path}",
                component="config",
                details={"config": str(context.config_path)},
            )
        except Exception as exc:
            context.proxy_config = None
            _add_share_doctor_check(
                checks,
                "config.proxy_loaded",
                False,
                f"failed to load proxy config: {exc}",
                component="config",
                details={"config": str(context.config_path)},
            )
            recommendations.append("Fix the generated snulbug.toml before sharing this MCP endpoint.")
        try:
            context.fabric_config = load_mcp_fabric_config(context.config_path)
            _add_share_doctor_check(
                checks,
                "config.fabric_loaded",
                True,
                f"loaded fabric config {context.config_path}",
                component="config",
                details={"config": str(context.config_path)},
            )
        except Exception as exc:
            context.fabric_config = None
            _add_share_doctor_check(
                checks,
                "config.fabric_loaded",
                False,
                f"failed to load fabric config: {exc}",
                component="config",
                details={"config": str(context.config_path)},
            )
        return ShareDoctorCheckResult(checks=checks, recommendations=recommendations)


class SharePolicyDoctorCheck(ShareDoctorCheck):
    name = "policy"
    component = "policy"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        result = _share_policy_doctor_checks(context.share_dir, context.proxy_config, context.status)
        return ShareDoctorCheckResult(
            checks=result["checks"],
            recommendations=result["recommendations"],
            artifacts={"policy": result["result"]},
        )


class ShareAcceptanceDoctorCheck(ShareDoctorCheck):
    name = "acceptance"
    component = "acceptance"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        result = _share_acceptance_doctor_checks(
            context.share_dir,
            status=context.status,
            invite_id=context.state.get("invite_id") if isinstance(context.state.get("invite_id"), str) else None,
            live_checks=context.live_checks,
            timeout=context.timeout,
        )
        return ShareDoctorCheckResult(
            checks=result["checks"],
            recommendations=result["recommendations"],
            artifacts={"acceptance": result},
        )


class ShareCloudflareDoctorCheck(ShareDoctorCheck):
    name = "cloudflare"
    component = "cloudflare"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        result = _share_cloudflare_profile_doctor_checks(context.proxy_config, context.manifest)
        return ShareDoctorCheckResult(
            checks=result["checks"],
            recommendations=result["recommendations"],
            artifacts={"cloudflare": result["result"]},
        )


class ShareTailscaleDoctorCheck(ShareDoctorCheck):
    name = "tailscale"
    component = "tailscale"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        result = _share_tailscale_profile_doctor_checks(
            context.proxy_config,
            context.manifest,
            context.status,
            public_url=context.url,
        )
        return ShareDoctorCheckResult(
            checks=result["checks"],
            recommendations=result["recommendations"],
            artifacts={"tailscale": result["result"]},
        )


class ShareFabricDoctorCheck(ShareDoctorCheck):
    name = "fabric"
    component = "fabric"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        checks: list[dict[str, Any]] = []
        recommendations: list[str] = []
        fabric = None
        if context.fabric_config is not None:
            from .fabric import doctor_fabric

            fabric = doctor_fabric(
                context.config_path,
                headers=context.headers,
                timeout=context.timeout,
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
        return ShareDoctorCheckResult(
            checks=checks,
            recommendations=recommendations,
            artifacts={"fabric": fabric},
        )


class ShareConformanceDoctorCheck(ShareDoctorCheck):
    name = "conformance"
    component = "conformance"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        conformance = _run_share_conformance_doctor(
            context.conformance_pack,
            headers=context.headers,
            timeout=context.timeout,
            require_conformance=context.require_conformance,
        )
        return ShareDoctorCheckResult(
            checks=conformance["checks"],
            recommendations=conformance["recommendations"],
            artifacts={"conformance": conformance["result"]},
        )


class ShareTunnelDoctorCheck(ShareDoctorCheck):
    name = "tunnel"
    component = "tunnel"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        from .tunnel import doctor_tunnel

        tunnel = doctor_tunnel(
            provider=context.provider,
            url=context.url,
            config=context.config_path,
            headers=context.headers,
            timeout=context.timeout,
        )
        checks: list[dict[str, Any]] = []
        _extend_component_checks(checks, tunnel.get("checks", []), component="tunnel", prefix="tunnel")
        return ShareDoctorCheckResult(
            checks=checks,
            recommendations=[str(item) for item in _sequence(tunnel.get("recommendations"))],
            artifacts={"tunnel": tunnel, "tunnel_doctor": tunnel},
        )


for _share_doctor_check in (
    ShareStatusDoctorCheck(),
    ShareConfigDoctorCheck(),
    SharePolicyDoctorCheck(),
    ShareAcceptanceDoctorCheck(),
    ShareCloudflareDoctorCheck(),
    ShareTailscaleDoctorCheck(),
    ShareFabricDoctorCheck(),
    ShareConformanceDoctorCheck(),
    ShareTunnelDoctorCheck(),
):
    register_share_doctor_check(_share_doctor_check, replace=True)


def doctor_mcp_share(
    directory: str | Path,
    *,
    timeout: float = 5.0,
    public_url: str | None = None,
    live_checks: bool = True,
    invite_id: str | None = None,
    conformance_pack: str | Path | None = None,
    require_conformance: bool = False,
) -> dict[str, Any]:
    """Run a unified readiness gate against a generated share session."""

    from .tunnel import parse_tunnel_headers

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
    status = share_status(share_dir, timeout=timeout, live_checks=live_checks)
    context = ShareDoctorContext(
        share_dir=share_dir,
        manifest=manifest,
        session=session,
        client=client,
        config_path=config_path,
        provider=str(provider),
        url=str(url),
        headers=doctor_headers,
        timeout=timeout,
        live_checks=live_checks,
        status=status,
        conformance_pack=conformance_pack,
        require_conformance=require_conformance,
        state={"invite_id": invite_id},
    )
    doctor_run = run_share_doctor_checks(context)
    checks = doctor_run["checks"]
    artifacts = _mapping(doctor_run.get("artifacts"))
    tunnel = _mapping(artifacts.get("tunnel"))

    summary = _share_doctor_summary(checks)
    result = {
        "ok": summary["failed"] == 0,
        "share": str(share_dir),
        "provider": provider,
        "url": tunnel.get("url") or url,
        "local_url": tunnel.get("local_url"),
        "config": str(config_path),
        "checks": checks,
        "summary": summary,
        "recommendations": _unique_strings(doctor_run["recommendations"]),
        "doctor_plugins": doctor_run["plugins"],
        "doctor_artifacts": artifacts,
        "acceptance": artifacts.get("acceptance"),
        "status": status,
        "policy": artifacts.get("policy"),
        "cloudflare": artifacts.get("cloudflare"),
        "tailscale": artifacts.get("tailscale"),
        "fabric": artifacts.get("fabric"),
        "conformance": artifacts.get("conformance"),
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


def generate_auth_conformance_pack(
    directory: str | Path | None = None,
    *,
    config: str | Path | None = None,
    public_url: str | None = None,
    schema_catalogs: Sequence[str | Path] = (),
    logs: Sequence[str | Path] = (),
    kind: str = "auto",
    token_envs: Sequence[str] = (),
    denied_token_envs: Sequence[str] = (),
    output: str | Path = ".snulbug/auth-conformance",
    force: bool = False,
) -> dict[str, Any]:
    """Generate a secret-safe auth conformance pack for an MCP share."""

    if kind not in {"auto", "record", "audit"}:
        raise ValueError("kind must be 'auto', 'record', or 'audit'")
    if not schema_catalogs:
        raise ValueError("at least one discovered schema catalog is required")
    if not logs:
        raise ValueError("at least one replay or audit log is required")
    token_refs = [
        *(_parse_auth_conformance_token_ref(value, expected_allowed=True) for value in token_envs),
        *(_parse_auth_conformance_token_ref(value, expected_allowed=False) for value in denied_token_envs),
    ]
    if not token_refs:
        raise ValueError("at least one --token-env reference is required")

    from .config import load_mcp_proxy_config

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
    public_url_candidates = _auth_public_url_candidates(
        manifest=manifest,
        session_model=session_model,
        proxy_config=proxy_config,
        public_url=public_url,
    )
    url = _resolve_auth_doctor_public_url(public_url_candidates=public_url_candidates, auth=auth)

    output_path = Path(output)
    if output_path.exists() and any(output_path.iterdir()) and not force:
        raise FileExistsError(f"auth conformance output already exists: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    schema_dir = output_path / "schemas"
    log_dir = output_path / "logs"
    schema_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    schema_entries = []
    for index, catalog in enumerate(schema_catalogs, start=1):
        catalog_path = Path(catalog)
        profile = _auth_schema_catalog_profile(catalog_path)
        profile_path = schema_dir / f"{index:02d}-{_safe_artifact_name(catalog_path.stem or 'schema')}.json"
        profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        schema_entries.append(
            {
                "path": _relative_pack_path(catalog_path, output_path),
                "sha256": _file_sha256(catalog_path),
                "profile": _relative_pack_path(profile_path, output_path),
                "hash": profile.get("hash"),
                "summary": profile.get("summary", {}),
            }
        )

    log_entries = []
    for index, log in enumerate(logs, start=1):
        log_path = Path(log)
        profile = _auth_log_profile(log_path, kind=kind)
        profile_path = log_dir / f"{index:02d}-{_safe_artifact_name(log_path.stem or 'log')}.json"
        profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        log_entries.append(
            {
                "path": _relative_pack_path(log_path, output_path),
                "sha256": _file_sha256(log_path),
                "kind": kind,
                "profile": _relative_pack_path(profile_path, output_path),
                "event_count": profile.get("event_count", 0),
                "auth_event_count": profile.get("auth_event_count", 0),
                "scope_map_event_count": profile.get("scope_map_event_count", 0),
                "claim_policy_event_count": profile.get("claim_policy_event_count", 0),
            }
        )

    manifest_path = output_path / "manifest.json"
    report_path = output_path / "AUTH_CONFORMANCE.md"
    pack_manifest = {
        "schema": AUTH_CONFORMANCE_SCHEMA,
        "version": AUTH_CONFORMANCE_VERSION,
        "generated_by": "snulbug mcp share auth conformance generate",
        "generated_at": _now_iso(),
        "share": str(share_dir) if share_dir is not None else None,
        "public_url": url,
        "config": {"path": _relative_pack_path(config_path, output_path), "sha256": _file_sha256(config_path)},
        "auth": _auth_conformance_expected(auth),
        "schemas": schema_entries,
        "tokens": token_refs,
        "logs": log_entries,
    }
    manifest_path.write_text(json.dumps(pack_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(_format_auth_conformance_pack_report(pack_manifest), encoding="utf-8")
    return {
        "ok": True,
        "output": str(output_path),
        "manifest": str(manifest_path),
        "report": str(report_path),
        "config": str(config_path),
        "url": url,
        "schema_catalogs": [str(path) for path in schema_catalogs],
        "logs": [str(path) for path in logs],
        "tokens": [
            {"label": token["label"], "env": token["env"], "expected_allowed": token["expected_allowed"]}
            for token in token_refs
        ],
        "next_steps": [
            f"review {report_path}",
            f"uv run snulbug mcp share auth conformance run {output_path}",
        ],
    }


def run_auth_conformance_pack(
    pack: str | Path,
    *,
    token_envs: Sequence[str] = (),
    public_url: str | None = None,
    headers: Sequence[str] | Mapping[str, str] | None = None,
    timeout: float = 5.0,
    live_checks: bool = True,
) -> dict[str, Any]:
    """Run a generated auth conformance pack."""

    from .config import load_mcp_proxy_config
    from .mcp_schemas import parse_mcp_schema_headers
    from .proxy import _oauth_resource_config

    pack_path = Path(pack)
    manifest_path = pack_path / "manifest.json"
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    manifest: Mapping[str, Any] | None = None

    try:
        manifest_value = _read_json(manifest_path)
        if not isinstance(manifest_value, Mapping):
            raise ValueError("auth conformance manifest must be a JSON object")
        if manifest_value.get("schema") != AUTH_CONFORMANCE_SCHEMA:
            raise ValueError(f"unsupported auth conformance schema: {manifest_value.get('schema')!r}")
        if manifest_value.get("version") != AUTH_CONFORMANCE_VERSION:
            raise ValueError(f"unsupported auth conformance version: {manifest_value.get('version')!r}")
        manifest = manifest_value
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "pack.manifest_loaded",
            False,
            f"failed to load auth conformance manifest: {exc}",
            component="auth-conformance",
        )
        return _auth_conformance_result(pack_path, manifest, checks, recommendations=recommendations)

    _add_share_doctor_check(
        checks,
        "pack.manifest_loaded",
        True,
        f"loaded auth conformance manifest {manifest_path}",
        component="auth-conformance",
    )
    config_ref = _mapping(manifest.get("config"))
    config_path = _resolve_pack_path(pack_path, config_ref.get("path"))
    proxy_config: Mapping[str, Any] = {}
    auth: Mapping[str, Any] = {}
    try:
        proxy_config = load_mcp_proxy_config(config_path)
        auth = _mapping(proxy_config.get("auth"))
        _add_share_doctor_check(
            checks,
            "config.loaded",
            True,
            f"loaded proxy config {config_path}",
            component="auth-conformance",
        )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "config.loaded",
            False,
            f"failed to load proxy config: {exc}",
            component="auth-conformance",
        )
        return _auth_conformance_result(
            pack_path,
            manifest,
            checks,
            config=config_path,
            recommendations=recommendations,
        )

    if config_ref.get("sha256"):
        actual_config_hash = _file_sha256(config_path)
        _add_share_doctor_check(
            checks,
            "config.fingerprint",
            actual_config_hash == config_ref.get("sha256"),
            "config file matches generated auth conformance fingerprint"
            if actual_config_hash == config_ref.get("sha256")
            else "config file changed since auth conformance pack generation",
            component="auth-conformance",
            details={"expected": config_ref.get("sha256"), "actual": actual_config_hash},
        )
    _run_auth_expected_checks(checks, auth, _mapping(manifest.get("auth")))

    token_refs = _merge_auth_token_refs(_sequence(manifest.get("tokens")), token_envs)
    token_results = _run_auth_token_checks(checks, token_refs, oauth_config=_oauth_resource_config(auth))
    doctor_token = next(
        (
            result.get("token")
            for result in token_results
            if result.get("expected_allowed") is True and result.get("token")
        ),
        None,
    )
    doctor_url = public_url or manifest.get("public_url")
    doctor_headers = (
        parse_mcp_schema_headers(headers, token=None)
        if not isinstance(headers, Mapping)
        else {str(name).lower(): str(value) for name, value in headers.items()}
    )
    doctor = doctor_mcp_share_auth(
        config=config_path,
        public_url=str(doctor_url) if isinstance(doctor_url, str) and doctor_url else None,
        headers=doctor_headers,
        token=str(doctor_token) if doctor_token else None,
        timeout=timeout,
        live_checks=live_checks,
    )
    _append_prefixed_checks(checks, doctor.get("checks"), prefix="doctor", component="auth-doctor")
    if not doctor.get("ok"):
        recommendations.extend(str(item) for item in _sequence(doctor.get("recommendations")))

    schema_profiles = []
    for index, schema_ref in enumerate(_sequence(manifest.get("schemas")), start=1):
        profile = _run_auth_schema_artifact_checks(checks, pack_path, _mapping(schema_ref), index=index)
        if profile:
            schema_profiles.append(profile)
    if not schema_profiles:
        _add_share_doctor_check(
            checks,
            "schemas.configured",
            False,
            "auth conformance pack does not include schema catalogs",
            component="schemas",
        )
    else:
        _run_auth_schema_policy_checks(checks, auth, schema_profiles)

    log_profiles = []
    for index, log_ref in enumerate(_sequence(manifest.get("logs")), start=1):
        profile = _run_auth_log_artifact_checks(checks, pack_path, _mapping(log_ref), index=index)
        if profile:
            log_profiles.append(profile)
    if not log_profiles:
        _add_share_doctor_check(
            checks,
            "logs.configured",
            False,
            "auth conformance pack does not include replay or audit logs",
            component="logs",
        )
    else:
        _run_auth_log_evidence_checks(checks, auth, log_profiles)

    return _auth_conformance_result(
        pack_path,
        manifest,
        checks,
        config=config_path,
        doctor=doctor,
        recommendations=recommendations,
    )


def format_share_auth_conformance_report(result: Mapping[str, Any]) -> str:
    """Render auth conformance pack run results as Markdown."""

    summary = _mapping(result.get("summary"))
    lines = [
        "# snulbug mcp share auth conformance",
        "",
        f"Pack: {result.get('pack')}",
        f"Config: {result.get('config') or '-'}",
        f"Result: {'pass' if result.get('ok') else 'fail'}",
        "",
        "## Checks",
    ]
    checks = result.get("checks", [])
    if not checks:
        lines.append("- none")
    for check in checks:
        if isinstance(check, Mapping):
            lines.append(f"- [{check.get('status')}] {check.get('id')}: {check.get('message')}")
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
    return "\n".join(lines).rstrip() + "\n"


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


def _parse_auth_conformance_token_ref(value: str, *, expected_allowed: bool) -> dict[str, Any]:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("token env reference must not be empty")
    label, separator, env = raw.partition("=")
    if not separator:
        env = label
        label = label.lower()
    label = _safe_artifact_name(label.strip())
    env = env.strip()
    if not label or not env:
        raise ValueError("token env references must use ENV or label=ENV")
    return {"label": label, "env": env, "expected_allowed": expected_allowed}


def _auth_schema_catalog_profile(path: Path) -> dict[str, Any]:
    from .mcp_schemas import normalize_mcp_schema_catalog

    catalog = normalize_mcp_schema_catalog(_read_json(path))
    surfaces = _mapping(catalog.get("surfaces"))
    tools = [
        str(item.get("name"))
        for item in _auth_schema_surface_items(surfaces.get("tools"))
        if isinstance(item, Mapping) and item.get("name")
    ]
    resources = [
        str(item.get("uri"))
        for item in _auth_schema_surface_items(surfaces.get("resources"))
        if isinstance(item, Mapping) and item.get("uri")
    ]
    prompts = [
        str(item.get("name"))
        for item in _auth_schema_surface_items(surfaces.get("prompts"))
        if isinstance(item, Mapping) and item.get("name")
    ]
    return {
        "ok": bool(catalog.get("ok")),
        "hash": catalog.get("hash"),
        "label": catalog.get("label"),
        "methods": [str(method) for method in _sequence(catalog.get("methods"))],
        "summary": _jsonish_copy(catalog.get("summary") or {}),
        "tools": sorted(tools),
        "resources": sorted(resources),
        "prompts": sorted(prompts),
        "errors": _jsonish_copy(catalog.get("errors") or []),
    }


def _auth_log_profile(path: Path, *, kind: str) -> dict[str, Any]:
    from .inspection import _load_events

    events = _load_events(path, kind=kind)
    reason_codes: Counter[str] = Counter()
    subjects: Counter[str] = Counter()
    issuers: Counter[str] = Counter()
    profiles: Counter[str] = Counter()
    scope_denials: Counter[str] = Counter()
    auth_event_count = 0
    allowed = 0
    denied = 0
    scope_map_event_count = 0
    claim_policy_event_count = 0
    runtime_event_count = 0
    for event in events:
        auth = _event_auth_metadata(event)
        if not auth:
            continue
        auth_event_count += 1
        if auth.get("allowed") is False:
            denied += 1
        else:
            allowed += 1
        if auth.get("reason_code"):
            reason_codes[str(auth["reason_code"])] += 1
        if auth.get("subject"):
            subjects[str(auth["subject"])] += 1
        if auth.get("issuer"):
            issuers[str(auth["issuer"])] += 1
        if auth.get("profile_id"):
            profiles[str(auth["profile_id"])] += 1
        if isinstance(auth.get("runtime"), Mapping):
            runtime_event_count += 1
        scope_map = auth.get("scope_map") if isinstance(auth.get("scope_map"), Mapping) else auth.get("scope_match")
        if isinstance(scope_map, Mapping):
            scope_map_event_count += 1
            if scope_map.get("allowed") is False:
                target = _mapping(scope_map.get("target"))
                tool = target.get("tool")
                if tool:
                    scope_denials[f"tools/call:{tool}"] += 1
                elif scope_map.get("reason_code"):
                    scope_denials[str(scope_map["reason_code"])] += 1
        if isinstance(auth.get("claim_policy"), Mapping):
            claim_policy_event_count += 1
    return {
        "ok": bool(events),
        "event_count": len(events),
        "auth_event_count": auth_event_count,
        "allowed": allowed,
        "denied": denied,
        "scope_map_event_count": scope_map_event_count,
        "claim_policy_event_count": claim_policy_event_count,
        "runtime_event_count": runtime_event_count,
        "reason_codes": _top_counter(reason_codes),
        "subjects": _top_counter(subjects),
        "issuers": _top_counter(issuers),
        "profiles": _top_counter(profiles),
        "scope_denials": _top_counter(scope_denials),
    }


def _auth_schema_surface_items(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return list(value.values())
    return _sequence(value)


def _event_auth_metadata(event: Mapping[str, Any]) -> Mapping[str, Any]:
    auth = event.get("auth")
    if isinstance(auth, Mapping):
        return auth
    metadata_auth = _mapping(_mapping(event.get("metadata")).get("auth"))
    return metadata_auth


def _top_counter(counter: Counter[str]) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common()]


def _auth_conformance_expected(auth: Mapping[str, Any]) -> dict[str, Any]:
    return _jsonish_copy(_auth_doctor_summary(auth))


def _format_auth_conformance_pack_report(manifest: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug auth conformance pack",
        "",
        f"Config: `{_mapping(manifest.get('config')).get('path')}`",
        f"Public/client URL: `{manifest.get('public_url') or '-'}`",
        "",
        "## Artifacts",
        f"- schema catalogs: {len(_sequence(manifest.get('schemas')))}",
        f"- replay/audit logs: {len(_sequence(manifest.get('logs')))}",
        f"- sample token refs: {len(_sequence(manifest.get('tokens')))}",
        "",
        "## Token Refs",
    ]
    for token in _sequence(manifest.get("tokens")):
        if isinstance(token, Mapping):
            expected = "allowed" if token.get("expected_allowed") else "denied"
            lines.append(f"- `{token.get('label')}` via `${token.get('env')}` expected `{expected}`")
    lines.extend(
        [
            "",
            "## Next Steps",
            "- Set the referenced token environment variables in your shell.",
            "- Run `uv run snulbug mcp share auth conformance run <pack-dir>` before sharing the MCP URL.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _run_auth_expected_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> None:
    actual = _auth_conformance_expected(auth)
    _add_share_doctor_check(
        checks,
        "auth.snapshot",
        actual == dict(expected),
        "auth config matches generated conformance snapshot"
        if actual == dict(expected)
        else "auth config changed since conformance pack generation",
        component="auth-conformance",
        details={"expected": expected, "actual": actual},
    )
    _add_share_doctor_check(
        checks,
        "auth.mode",
        auth.get("mode") == "oauth-resource",
        "OAuth protected-resource mode is enabled"
        if auth.get("mode") == "oauth-resource"
        else "OAuth protected-resource mode is not enabled",
        component="auth-conformance",
        details={"mode": auth.get("mode")},
    )


def _merge_auth_token_refs(stored: Sequence[Any], overrides: Sequence[str]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in stored:
        if not isinstance(item, Mapping):
            continue
        label = str(item.get("label") or "").strip()
        env = str(item.get("env") or "").strip()
        if label and env:
            merged[label] = {
                "label": label,
                "env": env,
                "expected_allowed": item.get("expected_allowed") is not False,
            }
    for value in overrides:
        parsed = _parse_auth_conformance_token_ref(value, expected_allowed=True)
        if parsed["label"] in merged:
            parsed["expected_allowed"] = merged[parsed["label"]]["expected_allowed"]
        merged[parsed["label"]] = parsed
    return [merged[key] for key in sorted(merged)]


def _run_auth_token_checks(
    checks: list[dict[str, Any]],
    token_refs: Sequence[Mapping[str, Any]],
    *,
    oauth_config: Any,
) -> list[dict[str, Any]]:
    from .mcp_auth import evaluate_oauth_request

    results = []
    if not token_refs:
        _add_share_doctor_check(
            checks,
            "tokens.configured",
            False,
            "auth conformance pack does not include sample token references",
            component="tokens",
        )
        return results
    for item in token_refs:
        label = str(item.get("label") or "token")
        env = str(item.get("env") or "")
        expected_allowed = item.get("expected_allowed") is not False
        token = os.environ.get(env) if env else None
        check_id = f"tokens.{_safe_artifact_name(label)}"
        if not token:
            _add_share_doctor_check(
                checks,
                check_id,
                False,
                f"sample token environment variable {env!r} is not set",
                component="tokens",
                details={"label": label, "env": env, "expected_allowed": expected_allowed},
            )
            results.append({"label": label, "env": env, "expected_allowed": expected_allowed, "token": None})
            continue
        decision = evaluate_oauth_request(
            {"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode("latin-1"))]},
            config=oauth_config,
            body=_auth_conformance_initialize_body(),
        )
        ok = decision.allowed is expected_allowed
        _add_share_doctor_check(
            checks,
            check_id,
            ok,
            f"sample token {label!r} matched expected auth decision"
            if ok
            else f"sample token {label!r} did not match expected auth decision",
            component="tokens",
            details={
                "label": label,
                "env": env,
                "expected_allowed": expected_allowed,
                "allowed": decision.allowed,
                "reason_code": decision.metadata.get("reason_code"),
                "subject": decision.metadata.get("subject"),
                "issuer": decision.metadata.get("issuer"),
                "profile_id": decision.metadata.get("profile_id"),
                "scopes": decision.metadata.get("scopes"),
            },
        )
        results.append({"label": label, "env": env, "expected_allowed": expected_allowed, "token": token})
    return results


def _auth_conformance_initialize_body() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "snulbug-auth-conformance",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "snulbug"}},
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _run_auth_schema_artifact_checks(
    checks: list[dict[str, Any]],
    pack_path: Path,
    schema_ref: Mapping[str, Any],
    *,
    index: int,
) -> dict[str, Any] | None:
    catalog_path = _resolve_pack_path(pack_path, schema_ref.get("path"))
    check_prefix = f"schemas.{index:02d}"
    try:
        actual_hash = _file_sha256(catalog_path)
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.fingerprint",
            actual_hash == schema_ref.get("sha256"),
            "schema catalog fingerprint matches generated conformance pack"
            if actual_hash == schema_ref.get("sha256")
            else "schema catalog changed since conformance pack generation",
            component="schemas",
            details={"path": str(catalog_path), "expected": schema_ref.get("sha256"), "actual": actual_hash},
        )
        profile = _auth_schema_catalog_profile(catalog_path)
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.loaded",
            profile.get("ok") is True,
            "schema catalog loaded without discovery errors"
            if profile.get("ok") is True
            else "schema catalog contains discovery errors",
            component="schemas",
            details={"path": str(catalog_path), "summary": profile.get("summary"), "errors": profile.get("errors")},
        )
        return profile
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.loaded",
            False,
            f"failed to load schema catalog: {exc}",
            component="schemas",
            details={"path": str(catalog_path)},
        )
        return None


def _run_auth_schema_policy_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    schema_profiles: Sequence[Mapping[str, Any]],
) -> None:
    tools = sorted({str(tool) for profile in schema_profiles for tool in _sequence(profile.get("tools"))})
    methods = {str(method) for profile in schema_profiles for method in _sequence(profile.get("methods"))}
    scope_missing = _missing_auth_scope_selector_targets(auth, tools=tools, methods=methods)
    _add_share_doctor_check(
        checks,
        "schemas.scope_map_targets",
        not scope_missing,
        "scope-map selectors resolve against discovered schemas"
        if not scope_missing
        else "scope-map selectors reference tools or methods missing from discovered schemas",
        component="schemas",
        details={"missing": scope_missing, "tool_count": len(tools), "methods": sorted(methods)},
    )
    claim_missing = _missing_auth_claim_policy_targets(auth, tools=tools)
    if _auth_has_claim_policy(auth):
        _add_share_doctor_check(
            checks,
            "schemas.claim_policy_targets",
            not claim_missing,
            "claim-policy tool entries resolve against discovered schemas"
            if not claim_missing
            else "claim-policy entries reference tools missing from discovered schemas",
            component="schemas",
            details={"missing": claim_missing, "tool_count": len(tools)},
        )
    else:
        _add_share_doctor_check(
            checks,
            "schemas.claim_policy_targets",
            None,
            "claim-policy schema target check skipped because claim policy is disabled",
            component="schemas",
        )


def _run_auth_log_artifact_checks(
    checks: list[dict[str, Any]],
    pack_path: Path,
    log_ref: Mapping[str, Any],
    *,
    index: int,
) -> dict[str, Any] | None:
    log_path = _resolve_pack_path(pack_path, log_ref.get("path"))
    kind = str(log_ref.get("kind") or "auto")
    check_prefix = f"logs.{index:02d}"
    try:
        actual_hash = _file_sha256(log_path)
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.fingerprint",
            actual_hash == log_ref.get("sha256"),
            "replay/audit log fingerprint matches generated conformance pack"
            if actual_hash == log_ref.get("sha256")
            else "replay/audit log changed since conformance pack generation",
            component="logs",
            details={"path": str(log_path), "expected": log_ref.get("sha256"), "actual": actual_hash},
        )
        profile = _auth_log_profile(log_path, kind=kind)
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.loaded",
            profile.get("event_count", 0) > 0,
            "replay/audit log contains events" if profile.get("event_count", 0) > 0 else "replay/audit log is empty",
            component="logs",
            details={"path": str(log_path), "profile": profile},
        )
        return profile
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            f"{check_prefix}.loaded",
            False,
            f"failed to load replay/audit log: {exc}",
            component="logs",
            details={"path": str(log_path)},
        )
        return None


def _run_auth_log_evidence_checks(
    checks: list[dict[str, Any]],
    auth: Mapping[str, Any],
    log_profiles: Sequence[Mapping[str, Any]],
) -> None:
    auth_events = sum(int(profile.get("auth_event_count", 0) or 0) for profile in log_profiles)
    scope_events = sum(int(profile.get("scope_map_event_count", 0) or 0) for profile in log_profiles)
    claim_events = sum(int(profile.get("claim_policy_event_count", 0) or 0) for profile in log_profiles)
    runtime_events = sum(int(profile.get("runtime_event_count", 0) or 0) for profile in log_profiles)
    _add_share_doctor_check(
        checks,
        "logs.auth_evidence",
        auth_events > 0,
        "replay/audit logs contain OAuth auth metadata"
        if auth_events > 0
        else "replay/audit logs do not contain OAuth auth metadata",
        component="logs",
        details={"auth_event_count": auth_events},
    )
    if _auth_has_scope_map(auth):
        _add_share_doctor_check(
            checks,
            "logs.scope_map_evidence",
            scope_events > 0,
            "replay/audit logs contain scope-map decisions"
            if scope_events > 0
            else "replay/audit logs do not contain scope-map decisions",
            component="logs",
            details={"scope_map_event_count": scope_events},
        )
    if _auth_has_claim_policy(auth):
        _add_share_doctor_check(
            checks,
            "logs.claim_policy_evidence",
            claim_events > 0,
            "replay/audit logs contain claim-policy decisions"
            if claim_events > 0
            else "replay/audit logs do not contain claim-policy decisions",
            component="logs",
            details={"claim_policy_event_count": claim_events},
        )
    _add_share_doctor_check(
        checks,
        "logs.runtime_observability",
        runtime_events > 0,
        "replay/audit logs contain auth runtime observability metadata"
        if runtime_events > 0
        else "replay/audit logs do not contain auth runtime observability metadata",
        component="logs",
        severity="warning",
        details={"runtime_event_count": runtime_events},
    )


def _auth_conformance_result(
    pack_path: Path,
    manifest: Mapping[str, Any] | None,
    checks: Sequence[Mapping[str, Any]],
    *,
    config: Path | None = None,
    doctor: Mapping[str, Any] | None = None,
    recommendations: Sequence[str] = (),
) -> dict[str, Any]:
    summary = _share_doctor_summary(checks)
    generated_recommendations = list(recommendations)
    if summary["failed"]:
        generated_recommendations.append("Fix failing auth conformance checks before sharing the public MCP URL.")
    return {
        "ok": summary["failed"] == 0,
        "pack": str(pack_path),
        "config": str(config) if config is not None else None,
        "manifest": _jsonish_copy(manifest or {}),
        "checks": [dict(check) for check in checks],
        "summary": summary,
        "doctor": _jsonish_copy(doctor or {}),
        "recommendations": _unique_strings(generated_recommendations),
    }


def _missing_auth_scope_selector_targets(
    auth: Mapping[str, Any],
    *,
    tools: Sequence[str],
    methods: set[str],
) -> list[dict[str, Any]]:
    missing = []
    tool_set = set(tools)
    for profile in _auth_policy_profiles(auth):
        scope_map = _mapping(profile.get("scope_map"))
        for scope, selectors in scope_map.items():
            for selector in _sequence(selectors):
                selector = str(selector)
                if selector == "tools/call":
                    if not tool_set:
                        missing.append({"profile": profile.get("id"), "scope": scope, "selector": selector})
                    continue
                if selector.startswith("tools/call:"):
                    pattern = selector.removeprefix("tools/call:")
                    if _missing_scope_map_tool_patterns([pattern], tool_set):
                        missing.append(
                            {"profile": profile.get("id"), "scope": scope, "selector": selector, "pattern": pattern}
                        )
                    continue
                if "/" in selector and selector not in methods:
                    missing.append({"profile": profile.get("id"), "scope": scope, "selector": selector})
    return missing


def _missing_auth_claim_policy_targets(auth: Mapping[str, Any], *, tools: Sequence[str]) -> list[dict[str, Any]]:
    missing = []
    tool_set = set(tools)
    for profile in _auth_policy_profiles(auth):
        policy = _mapping(profile.get("claim_policy"))
        if policy.get("enabled") is not True:
            continue
        for rule in _sequence(policy.get("rules")):
            if not isinstance(rule, Mapping):
                continue
            patterns = [
                *map(str, _sequence(rule.get("allow_tools"))),
                *(f"{prefix}*" for prefix in _sequence(rule.get("allow_tool_prefixes"))),
            ]
            for pattern in _missing_scope_map_tool_patterns(patterns, tool_set):
                missing.append({"profile": profile.get("id"), "rule": rule.get("id"), "pattern": pattern})
    return missing


def _auth_policy_profiles(auth: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    profiles: list[Mapping[str, Any]] = [{"id": auth.get("profile_id") or "default", **dict(auth)}]
    for issuer in _sequence(auth.get("issuers")):
        if isinstance(issuer, Mapping):
            profiles.append({"id": issuer.get("id") or issuer.get("issuer") or "issuer", **dict(issuer)})
    return profiles


def _auth_has_scope_map(auth: Mapping[str, Any]) -> bool:
    return any(bool(_mapping(profile.get("scope_map"))) for profile in _auth_policy_profiles(auth))


def _auth_has_claim_policy(auth: Mapping[str, Any]) -> bool:
    return any(_mapping(profile.get("claim_policy")).get("enabled") is True for profile in _auth_policy_profiles(auth))


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_pack_path(path: Path, base_dir: Path) -> str:
    try:
        return os.path.relpath(path.resolve(), base_dir.resolve())
    except OSError:
        return str(path)


def _resolve_pack_path(pack_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("pack path reference must be a non-empty string")
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    return (pack_path / path).resolve()


def _safe_artifact_name(value: str) -> str:
    return _check_slug(value).strip("-") or "artifact"


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

    contract = _mapping(status.get("contract"))
    if contract.get("required") is True:
        ok = (
            contract.get("exists") is not False
            and contract.get("file_valid") is not False
            and contract.get("drifted") is not True
        )
        if contract.get("drifted") is True:
            message = "required share contract has drifted from current share state"
        elif contract.get("file_valid") is False:
            message = "required share contract is invalid"
        elif contract.get("exists") is False:
            message = "required share contract file is missing"
        else:
            message = "required share contract matches current share state"
        _add_share_doctor_check(
            checks,
            "status.share_contract_bound",
            ok,
            message,
            component="status",
            details={
                "path": contract.get("path"),
                "digest": contract.get("digest"),
                "binding_digest": contract.get("binding_digest"),
                "current_binding_digest": contract.get("current_binding_digest"),
                "signed": contract.get("signed"),
                "key_id": contract.get("key_id"),
            },
        )
    else:
        _add_share_doctor_check(
            checks,
            "status.share_contract_bound",
            None,
            "share contract binding is not required",
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


def _share_cloudflare_profile_doctor_checks(
    proxy_config: Mapping[str, Any] | None,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    result: dict[str, Any] = {"ok": True, "profile": None, "provider": None}
    if proxy_config is None:
        return {"result": result, "checks": checks, "recommendations": recommendations}

    session = _mapping(manifest.get("session"))
    provider = str(session.get("provider") or proxy_config.get("tunnel_provider") or "generic")
    profile = proxy_config.get("cloudflare_access_profile") or session.get("cloudflare_access_profile")
    profile = str(profile) if profile else None
    if provider != "cloudflare" and profile is None:
        return {"result": result, "checks": checks, "recommendations": recommendations}

    auth = _mapping(proxy_config.get("auth"))
    access_mode = str(proxy_config.get("cloudflare_access") or "off")
    client_headers = _share_auth_client_headers(manifest, {})
    cf_client_header_names = sorted(name for name in client_headers if name in _CLOUDFLARE_ACCESS_HEADER_NAMES)
    result = {
        "ok": True,
        "profile": profile,
        "provider": provider,
        "access_mode": access_mode,
        "auth_mode": auth.get("mode"),
        "client_cloudflare_headers": cf_client_header_names,
    }

    profile_configured = profile in {"access-gate", "service-token", "oauth-resource", "audit"}
    _add_share_doctor_check(
        checks,
        "cloudflare.profile.configured",
        profile_configured,
        f"Cloudflare profile is {profile}" if profile_configured else "Cloudflare profile is not configured",
        component="cloudflare",
        details={"provider": provider, "profile": profile},
    )
    if not profile_configured:
        recommendations.append(
            "Recreate or update this share with --cloudflare-profile access-gate, service-token, "
            "oauth-resource, or audit."
        )
        result["ok"] = False
        return {"result": result, "checks": checks, "recommendations": recommendations}

    if profile in {"access-gate", "service-token"}:
        _add_cloudflare_access_gate_checks(
            checks,
            recommendations,
            proxy_config,
            auth,
            profile=profile,
        )
        if profile == "service-token":
            has_client_id = "cf-access-client-id" in client_headers
            has_client_secret = "cf-access-client-secret" in client_headers
            env_placeholders = all(
                str(client_headers.get(name, "")).startswith("${")
                for name in ("cf-access-client-id", "cf-access-client-secret")
                if name in client_headers
            )
            _add_share_doctor_check(
                checks,
                "cloudflare.service_token.client_headers",
                has_client_id and has_client_secret and env_placeholders,
                "Cloudflare Access service-token client headers use environment placeholders"
                if has_client_id and has_client_secret and env_placeholders
                else "Cloudflare Access service-token client headers are missing or not env placeholders",
                component="cloudflare",
                details={"headers": cf_client_header_names},
            )
            if not has_client_id or not has_client_secret:
                recommendations.append(
                    "Use the generated service-token client config or add CF-Access-Client-Id and "
                    "CF-Access-Client-Secret as environment-placeholder headers."
                )
    elif profile == "oauth-resource":
        auth_enabled = auth.get("mode") == "oauth-resource"
        _add_share_doctor_check(
            checks,
            "cloudflare.oauth_resource.auth_enabled",
            auth_enabled,
            "MCP OAuth protected-resource mode is enabled"
            if auth_enabled
            else "MCP OAuth protected-resource mode is not enabled",
            component="cloudflare",
            details={"auth_mode": auth.get("mode")},
        )
        access_does_not_block = access_mode != "enforce"
        _add_share_doctor_check(
            checks,
            "cloudflare.oauth_resource.access_not_enforced",
            access_does_not_block,
            "Cloudflare Access is not enforced in front of MCP OAuth discovery"
            if access_does_not_block
            else "Cloudflare Access enforcement can block MCP OAuth discovery",
            component="cloudflare",
            details={"cloudflare_access": access_mode},
        )
        no_cf_client_headers = not cf_client_header_names
        _add_share_doctor_check(
            checks,
            "cloudflare.oauth_resource.no_access_client_headers",
            no_cf_client_headers,
            "MCP OAuth client config does not embed Cloudflare Access client headers"
            if no_cf_client_headers
            else "Cloudflare Access client headers are embedded in an MCP OAuth client config",
            component="cloudflare",
            details={"headers": cf_client_header_names},
        )
        anti_passthrough = auth.get("strip_authorization_upstream") is True
        _add_share_doctor_check(
            checks,
            "cloudflare.oauth_resource.anti_passthrough",
            anti_passthrough,
            "caller Authorization headers are stripped before upstream forwarding"
            if anti_passthrough
            else "caller Authorization headers may be forwarded upstream",
            component="cloudflare",
        )
        if not auth_enabled:
            recommendations.append(
                "Regenerate with --cloudflare-profile oauth-resource --auth-issuer <issuer> or merge the "
                "generated share auth init snippet into snulbug.toml."
            )
        if not access_does_not_block:
            recommendations.append(
                "Keep Cloudflare Access in audit/off mode for MCP OAuth resource shares unless OAuth metadata "
                "and discovery paths are explicitly exempted."
            )
    elif profile == "audit":
        audit_mode = access_mode == "audit"
        _add_share_doctor_check(
            checks,
            "cloudflare.audit.mode",
            audit_mode,
            "Cloudflare Access audit mode is enabled"
            if audit_mode
            else "Cloudflare Access audit profile requires cloudflare_access = 'audit'",
            component="cloudflare",
            details={"cloudflare_access": access_mode},
        )
        no_cf_client_headers = not cf_client_header_names
        _add_share_doctor_check(
            checks,
            "cloudflare.audit.no_access_client_headers",
            no_cf_client_headers,
            "audit profile does not embed Cloudflare Access service-token headers"
            if no_cf_client_headers
            else "audit profile embeds Cloudflare Access service-token headers",
            component="cloudflare",
            details={"headers": cf_client_header_names},
        )

    result["ok"] = _checks_ok(checks, component="cloudflare")
    return {"result": result, "checks": checks, "recommendations": _unique_strings(recommendations)}


def _add_cloudflare_access_gate_checks(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    proxy_config: Mapping[str, Any],
    auth: Mapping[str, Any],
    *,
    profile: str,
) -> None:
    access_enforced = proxy_config.get("cloudflare_access") == "enforce"
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.enforced",
        access_enforced,
        "Cloudflare Access is enforced at the snulbug origin"
        if access_enforced
        else "Cloudflare Access gate profile requires cloudflare_access = 'enforce'",
        component="cloudflare",
        details={"cloudflare_access": proxy_config.get("cloudflare_access"), "profile": profile},
    )
    require_jwt = proxy_config.get("cloudflare_access_require_jwt") is True
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.jwt_required",
        require_jwt,
        "Cloudflare Access JWT assertion is required"
        if require_jwt
        else "Cloudflare Access JWT assertion is not required",
        component="cloudflare",
    )
    validate_jwt = proxy_config.get("cloudflare_access_validate_jwt") is True
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.jwt_validated",
        validate_jwt,
        "Cloudflare Access JWT assertion is cryptographically validated"
        if validate_jwt
        else "Cloudflare Access JWT assertion validation is disabled",
        component="cloudflare",
    )
    team_domain = bool(proxy_config.get("cloudflare_access_team_domain"))
    audience = bool(proxy_config.get("cloudflare_access_audience"))
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.jwt_config",
        team_domain and audience,
        "Cloudflare Access team domain and AUD tag are configured"
        if team_domain and audience
        else "Cloudflare Access team domain or AUD tag is missing",
        component="cloudflare",
        details={
            "team_domain": proxy_config.get("cloudflare_access_team_domain"),
            "audience_configured": audience,
        },
    )
    require_cf_ray = proxy_config.get("cloudflare_access_require_cf_ray") is True
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.cf_ray_required",
        require_cf_ray,
        "CF-Ray is required so requests are tied to Cloudflare edge traffic"
        if require_cf_ray
        else "CF-Ray is not required for Cloudflare Access profile",
        component="cloudflare",
    )
    not_oauth_resource = auth.get("mode") != "oauth-resource"
    _add_share_doctor_check(
        checks,
        "cloudflare.access_gate.not_wrapping_oauth_resource",
        not_oauth_resource,
        "Cloudflare Access profile is not wrapping MCP OAuth resource mode"
        if not_oauth_resource
        else "Cloudflare Access enforcement can block MCP OAuth protected-resource discovery",
        component="cloudflare",
        details={"auth_mode": auth.get("mode")},
    )
    if not validate_jwt or not team_domain or not audience:
        recommendations.append(
            "Set cloudflare_access_team_domain and cloudflare_access_audience, and keep "
            "cloudflare_access_validate_jwt = true for Cloudflare Access gate profiles."
        )
    if not not_oauth_resource:
        recommendations.append(
            "Use --cloudflare-profile oauth-resource for MCP OAuth shares, or remove [mcp.auth] "
            "OAuth protected-resource mode from this Access-gated share."
        )


def _checks_ok(checks: Sequence[Mapping[str, Any]], *, component: str) -> bool:
    return all(check.get("status") != "fail" for check in checks if check.get("component") == component)


def _share_tailscale_profile_doctor_checks(
    proxy_config: Mapping[str, Any] | None,
    manifest: Mapping[str, Any],
    status: Mapping[str, Any],
    *,
    public_url: str | None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    result: dict[str, Any] = {"ok": True, "profile": None, "provider": None}
    if proxy_config is None:
        return {"result": result, "checks": checks, "recommendations": recommendations}

    session = _mapping(manifest.get("session"))
    provider = str(session.get("provider") or proxy_config.get("tunnel_provider") or "generic")
    profile = proxy_config.get("tailscale_profile") or session.get("tailscale_profile")
    profile = str(profile) if profile else None
    if provider != "tailscale" and profile is None:
        return {"result": result, "checks": checks, "recommendations": recommendations}

    client_headers = _share_auth_client_headers(manifest, {})
    auth = _mapping(proxy_config.get("auth"))
    lease = _mapping(status.get("lease"))
    lease_summary = _mapping(status.get("leases"))
    result = {
        "ok": True,
        "profile": profile,
        "provider": provider,
        "auth_mode": auth.get("mode"),
        "lease_required": proxy_config.get("lease_required"),
        "active_leases": lease_summary.get("active_count"),
    }

    profile_configured = profile in {"funnel-public", "serve-tailnet", "oauth-resource"}
    _add_share_doctor_check(
        checks,
        "tailscale.profile.configured",
        profile_configured,
        f"Tailscale profile is {profile}" if profile_configured else "Tailscale profile is not configured",
        component="tailscale",
        details={"provider": provider, "profile": profile},
    )
    if not profile_configured:
        recommendations.append(
            "Recreate or update this share with --tailscale-profile funnel-public, serve-tailnet, or oauth-resource."
        )
        result["ok"] = False
        return {"result": result, "checks": checks, "recommendations": recommendations}

    provider_matches = proxy_config.get("tunnel_provider") == "tailscale" or provider == "tailscale"
    _add_share_doctor_check(
        checks,
        "tailscale.provider.configured",
        provider_matches,
        "Tailscale tunnel provider is configured"
        if provider_matches
        else "Tailscale profile requires tunnel_provider = 'tailscale'",
        component="tailscale",
        details={"manifest_provider": provider, "config_provider": proxy_config.get("tunnel_provider")},
    )

    tsnet_url = _tailscale_url_is_tsnet(public_url)
    _add_share_doctor_check(
        checks,
        "tailscale.url.tsnet",
        tsnet_url,
        "public/client URL uses a Tailscale .ts.net HTTPS host"
        if tsnet_url
        else "public/client URL does not look like a Tailscale .ts.net HTTPS host",
        component="tailscale",
        details={"url": public_url},
        severity="warning" if profile == "serve-tailnet" else "error",
    )
    if not tsnet_url:
        recommendations.append(
            "Pass --hostname HOST.TAILNET.ts.net or --url https://HOST.TAILNET.ts.net/mcp for Tailscale shares."
        )

    bearer_present = str(client_headers.get("authorization") or "").startswith("Bearer ")
    _add_share_doctor_check(
        checks,
        "tailscale.client.bearer",
        bearer_present,
        "MCP client config includes snulbug bearer authorization"
        if bearer_present
        else "MCP client config is missing snulbug bearer authorization",
        component="tailscale",
    )

    if profile == "funnel-public":
        _add_tailscale_lease_checks(
            checks,
            recommendations,
            proxy_config,
            lease,
            required=True,
            component="tailscale",
            prefix="tailscale.funnel_public",
        )
        not_oauth_resource = auth.get("mode") != "oauth-resource"
        _add_share_doctor_check(
            checks,
            "tailscale.funnel_public.not_oauth_resource",
            not_oauth_resource,
            "Funnel public profile is using bearer/lease policy rather than MCP OAuth mode"
            if not_oauth_resource
            else "Use --tailscale-profile oauth-resource for MCP OAuth shares",
            component="tailscale",
            details={"auth_mode": auth.get("mode")},
        )
    elif profile == "serve-tailnet":
        _add_tailscale_lease_checks(
            checks,
            recommendations,
            proxy_config,
            lease,
            required=False,
            component="tailscale",
            prefix="tailscale.serve_tailnet",
        )
        not_oauth_resource = auth.get("mode") != "oauth-resource"
        _add_share_doctor_check(
            checks,
            "tailscale.serve_tailnet.not_oauth_resource",
            not_oauth_resource,
            "Serve tailnet profile is using bearer policy rather than MCP OAuth mode"
            if not_oauth_resource
            else "Use --tailscale-profile oauth-resource for MCP OAuth shares",
            component="tailscale",
            severity="warning",
            details={"auth_mode": auth.get("mode")},
        )
    elif profile == "oauth-resource":
        auth_enabled = auth.get("mode") == "oauth-resource"
        _add_share_doctor_check(
            checks,
            "tailscale.oauth_resource.auth_enabled",
            auth_enabled,
            "MCP OAuth protected-resource mode is enabled"
            if auth_enabled
            else "MCP OAuth protected-resource mode is not enabled",
            component="tailscale",
            details={"auth_mode": auth.get("mode")},
        )
        resource_match = _tailscale_auth_resource_matches_url(auth, public_url)
        _add_share_doctor_check(
            checks,
            "tailscale.oauth_resource.resource_matches_url",
            resource_match,
            "MCP OAuth resource/audience includes the Tailscale client URL"
            if resource_match
            else "MCP OAuth resource/audience does not include the Tailscale client URL",
            component="tailscale",
            details={
                "url": public_url,
                "resource": auth.get("resource"),
                "resource_aliases": _sequence(auth.get("resource_aliases")),
                "audience": auth.get("audience"),
                "audiences": _sequence(auth.get("audiences")),
            },
        )
        anti_passthrough = auth.get("strip_authorization_upstream") is True
        _add_share_doctor_check(
            checks,
            "tailscale.oauth_resource.anti_passthrough",
            anti_passthrough,
            "caller Authorization headers are stripped before upstream forwarding"
            if anti_passthrough
            else "caller Authorization headers may be forwarded upstream",
            component="tailscale",
        )
        _add_tailscale_lease_checks(
            checks,
            recommendations,
            proxy_config,
            lease,
            required=False,
            component="tailscale",
            prefix="tailscale.oauth_resource",
        )
        if not auth_enabled:
            recommendations.append(
                "Regenerate with --tailscale-profile oauth-resource --auth-issuer <issuer> or merge an MCP OAuth "
                "protected-resource auth config into snulbug.toml."
            )
        if not resource_match:
            recommendations.append(
                "Set mcp.auth.resource and mcp.auth.audience to the exact Tailscale MCP URL, or add explicit aliases."
            )

    result["ok"] = _checks_ok(checks, component="tailscale")
    return {"result": result, "checks": checks, "recommendations": _unique_strings(recommendations)}


def _add_tailscale_lease_checks(
    checks: list[dict[str, Any]],
    recommendations: list[str],
    proxy_config: Mapping[str, Any],
    lease: Mapping[str, Any],
    *,
    required: bool,
    component: str,
    prefix: str,
) -> None:
    lease_required = proxy_config.get("lease_required") is True
    active_lease = lease.get("active") is True
    severity = "error" if required else "warning"
    _add_share_doctor_check(
        checks,
        f"{prefix}.lease_required",
        lease_required,
        "task leases are required for MCP tools/call"
        if lease_required
        else "task leases are not required for MCP tools/call",
        component=component,
        severity=severity,
    )
    _add_share_doctor_check(
        checks,
        f"{prefix}.active_lease",
        active_lease,
        "an active task lease exists" if active_lease else "no active task lease exists for this share",
        component=component,
        severity=severity,
        details={"lease": lease},
    )
    if required and (not lease_required or not active_lease):
        recommendations.append(
            "Keep lease_required = true and create an active task lease before sharing a public Tailscale Funnel URL."
        )


def _tailscale_url_is_tsnet(url: str | None) -> bool:
    if not isinstance(url, str) or not url:
        return False
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    return parsed.scheme == "https" and (host.endswith(".ts.net") or ".ts.net" in host)


def _tailscale_auth_resource_matches_url(auth: Mapping[str, Any], url: str | None) -> bool:
    if not isinstance(url, str) or not url:
        return False
    resources = [
        *([str(auth["resource"])] if isinstance(auth.get("resource"), str) and auth.get("resource") else []),
        *(str(item) for item in _sequence(auth.get("resource_aliases"))),
    ]
    audiences = [
        *([str(auth["audience"])] if isinstance(auth.get("audience"), str) and auth.get("audience") else []),
        *(str(item) for item in _sequence(auth.get("audiences"))),
    ]
    return _url_in_values(url, resources) and _url_in_values(url, audiences)


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


def _append_prefixed_checks(
    target: list[dict[str, Any]],
    checks: Any,
    *,
    prefix: str,
    component: str,
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


def _share_public_gateway_status(
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
    *,
    timeout: float,
    live_checks: bool,
) -> dict[str, Any]:
    tunnel = _mapping(session_model.get("tunnel"))
    client = _mapping(manifest.get("client"))
    provider = str(tunnel.get("provider") or "").strip()
    url = tunnel.get("public_url") or tunnel.get("client_url") or client.get("url")
    default_endpoint = False
    if provider and isinstance(url, str) and url:
        try:
            default_endpoint = get_tunnel_provider(provider).is_default_public_endpoint(url)
        except ValueError:
            default_endpoint = False
    configured = isinstance(url, str) and bool(url) and not default_endpoint
    result: dict[str, Any] = {
        "configured": configured,
        "url": url if configured else None,
        "provider": provider or tunnel.get("provider"),
        "checked": bool(live_checks and configured),
        "reachable": None,
    }
    if not result["checked"]:
        return result
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


def _share_schema_catalog_context(
    share_dir: Path,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
) -> dict[str, Any]:
    from .mcp_schemas import normalize_mcp_schema_catalog

    sources: list[dict[str, Any]] = []
    tools_by_name: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for candidate in _share_schema_catalog_candidates(share_dir, manifest, session_model):
        candidate_path = _resolve_share_path(share_dir, candidate.get("path"))
        path_key = str(candidate_path)
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)
        source = {
            "path": str(candidate_path),
            "source": candidate.get("source"),
            "explicit": bool(candidate.get("explicit")),
            "exists": candidate_path.is_file(),
            "loaded": False,
        }
        if not candidate_path.is_file():
            if candidate.get("explicit"):
                source["error"] = "schema catalog not found"
                sources.append(source)
            continue
        try:
            catalog = normalize_mcp_schema_catalog(_read_json(candidate_path))
            surfaces = _mapping(catalog.get("surfaces"))
            tools = [
                item
                for item in _auth_schema_surface_items(surfaces.get("tools"))
                if isinstance(item, Mapping) and item.get("name")
            ]
            source.update(
                {
                    "loaded": True,
                    "ok": bool(catalog.get("ok")),
                    "hash": catalog.get("hash"),
                    "label": catalog.get("label"),
                    "tool_count": len(tools),
                    "summary": _jsonish_copy(catalog.get("summary") or {}),
                }
            )
            sources.append(source)
            for tool in tools:
                _merge_share_schema_tool(tools_by_name, tool, catalog=catalog, path=candidate_path)
        except Exception as exc:
            source["error"] = str(exc)
            sources.append(source)

    loaded_sources = [source for source in sources if source.get("loaded") is True]
    errors = [source for source in sources if source.get("error")]
    tools = sorted(tools_by_name.values(), key=lambda item: str(item.get("name") or ""))
    return {
        "sources": sources,
        "tools": tools,
        "summary": {
            "catalog_count": len(loaded_sources),
            "source_count": len(sources),
            "tool_count": len(tools),
            "errors": len(errors),
        },
    }


def _share_schema_catalog_candidates(
    share_dir: Path,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def add_ref(value: Any, *, source: str, explicit: bool = True) -> None:
        if isinstance(value, Mapping):
            for key in ("path", "file", "catalog", "schema_catalog"):
                if value.get(key):
                    add_ref(value.get(key), source=source, explicit=explicit)
                    return
            return
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            for item in value:
                add_ref(item, source=source, explicit=explicit)
            return
        if value is None or str(value) == "":
            return
        candidates.append({"path": str(value), "source": source, "explicit": explicit})

    files = _mapping(manifest.get("files"))
    evidence = _mapping(session_model.get("evidence"))
    paths = _mapping(session_model.get("paths"))
    add_ref(manifest.get("schemas"), source="manifest.schemas")
    for key in ("schema_catalog", "schema_catalogs", "schemas"):
        add_ref(files.get(key), source=f"manifest.files.{key}")
        add_ref(evidence.get(key), source=f"session.evidence.{key}")
        add_ref(paths.get(key), source=f"session.paths.{key}")

    for path in (
        share_dir / "traces" / "schemas.json",
        share_dir / "schemas.json",
    ):
        add_ref(path, source="share.default", explicit=False)
    for directory in (share_dir / "schemas", share_dir / ".snulbug" / "schemas"):
        if directory.is_dir():
            for path in sorted(directory.glob("*.json")):
                add_ref(path, source="share.default", explicit=False)
    return candidates


def _merge_share_schema_tool(
    tools_by_name: dict[str, dict[str, Any]],
    tool: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    path: Path,
) -> None:
    name = str(tool.get("name") or "")
    if not name:
        return
    catalog_hash = catalog.get("hash") if isinstance(catalog.get("hash"), str) else None
    tool_hash = tool.get("hash") if isinstance(tool.get("hash"), str) else None
    existing = tools_by_name.get(name)
    if existing is None:
        entry = dict(tool)
        entry["schema_hash"] = tool_hash
        entry["schema_hashes"] = [tool_hash] if tool_hash else []
        entry["catalog_hashes"] = [catalog_hash] if catalog_hash else []
        entry["catalog_paths"] = [str(path)]
        entry["schema_variants"] = len(set(entry["schema_hashes"]))
        tools_by_name[name] = entry
        return

    if not existing.get("description") and tool.get("description"):
        existing["description"] = tool.get("description")
    for key in ("inputSchema", "outputSchema", "annotations"):
        if not existing.get(key) and tool.get(key):
            existing[key] = tool.get(key)
    if tool_hash:
        existing["schema_hashes"] = sorted({*map(str, _sequence(existing.get("schema_hashes"))), tool_hash})
        existing.setdefault("schema_hash", tool_hash)
    if catalog_hash:
        existing["catalog_hashes"] = sorted({*map(str, _sequence(existing.get("catalog_hashes"))), catalog_hash})
    existing["catalog_paths"] = sorted({*map(str, _sequence(existing.get("catalog_paths"))), str(path)})
    existing["schema_variants"] = len(set(_sequence(existing.get("schema_hashes"))))


def _share_tool_risk_inputs(
    observed_tools: Any,
    schema_catalogs: Mapping[str, Any],
) -> list[dict[str, Any]]:
    observed_counts = _share_observed_tool_counts(observed_tools)
    inputs: list[dict[str, Any]] = []
    schema_names: set[str] = set()
    for tool in _sequence(schema_catalogs.get("tools")):
        if not isinstance(tool, Mapping):
            continue
        name = str(tool.get("name") or "")
        if not name:
            continue
        schema_names.add(name)
        count = observed_counts.get(name, 0)
        entry = dict(tool)
        entry["count"] = count
        entry["evidence_sources"] = ["schema", *(("observed",) if count else ())]
        entry["confidence"] = "high" if count else "medium"
        inputs.append(entry)
    for name, count in sorted(observed_counts.items()):
        if name in schema_names:
            continue
        inputs.append({"name": name, "count": count, "evidence_sources": ["observed"], "confidence": "medium"})
    return inputs


def _share_observed_tool_counts(observed_tools: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in _sequence(observed_tools):
        if not isinstance(item, Mapping):
            continue
        name = item.get("value") or item.get("name")
        if name is None or str(name) == "":
            continue
        counts[str(name)] = counts.get(str(name), 0) + int(item.get("count") or 0)
    return counts


def _share_schema_catalog_status(schema_catalogs: Mapping[str, Any]) -> dict[str, Any]:
    summary = _mapping(schema_catalogs.get("summary"))
    sources = [
        {
            key: source.get(key)
            for key in ("path", "source", "explicit", "exists", "loaded", "ok", "hash", "label", "tool_count", "error")
            if source.get(key) is not None
        }
        for source in _sequence(schema_catalogs.get("sources"))
        if isinstance(source, Mapping)
    ]
    return {
        "catalog_count": int(summary.get("catalog_count", 0) or 0),
        "source_count": int(summary.get("source_count", 0) or 0),
        "tool_count": int(summary.get("tool_count", 0) or 0),
        "errors": int(summary.get("errors", 0) or 0),
        "sources": sources,
    }


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


def _share_contract_status(
    share_dir: Path,
    manifest: Mapping[str, Any],
    session_model: Mapping[str, Any],
) -> dict[str, Any]:
    runtime_contract = _mapping(_mapping(manifest.get("runtime")).get("contract")) or _mapping(
        _mapping(session_model.get("runtime")).get("contract")
    )
    generated_contract = _mapping(_mapping(manifest.get("contracts")).get("last"))
    source = runtime_contract or generated_contract
    if not source:
        return {"required": False, "configured": False}
    result: dict[str, Any] = {
        "configured": True,
        "required": bool(source.get("contract_required", runtime_contract is not None)),
        "path": source.get("contract_path"),
        "digest": source.get("contract_digest"),
        "binding_digest": source.get("contract_binding_digest"),
        "document_digest": source.get("contract_document_digest"),
        "key_id": source.get("contract_key_id"),
        "signed": source.get("contract_signed"),
        "verified": source.get("contract_verified"),
        "drifted": None,
    }
    path = source.get("contract_path")
    if isinstance(path, str) and path:
        resolved = _resolve_share_path(share_dir, path)
        result["path"] = str(resolved)
        result["exists"] = resolved.is_file()
        if resolved.is_file():
            try:
                loaded = load_share_contract(resolved)
                result["file_valid"] = True
                result["file_binding_digest"] = loaded.get("binding_digest")
            except Exception as exc:
                result["file_valid"] = False
                result["error"] = str(exc)
    if source.get("contract_binding_digest"):
        try:
            current = share_contract(share_dir, live_checks=False, include_doctor=False)["contract"]
            result["current_binding_digest"] = current.get("binding_digest")
            result["drifted"] = current.get("binding_digest") != source.get("contract_binding_digest")
        except Exception as exc:
            result["current_error"] = str(exc)
    return _drop_empty_json(result)


def _share_contract_payload(
    *,
    share_dir: Path,
    manifest: Mapping[str, Any],
    status: Mapping[str, Any],
    proxy_summary: Mapping[str, Any],
    doctor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    session = _mapping(manifest.get("session"))
    session_model = _mapping(status.get("session_model"))
    health = _mapping(manifest.get("health"))
    return _drop_empty_json(
        {
            "schema": SHARE_CONTRACT_SCHEMA,
            "version": SHARE_CONTRACT_VERSION,
            "generated_at": _now_iso(),
            "share": {
                "id": session.get("id") or session_model.get("id"),
                "state": status.get("state"),
                "directory": str(share_dir),
                "created_at": manifest.get("created_at"),
                "updated_at": manifest.get("updated_at"),
                "task": session.get("task"),
                "preset": session.get("preset"),
                "provider": session.get("provider"),
                "ttl": session.get("ttl"),
            },
            "client": _share_contract_client(manifest.get("client")),
            "gateway": _share_contract_gateway(status.get("gateway"), session_model=session_model),
            "auth": proxy_summary.get("auth"),
            "cloudflare_access": proxy_summary.get("cloudflare_access"),
            "tailscale": proxy_summary.get("tailscale"),
            "upstream_auth": proxy_summary.get("upstream_auth"),
            "policy": _share_contract_policy(status.get("policy")),
            "lease": _share_contract_lease(status.get("lease"), status.get("leases"), session=session),
            "upstreams": _share_contract_upstreams(status.get("upstreams")),
            "members": _share_contract_members(status.get("members")),
            "tunnel": status.get("tunnel_doctor"),
            "health": {
                "last_checked_at": health.get("last_checked_at"),
                "last_summary": health.get("last_summary"),
                "last_doctor_ok": _mapping(health.get("share_doctor")).get("ok"),
                "doctor": _share_contract_doctor(doctor),
            },
            "evidence": {
                "traffic": _share_contract_traffic(status.get("traffic")),
                "tool_risks": status.get("tool_risks"),
                "recordings": status.get("recordings"),
                "amendments": _share_contract_amendments(status.get("amendments")),
                "findings": status.get("findings"),
            },
            "commands": _share_contract_commands(status.get("commands")),
            "files": status.get("files"),
            "config": proxy_summary.get("config"),
        }
    )


def _share_contract_client(value: Any) -> dict[str, Any]:
    client = _mapping(value)
    headers = _mapping(client.get("headers"))
    return _drop_empty_json(
        {
            "name": client.get("name"),
            "url": client.get("url"),
            "config": client.get("config"),
            "header_names": sorted(str(key) for key in headers),
            "headers": {str(key): SECRET_REPLACEMENT for key in headers},
        }
    )


def _share_contract_gateway(value: Any, *, session_model: Mapping[str, Any]) -> dict[str, Any]:
    gateway = dict(_mapping(value))
    model_gateway = _mapping(session_model.get("gateway"))
    for key in ("host", "port", "local_url", "config", "fabric_config", "state_store"):
        if model_gateway.get(key) is not None:
            gateway.setdefault(key, model_gateway.get(key))
    return _drop_empty_json(gateway)


def _share_contract_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value)
    return _drop_empty_json(
        {
            "bundle": policy.get("bundle"),
            "active_policy": policy.get("active_policy"),
            "lifecycle_state": policy.get("lifecycle_state"),
            "lifecycle_signed": policy.get("lifecycle_signed"),
            "lifecycle_signature_key_id": _mapping(policy.get("lifecycle_signature")).get("key_id"),
            "last_amendment": policy.get("last_amendment"),
            "last_lifecycle": policy.get("last_lifecycle"),
        }
    )


def _share_contract_lease(value: Any, summary: Any, *, session: Mapping[str, Any]) -> dict[str, Any]:
    lease = _mapping(value)
    leases_summary = _mapping(summary)
    current = _mapping(leases_summary.get("current"))
    return _drop_empty_json(
        {
            "required": session.get("lease_required"),
            "header": session.get("lease_header"),
            "file": lease.get("file") or leases_summary.get("file"),
            "id": lease.get("id") or current.get("id"),
            "active": lease.get("active"),
            "active_count": leases_summary.get("active_count"),
            "expires_at": current.get("expires_at"),
            "task": current.get("task"),
            "allow_tools": current.get("allow_tools"),
            "allow_paths": current.get("allow_paths"),
            "allow_hosts": current.get("allow_hosts"),
            "allow_commands": current.get("allow_commands"),
            "max_calls": current.get("max_calls"),
            "used_calls": current.get("used_calls"),
        }
    )


def _share_contract_upstreams(value: Any) -> list[dict[str, Any]]:
    upstreams = []
    for item in _sequence(value):
        upstream = _mapping(item)
        upstreams.append(
            _drop_empty_json(
                {
                    "name": upstream.get("name"),
                    "url": upstream.get("url"),
                    "transport": upstream.get("transport"),
                    "route": upstream.get("route"),
                    "member_id": upstream.get("member_id"),
                    "reachable": upstream.get("reachable"),
                    "checked": upstream.get("checked"),
                    "status": upstream.get("status"),
                    "health": upstream.get("health"),
                }
            )
        )
    return upstreams


def _share_contract_members(value: Any) -> dict[str, Any]:
    members = _mapping(value)
    attachments = []
    for item in _sequence(members.get("attachments")):
        attachment = _mapping(item)
        attachments.append(
            _drop_empty_json(
                {
                    "member_id": attachment.get("member_id"),
                    "kind": attachment.get("kind"),
                    "status": attachment.get("status"),
                    "role": attachment.get("role"),
                    "upstreams": attachment.get("upstreams"),
                    "labels": attachment.get("labels"),
                }
            )
        )
    return _drop_empty_json(
        {
            "registry": members.get("registry"),
            "registry_key": members.get("registry_key"),
            "discovery_provider": members.get("discovery_provider"),
            "attachments": attachments,
        }
    )


def _share_contract_traffic(value: Any) -> dict[str, Any]:
    traffic = _mapping(value)
    return _drop_empty_json(
        {
            "source": traffic.get("source"),
            "source_kind": traffic.get("source_kind"),
            "exists": traffic.get("exists"),
            "event_count": traffic.get("event_count"),
            "allowed": traffic.get("allowed"),
            "blocked": traffic.get("blocked"),
            "confirmed": traffic.get("confirmed"),
            "confirmation_approved": traffic.get("confirmation_approved"),
            "confirmation_denied": traffic.get("confirmation_denied"),
            "redacted_events": traffic.get("redacted_events"),
            "response_redacted": traffic.get("response_redacted"),
            "record_redacted": traffic.get("record_redacted"),
            "methods": traffic.get("methods"),
            "tools": traffic.get("tools"),
            "clients": traffic.get("clients"),
            "source_ips": traffic.get("source_ips"),
            "inspection": _share_contract_inspection(traffic.get("inspection")),
            "inspection_error": traffic.get("inspection_error"),
        }
    )


def _share_contract_inspection(value: Any) -> dict[str, Any]:
    inspection = _mapping(value)
    return _drop_empty_json(
        {
            "ok": inspection.get("ok"),
            "event_count": inspection.get("event_count"),
            "methods": inspection.get("methods"),
            "tools": inspection.get("tools"),
            "findings": inspection.get("findings"),
        }
    )


def _share_contract_amendments(value: Any) -> dict[str, Any]:
    amendments = _mapping(value)
    return _drop_empty_json(
        {
            "candidate_count": amendments.get("candidate_count"),
            "last": amendments.get("last"),
        }
    )


def _share_contract_doctor(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return _drop_empty_json(
        {
            "ok": value.get("ok"),
            "summary": value.get("summary"),
            "recommendations": value.get("recommendations"),
            "checks": value.get("checks"),
            "conformance": value.get("conformance"),
        }
    )


def _share_contract_commands(value: Any) -> dict[str, Any]:
    commands = _mapping(value)
    result: dict[str, Any] = {}
    for key, command in commands.items():
        if command is None:
            continue
        name = str(key)
        if isinstance(command, Sequence) and not isinstance(command, str | bytes | bytearray):
            result[name] = [_redact_share_contract_command(str(item), name=name) for item in command]
        else:
            result[name] = _redact_share_contract_command(str(command), name=name)
    return result


def _redact_share_contract_command(command: str, *, name: str) -> str:
    if name == "export_token":
        return f"export {DEFAULT_SHARE_TOKEN_ENV}={SECRET_REPLACEMENT}"
    return command


def _share_contract_proxy_summary(share_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    files = _mapping(manifest.get("files"))
    config = files.get("config")
    if not isinstance(config, str) or not config:
        return {"config": {"loaded": False}}
    config_path = _resolve_share_path(share_dir, config)
    try:
        from .config import load_mcp_proxy_config
        from .credentials import credential_metadata

        proxy_config = load_mcp_proxy_config(config_path)
        return _drop_empty_json(
            {
                "config": {"path": str(config_path), "loaded": True},
                "auth": _share_contract_auth_config(proxy_config.get("auth")),
                "cloudflare_access": _share_contract_cloudflare_config(proxy_config),
                "tailscale": _share_contract_tailscale_config(proxy_config),
                "upstream_auth": _share_contract_upstream_auth(proxy_config, credential_metadata=credential_metadata),
            }
        )
    except Exception as exc:
        return {"config": {"path": str(config_path), "loaded": False, "error": str(exc)}}


def _share_contract_auth_config(value: Any) -> dict[str, Any]:
    auth = _mapping(value)
    issuers = []
    for issuer in _sequence(auth.get("issuers")):
        issuer_config = _mapping(issuer)
        issuers.append(_share_contract_auth_issuer_config(issuer_config))
    return _drop_empty_json(
        {
            "mode": auth.get("mode"),
            "resource": auth.get("resource"),
            "resource_aliases": auth.get("resource_aliases"),
            "issuer": auth.get("issuer"),
            "authorization_servers": auth.get("authorization_servers"),
            "audience": auth.get("audience"),
            "audiences": auth.get("audiences"),
            "required_scopes": auth.get("required_scopes"),
            "scopes_supported": auth.get("scopes_supported"),
            "token_validation": auth.get("token_validation"),
            "issuer_discovery": auth.get("issuer_discovery"),
            "jwks_url": auth.get("jwks_url"),
            "issuer_metadata_url": auth.get("issuer_metadata_url"),
            "resource_metadata_url": auth.get("resource_metadata_url"),
            "jwks_path": str(auth.get("jwks_path")) if auth.get("jwks_path") else None,
            "strip_authorization_upstream": auth.get("strip_authorization_upstream"),
            "scope_map": auth.get("scope_map"),
            "required_claims": auth.get("required_claims"),
            "claim_policy": _share_contract_claim_policy(auth.get("claim_policy")),
            "issuers": issuers,
        }
    )


def _share_contract_auth_issuer_config(value: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty_json(
        {
            "name": value.get("name"),
            "issuer": value.get("issuer"),
            "audience": value.get("audience"),
            "audiences": value.get("audiences"),
            "required_scopes": value.get("required_scopes"),
            "scopes_supported": value.get("scopes_supported"),
            "token_validation": value.get("token_validation"),
            "issuer_discovery": value.get("issuer_discovery"),
            "jwks_url": value.get("jwks_url"),
            "issuer_metadata_url": value.get("issuer_metadata_url"),
            "jwks_path": str(value.get("jwks_path")) if value.get("jwks_path") else None,
            "scope_map": value.get("scope_map"),
            "required_claims": value.get("required_claims"),
            "claim_policy": _share_contract_claim_policy(value.get("claim_policy")),
        }
    )


def _share_contract_claim_policy(value: Any) -> dict[str, Any]:
    claim_policy = _mapping(value)
    rules = []
    for rule in _sequence(claim_policy.get("rules")):
        rule_config = _mapping(rule)
        rules.append(
            _drop_empty_json(
                {
                    "name": rule_config.get("name"),
                    "claim": rule_config.get("claim"),
                    "matches": rule_config.get("matches"),
                    "tools": rule_config.get("tools"),
                    "methods": rule_config.get("methods"),
                    "upstreams": rule_config.get("upstreams"),
                    "effect": rule_config.get("effect"),
                }
            )
        )
    return _drop_empty_json(
        {
            "tenant_claim": claim_policy.get("tenant_claim"),
            "group_claim": claim_policy.get("group_claim"),
            "subject_claim": claim_policy.get("subject_claim"),
            "rules": rules,
        }
    )


def _share_contract_cloudflare_config(proxy_config: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty_json(
        {
            "profile": proxy_config.get("cloudflare_access_profile"),
            "mode": proxy_config.get("cloudflare_access"),
            "require_jwt": proxy_config.get("cloudflare_access_require_jwt"),
            "require_email": proxy_config.get("cloudflare_access_require_email"),
            "require_cf_ray": proxy_config.get("cloudflare_access_require_cf_ray"),
            "validate_jwt": proxy_config.get("cloudflare_access_validate_jwt"),
            "team_domain": proxy_config.get("cloudflare_access_team_domain"),
            "issuer": proxy_config.get("cloudflare_access_issuer"),
            "audience": proxy_config.get("cloudflare_access_audience"),
            "certs_url": proxy_config.get("cloudflare_access_certs_url"),
            "allowed_domains": proxy_config.get("cloudflare_access_allowed_domains"),
            "allowed_emails": proxy_config.get("cloudflare_access_allowed_emails"),
        }
    )


def _share_contract_tailscale_config(proxy_config: Mapping[str, Any]) -> dict[str, Any]:
    auth = _mapping(proxy_config.get("auth"))
    return _drop_empty_json(
        {
            "profile": proxy_config.get("tailscale_profile"),
            "provider": proxy_config.get("tunnel_provider"),
            "public_url": proxy_config.get("tunnel_public_url"),
            "lease_required": proxy_config.get("lease_required"),
            "lease_header": proxy_config.get("lease_header"),
            "auth_mode": auth.get("mode"),
            "strip_authorization_upstream": auth.get("strip_authorization_upstream"),
        }
    )


def _share_contract_upstream_auth(
    proxy_config: Mapping[str, Any],
    *,
    credential_metadata: Any,
) -> dict[str, Any]:
    upstreams = []
    for item in _sequence(proxy_config.get("upstreams")):
        upstream = _mapping(item)
        metadata = credential_metadata(upstream.get("credential"))
        if metadata:
            upstreams.append(
                _drop_empty_json(
                    {
                        "name": upstream.get("name"),
                        "url": upstream.get("url"),
                        "credential": metadata,
                    }
                )
            )
    return _drop_empty_json(
        {
            "strip_client_authorization": _mapping(proxy_config.get("auth")).get("strip_authorization_upstream"),
            "default": credential_metadata(proxy_config.get("upstream_credential")),
            "upstreams": upstreams,
        }
    )


def _finalize_share_contract(
    payload: Mapping[str, Any],
    *,
    sign: bool,
    secret: str | None,
    key_id: str,
) -> dict[str, Any]:
    contract = dict(_drop_empty_json(payload))
    contract["binding_digest"] = _share_contract_binding_digest(contract)
    contract["digest"] = _share_contract_digest(contract)
    if sign:
        if not secret:
            raise ValueError("share contract signing requires a non-empty secret")
        contract[SHARE_CONTRACT_SIGNATURE_FIELD] = {
            "algorithm": SHARE_CONTRACT_ALGORITHM,
            "key_id": key_id,
            "digest": contract["digest"],
            "value": _share_contract_signature_value(contract, secret),
        }
    return contract


def _share_contract_binding_digest(contract: Mapping[str, Any]) -> str:
    encoded = _share_contract_canonical_json(_share_contract_binding_payload(contract))
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _share_contract_binding_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    payload = _share_contract_payload_only(contract)
    payload.pop("generated_at", None)
    payload.pop("health", None)
    payload.pop("evidence", None)
    payload.pop("commands", None)
    payload.pop("files", None)
    payload.pop("config", None)
    share = dict(_mapping(payload.get("share")))
    for key in ("state", "directory", "created_at", "updated_at"):
        share.pop(key, None)
    if share:
        payload["share"] = share
    else:
        payload.pop("share", None)
    gateway = dict(_mapping(payload.get("gateway")))
    for key in ("checked", "reachable", "status", "error", "mcp_ok"):
        gateway.pop(key, None)
    if gateway:
        payload["gateway"] = gateway
    else:
        payload.pop("gateway", None)
    tunnel = dict(_mapping(payload.get("tunnel")))
    for key in ("checked", "last_checked_at", "ok", "summary", "recommendations"):
        tunnel.pop(key, None)
    if tunnel:
        payload["tunnel"] = tunnel
    else:
        payload.pop("tunnel", None)
    upstreams = []
    for item in _sequence(payload.get("upstreams")):
        upstream = dict(_mapping(item))
        for key in ("checked", "reachable", "status", "health", "error", "mcp_ok"):
            upstream.pop(key, None)
        if upstream:
            upstreams.append(upstream)
    if upstreams:
        payload["upstreams"] = upstreams
    else:
        payload.pop("upstreams", None)
    return _drop_empty_json(payload)


def _share_contract_digest(contract: Mapping[str, Any]) -> str:
    return (
        "sha256:" + hashlib.sha256(_share_contract_canonical_json(_share_contract_payload_only(contract))).hexdigest()
    )


def _share_contract_signature_value(contract: Mapping[str, Any], secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        _share_contract_canonical_json(_share_contract_payload_only(contract)),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _share_contract_payload_only(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in contract.items()
        if key not in {SHARE_CONTRACT_SIGNATURE_FIELD, "digest", "binding_digest"}
    }


def _share_contract_canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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


def _share_acceptance_target(status: Mapping[str, Any], *, invite_id: str | None) -> dict[str, Any]:
    invitations = [
        _mapping(invite)
        for invite in _sequence(_mapping(status.get("invitations")).get("items"))
        if isinstance(invite, Mapping)
    ]
    leases = [_mapping(lease) for lease in _sequence(_mapping(status.get("leases")).get("leases"))]
    leases_by_id = {str(lease.get("id")): lease for lease in leases if lease.get("id")}
    selected_invite = None
    for invite in invitations:
        if invite.get("revoked_at"):
            continue
        if invite_id and invite.get("id") != invite_id:
            continue
        selected_invite = invite
        break
    if selected_invite is not None:
        lease = leases_by_id.get(str(selected_invite.get("lease_id") or ""), {})
        return _drop_empty_json(
            {
                "kind": "invite",
                "id": selected_invite.get("id"),
                "label": selected_invite.get("recipient") or selected_invite.get("client_name"),
                "lease_id": selected_invite.get("lease_id"),
                "active": lease.get("active"),
                "capabilities": _string_list(selected_invite.get("capabilities") or lease.get("capabilities")),
                "allow_tools": _string_list(selected_invite.get("allow_tools") or lease.get("allow_tools")),
                "allow_paths": _string_list(selected_invite.get("allow_paths") or lease.get("allow_paths")),
                "task": selected_invite.get("task") or lease.get("task"),
                "expires_at": selected_invite.get("expires_at") or lease.get("expires_at"),
            }
        )
    for lease in leases:
        if lease.get("active") is True:
            return _drop_empty_json(
                {
                    "kind": "lease",
                    "id": lease.get("id"),
                    "label": lease.get("task") or lease.get("id"),
                    "lease_id": lease.get("id"),
                    "active": True,
                    "capabilities": _string_list(lease.get("capabilities")),
                    "allow_tools": _string_list(lease.get("allow_tools")),
                    "allow_paths": _string_list(lease.get("allow_paths")),
                    "task": lease.get("task"),
                    "expires_at": lease.get("expires_at"),
                }
            )
    return {}


def _share_acceptance_invite_checks(
    checks: list[dict[str, Any]],
    status: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
    invite_id: str | None,
) -> None:
    invitations = _mapping(status.get("invitations"))
    summary = _mapping(invitations.get("summary"))
    connection_summary = _mapping(invitations.get("connection_summary"))
    active_invites = int(summary.get("active", 0) or 0)
    active_leases = int(_mapping(status.get("leases")).get("active_count", 0) or 0)
    if invite_id and not target:
        _add_share_doctor_check(
            checks,
            "acceptance.invite_selected",
            False,
            f"selected invite was not found or is revoked: {invite_id}",
            component="acceptance",
        )
    else:
        _add_share_doctor_check(
            checks,
            "acceptance.active_grant",
            bool(target),
            "share has an active invite or lease for handoff"
            if target
            else "share has no active invite or lease for handoff",
            component="acceptance",
            details={"active_invites": active_invites, "active_leases": active_leases},
        )
    _add_share_doctor_check(
        checks,
        "acceptance.active_invite",
        active_invites > 0,
        f"{active_invites} active invite(s) available"
        if active_invites
        else "no active invite exists; lease-only handoff is possible but less explicit",
        component="acceptance",
        severity="warning",
        details={"connection_summary": dict(connection_summary)},
    )


def _share_acceptance_inspector_check(
    checks: list[dict[str, Any]],
    share_dir: Path,
    *,
    invite_id: str | None,
) -> None:
    try:
        setup = share_inspector_setup(share_dir, invite_id=invite_id, include_secrets=False)
        inspector = _mapping(setup.get("mcp_inspector"))
        cli = _mapping(inspector.get("cli"))
        ok = "tools/list" in str(cli.get("tools_list") or "") and str(inspector.get("url") or "")
        _add_share_doctor_check(
            checks,
            "acceptance.inspector_command",
            bool(ok),
            "MCP Inspector tools/list smoke command generated"
            if ok
            else "MCP Inspector tools/list smoke command could not be generated",
            component="acceptance",
        )
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "acceptance.inspector_command",
            False,
            f"MCP Inspector setup generation failed: {exc}",
            component="acceptance",
        )


def _share_acceptance_policy_path(share_dir: Path, status: Mapping[str, Any]) -> Path | None:
    policy = _mapping(status.get("policy"))
    value = policy.get("active_policy") or policy.get("path")
    if not value:
        return None
    return _resolve_share_path(share_dir, value)


def _share_acceptance_compile_policy(policy_path: Path | None, checks: list[dict[str, Any]]) -> Any:
    if policy_path is None:
        _add_share_doctor_check(
            checks,
            "acceptance.policy_compiles",
            False,
            "active policy path is not configured",
            component="acceptance",
        )
        return None
    try:
        script = compile_lua_file(policy_path)
    except Exception as exc:
        _add_share_doctor_check(
            checks,
            "acceptance.policy_compiles",
            False,
            f"active policy failed to compile: {exc}",
            component="acceptance",
            details={"policy": str(policy_path)},
        )
        return None
    _add_share_doctor_check(
        checks,
        "acceptance.policy_compiles",
        True,
        "active policy compiles",
        component="acceptance",
        details={"policy": str(policy_path)},
    )
    return script


def _share_acceptance_policy_checks(
    checks: list[dict[str, Any]],
    *,
    script: Any,
    status: Mapping[str, Any],
    target: Mapping[str, Any],
    tools: Sequence[Mapping[str, Any]],
) -> None:
    headers = _share_acceptance_client_headers(status)
    tools_list = _share_acceptance_simulate(
        script,
        _share_acceptance_mcp_request("tools/list", headers=headers),
        context={},
    )
    _add_share_acceptance_decision_check(
        checks,
        "acceptance.tools_list_allowed",
        tools_list,
        expected_allowed=True,
        component="acceptance",
        success="policy allows MCP tools/list",
        failure="policy blocks MCP tools/list",
    )
    if not target:
        _add_share_doctor_check(
            checks,
            "acceptance.representative_tool_allowed",
            None,
            "allowed tool simulation skipped because no active grant is available",
            component="acceptance",
        )
        _add_share_doctor_check(
            checks,
            "acceptance.unknown_tool_blocked",
            None,
            "unknown tool simulation skipped because no active grant is available",
            component="acceptance",
        )
        _add_share_doctor_check(
            checks,
            "acceptance.revoked_lease_blocked",
            None,
            "revoked lease simulation skipped because no active grant is available",
            component="acceptance",
        )
        return
    if target.get("kind") == "lease" and not _string_list(target.get("capabilities")):
        _add_share_doctor_check(
            checks,
            "acceptance.representative_tool_allowed",
            None,
            "representative tool simulation skipped because no capability-backed invite was selected",
            component="acceptance",
        )
        _add_share_doctor_check(
            checks,
            "acceptance.revoked_lease_blocked",
            None,
            "revoked lease simulation skipped because no capability-backed invite was selected",
            component="acceptance",
        )
        unknown_tool = {
            "name": "snulbug.acceptance.disallowed_write_probe",
            "risk": "high",
            "categories": ["mutation"],
            "properties": ["path", "content"],
            "required": ["path", "content"],
        }
        unknown_result = _share_acceptance_simulate(
            script,
            _share_acceptance_tool_request(unknown_tool, headers=headers),
            context=_share_acceptance_context(target, tool=unknown_tool, active=True),
        )
        _add_share_acceptance_decision_check(
            checks,
            "acceptance.unknown_tool_blocked",
            unknown_result,
            expected_allowed=False,
            component="acceptance",
            success="policy blocks an unknown high-risk tool",
            failure="policy allows an unknown high-risk tool",
        )
        return
    tool = _share_acceptance_primary_tool(tools, target)
    if tool:
        allowed_result = _share_acceptance_simulate(
            script,
            _share_acceptance_tool_request(tool, headers=headers),
            context=_share_acceptance_context(target, tool=tool, active=True),
        )
        _add_share_acceptance_decision_check(
            checks,
            "acceptance.representative_tool_allowed",
            allowed_result,
            expected_allowed=True,
            component="acceptance",
            success=f"policy allows representative tool {tool.get('name')}",
            failure=f"policy blocks representative tool {tool.get('name')}",
        )
        revoked_result = _share_acceptance_simulate(
            script,
            _share_acceptance_tool_request(tool, headers=headers),
            context=_share_acceptance_context(target, tool=tool, active=False, reason_code="lease.revoked"),
        )
        _add_share_acceptance_decision_check(
            checks,
            "acceptance.revoked_lease_blocked",
            revoked_result,
            expected_allowed=False,
            component="acceptance",
            success="policy blocks the same tool when the lease is revoked",
            failure="policy allows a tool even when the lease context is revoked",
        )
    else:
        _add_share_doctor_check(
            checks,
            "acceptance.representative_tool_allowed",
            None,
            "representative allowed tool simulation skipped because no tool surface is known",
            component="acceptance",
        )
        _add_share_doctor_check(
            checks,
            "acceptance.revoked_lease_blocked",
            None,
            "revoked lease simulation skipped because no tool surface is known",
            component="acceptance",
        )
    unknown_tool = {
        "name": "snulbug.acceptance.disallowed_write_probe",
        "risk": "high",
        "categories": ["mutation"],
        "properties": ["path", "content"],
        "required": ["path", "content"],
    }
    unknown_result = _share_acceptance_simulate(
        script,
        _share_acceptance_tool_request(unknown_tool, headers=headers),
        context=_share_acceptance_context(target, tool=unknown_tool, active=True),
    )
    _add_share_acceptance_decision_check(
        checks,
        "acceptance.unknown_tool_blocked",
        unknown_result,
        expected_allowed=False,
        component="acceptance",
        success="policy blocks an unknown high-risk tool",
        failure="policy allows an unknown high-risk tool",
    )


def _share_acceptance_client_headers(status: Mapping[str, Any]) -> dict[str, str]:
    headers = _mapping(_mapping(status.get("client")).get("headers"))
    result = {str(name).lower(): str(value) for name, value in headers.items() if value is not None}
    result.setdefault("content-type", "application/json")
    result.setdefault("accept", "application/json, text/event-stream")
    return result


def _share_acceptance_tools(status: Mapping[str, Any]) -> list[dict[str, Any]]:
    tools_by_name: dict[str, dict[str, Any]] = {}
    for tool in _sequence(_mapping(status.get("tool_risks")).get("tools")):
        if not isinstance(tool, Mapping):
            continue
        name = str(tool.get("name") or "")
        if name:
            tools_by_name[name] = {
                "name": name,
                "risk": tool.get("level") or tool.get("risk"),
                "categories": _string_list(tool.get("categories")),
                "properties": _string_list(tool.get("properties")),
                "required": _string_list(tool.get("required")),
                "schema_hash": tool.get("schema_hash"),
            }
    for lease in _sequence(_mapping(status.get("leases")).get("leases")):
        for name in _string_list(_mapping(lease).get("allow_tools")):
            if name and name != "*" and name not in tools_by_name:
                tools_by_name[name] = {"name": name, "source": "lease"}
    return sorted(tools_by_name.values(), key=lambda item: str(item.get("name") or ""))


def _share_acceptance_primary_tool(
    tools: Sequence[Mapping[str, Any]],
    target: Mapping[str, Any],
) -> Mapping[str, Any]:
    allowed = {str(name) for name in _string_list(target.get("allow_tools")) if name and name != "*"}
    if allowed:
        for tool in tools:
            if str(tool.get("name") or "") in allowed:
                return tool
        return {"name": sorted(allowed)[0], "source": "lease"}
    for tool in tools:
        if str(tool.get("risk") or "low") != "high":
            return tool
    return tools[0] if tools else {}


def _share_acceptance_mcp_request(method: str, *, headers: Mapping[str, str]) -> dict[str, Any]:
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": dict(headers),
        "body": json.dumps({"jsonrpc": "2.0", "id": f"acceptance-{method}", "method": method, "params": {}}),
    }


def _share_acceptance_tool_request(tool: Mapping[str, Any], *, headers: Mapping[str, str]) -> dict[str, Any]:
    name = str(tool.get("name") or "")
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": dict(headers),
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": f"acceptance-{_share_acceptance_slug(name)}",
                "method": "tools/call",
                "params": {"name": name, "arguments": _share_acceptance_sample_arguments(tool)},
            },
            sort_keys=True,
        ),
    }


def _share_acceptance_sample_arguments(tool: Mapping[str, Any]) -> dict[str, Any]:
    names = _string_list(tool.get("required")) or _string_list(tool.get("properties"))
    if not names and _share_acceptance_tool_needs_path(str(tool.get("name") or "")):
        names = ["path"]
    result: dict[str, Any] = {}
    for name in names[:8]:
        result[name] = _share_acceptance_sample_value(name)
    return result


def _share_acceptance_sample_value(name: str) -> Any:
    lowered = name.lower()
    if "content" in lowered or "text" in lowered:
        return "acceptance test"
    if lowered in {"paths", "files", "filenames"}:
        return ["README.md"]
    if "path" in lowered or "file" in lowered or "directory" in lowered:
        return "README.md"
    if "command" in lowered or lowered in {"cmd", "argv"}:
        return "status"
    if "url" in lowered or "host" in lowered:
        return "https://example.invalid"
    if "count" in lowered or "limit" in lowered or "max" in lowered:
        return 1
    if lowered.startswith("is_") or lowered.startswith("enable") or lowered.startswith("include"):
        return False
    return "example"


def _share_acceptance_tool_needs_path(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return any(term in normalized for term in ("read_file", "file_read", "list_project", "search_file", "grep"))


def _share_acceptance_context(
    target: Mapping[str, Any],
    *,
    tool: Mapping[str, Any],
    active: bool,
    reason_code: str | None = None,
) -> dict[str, Any]:
    return {
        "lease": _drop_empty_json(
            {
                "enabled": True,
                "required": True,
                "checked": True,
                "allowed": active,
                "method": "tools/call",
                "id": target.get("lease_id") or target.get("id"),
                "task": target.get("task"),
                "capabilities": _string_list(target.get("capabilities")),
                "allow_tools": _string_list(target.get("allow_tools")),
                "allow_paths": _string_list(target.get("allow_paths")),
                "expires_at": target.get("expires_at"),
                "reason_code": reason_code,
            }
        ),
        "intent": _drop_empty_json(
            {
                "name": tool.get("name"),
                "level": tool.get("risk"),
                "categories": _string_list(tool.get("categories")),
                "source": tool.get("source"),
            }
        ),
    }


def _share_acceptance_simulate(
    script: Any, request: Mapping[str, Any], *, context: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        normalized_request, _body_read = normalize_request(request)
        trace = script.decide_with_trace(normalized_request, context, None)
        decision = trace.decision
        action = str(decision.get("action") or "")
        return _drop_empty_json(
            {
                "ok": True,
                "allowed": _share_acceptance_action_allowed(action),
                "action": action,
                "status": decision.get("status"),
                "reason_code": decision.get("reason_code"),
                "reason": decision.get("reason") or decision.get("body"),
            }
        )
    except Exception as exc:
        return {"ok": False, "allowed": False, "action": "error", "reason_code": "simulation.error", "reason": str(exc)}


def _share_acceptance_action_allowed(action: str) -> bool:
    return action in CAPABILITY_MATCH_ALLOWED_ACTIONS


def _add_share_acceptance_decision_check(
    checks: list[dict[str, Any]],
    check_id: str,
    result: Mapping[str, Any],
    *,
    expected_allowed: bool,
    component: str,
    success: str,
    failure: str,
) -> None:
    ok = result.get("ok") is True and result.get("allowed") is expected_allowed
    message = success if ok else failure
    details = {
        key: result.get(key)
        for key in ("action", "status", "reason_code", "reason", "allowed")
        if result.get(key) is not None
    }
    _add_share_doctor_check(checks, check_id, ok, message, component=component, details=details)


def _share_acceptance_schema_checks(checks: list[dict[str, Any]], status: Mapping[str, Any]) -> None:
    schemas = _mapping(status.get("schemas"))
    errors = int(schemas.get("errors", 0) or 0)
    catalog_count = int(schemas.get("catalog_count", 0) or 0)
    _add_share_doctor_check(
        checks,
        "acceptance.schemas_loaded",
        None if catalog_count == 0 else errors == 0,
        "no schema catalog has been discovered yet"
        if catalog_count == 0
        else ("schema catalogs loaded without errors" if errors == 0 else f"{errors} schema catalog errors found"),
        component="acceptance",
        details={"catalog_count": catalog_count, "errors": errors},
    )
    drift = []
    for tool_value in _sequence(_mapping(status.get("tool_risks")).get("tools")):
        if not isinstance(tool_value, Mapping):
            continue
        tool = _mapping(tool_value)
        if any(_mapping(signal).get("code") == "schema.variant_conflict" for signal in _sequence(tool.get("signals"))):
            drift.append(tool)
    _add_share_doctor_check(
        checks,
        "acceptance.no_schema_variant_conflicts",
        not drift,
        "no schema variant conflicts detected" if not drift else f"{len(drift)} schema variant conflict(s) detected",
        component="acceptance",
        details={"tools": [tool.get("name") for tool in drift[:10]]},
    )


def _share_acceptance_redaction_checks(checks: list[dict[str, Any]], status: Mapping[str, Any]) -> None:
    traffic = _mapping(status.get("traffic"))
    exists = traffic.get("exists") is True
    event_count = int(traffic.get("event_count", 0) or 0)
    redacted = int(traffic.get("redacted_events", 0) or 0) + int(traffic.get("response_redacted", 0) or 0)
    if not exists or event_count == 0:
        _add_share_doctor_check(
            checks,
            "acceptance.redaction_evidence",
            None,
            "no audit traffic exists yet, so response redaction evidence is unavailable",
            component="acceptance",
        )
        return
    _add_share_doctor_check(
        checks,
        "acceptance.redaction_evidence",
        True if redacted else False,
        "audit traffic includes redaction evidence"
        if redacted
        else "audit traffic exists but no redaction events have been observed",
        component="acceptance",
        severity="warning",
        details={
            "event_count": event_count,
            "redacted_events": traffic.get("redacted_events"),
            "response_redacted": traffic.get("response_redacted"),
        },
    )


def _share_acceptance_live_check(
    checks: list[dict[str, Any]],
    status: Mapping[str, Any],
    *,
    timeout: float,
) -> None:
    client = _mapping(status.get("client"))
    url = str(client.get("url") or "")
    headers = _mapping(client.get("headers"))
    if not url:
        _add_share_doctor_check(
            checks,
            "acceptance.live_tools_list",
            False,
            "client URL is missing, so live tools/list could not run",
            component="acceptance",
        )
        return
    probe = _probe_mcp_url(url, headers=headers, timeout=timeout)
    _add_share_doctor_check(
        checks,
        "acceptance.live_tools_list",
        probe.get("mcp_ok") is True,
        "live tools/list succeeded through the share gateway"
        if probe.get("mcp_ok") is True
        else "live tools/list failed through the share gateway",
        component="acceptance",
        details=probe,
    )


def _share_acceptance_slug(value: str) -> str:
    result = []
    for char in value.lower():
        result.append(char if char.isalnum() else "-")
    return "-".join("".join(result).split("-")).strip("-") or "tool"


def _share_invitation_connection_statuses(
    share_dir: Path,
    session_model: Mapping[str, Any],
    invitations: Mapping[str, Any],
    lease_status: Mapping[str, Any],
) -> dict[str, Any]:
    items = [dict(_mapping(item)) for item in _sequence(invitations.get("items")) if isinstance(item, Mapping)]
    leases = [lease for lease in _sequence(lease_status.get("leases")) if isinstance(lease, Mapping)]
    leases_by_id = {str(lease.get("id")): lease for lease in leases if lease.get("id")}
    lease_to_invite = {
        str(item.get("lease_id")): str(item.get("id")) for item in items if item.get("lease_id") and item.get("id")
    }
    try:
        event_summaries = _share_invitation_connection_events(share_dir, session_model, lease_to_invite)
        error = None
    except Exception as exc:
        event_summaries = {}
        error = str(exc)
    enriched: list[dict[str, Any]] = []
    for item in items:
        invite_id = str(item.get("id") or "")
        lease_id = str(item.get("lease_id") or "")
        lease = _mapping(leases_by_id.get(lease_id))
        event_summary = _mapping(event_summaries.get(invite_id))
        item["connection_status"] = _share_invitation_connection_status(item, lease, event_summary, error=error)
        enriched.append(item)
    result = dict(invitations)
    result["items"] = enriched
    result["summary"] = dict(_mapping(invitations.get("summary"))) or _share_invite_summary(enriched)
    result["connection_summary"] = _share_invitation_connection_summary(enriched)
    return result


def _share_invitation_connection_events(
    share_dir: Path,
    session_model: Mapping[str, Any],
    lease_to_invite: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    source_path = _share_invitation_event_source_path(share_dir, session_model)
    if source_path is None or not source_path.exists():
        return {}
    summaries: dict[str, dict[str, Any]] = {}
    for event in _load_share_events(source_path):
        lease = _share_event_lease_metadata(event)
        lease_id = str(lease.get("id") or "")
        invite = _mapping(lease.get("invite"))
        invite_id = str(invite.get("id") or lease_to_invite.get(lease_id, ""))
        if not invite_id:
            continue
        mcp = _mapping(event.get("mcp"))
        decision = _mapping(event.get("decision"))
        access = _mapping(event.get("access") or _mapping(event.get("metadata")).get("access"))
        access_lease = _mapping(access.get("lease"))
        reason_code = str(
            lease.get("reason_code")
            or access_lease.get("reason_code")
            or access.get("reason_code")
            or decision.get("reason_code")
            or ""
        )
        allowed = _share_event_allowed(event, lease=lease, access=access)
        method = str(mcp.get("method") or "")
        tool = str(mcp.get("tool") or mcp.get("target") or lease.get("tool") or "")
        summary = summaries.setdefault(
            invite_id,
            {
                "event_count": 0,
                "healthy_methods": [],
                "denied_count": 0,
            },
        )
        summary["event_count"] = int(summary.get("event_count") or 0) + 1
        if allowed is False:
            summary["denied_count"] = int(summary.get("denied_count") or 0) + 1
        if allowed is True and method in {"initialize", "tools/list"}:
            summary["last_healthy_at"] = event.get("time")
            summary["healthy_methods"] = sorted({*map(str, _sequence(summary.get("healthy_methods"))), method})
        summary["last_seen_at"] = event.get("time")
        summary["last_method"] = method or None
        summary["last_tool"] = tool or None
        summary["last_allowed"] = allowed
        summary["last_reason_code"] = reason_code or None
        if lease_id:
            summary["lease_id"] = lease_id
        if invite.get("recipient"):
            summary["recipient"] = invite.get("recipient")
    return summaries


def _share_invitation_event_source_path(share_dir: Path, session_model: Mapping[str, Any]) -> Path | None:
    evidence = _mapping(session_model.get("evidence"))
    audit_path = _resolve_share_path(share_dir, evidence.get("audit_log", "traces/audit.jsonl"))
    if audit_path.exists():
        return audit_path
    record_path = _resolve_share_path(share_dir, evidence.get("record_log", "traces/session.jsonl"))
    if record_path.exists():
        return record_path
    return audit_path


def _share_event_lease_metadata(event: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = _mapping(event.get("metadata"))
    access = _mapping(event.get("access") or metadata.get("access"))
    access_lease = _mapping(access.get("lease"))
    if access_lease:
        return access_lease
    lease = _mapping(metadata.get("lease") or metadata.get("lease_preview"))
    if lease:
        return lease
    decision_context = _mapping(_mapping(event.get("decision")).get("context"))
    return _mapping(decision_context.get("lease"))


def _share_event_allowed(
    event: Mapping[str, Any],
    *,
    lease: Mapping[str, Any],
    access: Mapping[str, Any],
) -> bool | None:
    if "allowed" in access:
        return access.get("allowed") is True
    decision = _mapping(event.get("decision"))
    if "allowed" in decision:
        return decision.get("allowed") is True
    if "allowed" in lease:
        return lease.get("allowed") is True
    return None


def _share_invitation_connection_status(
    invite: Mapping[str, Any],
    lease: Mapping[str, Any],
    event_summary: Mapping[str, Any],
    *,
    error: str | None,
) -> dict[str, Any]:
    lease_id = str(invite.get("lease_id") or lease.get("id") or "")
    base = _drop_empty_json(
        {
            "lease_id": lease_id,
            "checked": error is None,
            "error": error,
            "event_count": event_summary.get("event_count"),
            "last_seen_at": event_summary.get("last_seen_at") or lease.get("last_used_at"),
            "last_method": event_summary.get("last_method"),
            "last_tool": event_summary.get("last_tool") or lease.get("last_tool"),
            "last_reason_code": event_summary.get("last_reason_code"),
            "healthy_methods": _sequence(event_summary.get("healthy_methods")),
        }
    )
    if invite.get("revoked_at"):
        return {
            **base,
            "state": "revoked",
            "label": "revoked",
            "severity": "neutral",
            "message": "invite has been revoked",
        }
    if lease and lease.get("active") is False:
        reason = "backing lease is inactive"
        if lease.get("revoked_at"):
            reason = "backing lease has been revoked"
        return {
            **base,
            "state": "inactive",
            "label": "inactive",
            "severity": "bad",
            "message": reason,
        }
    if error:
        return {
            **base,
            "state": "unknown",
            "label": "unknown",
            "severity": "warn",
            "message": "connection audit could not be read",
        }
    if event_summary:
        last_allowed = event_summary.get("last_allowed")
        reason_code = str(event_summary.get("last_reason_code") or "")
        healthy_methods = _sequence(event_summary.get("healthy_methods"))
        if reason_code in {"mcp.auth_required", "lease.missing", "lease.invalid", "oauth.rejected"}:
            return {
                **base,
                "state": "misconfigured",
                "label": "misconfigured",
                "severity": "bad",
                "message": f"client request was rejected before handoff completed ({reason_code})",
            }
        if reason_code in {"lease.revoked", "lease.expired", "lease.max_calls_exceeded"}:
            return {
                **base,
                "state": "inactive",
                "label": "inactive",
                "severity": "bad",
                "message": f"client used an inactive lease ({reason_code})",
            }
        if last_allowed is False:
            return {
                **base,
                "state": "blocked",
                "label": "blocked",
                "severity": "bad",
                "message": f"latest invite traffic was blocked ({reason_code or 'policy denied'})",
            }
        if healthy_methods:
            return {
                **base,
                "state": "connected",
                "label": "connected",
                "severity": "good",
                "message": "client successfully reached MCP using this invite",
            }
        return {
            **base,
            "state": "seen",
            "label": "seen",
            "severity": "warn",
            "message": "invite traffic was seen, but no initialize or tools/list success yet",
        }
    if lease.get("last_used_at"):
        return {
            **base,
            "state": "used",
            "label": "used",
            "severity": "warn",
            "message": "backing lease has been used, but no matching audit event was found",
        }
    return {
        **base,
        "state": "not_used",
        "label": "not used",
        "severity": "warn",
        "message": "waiting for the recipient to connect with this invite",
    }


def _share_invitation_connection_summary(items: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        status = _mapping(item.get("connection_status"))
        counts[str(status.get("state") or "unknown")] += 1
    return {
        "connected": counts.get("connected", 0),
        "waiting": counts.get("not_used", 0),
        "seen": counts.get("seen", 0) + counts.get("used", 0),
        "blocked": counts.get("blocked", 0),
        "misconfigured": counts.get("misconfigured", 0),
        "inactive": counts.get("inactive", 0),
        "revoked": counts.get("revoked", 0),
        "unknown": counts.get("unknown", 0),
    }


def _share_findings(
    *,
    gateway: Mapping[str, Any],
    upstreams: Sequence[Mapping[str, Any]],
    traffic: Mapping[str, Any],
    tool_risks: Mapping[str, Any],
    tunnel: Mapping[str, Any],
    policy: Mapping[str, Any],
    contract: Mapping[str, Any],
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
    high_risk_tools = [item for item in _sequence(tool_risks.get("tools")) if _mapping(item).get("level") == "high"]
    if high_risk_tools:
        findings.append(
            {
                "severity": "warning",
                "type": "high_risk_mcp_tools",
                "message": "high-risk MCP tools observed or declared: "
                + ", ".join(str(_mapping(item).get("name")) for item in high_risk_tools[:5]),
                "count": len(high_risk_tools),
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
    if contract.get("drifted") is True:
        findings.append(
            {
                "severity": "error",
                "type": "share_contract_drift",
                "message": "required share contract binding digest differs from current share state",
            }
        )
    inspection = _mapping(traffic.get("inspection"))
    for finding in _sequence(inspection.get("findings")):
        if isinstance(finding, Mapping):
            findings.append(dict(finding))
    return findings


def _share_review_lines(result: Mapping[str, Any]) -> list[str]:
    session = _mapping(result.get("session"))
    gateway = _mapping(result.get("gateway"))
    tunnel = _mapping(result.get("tunnel_doctor"))
    policy = _mapping(result.get("policy"))
    amendments = _mapping(result.get("amendments"))
    traffic = _mapping(result.get("traffic"))
    tool_risks = _mapping(result.get("tool_risks"))
    recordings = _mapping(result.get("recordings"))
    leases = _mapping(result.get("leases"))
    contract = _mapping(result.get("contract"))
    client = _mapping(result.get("client"))
    findings = [item for item in _sequence(result.get("findings")) if isinstance(item, Mapping)]
    upstreams = [item for item in _sequence(result.get("upstreams")) if isinstance(item, Mapping)]
    active_lease = _mapping(leases.get("current"))
    public_url = tunnel.get("public_url") or client.get("url") or "-"
    blocked = int(traffic.get("blocked", 0) or 0)
    allowed = int(traffic.get("allowed", 0) or 0)
    confirmed = int(traffic.get("confirmed", 0) or 0)
    event_count = int(traffic.get("event_count", 0) or 0)
    severity_counts = Counter(str(item.get("severity") or "info") for item in findings)
    lines = [
        "# snulbug MCP share report",
        "",
        "## Executive Summary",
        "",
        f"- Result: `{_share_report_result_label(result)}`",
        f"- Share: `{result.get('directory')}` state=`{result.get('state')}` task=`{session.get('task') or '-'}`",
        f"- Exposure: provider=`{session.get('provider') or '-'}` public_url=`{public_url}`",
        f"- Gateway: `{gateway.get('url') or '-'}` reachable=`{_yes_no_unknown(gateway.get('reachable'))}`",
        f"- Activity: `{event_count}` events, `{allowed}` allowed, `{blocked}` blocked, `{confirmed}` confirmed",
        (
            f"- Review load: `{severity_counts.get('error', 0)}` errors, "
            f"`{severity_counts.get('warning', 0)}` warnings, `{severity_counts.get('info', 0)}` info findings"
        ),
        "",
        "## Exposure Boundary",
        "",
        f"- Client URL: `{public_url}`",
        f"- Local gateway: `{gateway.get('url') or '-'}`",
        (
            f"- Provider: `{session.get('provider') or '-'}` "
            f"preset=`{session.get('preset') or '-'}` ttl=`{session.get('ttl') or '-'}`"
        ),
        (
            f"- Task lease required: `{_yes_no_unknown(session.get('lease_required'))}` "
            f"header=`{session.get('lease_header') or '-'}`"
        ),
        (
            f"- Current lease: `{active_lease.get('id') or '-'}` "
            f"active=`{_yes_no_unknown(active_lease.get('active'))}` "
            f"expires=`{active_lease.get('expires_at') or '-'}`"
        ),
        f"- Policy bundle: `{policy.get('bundle') or '-'}`",
        f"- Active policy: `{policy.get('active_policy') or '-'}`",
        "",
        "### Upstreams Exposed",
        "",
    ]
    if upstreams:
        for upstream in upstreams:
            lines.append(
                "- "
                f"`{upstream.get('name') or 'upstream'}` transport=`{upstream.get('transport') or 'http'}` "
                f"url=`{upstream.get('url') or '-'}` reachable=`{_yes_no_unknown(upstream.get('reachable'))}`"
            )
    else:
        lines.append("- None configured")

    lines.extend(
        [
            "",
            "## Access And Activity Review",
            "",
            f"- Total requests/events observed: `{event_count}`",
            f"- Allowed: `{allowed}`",
            f"- Blocked: `{blocked}`",
            f"- Human confirmations: `{confirmed}` approved=`{traffic.get('confirmation_approved', 0)}` "
            f"denied=`{traffic.get('confirmation_denied', 0)}`",
            f"- Observed MCP methods: {_inline_counts(traffic.get('methods'))}",
            f"- Observed MCP tools/targets: {_inline_counts(traffic.get('tools'))}",
            f"- Tool risk summary: {_tool_risk_summary_inline(tool_risks)}",
            f"- Observed clients: {_inline_counts(traffic.get('clients'))}",
            f"- Observed source IPs: {_inline_counts(traffic.get('source_ips'))}",
            "",
            "## Tool Risk Review",
            "",
            *_tool_risk_report_lines(tool_risks),
            "",
            "## Data Protection Review",
            "",
            "This report is secret-light: it does not include raw bearer tokens, lease tokens, request bodies, "
            "or response bodies.",
            "",
            f"- Secret-bearing client config: `{_mapping(client).get('config') or '-'}`",
            f"- Replay log: `{_mapping(recordings.get('record_log')).get('path') or '-'}` "
            f"exists=`{_yes_no_unknown(_mapping(recordings.get('record_log')).get('exists'))}`",
            f"- Audit log: `{_mapping(recordings.get('audit_log')).get('path') or '-'}` "
            f"exists=`{_yes_no_unknown(_mapping(recordings.get('audit_log')).get('exists'))}`",
            f"- Events containing redaction markers: `{traffic.get('redacted_events', 0)}`",
            f"- Replay records redacted: `{traffic.get('record_redacted', 0)}`",
            f"- Response redactions: `{traffic.get('response_redacted', 0)}`",
            "",
            "## Policy Review",
            "",
            (
                f"- Lifecycle: `{policy.get('lifecycle_state') or 'observed'}` "
                f"signed=`{_yes_no_unknown(policy.get('lifecycle_signed'))}`"
            ),
            f"- Last lifecycle action: `{_share_last_lifecycle_label(policy)}`",
            f"- Last amendment: `{amendments.get('last') or '-'}`",
            f"- Proposed amendment candidates: `{amendments.get('candidate_count', 0)}`",
            f"- Share contract required: `{_yes_no_unknown(contract.get('required'))}` "
            f"signed=`{_yes_no_unknown(contract.get('signed'))}` drifted=`{_yes_no_unknown(contract.get('drifted'))}`",
            "",
            "## Findings To Review",
            "",
        ]
    )
    if findings:
        for finding in findings:
            message = finding.get("message", finding.get("count", ""))
            lines.append(f"- `{finding.get('severity', 'info')}` `{finding.get('type')}`: {message}")
    else:
        lines.append("- None")
    lines.extend(_share_action_checklist(result))
    return lines


def _share_report_result_label(result: Mapping[str, Any]) -> str:
    findings = [item for item in _sequence(result.get("findings")) if isinstance(item, Mapping)]
    if any(item.get("severity") == "error" for item in findings):
        return "attention required"
    if any(item.get("severity") == "warning" for item in findings):
        return "review recommended"
    traffic = _mapping(result.get("traffic"))
    if int(traffic.get("event_count", 0) or 0) == 0:
        return "no traffic observed"
    return "ready for review"


def _share_action_checklist(result: Mapping[str, Any]) -> list[str]:
    commands = _mapping(result.get("commands"))
    traffic = _mapping(result.get("traffic"))
    policy = _mapping(result.get("policy"))
    lines = ["", "## Action Checklist", ""]
    doctor = commands.get("doctor") or commands.get("share_doctor")
    client = commands.get("client")
    inspector = commands.get("inspector")
    close = commands.get("close")
    inspect_audit = commands.get("inspect_audit")
    if isinstance(doctor, str):
        lines.append(f"- [ ] Run readiness checks: `{doctor}`")
    if int(traffic.get("blocked", 0) or 0):
        if isinstance(inspect_audit, str):
            lines.append(f"- [ ] Review blocked decisions and redactions: `{inspect_audit}`")
        else:
            lines.append("- [ ] Review blocked decisions and redactions in the audit log.")
    if policy.get("lifecycle_state") != "active":
        lines.append("- [ ] Promote and activate the reviewed policy bundle before reusing this share shape.")
    if isinstance(client, str):
        lines.append(f"- [ ] Generate or inspect the MCP client config: `{client}`")
    if isinstance(inspector, str):
        lines.append(f"- [ ] Smoke-test with MCP Inspector: `{inspector}`")
    if isinstance(close, str):
        lines.append(f"- [ ] Close the share and revoke its lease when finished: `{close}`")
    if len(lines) == 3:
        lines.append("- [ ] No immediate follow-up actions were generated.")
    return lines


def _inline_counts(values: Any, *, limit: int = 5) -> str:
    entries = [item for item in _sequence(values) if isinstance(item, Mapping)]
    if not entries:
        return "`none`"
    rendered = [f"`{item.get('value')}` (`{item.get('count', 0)}`)" for item in entries[:limit]]
    if len(entries) > limit:
        rendered.append(f"`+{len(entries) - limit} more`")
    return ", ".join(rendered)


def _tool_risk_summary_inline(tool_risks: Mapping[str, Any]) -> str:
    summary = _mapping(tool_risks.get("summary"))
    return (
        f"`{int(summary.get('high', 0) or 0)}` high, "
        f"`{int(summary.get('medium', 0) or 0)}` medium, "
        f"`{int(summary.get('low', 0) or 0)}` low"
    )


def _tool_risk_report_lines(tool_risks: Mapping[str, Any]) -> list[str]:
    tools = [item for item in _sequence(tool_risks.get("tools")) if isinstance(item, Mapping)]
    schema_catalogs = _mapping(tool_risks.get("schema_catalogs"))
    lines = [
        f"- Summary: {_tool_risk_summary_inline(tool_risks)}",
        f"- Categories: {_inline_counts(tool_risks.get('categories'))}",
        (
            f"- Schema catalogs: `{schema_catalogs.get('catalog_count', 0)}` loaded, "
            f"`{schema_catalogs.get('tool_count', 0)}` declared tools, "
            f"`{schema_catalogs.get('errors', 0)}` errors"
        ),
        "",
        "| Tool | Risk | Count | Evidence | Confidence | Categories | Signals |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not tools:
        lines.append("| - | - | - | - | - | - | - |")
        return lines
    for tool in tools[:10]:
        signals = [
            str(_mapping(signal).get("code"))
            for signal in _sequence(tool.get("signals"))
            if _mapping(signal).get("code")
        ]
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_table_cell(f"`{tool.get('name') or '-'}`"),
                    _markdown_table_cell(tool.get("level")),
                    _markdown_table_cell(tool.get("count", 0)),
                    _markdown_table_cell(
                        ", ".join(f"`{item}`" for item in _sequence(tool.get("evidence_sources"))) or "-"
                    ),
                    _markdown_table_cell(tool.get("confidence") or "-"),
                    _markdown_table_cell(", ".join(f"`{item}`" for item in _sequence(tool.get("categories"))) or "-"),
                    _markdown_table_cell(", ".join(f"`{item}`" for item in signals[:4]) or "-"),
                ]
            )
            + " |"
        )
    return lines


def _share_report_lines(result: Mapping[str, Any], *, title: str) -> list[str]:
    session = _mapping(result.get("session"))
    gateway = _mapping(result.get("gateway"))
    tunnel = _mapping(result.get("tunnel_doctor"))
    policy = _mapping(result.get("policy"))
    members = _mapping(result.get("members"))
    amendments = _mapping(result.get("amendments"))
    traffic = _mapping(result.get("traffic"))
    tool_risks = _mapping(result.get("tool_risks"))
    recordings = _mapping(result.get("recordings"))
    leases = _mapping(result.get("leases"))
    contract = _mapping(result.get("contract"))
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
            "## Share Contract",
            "",
            f"- Required: `{_yes_no_unknown(contract.get('required'))}`",
            f"- Signed: `{_yes_no_unknown(contract.get('signed'))}`",
            f"- Key id: `{contract.get('key_id') or '-'}`",
            f"- Binding digest: `{contract.get('binding_digest') or contract.get('digest') or '-'}`",
            f"- Drifted: `{_yes_no_unknown(contract.get('drifted'))}`",
            f"- Path: `{contract.get('path') or '-'}`",
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
            "### Tool Risk Classifier",
            "",
            *_tool_risk_report_lines(tool_risks),
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
        for name in ("run", "doctor", "client", "inspector", "close", "inspect_audit", "inspect_session"):
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
        "x-snulbug-internal-probe": "share-status",
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


def _markdown_table_cell(value: Any) -> str:
    text = "-" if value in (None, "") else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


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
    require_contract: str | Path | None = None,
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
    contract: dict[str, Any] | None = None
    contract_metadata: dict[str, Any] | None = None
    contract_path = _resolve_optional_share_path(share_dir, require_contract)
    if contract_path is not None:
        contract = load_share_contract(contract_path)
        current_contract = share_contract(share_dir, live_checks=False, include_doctor=False)["contract"]
        if current_contract.get("binding_digest") != contract.get("binding_digest"):
            raise ValueError(
                "required share contract has drifted from current share state: "
                f"expected {contract.get('binding_digest')}, current {current_contract.get('binding_digest')}"
            )
        contract_metadata = share_contract_runtime_metadata(contract, path=contract_path, required=True, verified=True)
        contract_metadata["contract_matched_at_startup"] = True
        contract_metadata["contract_drifted"] = False
    if dry_run:
        return {
            "ok": True,
            "share": str(share_dir),
            "state": context["state"],
            "source": context["source"],
            "session_model_path": str(context["session_model_path"]),
            "resolved_paths": {key: str(value) for key, value in resolved_paths.items() if isinstance(value, Path)},
            "contract": contract_metadata or {},
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
    if contract_metadata is not None:
        runtime["contract"] = contract_metadata
    if manifest is not None:
        _update_share_manifest(share_dir, state="running", runtime=runtime)
        _update_share_session_runtime(share_dir, session_model, runtime=runtime)
    else:
        _update_share_session_runtime(share_dir, session_model, runtime=runtime)
    run_mcp_proxy_config(proxy_config, fabric_config, share_contract=contract)
    return None


def _enrich_capability_requests_with_policy_labels(
    share_dir: Path,
    manifest: Mapping[str, Any] | None,
    session_model: Mapping[str, Any],
    requests: dict[str, dict[str, Any]],
) -> None:
    if not requests:
        return
    resolved = _share_run_resolved_paths(share_dir, session_model, manifest)
    policy_path = resolved.get("policy")
    if policy_path is None or not policy_path.is_file():
        return
    try:
        script = compile_lua_file(policy_path)
    except Exception:
        return
    declared = [dict(item) for item in script.capabilities if isinstance(item, Mapping) and item.get("id")]
    if not declared:
        return
    headers = _capability_match_client_headers(manifest)
    corpus = _capability_match_corpus(requests.values())
    for request in requests.values():
        match = _capability_match_for_request(script, declared, request, corpus=corpus, headers=headers)
        if not match:
            continue
        request["capability_match"] = match
        if match.get("mode") == "declared_capability":
            selected = str(match.get("selected") or "")
            if selected:
                original = dict(_mapping(request.get("suggested_lease")))
                request["raw_policy_change"] = _drop_empty_json({"suggested_lease": original})
                request["suggested_lease"] = _capability_label_suggested_lease(request, selected, original)


def _capability_match_client_headers(manifest: Mapping[str, Any] | None) -> dict[str, str]:
    headers = _share_auth_client_headers(manifest or {}, {})
    headers.setdefault("content-type", "application/json")
    headers.setdefault("accept", "application/json, text/event-stream")
    return headers


def _capability_match_for_request(
    script: Any,
    declared: Sequence[Mapping[str, Any]],
    request: Mapping[str, Any],
    *,
    corpus: Sequence[Mapping[str, Any]],
    headers: Mapping[str, str],
) -> dict[str, Any] | None:
    sample = _capability_match_sample_request(request, headers=headers)
    if sample is None:
        return _capability_raw_policy_match("request is not a tools/call capability request")
    candidates: list[dict[str, Any]] = []
    for index, capability in enumerate(declared):
        capability_id = str(capability.get("id") or "")
        if not capability_id:
            continue
        row = _capability_candidate_decision(script, sample, capability, index=index)
        if row.get("allowed") is True:
            candidates.append(row)
    if not candidates:
        return _capability_raw_policy_match("no declared policy capability covers this request")
    ranked = [
        _capability_candidate_with_breadth(script, candidate, corpus, headers=headers, request=request)
        for candidate in candidates
    ]
    ranked.sort(
        key=lambda item: (
            float(item.get("score") or 0),
            int(item.get("order") or 0),
            str(item.get("id") or ""),
        )
    )
    selected = ranked[0]
    return _drop_empty_json(
        {
            "mode": "declared_capability",
            "selection": "least_upper_declared_capability",
            "selected": selected.get("id"),
            "selected_label": selected.get("label"),
            "reason": "selected the policy-declared capability with the narrowest simulated coverage",
            "fallback_required": False,
            "candidates": [
                _drop_empty_json(
                    {
                        "id": item.get("id"),
                        "label": item.get("label"),
                        "allowed_count": item.get("allowed_count"),
                        "score": item.get("score"),
                        "default": item.get("default"),
                        "reason_code": item.get("reason_code"),
                    }
                )
                for item in ranked[:8]
            ],
        }
    )


def _capability_raw_policy_match(reason: str) -> dict[str, Any]:
    return {
        "mode": "raw_policy_change",
        "selection": "raw_request",
        "fallback_required": True,
        "reason": reason,
    }


def _capability_candidate_decision(
    script: Any,
    request: Mapping[str, Any],
    capability: Mapping[str, Any],
    *,
    index: int,
) -> dict[str, Any]:
    capability_id = str(capability.get("id") or "")
    context = _capability_match_context(request, capability_id)
    try:
        normalized_request, _body_read = normalize_request(request)
        trace = script.decide_with_trace(normalized_request, context, None)
        decision = trace.decision
        action = str(decision.get("action") or "")
        allowed = action in CAPABILITY_MATCH_ALLOWED_ACTIONS
        return _drop_empty_json(
            {
                "id": capability_id,
                "label": capability.get("label"),
                "description": capability.get("description"),
                "default": capability.get("default") is True,
                "order": index,
                "action": action,
                "allowed": allowed,
                "reason_code": decision.get("reason_code"),
                "reason": decision.get("reason") or decision.get("body"),
            }
        )
    except Exception as exc:
        return _drop_empty_json(
            {
                "id": capability_id,
                "label": capability.get("label"),
                "default": capability.get("default") is True,
                "order": index,
                "action": "error",
                "allowed": False,
                "reason_code": "capability_match.simulation_failed",
                "reason": str(exc),
            }
        )


def _capability_candidate_with_breadth(
    script: Any,
    candidate: Mapping[str, Any],
    corpus: Sequence[Mapping[str, Any]],
    *,
    headers: Mapping[str, str],
    request: Mapping[str, Any],
) -> dict[str, Any]:
    allowed_count = 0
    for corpus_request in corpus:
        sample = _capability_match_sample_request(corpus_request, headers=headers)
        if sample is None:
            continue
        row = _capability_candidate_decision(script, sample, candidate, index=int(candidate.get("order") or 0))
        if row.get("allowed") is True:
            allowed_count += 1
    score = (
        float(allowed_count)
        + _capability_default_penalty(candidate)
        + _capability_affinity_adjustment(candidate, request)
    )
    enriched = dict(candidate)
    enriched["allowed_count"] = allowed_count
    enriched["score"] = round(score, 3)
    return enriched


def _capability_default_penalty(candidate: Mapping[str, Any]) -> float:
    return 0.25 if candidate.get("default") is True else 0.0


def _capability_affinity_adjustment(candidate: Mapping[str, Any], request: Mapping[str, Any]) -> float:
    text = " ".join(str(candidate.get(key) or "").lower() for key in ("id", "label", "description")).replace("-", "_")
    tool = str(request.get("tool") or "").lower().replace("-", "_")
    suggested = _mapping(request.get("suggested_lease"))
    paths = " ".join(_string_list(suggested.get("allow_paths"))).lower()
    adjustment = 0.0
    if any(token in text for token in ("docs", "documentation")) and any(
        token in paths for token in ("readme", "docs", "examples")
    ):
        adjustment -= 0.35
    if "git" in text and "git" in tool:
        adjustment -= 0.3
    if "search" in text and any(token in tool for token in ("search", "grep", "find")):
        adjustment -= 0.3
    if any(token in text for token in ("readonly", "read_only", "read only")) and any(
        token in tool for token in ("read", "list", "show", "get")
    ):
        adjustment -= 0.1
    if "low_risk" in text or "low-risk" in text:
        adjustment += 0.15
    return adjustment


def _capability_match_corpus(requests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    corpus: list[dict[str, Any]] = []
    seen: set[str] = set()
    for request in requests:
        sample = _capability_corpus_request(request)
        key = json.dumps(sample, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        corpus.append(sample)
    for tool in DEFAULT_ALLOWED_TOOLS:
        sample = _capability_corpus_request({"method": "tools/call", "tool": tool})
        key = json.dumps(sample, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            corpus.append(sample)
    return corpus


def _capability_corpus_request(request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "method": request.get("method") or "tools/call",
        "tool": request.get("tool"),
        "argument_keys": _string_list(request.get("argument_keys")),
        "suggested_lease": dict(_mapping(request.get("suggested_lease"))),
    }


def _capability_match_sample_request(
    request: Mapping[str, Any],
    *,
    headers: Mapping[str, str],
) -> dict[str, Any] | None:
    method = str(request.get("method") or "tools/call")
    tool = request.get("tool")
    if method != "tools/call" or not isinstance(tool, str) or not tool:
        return None
    arguments = _capability_match_sample_arguments(request)
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": dict(headers),
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "capability-match",
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
            sort_keys=True,
        ),
    }


def _capability_match_sample_arguments(request: Mapping[str, Any]) -> dict[str, Any]:
    keys = _string_list(request.get("argument_keys"))
    suggested = _mapping(request.get("suggested_lease"))
    result: dict[str, Any] = {}
    for key in keys:
        result[key] = _capability_match_sample_value(key, suggested)
    tool = str(request.get("tool") or "")
    if not result and _capability_tool_needs_path(tool):
        result["path"] = _first_string(suggested.get("allow_paths")) or "README.md"
    return result


def _capability_match_sample_value(name: str, suggested: Mapping[str, Any]) -> Any:
    lowered = name.lower()
    if lowered in {"paths", "files", "filenames"}:
        return [_first_string(suggested.get("allow_paths")) or "README.md"]
    if "path" in lowered or "file" in lowered or "directory" in lowered:
        return _first_string(suggested.get("allow_paths")) or "README.md"
    if "host" in lowered or "url" in lowered or "uri" in lowered:
        host = _first_string(suggested.get("allow_hosts"))
        return f"https://{host}" if host else "https://example.invalid"
    if "command" in lowered or lowered in {"cmd", "argv"}:
        return _first_string(suggested.get("allow_commands")) or "status"
    if "query" in lowered or "pattern" in lowered or "search" in lowered:
        return "README"
    if "count" in lowered or "limit" in lowered or "max" in lowered:
        return 1
    return "example"


def _first_string(value: Any) -> str | None:
    values = _string_list(value)
    return values[0] if values else None


def _capability_tool_needs_path(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(token in lowered for token in ("read_file", "file_read", "list_project", "search_file", "grep"))


def _capability_match_context(request: Mapping[str, Any], capability_id: str) -> dict[str, Any]:
    return {
        "lease": {
            "enabled": True,
            "required": True,
            "checked": True,
            "allowed": True,
            "method": request.get("method") or "tools/call",
            "id": "capability-match-preview",
            "task": "Capability request preview",
            "capabilities": [capability_id],
        }
    }


def _capability_label_suggested_lease(
    request: Mapping[str, Any],
    capability_id: str,
    original: Mapping[str, Any],
) -> dict[str, Any]:
    return _drop_empty_json(
        {
            "task": original.get("task") or request.get("task") or f"Temporary MCP access for {request.get('tool')}",
            "ttl": original.get("ttl") or "30m",
            "max_calls": original.get("max_calls"),
            "allow_tools": ["*"],
            "capabilities": [capability_id],
        }
    )


def _observed_capability_requests(
    share_dir: Path,
    session_model: Mapping[str, Any],
    *,
    log: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    requests: dict[str, dict[str, Any]] = {}
    for path in _share_capability_log_paths(share_dir, session_model, log=log):
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw_event = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not isinstance(raw_event, Mapping):
                    continue
                event = build_audit_event(raw_event) if raw_event.get("type") == "snulbug.request_record" else raw_event
                request = _capability_request_from_event(event, source=path, line=line_number)
                if request is None:
                    continue
                existing = requests.get(request["id"])
                if existing is None:
                    requests[request["id"]] = request
                    continue
                existing["observations"] = int(existing.get("observations") or 1) + 1
                existing["last_seen_at"] = request.get("last_seen_at") or existing.get("last_seen_at")
                sources = [dict(item) for item in _sequence(existing.get("sources")) if isinstance(item, Mapping)]
                sources.extend(item for item in _sequence(request.get("sources")) if isinstance(item, Mapping))
                existing["sources"] = sources
    return requests


def _capability_request_from_event(
    event: Mapping[str, Any],
    *,
    source: Path,
    line: int,
) -> dict[str, Any] | None:
    metadata = _mapping(event.get("metadata"))
    envelope = _mapping(metadata.get("capability_request"))
    capability = _mapping(envelope.get("capability_request"))
    if not capability:
        decision = _mapping(event.get("decision"))
        capability = _mapping(_mapping(decision.get("context")).get("capability_request"))
    if not capability:
        return None
    mcp = _mapping(event.get("mcp"))
    decision = _mapping(event.get("decision"))
    auth = _capability_request_auth(event)
    suggested = _mapping(capability.get("suggested_lease"))
    tool = capability.get("tool") or mcp.get("tool") or mcp.get("target")
    method = capability.get("method") or mcp.get("method")
    request = _drop_empty_json(
        {
            "task": capability.get("task") or suggested.get("task"),
            "reason_code": capability.get("reason_code") or envelope.get("reason_code") or decision.get("reason_code"),
            "method": method,
            "tool": tool,
            "argument_keys": _string_list(capability.get("argument_keys")),
            "suggested_lease": suggested,
            "auth": auth,
        }
    )
    request_id = _capability_request_id(request)
    return _drop_empty_json(
        {
            "id": request_id,
            "status": "pending",
            "first_seen_at": event.get("time") or event.get("recorded_at"),
            "last_seen_at": event.get("time") or event.get("recorded_at"),
            "observations": 1,
            "source": str(source),
            "sources": [{"path": str(source), "line": line}],
            "mcp": {"method": method, "tool": tool},
            "decision": {
                "reason_code": decision.get("reason_code"),
                "confirmation": decision.get("confirmation"),
            },
            **request,
        }
    )


def _capability_request_auth(event: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _mapping(event.get("metadata"))
    auth = dict(_mapping(event.get("auth")) or _mapping(metadata.get("auth")))
    access_auth = _mapping(_mapping(metadata.get("access")).get("auth"))
    for key in ("subject", "issuer", "tenant", "client_id", "groups", "profile_id"):
        if auth.get(key) in (None, "", []):
            value = access_auth.get(key)
            if value not in (None, "", []):
                auth[key] = value
    return _drop_empty_json(
        {
            "subject": auth.get("subject"),
            "issuer": auth.get("issuer"),
            "tenant": auth.get("tenant"),
            "client_id": auth.get("client_id"),
            "groups": _string_list(auth.get("groups")),
            "profile_id": auth.get("profile_id"),
        }
    )


def _capability_request_id(request: Mapping[str, Any]) -> str:
    identity = {
        "reason_code": request.get("reason_code"),
        "method": request.get("method"),
        "tool": request.get("tool"),
        "suggested_lease": request.get("suggested_lease"),
        "auth": request.get("auth"),
    }
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return f"cap_{digest[:12]}"


def _share_capability_log_paths(
    share_dir: Path,
    session_model: Mapping[str, Any],
    *,
    log: str | Path | None = None,
) -> list[Path]:
    if log is not None:
        return [_resolve_share_path(share_dir, log)]
    evidence = _mapping(session_model.get("evidence"))
    paths = _mapping(session_model.get("paths"))
    candidates = [
        evidence.get("audit_log"),
        paths.get("audit_log"),
        "traces/audit.jsonl",
        evidence.get("record_log"),
        paths.get("record_log"),
        "traces/session.jsonl",
    ]
    result: list[Path] = []
    seen: set[str] = set()
    for value in candidates:
        if not isinstance(value, str) or not value:
            continue
        path = _resolve_share_path(share_dir, value)
        key = str(path)
        if key not in seen:
            result.append(path)
            seen.add(key)
    return result


def _capability_request_review_path(share_dir: Path) -> Path:
    return share_dir / CAPABILITY_REQUEST_REVIEW_PATH


def _load_capability_request_reviews(share_dir: Path) -> dict[str, Any]:
    path = _capability_request_review_path(share_dir)
    if not path.is_file():
        return {"version": 1, "requests": {}}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError(f"capability request review store must be a JSON object: {path}")
    requests = loaded.get("requests")
    if not isinstance(requests, Mapping):
        requests = {}
    return {"version": int(loaded.get("version", 1)), "requests": dict(requests)}


def _write_capability_request_reviews(share_dir: Path, reviews: Mapping[str, Any]) -> Path:
    path = _capability_request_review_path(share_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(reviews), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return path


def _record_capability_request_review(
    share_dir: Path,
    request_id: str,
    review: Mapping[str, Any],
) -> dict[str, Any]:
    reviews = _load_capability_request_reviews(share_dir)
    request_reviews = dict(_mapping(reviews.get("requests")))
    request_reviews[request_id] = dict(review)
    reviews["requests"] = request_reviews
    reviews["updated_at"] = _now_iso()
    _write_capability_request_reviews(share_dir, reviews)
    return reviews


def _record_share_capability_request_review(
    share_dir: Path,
    session_model: Mapping[str, Any],
    *,
    review: Mapping[str, Any],
    reviews: Mapping[str, Any],
) -> dict[str, Any]:
    model = json.loads(json.dumps(dict(session_model), default=str))
    status = dict(_mapping(model.get("status")))
    status["updated_at"] = _now_iso()
    model["status"] = status
    capability = dict(_mapping(model.get("capability_requests")))
    capability["store"] = str(_capability_request_review_path(share_dir))
    capability["last_review"] = dict(review)
    capability["summary"] = _capability_request_review_summary(reviews)
    model["capability_requests"] = capability
    write_share_session_model(share_dir, model, force=True)
    return model


def _capability_request_summary(
    requests: Sequence[Mapping[str, Any]],
    *,
    reviews: Mapping[str, Any],
    store_path: Path,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    known_ids: set[str] = set()
    for request in requests:
        request_id = str(request.get("id") or "")
        if request_id:
            known_ids.add(request_id)
        review = _mapping(reviews.get(request_id))
        counts[str(review.get("status") or request.get("status") or "pending")] += 1
    for request_id, review in reviews.items():
        if str(request_id) not in known_ids:
            counts[str(_mapping(review).get("status") or "pending")] += 1
    return {
        "store": str(store_path),
        "total": sum(counts.values()),
        "pending": counts.get("pending", 0),
        "approved": counts.get("approved", 0),
        "denied": counts.get("denied", 0),
    }


def _capability_request_review_summary(reviews: Mapping[str, Any]) -> dict[str, Any]:
    request_reviews = _mapping(reviews.get("requests"))
    counts = Counter(str(_mapping(review).get("status") or "pending") for review in request_reviews.values())
    return {
        "reviewed": len(request_reviews),
        "approved": counts.get("approved", 0),
        "denied": counts.get("denied", 0),
        "updated_at": reviews.get("updated_at"),
    }


def _capability_request_review_snapshot(request: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty_json(
        {
            "id": request.get("id"),
            "task": request.get("task"),
            "reason_code": request.get("reason_code"),
            "method": request.get("method"),
            "tool": request.get("tool"),
            "argument_keys": request.get("argument_keys"),
            "capability_match": request.get("capability_match"),
            "suggested_lease": request.get("suggested_lease"),
            "raw_policy_change": request.get("raw_policy_change"),
            "auth": request.get("auth"),
            "source": request.get("source"),
            "observations": request.get("observations"),
        }
    )


def _share_capability_lease_file(
    share_dir: Path,
    session_model: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> Path:
    files = _mapping(manifest.get("files")) if manifest is not None else {}
    lease = _mapping(session_model.get("lease"))
    paths = _mapping(session_model.get("paths"))
    value = lease.get("file") or paths.get("lease_file") or files.get("lease_file") or "leases.json"
    return _resolve_share_path(share_dir, value)


def _share_capability_lease_header(
    session_model: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> str:
    session = _mapping(manifest.get("session")) if manifest is not None else {}
    lease = _mapping(session_model.get("lease"))
    return str(lease.get("header") or session.get("lease_header") or "x-snulbug-lease")


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Mapping):
        return [str(key) for key, enabled in value.items() if enabled is True and str(key)]
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item) for item in value if str(item)]
    return []


def _merge_string_lists(*values: Any) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in _string_list(value):
            if item not in seen:
                result.append(item)
                seen.add(item)
    return result


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed > 0 else None
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


def _share_policy_amend_log_path(
    share_dir: Path,
    session_model: Mapping[str, Any],
    log: str | Path | None,
) -> Path:
    if log is not None:
        return _resolve_share_path(share_dir, log)
    evidence = _mapping(session_model.get("evidence"))
    paths = _mapping(session_model.get("paths"))
    for value in (
        evidence.get("audit_log"),
        evidence.get("record_log"),
        paths.get("audit_log"),
        paths.get("record_log"),
    ):
        if isinstance(value, str) and value:
            path = _resolve_share_path(share_dir, value)
            if path.is_file():
                return path
    raise FileNotFoundError("share policy amend requires --log or an existing audit/session log")


def _share_policy_amend_output_path(share_dir: Path, bundle: Path, output: str | Path | None) -> Path:
    if output is not None:
        return _resolve_share_path(share_dir, output)
    return bundle


def _share_policy_amend_preview_output_path(share_dir: Path, output: str | Path | None) -> Path:
    if output is not None:
        return _resolve_share_path(share_dir, output)
    return share_dir / ".snulbug" / "share" / "previews" / "policy-amendment.snulbug"


def _record_share_policy_amendment(
    share_dir: Path,
    manifest: Mapping[str, Any] | None,
    session_model: Mapping[str, Any],
    *,
    amendment: Mapping[str, Any],
) -> dict[str, Any]:
    output = amendment.get("output")
    if manifest is not None:
        updated_manifest = json.loads(json.dumps(dict(manifest), default=str))
        policy = dict(_mapping(updated_manifest.get("policy")))
        policy["last_amendment"] = dict(amendment)
        updated_manifest["policy"] = policy
        amendments = dict(_mapping(updated_manifest.get("amendments")))
        candidates = [dict(item) for item in _sequence(amendments.get("candidates")) if isinstance(item, Mapping)]
        candidates.append(dict(amendment))
        amendments["last"] = output
        amendments["candidates"] = candidates
        updated_manifest["amendments"] = amendments
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
    policy["last_amendment"] = dict(amendment)
    model["policy"] = policy
    amendments = dict(_mapping(model.get("amendments")))
    candidates = [dict(item) for item in _sequence(amendments.get("candidates")) if isinstance(item, Mapping)]
    candidates.append(dict(amendment))
    amendments["last"] = output
    amendments["candidates"] = candidates
    model["amendments"] = amendments
    write_share_session_model(share_dir, model, force=True)
    return model


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
        raise ValueError("share member attach requires --member-id or metadata member_id")
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
        "attached_by": "snulbug mcp share member attach",
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
    lines = ["# Remote members attached by `snulbug mcp share member attach`."]
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


def _new_share_invite_id() -> str:
    return f"invite_{secrets.token_urlsafe(9).replace('-', '').replace('_', '')[:12]}"


def _share_client_bearer_token(manifest: Mapping[str, Any]) -> tuple[str, str, str]:
    client = _mapping(manifest.get("client"))
    headers = _mapping(client.get("headers"))
    for name, value in headers.items():
        if str(name).lower() != "authorization":
            continue
        auth_value = str(value)
        prefix = "bearer "
        if not auth_value.lower().startswith(prefix):
            raise ValueError("share client Authorization header is not a bearer token")
        token = auth_value[len(prefix) :].strip()
        if not token or token.startswith("${"):
            raise ValueError("share bearer token is not stored locally; mint or resolve it client-side")
        return str(name), f"Bearer {token}", token
    raise ValueError("share client does not include an Authorization bearer token")


def _redacted_invite_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    redacted = {}
    for name, value in headers.items():
        if str(name).lower() == "authorization":
            redacted[str(name)] = "Bearer " + SECRET_REPLACEMENT
        else:
            redacted[str(name)] = SECRET_REPLACEMENT if value else ""
    return redacted


def _share_invite_setup_snippets(
    *,
    client_name: str,
    client_url: str,
    headers: Mapping[str, str],
    bearer_token: str,
    lease_header: str,
    lease_token: str,
) -> dict[str, Any]:
    config = _client_config(client_name, client_url, {str(key): str(value) for key, value in headers.items()})
    header_args = " ".join(f"-H {shlex.quote(f'{name}: {value}')}" for name, value in headers.items())
    curl_body = json.dumps({"jsonrpc": "2.0", "id": "tools-list", "method": "tools/list", "params": {}})
    curl = (
        f"curl -sS {shlex.quote(client_url)} "
        f"{header_args} -H 'Content-Type: application/json' "
        f"-H 'Accept: application/json, text/event-stream' -d {shlex.quote(curl_body)}"
    )
    claude_code_headers = " ".join(f"--header {shlex.quote(f'{name}: {value}')}" for name, value in headers.items())
    codex_env = {
        "SNULBUG_MCP_BEARER_TOKEN": bearer_token,
        "SNULBUG_MCP_LEASE_TOKEN": lease_token,
    }
    codex_config = _codex_mcp_config_toml(
        client_name=client_name,
        client_url=client_url,
        bearer_env="SNULBUG_MCP_BEARER_TOKEN",
        lease_header=lease_header,
        lease_env="SNULBUG_MCP_LEASE_TOKEN",
    )
    inspector = _mcp_inspector_setup_snippets(client_name=client_name, client_url=client_url, headers=headers)
    return {
        "client_url": client_url,
        "headers": dict(headers),
        "mcp_client_json": config,
        "claude_desktop": {
            "description": "Merge this into Claude Desktop's MCP server configuration.",
            "json": config,
        },
        "cursor": {
            "description": "Merge this into Cursor's MCP server configuration.",
            "json": config,
        },
        "claude_code": {
            "description": "HTTP MCP server setup command for Claude Code.",
            "command": (
                f"claude mcp add --transport http {shlex.quote(client_name)} "
                f"{shlex.quote(client_url)} {claude_code_headers}"
            ),
        },
        "codex": {
            "description": "Add this to ~/.codex/config.toml or a trusted project .codex/config.toml.",
            "config_toml": codex_config,
            "env": codex_env,
        },
        "mcp_inspector": inspector,
        "curl": {
            "description": "Smoke-test the invite by listing tools.",
            "command": curl,
        },
        "env": {
            "SNULBUG_INVITE_URL": client_url,
            "SNULBUG_BEARER_TOKEN": bearer_token,
            "SNULBUG_LEASE_HEADER": lease_header,
            "SNULBUG_LEASE_TOKEN": lease_token,
        },
    }


def _mcp_inspector_setup_snippets(
    *,
    client_name: str,
    client_url: str,
    headers: Mapping[str, str],
) -> dict[str, Any]:
    header_args = _mcp_inspector_header_args(headers)
    query = urlencode({"transport": "streamable-http", "serverUrl": client_url})
    ui_url = f"http://localhost:6274/?{query}"
    config = {
        "mcpServers": {
            client_name: {
                "type": "streamable-http",
                "url": client_url,
            }
        }
    }
    base_cli = f"npx {MCP_INSPECTOR_PACKAGE} --cli {shlex.quote(client_url)} --transport http"
    if header_args:
        base_cli = f"{base_cli} {header_args}"
    return {
        "description": "Test this Snulbug share with MCP Inspector as a real MCP client.",
        "url": client_url,
        "headers": dict(headers),
        "ui": {
            "description": "Start Inspector, then open this URL to preselect Streamable HTTP and the Snulbug MCP URL.",
            "launch_command": f"npx {MCP_INSPECTOR_PACKAGE}",
            "open_url": ui_url,
        },
        "cli": {
            "description": (
                "Scriptable Inspector checks that should show up in Snulbug audit and invite connection status."
            ),
            "tools_list": f"{base_cli} --method tools/list",
            "resources_list": f"{base_cli} --method resources/list",
            "prompts_list": f"{base_cli} --method prompts/list",
        },
        "config": {
            "description": (
                "Inspector config file payload. Headers are supplied by the CLI command or Inspector UI fields."
            ),
            "json": config,
            "command": f"npx {MCP_INSPECTOR_PACKAGE} --config mcp-inspector.json --server {shlex.quote(client_name)}",
        },
    }


def _mcp_inspector_header_args(headers: Mapping[str, str]) -> str:
    return " ".join(f"--header {shlex.quote(f'{name}: {value}')}" for name, value in headers.items())


def _share_inspector_invite_headers(
    share_dir: Path,
    invite: Mapping[str, Any],
    *,
    include_secrets: bool,
) -> dict[str, str]:
    if include_secrets:
        store = _load_share_invite_secret_store(share_dir)
        secret_payload = _mapping(_mapping(store.get("invitations")).get(str(invite.get("id") or "")))
        headers = _string_mapping(_mapping(secret_payload.get("headers")))
        if headers:
            return headers
    lease_header = str(invite.get("lease_header") or "x-snulbug-lease")
    return {
        "Authorization": "Bearer ${SNULBUG_MCP_BEARER_TOKEN}",
        lease_header: "${SNULBUG_MCP_LEASE_TOKEN}",
    }


def _share_inspector_placeholder_headers(
    headers: Mapping[str, str],
    *,
    session_model: Mapping[str, Any],
) -> dict[str, str]:
    result: dict[str, str] = {}
    lease_header = _share_capability_lease_header(session_model, {})
    for name, value in headers.items():
        normalized = str(name).lower()
        if normalized == "authorization":
            result[str(name)] = "Bearer ${SNULBUG_MCP_BEARER_TOKEN}"
        elif normalized == str(lease_header).lower() or "lease" in normalized:
            result[str(name)] = "${SNULBUG_MCP_LEASE_TOKEN}"
        else:
            result[str(name)] = str(value)
    return result


def _codex_mcp_config_toml(
    *,
    client_name: str,
    client_url: str,
    bearer_env: str,
    lease_header: str,
    lease_env: str,
) -> str:
    return "\n".join(
        [
            f"[mcp_servers.{_toml_bare_or_quoted_key(client_name)}]",
            f"url = {_toml_string(client_url)}",
            f"bearer_token_env_var = {_toml_string(bearer_env)}",
            f"env_http_headers = {{ {_toml_string(lease_header)} = {_toml_string(lease_env)} }}",
        ]
    )


def _toml_bare_or_quoted_key(value: str) -> str:
    if value and all(char.isalnum() or char in "_-" for char in value):
        return value
    return _toml_string(value)


def _toml_string(value: str) -> str:
    return json.dumps(str(value))


def _record_share_invite(
    share_dir: Path,
    session_model: Mapping[str, Any],
    invite: Mapping[str, Any],
) -> dict[str, Any]:
    model = json.loads(json.dumps(dict(session_model), default=str))
    invitations = dict(_mapping(model.get("invitations")))
    items = [dict(_mapping(item)) for item in _sequence(invitations.get("items")) if isinstance(item, Mapping)]
    items.append(dict(invite))
    invitations["items"] = items
    invitations["last_created"] = dict(invite)
    invitations["summary"] = _share_invite_summary(items)
    model["invitations"] = invitations
    write_share_session_model(share_dir, model, force=True)
    return model


def _share_invite_secret_store_path(share_dir: Path) -> Path:
    return share_dir / SHARE_INVITE_SECRET_STORE_PATH


def _load_share_invite_secret_store(share_dir: Path) -> dict[str, Any]:
    path = _share_invite_secret_store_path(share_dir)
    if not path.is_file():
        return {
            "schema": "snulbug.share.invite-secret-store.v1",
            "invitations": {},
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "schema": "snulbug.share.invite-secret-store.v1",
            "invitations": {},
        }
    if not isinstance(payload, Mapping):
        return {
            "schema": "snulbug.share.invite-secret-store.v1",
            "invitations": {},
        }
    store = dict(payload)
    if not isinstance(store.get("invitations"), Mapping):
        store["invitations"] = {}
    return store


def _write_share_invite_secret_store(share_dir: Path, store: Mapping[str, Any]) -> None:
    path = _share_invite_secret_store_path(share_dir)
    _write_json(path, store, force=True)


def _record_share_invite_secret(share_dir: Path, invite_id: str, payload: Mapping[str, Any]) -> None:
    store = _load_share_invite_secret_store(share_dir)
    invitations = dict(_mapping(store.get("invitations")))
    invitations[invite_id] = json.loads(json.dumps(dict(payload), default=str))
    updated = dict(store)
    updated["schema"] = updated.get("schema") or "snulbug.share.invite-secret-store.v1"
    updated["updated_at"] = _now_iso()
    updated["invitations"] = invitations
    _write_share_invite_secret_store(share_dir, updated)


def _share_active_lease_ids(
    share_dir: Path,
    session_model: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> set[str]:
    from .leases import list_leases

    try:
        listed = list_leases(_share_capability_lease_file(share_dir, session_model, manifest))
    except Exception:
        return set()
    return {
        str(lease.get("id"))
        for lease in _sequence(listed.get("leases"))
        if isinstance(lease, Mapping) and lease.get("id") and lease.get("active")
    }


def _share_invite_is_stale(
    invite: Mapping[str, Any],
    *,
    active_secret_ids: set[str],
    active_lease_ids: set[str],
) -> bool:
    invite_id = str(invite.get("id") or "")
    lease_id = str(invite.get("lease_id") or "")
    return not invite_id or invite_id not in active_secret_ids or not lease_id or lease_id not in active_lease_ids


def _remove_share_invite_secret(share_dir: Path, invite_id: str) -> None:
    store = _load_share_invite_secret_store(share_dir)
    invitations = dict(_mapping(store.get("invitations")))
    if invite_id not in invitations:
        return
    invitations.pop(invite_id, None)
    updated = dict(store)
    updated["updated_at"] = _now_iso()
    updated["invitations"] = invitations
    _write_share_invite_secret_store(share_dir, updated)


def _prune_share_invite_secrets(share_dir: Path, *, active_ids: set[str]) -> None:
    store = _load_share_invite_secret_store(share_dir)
    invitations = dict(_mapping(store.get("invitations")))
    kept = {invite_id: payload for invite_id, payload in invitations.items() if str(invite_id) in active_ids}
    if kept == invitations:
        return
    updated = dict(store)
    updated["updated_at"] = _now_iso()
    updated["invitations"] = kept
    _write_share_invite_secret_store(share_dir, updated)


def _attach_share_invite_secrets(
    share_dir: Path,
    items: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    store = _load_share_invite_secret_store(share_dir)
    secrets_by_invite = _mapping(store.get("invitations"))
    hydrated: list[dict[str, Any]] = []
    for item in items:
        invite = dict(_mapping(item))
        invite_id = str(invite.get("id") or "")
        secret_payload = _mapping(secrets_by_invite.get(invite_id))
        if invite_id and not invite.get("revoked_at") and secret_payload:
            invite["setup_available"] = True
            if isinstance(secret_payload.get("headers"), Mapping):
                invite["headers"] = dict(_mapping(secret_payload.get("headers")))
            if isinstance(secret_payload.get("setup_snippets"), Mapping):
                invite["setup_snippets"] = dict(_mapping(secret_payload.get("setup_snippets")))
            for key in ("bearer_token", "lease_token"):
                value = secret_payload.get(key)
                if isinstance(value, str) and value:
                    invite[key] = value
        else:
            invite["setup_available"] = False
            invite.pop("headers", None)
            invite.pop("setup_snippets", None)
            invite.pop("bearer_token", None)
            invite.pop("lease_token", None)
        hydrated.append(invite)
    return hydrated


def _share_invite_summary(items: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    total = len(items)
    revoked = sum(1 for item in items if item.get("revoked_at"))
    return {
        "total": total,
        "active": total - revoked,
        "revoked": revoked,
    }


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
    share_doctor = f"uv run snulbug mcp share doctor {shlex.quote(str(share_dir))}"
    return {
        "export_token": f"export {DEFAULT_SHARE_TOKEN_ENV}={shlex.quote(token)}",
        "run": f"uv run snulbug mcp share run {shlex.quote(str(share_dir))}",
        "proxy": f"uv run snulbug mcp share run --config {shlex.quote(str(config))}",
        "provider": [str(command["command"]) for command in provider_commands],
        "doctor": share_doctor,
        "share_doctor": share_doctor,
        "client": f"uv run snulbug mcp share client {shlex.quote(str(share_dir))}",
        "inspector": f"uv run snulbug mcp share inspector {shlex.quote(str(share_dir))}",
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
            "cloudflare_access_profile": _mapping(quickstart.get("cloudflare")).get("profile"),
            "tailscale_profile": _mapping(quickstart.get("tailscale")).get("profile"),
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


def _record_share_contract(
    share_dir: Path,
    contract: Mapping[str, Any],
    *,
    path: str | Path,
    required: bool,
) -> dict[str, Any]:
    manifest = load_mcp_share(share_dir)
    metadata = share_contract_runtime_metadata(contract, path=path, required=required, verified=True)
    contracts = dict(_mapping(manifest.get("contracts")))
    contracts["last"] = dict(metadata)
    manifest["contracts"] = contracts
    manifest["updated_at"] = _now_iso()
    (share_dir / SHARE_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    update_share_session_model(share_dir, manifest=manifest)
    return metadata


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
    if path.is_absolute():
        return path
    if _relative_path_starts_with(path, share_dir):
        return path
    if path.exists():
        return path
    return share_dir / path


def _relative_path_starts_with(path: Path, prefix: Path) -> bool:
    if path.is_absolute() or prefix.is_absolute():
        return False
    try:
        path.relative_to(prefix)
    except ValueError:
        return False
    return True


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
    client_extra_headers: Mapping[str, str] | None,
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
    client_headers.update(dict(client_extra_headers or {}))
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

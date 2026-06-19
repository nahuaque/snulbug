from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SHARE_SESSION_MODEL_TYPE = "snulbug.share.session"
SHARE_SESSION_MODEL_VERSION = 1
SHARE_SESSION_MODEL_PATH = Path(".snulbug") / "share" / "session.json"
SESSION_MODEL_PRESERVED_KEYS = ("invitations", "capability_requests")


def share_session_model_path(directory: str | Path) -> Path:
    """Return the canonical control-plane session model path for a share directory."""

    return Path(directory) / SHARE_SESSION_MODEL_PATH


def build_share_session_model(
    manifest: Mapping[str, Any],
    *,
    directory: str | Path | None = None,
) -> dict[str, Any]:
    """Build a secret-light, control-plane oriented share session model."""

    if directory is not None:
        share_dir = Path(directory)
    else:
        share_dir = Path(str(_mapping(manifest.get("session")).get("directory", ".")))
    session = _mapping(manifest.get("session"))
    files = _mapping(manifest.get("files"))
    tunnel = _mapping(manifest.get("tunnel"))
    tunnel_client = _mapping(tunnel.get("client"))
    client = _mapping(manifest.get("client"))
    lease = _mapping(manifest.get("lease"))
    runtime = _mapping(manifest.get("runtime"))
    contracts = _mapping(manifest.get("contracts"))
    closeout = _mapping(manifest.get("closeout"))
    recipes = _mapping(manifest.get("recipes"))
    health = _mapping(manifest.get("health"))
    members = _mapping(manifest.get("members"))
    policy_metadata = _mapping(manifest.get("policy"))

    policy_bundle = files.get("policy")
    policy_file = files.get("policy_file")
    config = files.get("config")
    lifecycle = _policy_lifecycle(share_dir, policy_bundle)
    public_url = client.get("url") or tunnel_client.get("url") or tunnel.get("public_url")
    local_url = tunnel.get("local_url") or _local_gateway_url(session)

    model = {
        "type": SHARE_SESSION_MODEL_TYPE,
        "version": SHARE_SESSION_MODEL_VERSION,
        "id": session.get("id"),
        "status": {
            "state": manifest.get("state", "created"),
            "created_at": manifest.get("created_at"),
            "updated_at": manifest.get("updated_at"),
            "closed_at": _mapping(closeout).get("closed_at"),
        },
        "share": {
            "directory": str(share_dir),
            "task": session.get("task"),
            "preset": session.get("preset"),
            "ttl": session.get("ttl"),
        },
        "gateway": {
            "host": session.get("host"),
            "port": session.get("port"),
            "state_store": session.get("state"),
            "local_url": local_url,
            "config": config,
            "fabric_config": config,
        },
        "tunnel": {
            "provider": session.get("provider") or tunnel.get("provider"),
            "cloudflare_access_profile": session.get("cloudflare_access_profile"),
            "tailscale_profile": session.get("tailscale_profile"),
            "public_url": public_url,
            "local_url": local_url,
            "client_url": public_url,
            "bridge": tunnel.get("bridge"),
        },
        "upstreams": _upstreams(session),
        "policy": {
            "bundle": policy_bundle,
            "active_policy": policy_file,
            "lifecycle_state": lifecycle.get("state"),
            "lifecycle_signed": lifecycle.get("signed"),
            "lifecycle_signature": lifecycle.get("signature"),
            "last_amendment": policy_metadata.get("last_amendment"),
            "last_lifecycle": policy_metadata.get("last_lifecycle"),
        },
        "lease": {
            "file": files.get("lease_file") or lease.get("file"),
            "required": session.get("lease_required"),
            "header": session.get("lease_header") or lease.get("header"),
            "active_id": lease.get("id"),
            "expires_at": lease.get("expires_at"),
        },
        "evidence": {
            "record_log": files.get("session_log"),
            "audit_log": files.get("audit_log"),
            "share_report": files.get("report"),
            "closeout_report": closeout.get("report"),
        },
        "client": {
            "name": client.get("name"),
            "url": public_url,
            "config": client.get("config"),
            "header_names": sorted(str(key) for key in _mapping(client.get("headers")).keys()),
        },
        "health": {
            "last_summary": health.get("last_summary"),
            "last_checked_at": health.get("last_checked_at"),
            "share_doctor": health.get("share_doctor"),
            "tunnel_doctor": health.get("tunnel_doctor"),
        },
        "amendments": {
            "last": _mapping(manifest.get("amendments")).get("last"),
            "candidates": list(_sequence(_mapping(manifest.get("amendments")).get("candidates"))),
        },
        "runtime": {
            "started_at": runtime.get("started_at"),
            "config": runtime.get("config"),
            "contract": runtime.get("contract"),
        },
        "contracts": {
            "last": contracts.get("last"),
        },
        "members": {
            "registry": members.get("registry"),
            "registry_key": members.get("registry_key"),
            "discovery_provider": members.get("discovery_provider"),
            "attachments": list(_sequence(members.get("attachments"))),
        },
        "paths": {
            "legacy_manifest": files.get("manifest"),
            "session_model": str(share_session_model_path(share_dir)),
            "config": config,
            "fabric_config": config,
            "policy_bundle": policy_bundle,
            "active_policy": policy_file,
            "lease_file": files.get("lease_file") or lease.get("file"),
            "member_registry": files.get("member_registry") or members.get("registry"),
            "record_log": files.get("session_log"),
            "audit_log": files.get("audit_log"),
            "share_report": files.get("report"),
            "client_config": client.get("config"),
            "container_recipes": files.get("container_recipes"),
        },
        "remote_dev": {
            "container_recipe": _mapping(recipes.get("remote_container_upstream")).get("directory"),
        },
    }
    return _drop_empty(model)


def write_share_session_model(
    directory: str | Path,
    model: Mapping[str, Any],
    *,
    force: bool = False,
) -> Path:
    """Write the canonical share session model."""

    path = share_session_model_path(directory)
    if path.exists() and not force:
        raise FileExistsError(f"share session model already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(model), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_share_session_model(directory: str | Path) -> dict[str, Any]:
    """Load a canonical share session model."""

    path = Path(directory)
    model_path = path if path.is_file() else share_session_model_path(path)
    with model_path.open("r", encoding="utf-8") as file:
        model = json.load(file)
    if not isinstance(model, Mapping):
        raise ValueError(f"share session model must contain a JSON object: {model_path}")
    if model.get("type") != SHARE_SESSION_MODEL_TYPE:
        raise ValueError(f"unsupported share session model type: {model.get('type')!r}")
    return dict(model)


def update_share_session_model(
    directory: str | Path,
    *,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild and write the session model from the current share manifest."""

    existing: Mapping[str, Any] = {}
    try:
        existing = load_share_session_model(directory)
    except (OSError, ValueError, json.JSONDecodeError):
        existing = {}
    model = build_share_session_model(manifest, directory=directory)
    for key in SESSION_MODEL_PRESERVED_KEYS:
        if key not in model and key in existing:
            model[key] = existing[key]
    write_share_session_model(directory, model, force=True)
    return model


def _upstreams(session: Mapping[str, Any]) -> list[dict[str, Any]]:
    upstream = session.get("upstream")
    if not isinstance(upstream, str) or not upstream:
        return []
    return [{"name": "default", "transport": "http", "url": upstream}]


def _local_gateway_url(session: Mapping[str, Any]) -> str | None:
    host = session.get("host")
    port = session.get("port")
    if host is None or port is None:
        return None
    return f"http://{host}:{port}/mcp"


def _policy_lifecycle(share_dir: Path, bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, str) or not bundle:
        return {"state": "observed", "signed": False}
    manifest_path = _resolve_path(share_dir, bundle) / "manifest.json"
    if not manifest_path.is_file():
        return {"state": "observed", "signed": False}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {"state": "unknown", "signed": False}
    manifest_mapping = _mapping(manifest)
    lifecycle = _mapping(manifest_mapping.get("snulbug_lifecycle") or manifest_mapping.get("lifecycle"))
    signature = _mapping(lifecycle.get("signature"))
    return {
        "state": lifecycle.get("state", "observed"),
        "signed": bool(signature),
        "signature": signature,
        "signature_key_id": signature.get("key_id"),
    }


def _resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, list | tuple):
        return list(value)
    return []


def _drop_empty(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {str(key): _drop_empty(item) for key, item in value.items()}
        return {key: item for key, item in result.items() if item not in ({}, [], None)}
    if isinstance(value, list):
        return [_drop_empty(item) for item in value]
    return value

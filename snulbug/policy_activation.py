from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .bundle import (
    inspect_bundle_lifecycle,
    load_bundle,
    promote_bundle_lifecycle,
    verify_bundle_lifecycle,
)
from .config import DEFAULT_CONFIG_PATH, load_mcp_fabric_config

POLICY_ACTIVATION_MODES = ("off", "require_active", "promote_approved")


def reconcile_policy_activation(config: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Reconcile configured policy bundle lifecycle state for a fabric."""

    config_path = Path(config)
    fabric = load_mcp_fabric_config(config_path)
    activation = _activation_config(fabric.get("policy_activation"))
    mode = str(activation.get("mode", "off"))
    if mode == "off":
        return {"ok": True, "mode": mode, "action": "skipped", "reason": "policy activation is disabled"}

    proxy = _mapping(fabric.get("proxy"))
    policy_path = Path(str(proxy.get("policy"))) if proxy.get("policy") is not None else None
    if policy_path is None:
        return _failed(mode, "mcp.proxy.policy is not configured")
    bundle_root = _policy_bundle_root(policy_path)
    if bundle_root is None:
        return _failed(mode, f"policy is not a bundle entrypoint: {policy_path}", policy=policy_path)

    lifecycle = inspect_bundle_lifecycle(bundle_root)
    state = str(lifecycle.get("state"))
    secret_env = str(activation.get("secret_env") or "SNULBUG_BUNDLE_SECRET")
    secret = os.environ.get(secret_env, "")
    key_id = _activation_key_id(activation, lifecycle)
    base = {
        "mode": mode,
        "policy": str(policy_path),
        "bundle": str(bundle_root),
        "name": lifecycle.get("name"),
        "version": lifecycle.get("version"),
        "previous_state": state,
        "secret_env": secret_env,
        "key_id": key_id,
    }
    if not secret:
        return {**base, "ok": False, "action": "blocked", "error": f"{secret_env} is not set"}
    if not key_id:
        return {**base, "ok": False, "action": "blocked", "error": "policy bundle signing key id is not configured"}

    if mode == "require_active":
        return _verify_active(bundle_root, base=base, secret=secret, key_id=key_id)

    if state == "active":
        return _verify_active(bundle_root, base=base, secret=secret, key_id=key_id)
    if state != "approved":
        return {
            **base,
            "ok": False,
            "action": "blocked",
            "error": f"policy bundle lifecycle state {state!r} is not approved or active",
        }

    try:
        approved_verification = verify_bundle_lifecycle(
            bundle_root,
            secrets={key_id: secret},
            required_state="approved",
        )
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "action": "blocked",
            "state": state,
            "error": f"approved policy bundle verification failed: {exc}",
        }

    try:
        promoted = promote_bundle_lifecycle(
            bundle_root,
            to_state="active",
            secret=secret,
            key_id=key_id,
            actor=str(activation.get("actor") or "snulbug fabric controller"),
            note=str(activation.get("note") or "activated by fabric controller"),
            instruction_limit=int(activation.get("instruction_limit") or 100_000),
            memory_limit_bytes=_memory_limit(activation.get("memory_limit_bytes")),
        )
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "action": "blocked",
            "state": state,
            "approved_verification": approved_verification,
            "error": f"policy bundle promotion failed: {exc}",
        }
    if not promoted.get("ok"):
        return {
            **base,
            "ok": False,
            "action": "blocked",
            "state": state,
            "approved_verification": approved_verification,
            "error": promoted.get("error", "policy bundle promotion failed"),
            "validation": promoted.get("validation"),
        }
    try:
        verified = verify_bundle_lifecycle(bundle_root, secrets={key_id: secret}, required_state="active")
    except Exception as exc:
        return {
            **base,
            "ok": False,
            "action": "blocked",
            "state": "active",
            "approved_verification": approved_verification,
            "validation": promoted.get("validation"),
            "signature": promoted.get("signature"),
            "error": f"activated policy bundle verification failed: {exc}",
        }
    return {
        **base,
        "ok": True,
        "action": "activated",
        "state": "active",
        "activated": True,
        "approved_verification": approved_verification,
        "validation": promoted.get("validation"),
        "signature": promoted.get("signature"),
        "verified": verified,
    }


def _verify_active(bundle_root: Path, *, base: Mapping[str, Any], secret: str, key_id: str) -> dict[str, Any]:
    try:
        verified = verify_bundle_lifecycle(bundle_root, secrets={key_id: secret}, required_state="active")
    except Exception as exc:
        return {
            **dict(base),
            "ok": False,
            "action": "blocked",
            "state": base.get("previous_state"),
            "error": str(exc),
        }
    return {
        **dict(base),
        "ok": True,
        "action": "verified_active",
        "state": "active",
        "activated": False,
        "verified": verified,
    }


def _activation_config(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _activation_key_id(activation: Mapping[str, Any], lifecycle: Mapping[str, Any]) -> str:
    configured = activation.get("key_id")
    if isinstance(configured, str) and configured:
        return configured
    signature = lifecycle.get("signature")
    if isinstance(signature, Mapping):
        key_id = signature.get("key_id")
        if isinstance(key_id, str) and key_id:
            return key_id
    return ""


def _policy_bundle_root(policy_path: Path) -> Path | None:
    try:
        bundle = load_bundle(policy_path.parent)
    except Exception:
        return None
    try:
        if bundle.entrypoint.resolve() != policy_path.resolve():
            return None
    except OSError:
        return None
    return bundle.root


def _memory_limit(value: Any) -> int | None:
    if value is None:
        return 8 * 1024 * 1024
    if value == "none":
        return None
    return int(value)


def _failed(mode: str, error: str, *, policy: Path | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "mode": mode,
        "action": "blocked",
        **({"policy": str(policy)} if policy is not None else {}),
        "error": error,
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

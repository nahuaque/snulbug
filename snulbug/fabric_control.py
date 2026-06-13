from __future__ import annotations

import os
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FABRIC_CONTROL_STATE_SCHEMA = "snulbug.fabric-control-actions.v1"
FABRIC_CONTROL_ACTION_TYPES = (
    "pause_sharing",
    "drain_upstream",
    "quarantine_upstream",
    "force_reload",
    "rollback_policy",
)
UPSTREAM_CONTROL_ACTION_TYPES = {"drain_upstream", "quarantine_upstream"}
DEFAULT_FORCE_RELOAD_TTL_SECONDS = 60.0


def load_fabric_control_state(
    spec: str | Path | Any = None,
    *,
    key: str | None = None,
) -> dict[str, Any]:
    from .fabric_runtime import DEFAULT_FABRIC_RUNTIME_STATE, DEFAULT_FABRIC_RUNTIME_STATE_KEY

    store = _open_store(
        DEFAULT_FABRIC_RUNTIME_STATE if spec is None else spec,
        key=DEFAULT_FABRIC_RUNTIME_STATE_KEY if key is None else key,
    )
    if store is None:
        return _control_state_result(
            spec="none",
            key=DEFAULT_FABRIC_RUNTIME_STATE_KEY if key is None else key,
            state=None,
            error="fabric runtime state is disabled",
        )
    should_close = not _looks_like_runtime_store(spec)
    try:
        state = _load_store_control_state(store)
        return _control_state_result(
            spec=DEFAULT_FABRIC_RUNTIME_STATE if spec is None else spec,
            key=DEFAULT_FABRIC_RUNTIME_STATE_KEY if key is None else key,
            state=state,
        )
    finally:
        if should_close:
            store.close()


def issue_fabric_control_action(
    spec: str | Path | Any = None,
    *,
    key: str | None = None,
    action_type: str,
    target: str | None = None,
    policy: str | Path | None = None,
    reason: str | None = None,
    actor: str | None = None,
    ttl_seconds: float | None = None,
) -> dict[str, Any]:
    from .fabric_runtime import DEFAULT_FABRIC_RUNTIME_STATE, DEFAULT_FABRIC_RUNTIME_STATE_KEY

    runtime_state = DEFAULT_FABRIC_RUNTIME_STATE if spec is None else spec
    runtime_key = DEFAULT_FABRIC_RUNTIME_STATE_KEY if key is None else key
    _validate_action_input(action_type, target=target, policy=policy, ttl_seconds=ttl_seconds)
    store = _open_store(runtime_state, key=runtime_key)
    if store is None:
        return {
            "ok": False,
            "runtime_state": "none",
            "runtime_state_key": runtime_key,
            "error": "fabric runtime state is disabled",
        }
    should_close = not _looks_like_runtime_store(spec)
    try:
        state = _normalized_control_state(_load_store_control_state(store))
        action = _new_action(
            action_type,
            target=target,
            policy=policy,
            reason=reason,
            actor=actor,
            ttl_seconds=_default_ttl(action_type, ttl_seconds),
        )
        state["actions"].append(action)
        state["updated_at"] = _utc_now()
        _save_store_control_state(store, state)
        summary = summarize_fabric_control_state(state)
        return {
            "ok": True,
            "runtime_state": str(runtime_state),
            "runtime_state_key": runtime_key,
            "issued": True,
            "action": action,
            "summary": summary,
        }
    finally:
        if should_close:
            store.close()


def clear_fabric_control_actions(
    spec: str | Path | Any = None,
    *,
    key: str | None = None,
    action_id: str | None = None,
    action_type: str | None = None,
    target: str | None = None,
    actor: str | None = None,
) -> dict[str, Any]:
    from .fabric_runtime import DEFAULT_FABRIC_RUNTIME_STATE, DEFAULT_FABRIC_RUNTIME_STATE_KEY

    runtime_state = DEFAULT_FABRIC_RUNTIME_STATE if spec is None else spec
    runtime_key = DEFAULT_FABRIC_RUNTIME_STATE_KEY if key is None else key
    store = _open_store(runtime_state, key=runtime_key)
    if store is None:
        return {
            "ok": False,
            "runtime_state": "none",
            "runtime_state_key": runtime_key,
            "cleared": 0,
            "error": "fabric runtime state is disabled",
        }
    should_close = not _looks_like_runtime_store(spec)
    try:
        state = _normalized_control_state(_load_store_control_state(store))
        now = _utc_now()
        cleared = []
        for action in state["actions"]:
            if action.get("status") != "active":
                continue
            if action_id is not None and action.get("id") != action_id:
                continue
            if action_type is not None and action.get("type") != action_type:
                continue
            if target is not None and action.get("target") != target:
                continue
            action["status"] = "cleared"
            action["cleared_at"] = now
            action["cleared_by"] = _actor(actor)
            cleared.append(action)
        state["updated_at"] = now
        _save_store_control_state(store, state)
        summary = summarize_fabric_control_state(state)
        return {
            "ok": True,
            "runtime_state": str(runtime_state),
            "runtime_state_key": runtime_key,
            "cleared": len(cleared),
            "actions": cleared,
            "summary": summary,
        }
    finally:
        if should_close:
            store.close()


def summarize_fabric_control_state(state: Mapping[str, Any] | None) -> dict[str, Any]:
    if _looks_like_control_summary(state):
        return _normalized_control_summary(state)
    normalized = _normalized_control_state(state)
    active = active_fabric_control_actions(normalized)
    drained = sorted(
        {
            str(action["target"])
            for action in active
            if action.get("type") == "drain_upstream" and isinstance(action.get("target"), str)
        }
    )
    quarantined = sorted(
        {
            str(action["target"])
            for action in active
            if action.get("type") == "quarantine_upstream" and isinstance(action.get("target"), str)
        }
    )
    force_reload_actions = [action for action in active if action.get("type") == "force_reload"]
    rollback_actions = [action for action in active if action.get("type") == "rollback_policy"]
    return _drop_empty(
        {
            "schema": FABRIC_CONTROL_STATE_SCHEMA,
            "active_count": len(active),
            "paused": any(action.get("type") == "pause_sharing" for action in active),
            "drained_upstreams": drained,
            "quarantined_upstreams": quarantined,
            "disabled_upstreams": sorted(set(drained) | set(quarantined)),
            "force_reload": bool(force_reload_actions),
            "force_reload_ids": [str(action.get("id")) for action in force_reload_actions if action.get("id")],
            "rollback_policy": _action_summary(rollback_actions[-1]) if rollback_actions else None,
            "actions": [_action_summary(action) for action in active],
        }
    )


def active_fabric_control_actions(state: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    normalized = _normalized_control_state(state)
    now = datetime.now(timezone.utc)
    actions = []
    for action in _sequence_mappings(normalized.get("actions")):
        if action.get("status") != "active":
            continue
        expires_at = action.get("expires_at")
        if isinstance(expires_at, str) and expires_at:
            parsed = _parse_timestamp(expires_at)
            if parsed is not None and parsed <= now:
                continue
        actions.append(_copy_jsonish(action))
    return sorted(actions, key=lambda item: str(item.get("created_at", "")))


def annotate_fabric_status_with_controls(
    status: Mapping[str, Any],
    control_state: Mapping[str, Any] | None,
) -> dict[str, Any]:
    updated = _copy_jsonish(status)
    controls = summarize_fabric_control_state(control_state)
    disabled = set(controls.get("disabled_upstreams", []))
    drained = set(controls.get("drained_upstreams", []))
    quarantined = set(controls.get("quarantined_upstreams", []))
    upstreams = []
    for upstream in _sequence_mappings(updated.get("upstreams")):
        name = upstream.get("name")
        operational_status = "active"
        if name in quarantined:
            operational_status = "quarantined"
        elif name in drained:
            operational_status = "draining"
        upstreams.append(
            _drop_empty(
                {
                    **_copy_jsonish(upstream),
                    "routable": name not in disabled and not controls.get("paused"),
                    "operational_status": operational_status,
                }
            )
        )
    updated["upstreams"] = upstreams
    updated["operational_controls"] = controls
    if controls.get("active_count"):
        recommendations = list(updated.get("recommendations", []))
        recommendations.append("Review active fabric operational controls before sharing this gateway.")
        updated["recommendations"] = recommendations
    return updated


def upstream_is_disabled_by_controls(upstream_name: str, controls: Mapping[str, Any] | None) -> bool:
    summary = summarize_fabric_control_state(controls)
    return bool(summary.get("paused")) or upstream_name in set(summary.get("disabled_upstreams", []))


def control_share_gate_signals(controls: Mapping[str, Any] | None) -> tuple[list[str], list[str]]:
    summary = summarize_fabric_control_state(controls)
    blocks = []
    warnings = []
    if summary.get("paused"):
        blocks.append("sharing_paused")
    if summary.get("rollback_policy"):
        blocks.append("policy_rollback_requested")
    active_count = int(summary.get("active_count", 0) or 0)
    if active_count:
        warnings.append("operational_controls_active")
    if summary.get("disabled_upstreams"):
        warnings.append("upstreams_disabled_by_control")
    if summary.get("force_reload"):
        warnings.append("force_reload_requested")
    return blocks, warnings


def format_fabric_control_report(result: Mapping[str, Any]) -> str:
    summary = _mapping(result.get("summary"))
    actions = _sequence_mappings(summary.get("actions"))
    lines = [
        "# snulbug fabric control",
        "",
        f"Store: {result.get('runtime_state')}",
        f"Key: {result.get('runtime_state_key')}",
        f"Status: {'ok' if result.get('ok') else 'error'}",
    ]
    if result.get("error"):
        lines.append(f"Error: {result.get('error')}")
    if result.get("issued"):
        action = _mapping(result.get("action"))
        lines.append(f"Issued: `{action.get('type')}` id=`{action.get('id')}`")
    if "cleared" in result:
        lines.append(f"Cleared: {result.get('cleared')}")
    lines.extend(
        [
            "",
            "## Active Controls",
            f"- paused: `{str(bool(summary.get('paused'))).lower()}`",
            f"- active actions: {summary.get('active_count', 0)}",
            "- disabled upstreams: "
            f"`{', '.join(str(item) for item in summary.get('disabled_upstreams', [])) or 'none'}`",
            f"- force reload: `{str(bool(summary.get('force_reload'))).lower()}`",
        ]
    )
    rollback = _mapping(summary.get("rollback_policy"))
    if rollback:
        lines.append(f"- rollback policy: `{rollback.get('policy', rollback.get('target', 'requested'))}`")
    if actions:
        lines.extend(["", "## Actions"])
        for action in actions:
            target = f" target=`{action.get('target')}`" if action.get("target") else ""
            policy = f" policy=`{action.get('policy')}`" if action.get("policy") else ""
            lines.append(f"- `{action.get('id')}` `{action.get('type')}`{target}{policy}")
    return "\n".join(lines).rstrip()


def _control_state_result(
    *,
    spec: str | Path | Any,
    key: str,
    state: Mapping[str, Any] | None,
    error: str | None = None,
) -> dict[str, Any]:
    summary = summarize_fabric_control_state(state)
    return {
        "ok": error is None,
        "runtime_state": str(spec),
        "runtime_state_key": key,
        "state": _normalized_control_state(state),
        "summary": summary,
        **({"error": error} if error else {}),
    }


def _new_action(
    action_type: str,
    *,
    target: str | None,
    policy: str | Path | None,
    reason: str | None,
    actor: str | None,
    ttl_seconds: float | None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    expires_at = None
    if ttl_seconds is not None:
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, timezone.utc).isoformat()
    return _drop_empty(
        {
            "id": f"ctrl_{uuid.uuid4().hex}",
            "type": action_type,
            "target": target,
            "policy": str(policy) if policy is not None else None,
            "reason": reason,
            "actor": _actor(actor),
            "status": "active",
            "created_at": now.isoformat(),
            "expires_at": expires_at,
        }
    )


def _validate_action_input(
    action_type: str,
    *,
    target: str | None,
    policy: str | Path | None,
    ttl_seconds: float | None,
) -> None:
    if action_type not in FABRIC_CONTROL_ACTION_TYPES:
        raise ValueError(f"unknown fabric control action type: {action_type}")
    if action_type in UPSTREAM_CONTROL_ACTION_TYPES and not target:
        raise ValueError(f"{action_type} requires an upstream target")
    if action_type not in UPSTREAM_CONTROL_ACTION_TYPES and target is not None:
        raise ValueError(f"{action_type} does not accept an upstream target")
    if action_type == "rollback_policy" and policy is None:
        raise ValueError("rollback_policy requires a policy path")
    if action_type != "rollback_policy" and policy is not None:
        raise ValueError(f"{action_type} does not accept a policy path")
    if ttl_seconds is not None and ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")


def _default_ttl(action_type: str, ttl_seconds: float | None) -> float | None:
    if ttl_seconds is not None:
        return ttl_seconds
    if action_type == "force_reload":
        return DEFAULT_FORCE_RELOAD_TTL_SECONDS
    return None


def _actor(actor: str | None) -> str:
    if actor:
        return actor
    return os.environ.get("USER") or os.environ.get("USERNAME") or "snulbug"


def _normalized_control_state(state: Mapping[str, Any] | None) -> dict[str, Any]:
    if state is None:
        return {
            "schema": FABRIC_CONTROL_STATE_SCHEMA,
            "version": 1,
            "updated_at": None,
            "actions": [],
        }
    if state.get("schema") != FABRIC_CONTROL_STATE_SCHEMA or state.get("version") != 1:
        raise ValueError("fabric control state schema is unsupported")
    actions = []
    for action in _sequence_mappings(state.get("actions")):
        action_type = action.get("type")
        if action_type not in FABRIC_CONTROL_ACTION_TYPES:
            continue
        item = _copy_jsonish(action)
        item.setdefault("status", "active")
        actions.append(item)
    return {
        "schema": FABRIC_CONTROL_STATE_SCHEMA,
        "version": 1,
        "updated_at": state.get("updated_at"),
        "actions": actions,
    }


def _looks_like_control_summary(state: Mapping[str, Any] | None) -> bool:
    if not isinstance(state, Mapping):
        return False
    if state.get("version") == 1:
        return False
    return "active_count" in state or "disabled_upstreams" in state or "paused" in state


def _normalized_control_summary(state: Mapping[str, Any]) -> dict[str, Any]:
    actions = [_action_summary(action) for action in _sequence_mappings(state.get("actions"))]
    return _drop_empty(
        {
            "schema": FABRIC_CONTROL_STATE_SCHEMA,
            "active_count": int(state.get("active_count", len(actions)) or 0),
            "paused": bool(state.get("paused", False)),
            "drained_upstreams": sorted(str(item) for item in state.get("drained_upstreams", []) or []),
            "quarantined_upstreams": sorted(str(item) for item in state.get("quarantined_upstreams", []) or []),
            "disabled_upstreams": sorted(str(item) for item in state.get("disabled_upstreams", []) or []),
            "force_reload": bool(state.get("force_reload", False)),
            "force_reload_ids": [str(item) for item in state.get("force_reload_ids", []) or []],
            "rollback_policy": _copy_jsonish(state.get("rollback_policy")),
            "actions": actions,
        }
    )


def _action_summary(action: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "id": action.get("id"),
            "type": action.get("type"),
            "target": action.get("target"),
            "policy": action.get("policy"),
            "reason": action.get("reason"),
            "actor": action.get("actor"),
            "created_at": action.get("created_at"),
            "expires_at": action.get("expires_at"),
        }
    )


def _open_store(spec: Any, *, key: str) -> Any:
    from .fabric_runtime import open_fabric_runtime_state_store

    return open_fabric_runtime_state_store(spec, key=key)


def _load_store_control_state(store: Any) -> dict[str, Any] | None:
    load = getattr(store, "load_control_state", None)
    if not callable(load):
        return None
    state = load()
    return _normalized_control_state(state)


def _save_store_control_state(store: Any, state: Mapping[str, Any]) -> None:
    save = getattr(store, "save_control_state", None)
    if not callable(save):
        raise ValueError("fabric runtime store does not support operational controls")
    save(_normalized_control_state(state))


def _looks_like_runtime_store(value: Any) -> bool:
    return callable(getattr(value, "load_status", None)) and callable(getattr(value, "save_status", None))


def _sequence_mappings(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_copy_jsonish(item) for item in value]
    return value


def _drop_empty(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in payload.items() if item is not None and item != [] and item != {}}


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

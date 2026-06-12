from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .runtime import CompiledLuaScript, LuaDecisionError, LuaRuntimeError, compile_lua_file
from .simulator import normalize_request
from .state import BoundedPolicyState, SnapshotStateStore

_ACTIONS = {"continue", "set_context", "rewrite", "respond", "reject", "challenge", "redirect", "rate_limit"}
_COMPARE_FIELDS = (
    "action",
    "status",
    "path",
    "query",
    "query_string",
    "headers",
    "body",
    "body_base64",
    "context",
    "scheme",
    "realm",
    "error",
    "error_description",
    "scope",
    "location",
    "key",
    "limit",
    "window",
)


def diff_policies(
    old_script_path: str | Path,
    new_script_path: str | Path,
    fixtures_path: str | Path,
    *,
    context: Mapping[str, Any] | None = None,
    state_snapshots_path: str | Path | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Replay fixtures against two policies and report promotion risk."""

    old_script = compile_lua_file(
        old_script_path,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    new_script = compile_lua_file(
        new_script_path,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )

    fixture_paths = list_fixture_paths(fixtures_path)
    results = []
    for fixture_path in fixture_paths:
        state_snapshot = load_state_snapshot_for_fixture(state_snapshots_path, fixture_path)
        results.append(diff_fixture(old_script, new_script, fixture_path, context=context, state_snapshot=state_snapshot))
    changed = [result for result in results if result["changed"]]
    regressions = [result for result in results if result["regression"]]
    return {
        "safe_to_promote": not regressions,
        "old_policy": str(old_script_path),
        "new_policy": str(new_script_path),
        "fixture_count": len(results),
        "changed_decisions": len(changed),
        "regression_count": len(regressions),
        "regressions": regressions,
        "results": results,
    }


def diff_fixture(
    old_script: CompiledLuaScript,
    new_script: CompiledLuaScript,
    fixture_path: str | Path,
    *,
    context: Mapping[str, Any] | None = None,
    state_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    fixture = _read_json(Path(fixture_path))
    request, body_read = normalize_request(fixture)

    old_result = _execute_policy(old_script, request, context or {}, state_snapshot=state_snapshot)
    new_result = _execute_policy(new_script, request, context or {}, state_snapshot=state_snapshot)
    comparison = compare_decisions(old_result.get("decision"), new_result.get("decision"))
    return {
        "fixture": str(fixture_path),
        "body_read": body_read,
        "old": old_result,
        "new": new_result,
        **comparison,
    }


def compare_decisions(old_decision: Any, new_decision: Any) -> dict[str, Any]:
    old_error = old_decision if isinstance(old_decision, str) else None
    new_error = new_decision if isinstance(new_decision, str) else None
    if old_error or new_error:
        changed = old_error != new_error
        return {
            "changed": changed,
            "regression": new_error is not None,
            "reason": _error_reason(old_error, new_error),
            "differences": [],
        }

    if not isinstance(old_decision, Mapping) or not isinstance(new_decision, Mapping):
        return {
            "changed": old_decision != new_decision,
            "regression": True,
            "reason": "policy returned a non-object decision",
            "differences": [],
        }

    differences = [
        {"field": field, "old": old_decision.get(field), "new": new_decision.get(field)}
        for field in _COMPARE_FIELDS
        if old_decision.get(field) != new_decision.get(field)
    ]
    changed = bool(differences)
    regression = _is_regression(old_decision, new_decision)
    return {
        "changed": changed,
        "regression": regression,
        "reason": _regression_reason(old_decision, new_decision) if regression else None,
        "differences": differences,
    }


def list_fixture_paths(path: str | Path) -> list[Path]:
    fixture_path = Path(path)
    if fixture_path.is_file():
        return [fixture_path]
    if not fixture_path.is_dir():
        raise FileNotFoundError(f"fixture path does not exist: {fixture_path}")
    return sorted(fixture_path.rglob("*.json"))


def load_state_snapshot_for_fixture(path: str | Path | None, fixture_path: str | Path) -> Mapping[str, Any] | None:
    if path is None:
        return None

    snapshot_path = Path(path)
    fixture = Path(fixture_path)
    if snapshot_path.is_file():
        return _read_json(snapshot_path)
    if not snapshot_path.is_dir():
        raise FileNotFoundError(f"state snapshot path does not exist: {snapshot_path}")

    candidates = [
        snapshot_path / fixture.name,
        snapshot_path / f"{fixture.stem}.state.json",
        snapshot_path / f"{fixture.stem}.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return _read_json(candidate)
    return None


def _execute_policy(
    script: CompiledLuaScript,
    request: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    state_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        snapshot_store = SnapshotStateStore.from_snapshot(state_snapshot) if state_snapshot is not None else None
        state = BoundedPolicyState(snapshot_store) if snapshot_store is not None else None
        trace = script.decide_with_trace(request, context, state)
        action = trace.decision["action"]
        if action not in _ACTIONS:
            raise LuaDecisionError(
                "Lua action must be one of continue, set_context, rewrite, respond, reject, "
                f"challenge, redirect, rate_limit; got {action!r}"
            )
        result = {
            "ok": True,
            "action": action,
            "decision": trace.decision,
            "trace": trace.to_dict(),
        }
        if snapshot_store is not None:
            result["state_snapshot"] = snapshot_store.snapshot()
        return result
    except (LuaDecisionError, LuaRuntimeError) as exc:
        return {
            "ok": False,
            "action": "error",
            "decision": str(exc),
            "trace": {},
        }


def _is_regression(old_decision: Mapping[str, Any], new_decision: Mapping[str, Any]) -> bool:
    old_action = old_decision.get("action", "continue")
    new_action = new_decision.get("action", "continue")
    if new_action in {"reject", "challenge"} and old_action != new_action:
        return True

    old_status = _effective_status(old_decision)
    new_status = _effective_status(new_decision)
    return old_status is not None and old_status < 400 and new_status is not None and new_status >= 400


def _effective_status(decision: Mapping[str, Any]) -> int | None:
    action = decision.get("action", "continue")
    if action == "reject":
        return int(decision.get("status", 403))
    if action == "challenge":
        return int(decision.get("status", 401))
    if action == "respond":
        return int(decision.get("status", 200))
    if action == "redirect":
        return int(decision.get("status", 307))
    return None


def _regression_reason(old_decision: Mapping[str, Any], new_decision: Mapping[str, Any]) -> str:
    old_action = old_decision.get("action", "continue")
    new_action = new_decision.get("action", "continue")
    if new_action in {"reject", "challenge"} and old_action != new_action:
        return f"action changed from {old_action} to {new_action}"
    return f"status changed from {_effective_status(old_decision)} to {_effective_status(new_decision)}"


def _error_reason(old_error: str | None, new_error: str | None) -> str | None:
    if new_error and not old_error:
        return f"new policy errored: {new_error}"
    if old_error and not new_error:
        return None
    if old_error != new_error:
        return "policy errors changed"
    return None


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

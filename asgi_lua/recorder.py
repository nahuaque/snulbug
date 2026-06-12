from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .simulator import simulate_policy

RECORD_TYPE = "asgi-lua.request_record"
RECORD_VERSION = 1


def record_policy_request(
    script_path: str | Path,
    request: Mapping[str, Any],
    *,
    context: Mapping[str, Any] | None = None,
    state_snapshot: Mapping[str, Any] | None = None,
    response: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    recorded_at: str | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Record a replayable policy decision for one request fixture."""

    result = simulate_policy(
        script_path,
        request,
        context=context,
        state_snapshot=state_snapshot,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    record: dict[str, Any] = {
        "type": RECORD_TYPE,
        "version": RECORD_VERSION,
        "recorded_at": recorded_at or datetime.now(timezone.utc).isoformat(),
        "policy": {"source": str(script_path)},
        "request": dict(request),
        "result": result,
    }
    if context is not None:
        record["context"] = dict(context)
    if state_snapshot is not None:
        record["state"] = {"input": dict(state_snapshot)}
    if response is not None:
        record["response"] = dict(response)
    if metadata is not None:
        record["metadata"] = dict(metadata)
    return record


def append_record(path: str | Path, record: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
        file.write("\n")


def load_record_log(path: str | Path) -> list[dict[str, Any]]:
    records = []
    with Path(path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValueError(f"record line {line_number} must be a JSON object")
            _validate_record(value, line_number)
            records.append(value)
    return records


def replay_record_log(
    path: str | Path,
    *,
    script_path: str | Path | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Replay a JSONL request log and compare current decisions to recorded decisions."""

    records = load_record_log(path)
    results = [
        _replay_record(
            record,
            script_path=script_path,
            instruction_limit=instruction_limit,
            memory_limit_bytes=memory_limit_bytes,
        )
        for record in records
    ]
    changed = [result for result in results if result["changed"]]
    failed = [result for result in results if result.get("error")]
    return {
        "ok": not changed and not failed,
        "log": str(path),
        "record_count": len(records),
        "changed": len(changed),
        "failed": len(failed),
        "results": results,
    }


def _replay_record(
    record: Mapping[str, Any],
    *,
    script_path: str | Path | None,
    instruction_limit: int,
    memory_limit_bytes: int | None,
) -> dict[str, Any]:
    source = str(script_path or _record_policy_source(record))
    try:
        result = simulate_policy(
            source,
            _mapping(record.get("request"), "request"),
            context=_optional_mapping(record.get("context"), "context"),
            state_snapshot=_record_state_input(record),
            instruction_limit=instruction_limit,
            memory_limit_bytes=memory_limit_bytes,
        )
    except Exception as exc:
        return {
            "ok": False,
            "changed": False,
            "policy": source,
            "error": str(exc),
            "recorded": _recorded_result(record),
        }

    recorded = _recorded_result(record)
    recorded_decision = recorded.get("decision") if isinstance(recorded, Mapping) else None
    actual_decision = result.get("decision")
    changed = actual_decision != recorded_decision
    return {
        "ok": not changed,
        "changed": changed,
        "policy": source,
        "recorded": recorded,
        "actual": result,
    }


def _validate_record(record: Mapping[str, Any], line_number: int) -> None:
    if record.get("type") != RECORD_TYPE:
        raise ValueError(f"record line {line_number} has unsupported type: {record.get('type')!r}")
    if record.get("version") != RECORD_VERSION:
        raise ValueError(f"record line {line_number} has unsupported version: {record.get('version')!r}")
    _mapping(record.get("policy"), "policy")
    _mapping(record.get("request"), "request")
    _mapping(record.get("result"), "result")


def _record_policy_source(record: Mapping[str, Any]) -> str:
    policy = _mapping(record.get("policy"), "policy")
    source = policy.get("source")
    if not isinstance(source, str) or not source:
        raise ValueError("record policy.source must be a non-empty string")
    return source


def _record_state_input(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    state = record.get("state")
    if state is None:
        return None
    return _optional_mapping(_mapping(state, "state").get("input"), "state.input")


def _recorded_result(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(record.get("result"), "result")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"record {label} must be an object")
    return value


def _optional_mapping(value: Any, label: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    return _mapping(value, label)

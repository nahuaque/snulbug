from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

CONTROL_EVENT_SCHEMA = "snulbug.control-plane-event.v1"
CONTROL_EVENT_VERSION = 1

EVENT_ROUTE_CHANGED = "snulbug.fabric.route.changed"
EVENT_MANIFEST_CHANGED = "snulbug.fabric.manifest.changed"
EVENT_POLICY_CHANGED = "snulbug.fabric.policy.changed"
EVENT_DISCOVERY_DEGRADED = "snulbug.fabric.discovery.degraded"
EVENT_DISCOVERY_RECOVERED = "snulbug.fabric.discovery.recovered"
EVENT_UPSTREAM_DEGRADED = "snulbug.fabric.upstream.degraded"
EVENT_UPSTREAM_UNHEALTHY = "snulbug.fabric.upstream.unhealthy"
EVENT_UPSTREAM_RECOVERED = "snulbug.fabric.upstream.recovered"
EVENT_RELOAD_FAILED = "snulbug.fabric.reload.failed"
EVENT_RELOAD_RECOVERED = "snulbug.fabric.reload.recovered"


def make_control_event(
    event_type: str,
    *,
    time: str,
    message: str,
    severity: str = "info",
    subject: Mapping[str, Any] | None = None,
    reason_code: str | None = None,
    previous: Any = None,
    current: Any = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable control-plane event record."""

    return _drop_empty(
        {
            "schema": CONTROL_EVENT_SCHEMA,
            "version": CONTROL_EVENT_VERSION,
            "type": event_type,
            "event_type": event_type,
            "time": time,
            "severity": severity,
            "subject": _copy_jsonish(subject or {}),
            "reason_code": reason_code,
            "message": message,
            "previous": _copy_jsonish(previous),
            "current": _copy_jsonish(current),
            "details": _copy_jsonish(details or {}),
        }
    )


def event_types(events: Any) -> list[str]:
    return [str(event["type"]) for event in _event_sequence(events) if isinstance(event.get("type"), str)]


def _event_sequence(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, tuple):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    try:
        json.dumps(value)
    except TypeError:
        return str(value)
    return value

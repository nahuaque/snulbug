from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .recorder import RECORD_TYPE
from .redaction import build_audit_event

AUDIT_TYPE = "asgi-lua.audit"


def inspect_mcp_log(path: str | Path, *, kind: str = "auto", top: int = 10) -> dict[str, Any]:
    """Inspect replay or audit JSONL logs without replaying requests."""

    if kind not in {"auto", "audit", "record"}:
        raise ValueError("kind must be 'auto', 'audit', or 'record'")
    if top <= 0:
        raise ValueError("top must be positive")

    events = _load_events(path, kind=kind)
    inspector = _Inspector(top=top)
    for event in events:
        inspector.add(event)
    return inspector.report(path, source_kinds={event["source_kind"] for event in events})


class _Inspector:
    def __init__(self, *, top: int) -> None:
        self.top = top
        self.event_count = 0
        self.first_time: str | None = None
        self.last_time: str | None = None
        self.actions: Counter[str] = Counter()
        self.reason_codes: Counter[str] = Counter()
        self.decision_statuses: Counter[str] = Counter()
        self.response_statuses: Counter[str] = Counter()
        self.http_methods: Counter[str] = Counter()
        self.paths: Counter[str] = Counter()
        self.mcp_methods: Counter[str] = Counter()
        self.operations: Counter[str] = Counter()
        self.tools: Counter[str] = Counter()
        self.targets: Counter[str] = Counter()
        self.body_kinds: Counter[str] = Counter()
        self.allowed = 0
        self.blocked = 0
        self.batch_requests = 0
        self.invalid_mcp_json = 0
        self.missing_reason_code = 0
        self.upstream_errors = 0
        self.blocked_examples: list[dict[str, Any]] = []
        self.invalid_json_examples: list[dict[str, Any]] = []
        self.upstream_error_examples: list[dict[str, Any]] = []

    def add(self, event: Mapping[str, Any]) -> None:
        self.event_count += 1
        self._record_time(event.get("time"))
        request = _mapping(event.get("request"))
        decision = _mapping(event.get("decision"))
        response = _mapping(event.get("response"))
        mcp = _mapping(event.get("mcp"))

        action = _string(decision.get("action"), "unknown")
        self.actions[action] += 1
        if decision.get("allowed") is False:
            self.blocked += 1
            self._append_example(self.blocked_examples, event)
        else:
            self.allowed += 1

        self._count(self.reason_codes, decision.get("reason_code"))
        if not decision.get("reason_code"):
            self.missing_reason_code += 1
        self._count(self.decision_statuses, decision.get("status"))
        self._count(self.response_statuses, response.get("status"))
        self._count(self.http_methods, request.get("method"))
        self._count(self.paths, request.get("path"))
        self._count(self.mcp_methods, mcp.get("method"))
        self._count(self.operations, mcp.get("operation"))
        self._count(self.tools, mcp.get("tool"))
        self._count(self.targets, mcp.get("target"))
        self._count(self.body_kinds, mcp.get("body_kind"))

        if mcp.get("batch") is True:
            self.batch_requests += 1
        if mcp.get("valid_json") is False:
            self.invalid_mcp_json += 1
            self._append_example(self.invalid_json_examples, event)
        if _status_is_server_error(response.get("status")):
            self.upstream_errors += 1
            self._append_example(self.upstream_error_examples, event)

    def report(self, path: str | Path, *, source_kinds: set[str]) -> dict[str, Any]:
        return {
            "ok": True,
            "log": str(path),
            "kind": _source_kind(source_kinds),
            "event_count": self.event_count,
            "time_range": {"first": self.first_time, "last": self.last_time},
            "decisions": {
                "allowed": self.allowed,
                "blocked": self.blocked,
                "actions": _top_counts(self.actions, self.top),
                "reason_codes": _top_counts(self.reason_codes, self.top),
                "statuses": _top_counts(self.decision_statuses, self.top),
                "missing_reason_code": self.missing_reason_code,
            },
            "mcp": {
                "methods": _top_counts(self.mcp_methods, self.top),
                "operations": _top_counts(self.operations, self.top),
                "tools": _top_counts(self.tools, self.top),
                "targets": _top_counts(self.targets, self.top),
                "body_kinds": _top_counts(self.body_kinds, self.top),
                "batch_requests": self.batch_requests,
                "invalid_json": self.invalid_mcp_json,
            },
            "requests": {
                "methods": _top_counts(self.http_methods, self.top),
                "paths": _top_counts(self.paths, self.top),
            },
            "responses": {"statuses": _top_counts(self.response_statuses, self.top)},
            "findings": self._findings(),
            "examples": {
                "blocked": self.blocked_examples,
                "invalid_json": self.invalid_json_examples,
                "upstream_errors": self.upstream_error_examples,
            },
        }

    def _record_time(self, value: Any) -> None:
        if not isinstance(value, str) or not value:
            return
        if self.first_time is None or value < self.first_time:
            self.first_time = value
        if self.last_time is None or value > self.last_time:
            self.last_time = value

    def _count(self, counter: Counter[str], value: Any) -> None:
        if value is not None and value != "":
            counter[_string(value, "unknown")] += 1

    def _append_example(self, examples: list[dict[str, Any]], event: Mapping[str, Any]) -> None:
        if len(examples) < 5:
            examples.append(_event_summary(event))

    def _findings(self) -> list[dict[str, Any]]:
        findings = []
        self._add_finding(findings, "blocked_decisions", self.blocked, "warning")
        self._add_finding(findings, "missing_reason_code", self.missing_reason_code, "info")
        self._add_finding(findings, "invalid_mcp_json", self.invalid_mcp_json, "warning")
        self._add_finding(findings, "batch_requests", self.batch_requests, "info")
        self._add_finding(findings, "upstream_errors", self.upstream_errors, "error")
        tool_blocks = self.reason_codes.get("mcp.tool_not_allowed", 0)
        self._add_finding(findings, "blocked_mcp_tools", tool_blocks, "warning")
        auth_failures = self.reason_codes.get("mcp.auth_required", 0)
        self._add_finding(findings, "auth_challenges", auth_failures, "info")
        return findings

    @staticmethod
    def _add_finding(findings: list[dict[str, Any]], finding_type: str, count: int, severity: str) -> None:
        if count:
            findings.append({"type": finding_type, "severity": severity, "count": count})


def _load_events(path: str | Path, *, kind: str) -> list[dict[str, Any]]:
    events = []
    with Path(path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValueError(f"inspect line {line_number} must be a JSON object")
            events.append(_normalize_event(value, kind=kind, line_number=line_number))
    return events


def _normalize_event(value: Mapping[str, Any], *, kind: str, line_number: int) -> dict[str, Any]:
    event_type = value.get("type")
    if kind == "record" or (kind == "auto" and event_type == RECORD_TYPE):
        event = build_audit_event(value)
        event["source_kind"] = "record"
    elif kind == "audit" or (kind == "auto" and _looks_like_audit_event(value)):
        event = dict(value)
        event["source_kind"] = "audit"
    else:
        raise ValueError(f"inspect line {line_number} has unsupported event type: {event_type!r}")
    event["line"] = line_number
    return event


def _looks_like_audit_event(value: Mapping[str, Any]) -> bool:
    return value.get("type") == AUDIT_TYPE or ("decision" in value and "mcp" in value)


def _event_summary(event: Mapping[str, Any]) -> dict[str, Any]:
    request = _mapping(event.get("request"))
    decision = _mapping(event.get("decision"))
    response = _mapping(event.get("response"))
    mcp = _mapping(event.get("mcp"))
    return {
        "line": event.get("line"),
        "time": event.get("time"),
        "action": decision.get("action"),
        "reason_code": decision.get("reason_code"),
        "status": response.get("status", decision.get("status")),
        "path": request.get("path"),
        "mcp_method": mcp.get("method"),
        "tool": mcp.get("tool"),
        "target": mcp.get("target"),
    }


def _top_counts(counter: Counter[str], top: int) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(top)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: Any, default: str) -> str:
    return default if value is None else str(value)


def _source_kind(kinds: set[str]) -> str:
    if not kinds:
        return "empty"
    return next(iter(kinds)) if len(kinds) == 1 else "mixed"


def _status_is_server_error(value: Any) -> bool:
    try:
        return int(value) >= 500
    except (TypeError, ValueError):
        return False

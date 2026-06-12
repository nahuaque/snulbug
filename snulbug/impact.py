from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .leases import list_leases, preview_mcp_lease_coverage
from .recorder import load_record_log
from .redaction import build_audit_event
from .simulator import simulate_policy

ALLOWED_ACTIONS = {"continue", "set_context", "rewrite", "rate_limit"}
RISKY_TOOL_PATTERN = re.compile(r"(?:^|[._-])(shell|exec|command|cmd|process|terminal|run)(?:$|[._-])", re.I)


def analyze_mcp_impact(
    log: str | Path,
    *,
    policy: str | Path | None = None,
    lease_file: str | Path | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Preview candidate policy and lease impact against captured MCP replay records."""

    if policy is None and lease_file is None:
        raise ValueError("at least one of policy or lease_file is required")

    records = load_record_log(log)
    policy_report = _analyze_policy(
        records,
        policy=policy,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    lease_report = _analyze_lease(records, lease_file=lease_file)
    findings = _findings(policy_report, lease_report)
    ok = not any(finding["severity"] == "error" for finding in findings)
    return {
        "ok": ok,
        "log": str(log),
        "record_count": len(records),
        "policy": policy_report,
        "lease": lease_report,
        "findings": findings,
    }


def format_mcp_impact_report(report: Mapping[str, Any], *, output_format: str = "markdown") -> str:
    """Format an impact analysis as a Markdown review report."""

    if output_format != "markdown":
        raise ValueError("output_format must be 'markdown'")

    policy = _mapping(report.get("policy"))
    lease = _mapping(report.get("lease"))
    lines = [
        "# snulbug MCP Impact Report",
        "",
        "## Overview",
        "",
        _table(
            ["Field", "Value"],
            [
                ["Log", report.get("log")],
                ["Records", report.get("record_count")],
                ["OK", report.get("ok")],
            ],
        ),
        "",
        "## Policy Impact",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Enabled", policy.get("enabled")],
                ["Policy", policy.get("path") or "-"],
                ["Changed", policy.get("changed", 0)],
                ["Newly allowed", policy.get("newly_allowed", 0)],
                ["Newly blocked", policy.get("newly_blocked", 0)],
                ["Action changed", policy.get("action_changed", 0)],
                ["Failed", policy.get("failed", 0)],
            ],
        ),
        "",
        "### Changed Decisions",
        "",
        _examples_table(policy.get("changes")),
        "",
        "## Lease Coverage",
        "",
        _table(
            ["Metric", "Value"],
            [
                ["Enabled", lease.get("enabled")],
                ["Lease file", lease.get("file") or "-"],
                ["Tool calls", lease.get("tool_call_count", 0)],
                ["Covered", lease.get("covered", 0)],
                ["Uncovered", lease.get("uncovered", 0)],
                ["Coverage", f"{lease.get('coverage_percent', 0):.1f}%"],
            ],
        ),
        "",
        "### Tool Calls",
        "",
        _counts_table(lease.get("tools")),
        "",
        "### Uncovered Calls",
        "",
        _examples_table(lease.get("uncovered_examples")),
        "",
        "## Findings",
        "",
        _findings_table(report.get("findings")),
        "",
    ]
    return "\n".join(lines)


def _analyze_policy(
    records: Sequence[Mapping[str, Any]],
    *,
    policy: str | Path | None,
    instruction_limit: int,
    memory_limit_bytes: int | None,
) -> dict[str, Any]:
    if policy is None:
        return {"enabled": False, "path": None}

    changes = []
    failed = []
    unchanged = 0
    newly_allowed = 0
    newly_blocked = 0
    action_changed = 0
    policy_path = str(policy)

    for line, record in enumerate(records, start=1):
        event = build_audit_event(record, redact=False)
        recorded = _recorded_result(record)
        try:
            actual = simulate_policy(
                policy_path,
                _mapping_required(record.get("request"), "request"),
                context=_optional_mapping(record.get("context"), "context"),
                state_snapshot=_record_state_input(record),
                instruction_limit=instruction_limit,
                memory_limit_bytes=memory_limit_bytes,
            )
        except Exception as exc:
            failed.append({"line": line, "error": str(exc), **_event_summary(event)})
            continue

        recorded_decision = _mapping(recorded.get("decision"))
        actual_decision = _mapping(actual.get("decision"))
        recorded_action = str(recorded.get("action") or recorded_decision.get("action") or "")
        actual_action = str(actual.get("action") or actual_decision.get("action") or "")
        recorded_allowed = _action_allowed(recorded_action)
        actual_allowed = _action_allowed(actual_action)
        recorded_reason = recorded_decision.get("reason_code")
        actual_reason = actual_decision.get("reason_code")
        changed = (
            recorded_action != actual_action or recorded_allowed != actual_allowed or recorded_reason != actual_reason
        )
        if not changed:
            unchanged += 1
            continue
        if not recorded_allowed and actual_allowed:
            newly_allowed += 1
        if recorded_allowed and not actual_allowed:
            newly_blocked += 1
        if recorded_action != actual_action:
            action_changed += 1
        changes.append(
            {
                "line": line,
                **_event_summary(event),
                "recorded_action": recorded_action,
                "actual_action": actual_action,
                "recorded_allowed": recorded_allowed,
                "actual_allowed": actual_allowed,
                "recorded_reason_code": recorded_reason,
                "actual_reason_code": actual_reason,
            }
        )

    return {
        "enabled": True,
        "path": policy_path,
        "record_count": len(records),
        "unchanged": unchanged,
        "changed": len(changes),
        "newly_allowed": newly_allowed,
        "newly_blocked": newly_blocked,
        "action_changed": action_changed,
        "failed": len(failed),
        "changes": changes[:50],
        "failures": failed[:20],
    }


def _analyze_lease(records: Sequence[Mapping[str, Any]], *, lease_file: str | Path | None) -> dict[str, Any]:
    if lease_file is None:
        return {"enabled": False, "file": None}

    coverage_consumption: dict[str, int] = {}
    tools: Counter[str] = Counter()
    covered = 0
    uncovered = 0
    uncovered_examples = []
    coverage_results = []
    lease_path = Path(lease_file)

    for line, record in enumerate(records, start=1):
        event = build_audit_event(record, redact=False)
        mcp = _mapping(event.get("mcp"))
        if mcp.get("method") != "tools/call":
            continue
        tool = mcp.get("tool")
        if isinstance(tool, str):
            tools[tool] += 1
        request = _jsonrpc_request(record)
        coverage = preview_mcp_lease_coverage(request, lease_path, consumption=coverage_consumption)
        coverage_results.append({"line": line, **_event_summary(event), **_coverage_summary(coverage)})
        if coverage.get("covered"):
            covered += 1
        else:
            uncovered += 1
            if len(uncovered_examples) < 20:
                uncovered_examples.append({"line": line, **_event_summary(event), **_coverage_summary(coverage)})

    tool_call_count = covered + uncovered
    coverage_percent = 100.0 if tool_call_count == 0 else (covered / tool_call_count) * 100.0
    lease_list = list_leases(lease_path) if lease_path.exists() else {"ok": False, "leases": []}
    return {
        "enabled": True,
        "file": str(lease_path),
        "tool_call_count": tool_call_count,
        "covered": covered,
        "uncovered": uncovered,
        "coverage_percent": coverage_percent,
        "tools": _top_counts(tools),
        "uncovered_examples": uncovered_examples,
        "results": coverage_results[:100],
        "risk_findings": _lease_risks(lease_list.get("leases", [])),
        "leases": lease_list.get("leases", []),
    }


def _findings(policy: Mapping[str, Any], lease: Mapping[str, Any]) -> list[dict[str, Any]]:
    findings = []
    if policy.get("enabled"):
        _add_finding(findings, "policy.newly_blocked", policy.get("newly_blocked", 0), "error")
        _add_finding(findings, "policy.failed_replay", policy.get("failed", 0), "error")
        _add_finding(findings, "policy.newly_allowed", policy.get("newly_allowed", 0), "warning")
        _add_finding(findings, "policy.changed_decisions", policy.get("changed", 0), "info")
    if lease.get("enabled"):
        _add_finding(findings, "lease.uncovered_calls", lease.get("uncovered", 0), "error")
        for risk in lease.get("risk_findings", []):
            if isinstance(risk, Mapping):
                findings.append(dict(risk))
    return findings


def _lease_risks(leases: Any) -> list[dict[str, Any]]:
    risks = []
    if not isinstance(leases, Sequence) or isinstance(leases, str | bytes | bytearray):
        return risks
    for lease in leases:
        if not isinstance(lease, Mapping):
            continue
        lease_id = lease.get("id")
        tools = [str(tool) for tool in lease.get("allow_tools", [])]
        paths = [str(path) for path in lease.get("allow_paths", [])]
        if "*" in tools:
            risks.append(_risk("lease.wildcard_tool", "warning", lease_id, "lease allows every tool"))
        for tool in tools:
            if RISKY_TOOL_PATTERN.search(tool):
                risks.append(_risk("lease.risky_tool_name", "warning", lease_id, f"risky tool name: {tool}"))
        if any(path in {"", ".", "/", "*"} for path in paths):
            risks.append(_risk("lease.broad_path", "warning", lease_id, "lease grants a broad path prefix"))
        if tools and not paths and not lease.get("allow_hosts") and not lease.get("allow_commands"):
            risks.append(_risk("lease.unconstrained_arguments", "info", lease_id, "lease has no argument constraints"))
    return risks


def _risk(finding_type: str, severity: str, lease_id: Any, message: str) -> dict[str, Any]:
    return {"type": finding_type, "severity": severity, "lease": lease_id, "message": message, "count": 1}


def _add_finding(findings: list[dict[str, Any]], finding_type: str, count: Any, severity: str) -> None:
    value = int(count or 0)
    if value:
        findings.append({"type": finding_type, "severity": severity, "count": value})


def _coverage_summary(coverage: Mapping[str, Any]) -> dict[str, Any]:
    summary = {
        "lease_covered": bool(coverage.get("covered")),
        "lease_reason_code": coverage.get("reason_code"),
    }
    matches = coverage.get("matches")
    if isinstance(matches, Sequence) and not isinstance(matches, str | bytes | bytearray) and matches:
        first = matches[0]
        if isinstance(first, Mapping):
            summary["lease_id"] = first.get("id")
            summary["lease_task"] = first.get("task")
    return summary


def _event_summary(event: Mapping[str, Any]) -> dict[str, Any]:
    request = _mapping(event.get("request"))
    mcp = _mapping(event.get("mcp"))
    return {
        "path": request.get("path"),
        "mcp_method": mcp.get("method"),
        "tool": mcp.get("tool"),
        "target": mcp.get("target"),
        "argument_keys": mcp.get("argument_keys", []),
    }


def _jsonrpc_request(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    request = _mapping(record.get("request"))
    body = request.get("body")
    if not isinstance(body, str):
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, Mapping) and not isinstance(payload, list) else None


def _recorded_result(record: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(record.get("result"))


def _record_state_input(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    state = record.get("state")
    if not isinstance(state, Mapping):
        return None
    state_input = state.get("input")
    return state_input if isinstance(state_input, Mapping) else None


def _action_allowed(action: str) -> bool:
    return action in ALLOWED_ACTIONS


def _optional_mapping(value: Any, label: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    return _mapping_required(value, label)


def _mapping_required(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"record {label} must be an object")
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _top_counts(counter: Counter[str], top: int = 20) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(top)]


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not rows:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")
        return "\n".join(lines)
    for row in rows:
        lines.append("| " + " | ".join(_markdown_cell(value) for value in row) + " |")
    return "\n".join(lines)


def _counts_table(values: Any) -> str:
    rows = []
    if isinstance(values, Sequence) and not isinstance(values, str | bytes | bytearray):
        for item in values:
            if isinstance(item, Mapping):
                rows.append([item.get("value"), item.get("count")])
    return _table(["Value", "Count"], rows)


def _examples_table(values: Any) -> str:
    rows = []
    if isinstance(values, Sequence) and not isinstance(values, str | bytes | bytearray):
        for item in values:
            if isinstance(item, Mapping):
                rows.append(
                    [
                        item.get("line"),
                        item.get("tool") or item.get("target") or "-",
                        item.get("recorded_action", "-"),
                        item.get("actual_action", "-"),
                        item.get("lease_reason_code", "-"),
                    ]
                )
    return _table(["Line", "Target", "Recorded", "Candidate", "Lease reason"], rows)


def _findings_table(values: Any) -> str:
    rows = []
    if isinstance(values, Sequence) and not isinstance(values, str | bytes | bytearray):
        for item in values:
            if isinstance(item, Mapping):
                rows.append([item.get("severity"), item.get("type"), item.get("count", 1), item.get("message", "")])
    return _table(["Severity", "Finding", "Count", "Message"], rows)


def _markdown_cell(value: Any) -> str:
    text = "-" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")

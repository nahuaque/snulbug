from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def write_share_report_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(share_report_renderable(result))


def write_share_doctor_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(doctor_renderable(result, title="snulbug share doctor"))


def write_share_auth_doctor_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(doctor_renderable(result, title="snulbug share auth doctor"))


def write_fabric_status_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(fabric_status_renderable(result))


def write_fabric_doctor_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(doctor_renderable(result, title="snulbug fabric doctor"))


def write_evidence_inspect_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(evidence_inspect_renderable(result))


def write_evidence_impact_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(evidence_impact_renderable(result))


def write_evidence_diff_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(evidence_diff_renderable(result))


def write_policy_lifecycle_status_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    console = _console(stream)
    console.print(policy_lifecycle_status_renderable(result))


def format_policy_lifecycle_status_rich(result: Mapping[str, Any]) -> str:
    console = Console(record=True, highlight=False, color_system=None, width=120)
    console.print(policy_lifecycle_status_renderable(result))
    return console.export_text().rstrip()


def share_report_renderable(result: Mapping[str, Any]) -> Group:
    status = _mapping(result.get("status"))
    traffic = _mapping(status.get("traffic"))
    tool_risks = _mapping(status.get("tool_risks"))
    findings = [item for item in _sequence(status.get("findings")) if isinstance(item, Mapping)]
    path = result.get("path")
    overview = _kv_panel(
        "snulbug share report",
        (
            ("Share", result.get("share")),
            ("Report file", path or "not written"),
            ("Result", _ok_text(result.get("ok"))),
            ("Events", traffic.get("event_count", 0)),
            ("Allowed", traffic.get("allowed", 0)),
            ("Blocked", traffic.get("blocked", 0)),
            ("Findings", len(findings)),
        ),
        border_style="cyan",
    )
    return Group(
        overview,
        _tool_risk_table(tool_risks),
        _findings_panel(findings),
        _commands_panel(_mapping(status.get("commands"))),
    )


def doctor_renderable(result: Mapping[str, Any], *, title: str) -> Group:
    summary = _mapping(result.get("summary"))
    checks = [item for item in _sequence(result.get("checks")) if isinstance(item, Mapping)]
    rows = [
        ("Result", _ok_text(result.get("ok"))),
        ("Config", result.get("config")),
        ("Share", result.get("share")),
        ("URL", result.get("url") or result.get("gateway_url")),
        ("Passed", summary.get("passed", 0)),
        ("Failed", summary.get("failed", 0)),
        ("Warnings", summary.get("warnings", 0)),
        ("Skipped", summary.get("skipped", 0)),
    ]
    return Group(
        _kv_panel(title, rows, border_style="green" if result.get("ok") else "red"),
        _checks_table(checks),
        _recommendations_panel(result.get("recommendations")),
    )


def fabric_status_renderable(result: Mapping[str, Any]) -> Group:
    summary = _mapping(result.get("summary"))
    proxy = _mapping(result.get("proxy"))
    discovery = _mapping(result.get("discovery"))
    discovery_summary = _mapping(discovery.get("summary"))
    overview = _kv_panel(
        "snulbug fabric status",
        (
            ("Result", _ok_text(result.get("ok"))),
            ("Fabric", result.get("name")),
            ("Config", result.get("config")),
            ("Gateway", result.get("gateway_url")),
            ("Require manifests", _bool_text(result.get("require_manifests"))),
            ("Upstreams", summary.get("upstream_count", 0)),
            ("Discovery providers", discovery_summary.get("provider_count", 0)),
        ),
        border_style="cyan",
    )
    proxy_table = Table(title="Proxy", box=box.SIMPLE_HEAVY, expand=True)
    proxy_table.add_column("Field", style="bold cyan")
    proxy_table.add_column("Value", overflow="fold")
    for key in ("host", "port", "policy", "state", "tunnel_provider", "lease_required", "facade"):
        proxy_table.add_row(key, _text(proxy.get(key)))

    providers = Table(title="Discovery Providers", box=box.SIMPLE_HEAVY, expand=True)
    providers.add_column("Name", style="bold")
    providers.add_column("Type")
    providers.add_column("Status")
    providers.add_column("Upstreams", justify="right")
    for provider in _sequence(discovery.get("providers")):
        if isinstance(provider, Mapping):
            providers.add_row(
                _text(provider.get("name")),
                _text(provider.get("type")),
                _status_text(provider.get("status")),
                _text(provider.get("upstream_count", 0)),
            )
    if not providers.rows:
        providers.add_row("-", "-", "-", "0")
    return Group(
        overview,
        proxy_table,
        providers,
        _upstreams_table(result.get("upstreams")),
        _recommendations_panel(result.get("recommendations")),
    )


def evidence_inspect_renderable(result: Mapping[str, Any]) -> Group:
    decisions = _mapping(result.get("decisions"))
    mcp = _mapping(result.get("mcp"))
    time_range = _mapping(result.get("time_range"))
    overview = _kv_panel(
        "snulbug evidence inspect",
        (
            ("Result", _ok_text(result.get("ok"))),
            ("Log", result.get("log")),
            ("Kind", result.get("kind")),
            ("Events", result.get("event_count", 0)),
            ("First event", time_range.get("first")),
            ("Last event", time_range.get("last")),
            ("Allowed", decisions.get("allowed", 0)),
            ("Blocked", decisions.get("blocked", 0)),
        ),
        border_style="cyan",
    )
    return Group(
        overview,
        _counts_table("Decision Actions", decisions.get("actions")),
        _counts_table("Reason Codes", decisions.get("reason_codes")),
        _counts_table("MCP Methods", mcp.get("methods")),
        _counts_table("MCP Tools", mcp.get("tools")),
        _findings_panel(result.get("findings")),
        _examples_table("Blocked Examples", _mapping(result.get("examples")).get("blocked")),
    )


def evidence_impact_renderable(result: Mapping[str, Any]) -> Group:
    policy = _mapping(result.get("policy"))
    lease = _mapping(result.get("lease"))
    overview = _kv_panel(
        "snulbug evidence impact",
        (
            ("Result", _ok_text(result.get("ok"))),
            ("Log", result.get("log")),
            ("Records", result.get("record_count", 0)),
            ("Policy", policy.get("path") or "disabled"),
            ("Policy changes", policy.get("changed", 0)),
            ("Newly allowed", policy.get("newly_allowed", 0)),
            ("Newly blocked", policy.get("newly_blocked", 0)),
            ("Lease coverage", f"{float(lease.get('coverage_percent', 0) or 0):.1f}%"),
        ),
        border_style="green" if result.get("ok") else "yellow",
    )
    return Group(
        overview,
        _policy_impact_table(policy),
        _lease_impact_table(lease),
        _findings_panel(result.get("findings")),
        _examples_table("Changed Decisions", policy.get("changes")),
        _examples_table("Uncovered Lease Calls", lease.get("uncovered_examples")),
    )


def evidence_diff_renderable(result: Mapping[str, Any]) -> Group:
    capability_delta = _mapping(result.get("capability_delta"))
    overview = _kv_panel(
        "snulbug evidence diff",
        (
            ("Safe to promote", _ok_text(result.get("safe_to_promote"))),
            ("Old policy", result.get("old_policy")),
            ("New policy", result.get("new_policy")),
            ("Fixtures", result.get("fixture_count", 0)),
            ("Changed decisions", result.get("changed_decisions", 0)),
            ("Regressions", result.get("regression_count", 0)),
        ),
        border_style="green" if result.get("safe_to_promote") else "red",
    )
    return Group(
        overview,
        _capability_delta_table(capability_delta),
        _policy_diff_table("Regressions", result.get("regressions")),
        _policy_diff_table(
            "Changed Fixtures",
            [item for item in _sequence(result.get("results")) if isinstance(item, Mapping) and item.get("changed")],
        ),
    )


def policy_lifecycle_status_renderable(result: Mapping[str, Any]) -> Group:
    signature = _mapping(result.get("signature"))
    validation = _mapping(result.get("validation"))
    overview = _kv_panel(
        "snulbug policy lifecycle",
        (
            ("Result", _ok_text(result.get("ok"))),
            ("Bundle", result.get("bundle")),
            ("Name", result.get("name")),
            ("Version", result.get("version")),
            ("State", _lifecycle_text(result.get("state"))),
            ("Next state", result.get("next_state") or "-"),
            ("Signed", _bool_text(result.get("signed"))),
            ("Key id", signature.get("key_id") or "-"),
        ),
        border_style="green" if result.get("ok") else "red",
    )
    return Group(
        overview,
        _signature_table(signature),
        _validation_table(validation),
        _history_table(result.get("history")),
    )


def _tool_risk_table(tool_risks: Mapping[str, Any]) -> Table:
    summary = _mapping(tool_risks.get("summary"))
    table = Table(
        title=(
            "Tool Risk Review "
            f"({summary.get('high', 0)} high, {summary.get('medium', 0)} medium, {summary.get('low', 0)} low)"
        ),
        box=box.SIMPLE_HEAVY,
        expand=True,
    )
    table.add_column("Tool", style="bold")
    table.add_column("Risk")
    table.add_column("Count", justify="right")
    table.add_column("Evidence")
    table.add_column("Confidence")
    table.add_column("Signals", overflow="fold")
    tools = [item for item in _sequence(tool_risks.get("tools")) if isinstance(item, Mapping)]
    if not tools:
        table.add_row("-", "-", "0", "-", "-", "-")
        return table
    for tool in tools[:10]:
        signals = [
            str(_mapping(signal).get("code"))
            for signal in _sequence(tool.get("signals"))
            if _mapping(signal).get("code")
        ]
        table.add_row(
            _text(tool.get("name")),
            _risk_text(tool.get("level")),
            _text(tool.get("count", 0)),
            _text(", ".join(map(str, _sequence(tool.get("evidence_sources")))) or "-"),
            _text(tool.get("confidence") or "-"),
            _text(", ".join(signals[:4]) or "-"),
        )
    return table


def _checks_table(checks: Sequence[Mapping[str, Any]]) -> Table:
    table = Table(title="Checks", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Status", style="bold", no_wrap=True)
    table.add_column("ID", overflow="fold")
    table.add_column("Component")
    table.add_column("Message", overflow="fold")
    if not checks:
        table.add_row("skip", "-", "-", "no checks")
        return table
    for check in checks:
        table.add_row(
            _status_text(check.get("status")),
            _text(check.get("id")),
            _text(check.get("component") or "-"),
            _text(check.get("message") or "-"),
        )
    return table


def _upstreams_table(value: Any) -> Table:
    table = Table(title="Upstreams", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Name", style="bold")
    table.add_column("Transport")
    table.add_column("Prefix")
    table.add_column("URL", overflow="fold")
    table.add_column("Member")
    table.add_column("Manifest", overflow="fold")
    upstreams = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not upstreams:
        table.add_row("-", "-", "-", "-", "-", "-")
        return table
    for upstream in upstreams:
        manifest = _mapping(upstream.get("manifest"))
        member = _mapping(upstream.get("member"))
        manifest_text = "-"
        if manifest:
            state = "exists" if manifest.get("exists") else "missing"
            manifest_text = f"{manifest.get('path') or '-'} ({state})"
        table.add_row(
            _text(upstream.get("name")),
            _text(upstream.get("transport")),
            _text(upstream.get("tool_prefix") or "-"),
            _text(upstream.get("url") or "-"),
            _text(member.get("id") or upstream.get("fabric_member_id") or "-"),
            _text(manifest_text),
        )
    return table


def _policy_impact_table(policy: Mapping[str, Any]) -> Table:
    return _metric_table(
        "Policy Impact",
        (
            ("Enabled", _bool_text(policy.get("enabled"))),
            ("Changed", policy.get("changed", 0)),
            ("Newly allowed", policy.get("newly_allowed", 0)),
            ("Newly blocked", policy.get("newly_blocked", 0)),
            ("Action changed", policy.get("action_changed", 0)),
            ("Failed", policy.get("failed", 0)),
        ),
    )


def _lease_impact_table(lease: Mapping[str, Any]) -> Table:
    return _metric_table(
        "Lease Coverage",
        (
            ("Enabled", _bool_text(lease.get("enabled"))),
            ("File", lease.get("file") or "-"),
            ("Tool calls", lease.get("tool_call_count", 0)),
            ("Covered", lease.get("covered", 0)),
            ("Uncovered", lease.get("uncovered", 0)),
            ("Coverage", f"{float(lease.get('coverage_percent', 0) or 0):.1f}%"),
        ),
    )


def _capability_delta_table(delta: Mapping[str, Any]) -> Table:
    summary = _mapping(delta.get("summary"))
    table = _metric_table(
        "Newly Allowed Capability Delta",
        (
            ("Tools", summary.get("tools", 0)),
            ("Path patterns", summary.get("path_patterns", 0)),
            ("Argument shapes", summary.get("argument_shapes", 0)),
        ),
    )
    return table


def _policy_diff_table(title: str, value: Any) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Fixture", overflow="fold")
    table.add_column("Reason", overflow="fold")
    table.add_column("Old")
    table.add_column("New")
    rows = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not rows:
        table.add_row("-", "-", "-", "-")
        return table
    for item in rows[:10]:
        old = _mapping(item.get("old"))
        new = _mapping(item.get("new"))
        table.add_row(
            _text(item.get("fixture") or "-"),
            _text(item.get("reason") or "-"),
            _text(old.get("action") or _mapping(old.get("decision")).get("action") or "-"),
            _text(new.get("action") or _mapping(new.get("decision")).get("action") or "-"),
        )
    return table


def _counts_table(title: str, value: Any) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Value", style="bold", overflow="fold")
    table.add_column("Count", justify="right")
    rows = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not rows:
        table.add_row("-", "0")
        return table
    for item in rows[:10]:
        table.add_row(_text(item.get("value")), _text(item.get("count", 0)))
    return table


def _findings_panel(value: Any) -> Panel:
    findings = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not findings:
        return Panel(Text("No findings", style="green"), title="Findings", border_style="green")
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Severity", style="bold")
    table.add_column("Type", overflow="fold")
    table.add_column("Count", justify="right")
    table.add_column("Message", overflow="fold")
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        table.add_row(
            _severity_text(severity),
            _text(finding.get("type")),
            _text(finding.get("count", "")),
            _text(finding.get("message") or ""),
        )
    return Panel(table, title="Findings", border_style="yellow")


def _examples_table(title: str, value: Any) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Line", justify="right")
    table.add_column("Method")
    table.add_column("Tool/Target", overflow="fold")
    table.add_column("Action")
    table.add_column("Reason", overflow="fold")
    rows = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not rows:
        table.add_row("-", "-", "-", "-", "-")
        return table
    for item in rows[:8]:
        table.add_row(
            _text(item.get("line") or "-"),
            _text(item.get("mcp_method") or "-"),
            _text(item.get("tool") or item.get("target") or "-"),
            _text(item.get("action") or item.get("actual_action") or "-"),
            _text(item.get("reason_code") or item.get("actual_reason_code") or item.get("error") or "-"),
        )
    return table


def _signature_table(signature: Mapping[str, Any]) -> Table:
    return _metric_table(
        "Signature",
        (
            ("Algorithm", signature.get("algorithm") or "-"),
            ("Key id", signature.get("key_id") or "-"),
            ("Digest", signature.get("digest") or "-"),
            ("Signed at", signature.get("signed_at") or "-"),
        ),
    )


def _validation_table(validation: Mapping[str, Any]) -> Table:
    if not validation:
        return _metric_table("Validation", (("Status", "not recorded"),))
    return _metric_table(
        "Validation",
        (
            ("OK", _ok_text(validation.get("ok"))),
            ("Validated at", validation.get("validated_at") or "-"),
            ("Fixtures", validation.get("fixture_count", 0)),
            ("Passed", validation.get("passed", 0)),
            ("Failed", validation.get("failed", 0)),
        ),
    )


def _history_table(value: Any) -> Table:
    table = Table(title="History", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("State", style="bold")
    table.add_column("At")
    table.add_column("Actor")
    table.add_column("Note", overflow="fold")
    rows = [item for item in _sequence(value) if isinstance(item, Mapping)]
    if not rows:
        table.add_row("-", "-", "-", "-")
        return table
    for item in rows[-8:]:
        table.add_row(
            _lifecycle_text(item.get("state")),
            _text(item.get("at") or item.get("time") or "-"),
            _text(item.get("actor") or "-"),
            _text(item.get("note") or "-"),
        )
    return table


def _recommendations_panel(value: Any) -> Panel:
    recommendations = [str(item) for item in _sequence(value) if str(item)]
    if not recommendations:
        return Panel(Text("No recommendations", style="green"), title="Recommendations", border_style="green")
    table = Table.grid()
    for item in recommendations[:10]:
        table.add_row(Text("- ", style="yellow") + Text(item))
    return Panel(table, title="Recommendations", border_style="yellow")


def _commands_panel(commands: Mapping[str, Any]) -> Panel:
    rows = [(name, command) for name, command in commands.items() if isinstance(command, str) and command]
    if not rows:
        return Panel(Text("No commands", style="dim"), title="Next Commands", border_style="blue")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")
    for name, command in rows[:8]:
        table.add_row(Text(str(name)), Text(str(command)))
    return Panel(table, title="Next Commands", border_style="blue")


def _metric_table(title: str, rows: Sequence[tuple[str, Any]]) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", overflow="fold")
    for key, value in rows:
        table.add_row(key, value if isinstance(value, Text) else _text(value))
    return table


def _kv_panel(title: str, rows: Sequence[tuple[str, Any]], *, border_style: str) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(overflow="fold")
    for key, value in rows:
        if value in (None, ""):
            continue
        grid.add_row(Text(key), value if isinstance(value, Text) else _text(value))
    return Panel(grid, title=Text(title, style=f"bold {border_style}"), border_style=border_style)


def _console(stream: TextIO | None) -> Console:
    return Console(file=stream or sys.stdout, highlight=False)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) else []


def _text(value: Any) -> Text:
    if value in (None, ""):
        return Text("-", style="dim")
    if isinstance(value, Text):
        return value
    return Text(str(value))


def _ok_text(value: Any) -> Text:
    if value is True:
        return Text("pass", style="green")
    if value is False:
        return Text("fail", style="red")
    return Text("unknown", style="yellow")


def _bool_text(value: Any) -> Text:
    if value is True:
        return Text("yes", style="green")
    if value is False:
        return Text("no", style="red")
    return Text("unknown", style="yellow")


def _status_text(value: Any) -> Text:
    text = str(value or "unknown")
    style = {
        "pass": "green",
        "fail": "red",
        "warn": "yellow",
        "skip": "cyan",
        "ok": "green",
        "active": "green",
        "degraded": "yellow",
        "unhealthy": "red",
        "error": "red",
    }.get(text, "white")
    return Text(text, style=style)


def _severity_text(value: str) -> Text:
    style = {"error": "red", "warning": "yellow", "info": "blue"}.get(value, "white")
    return Text(value, style=style)


def _risk_text(value: Any) -> Text:
    text = str(value or "unknown")
    style = {"high": "red", "medium": "yellow", "low": "green"}.get(text, "white")
    return Text(text, style=style)


def _lifecycle_text(value: Any) -> Text:
    text = str(value or "observed")
    style = {
        "observed": "cyan",
        "proposed": "yellow",
        "approved": "blue",
        "active": "green",
    }.get(text, "white")
    return Text(text, style=style)

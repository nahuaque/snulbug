from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from typing import Any, TextIO

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def write_share_status_rich(result: Mapping[str, Any], *, stream: TextIO | None = None) -> None:
    """Render `snulbug mcp share status` with Rich."""

    console = Console(file=stream or sys.stdout, highlight=False)
    console.print(share_status_renderable(result))


def share_status_renderable(result: Mapping[str, Any]) -> Group:
    """Build a Rich renderable for a share status payload."""

    return Group(
        _overview_panel(result),
        _health_table(result),
        _policy_table(result),
        _traffic_table(result),
        _tools_table(result),
        _findings_panel(result),
        _commands_panel(result),
    )


def _overview_panel(result: Mapping[str, Any]) -> Panel:
    session = _mapping(result.get("session"))
    gateway = _mapping(result.get("gateway"))
    tunnel = _mapping(result.get("tunnel_doctor"))
    policy = _mapping(result.get("policy"))
    leases = _mapping(result.get("leases"))
    traffic = _mapping(result.get("traffic"))
    client = _mapping(result.get("client"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(overflow="fold")
    _add_kv(grid, "Share", result.get("directory"))
    _add_kv(grid, "State", _state_text(result.get("state")))
    _add_kv(grid, "Provider", session.get("provider") or "-")
    _add_kv(grid, "Public URL", tunnel.get("public_url") or client.get("url") or "-")
    _add_kv(grid, "Local gateway", gateway.get("url") or "-")
    _add_kv(grid, "Gateway", _health_text(gateway.get("reachable"), checked=gateway.get("checked")))
    _add_kv(grid, "Policy", _policy_text(policy.get("lifecycle_state")))
    _add_kv(grid, "Active leases", str(leases.get("active_count", 0)))
    _add_kv(
        grid,
        "Traffic",
        (
            f"{traffic.get('allowed', 0)} allowed, {traffic.get('blocked', 0)} blocked, "
            f"{traffic.get('confirmed', 0)} confirmed"
        ),
    )
    return Panel(grid, title=Text("snulbug share status", style="bold cyan"), border_style="cyan")


def _health_table(result: Mapping[str, Any]) -> Table:
    gateway = _mapping(result.get("gateway"))
    table = Table(title="Health", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Target", style="bold")
    table.add_column("URL", overflow="fold")
    table.add_column("Checked", justify="center")
    table.add_column("Reachable", justify="center")
    table.add_column("Status", justify="right")
    table.add_column("Detail", overflow="fold")
    table.add_row(
        Text("gateway", style="cyan"),
        _value(gateway.get("url")),
        _bool_text(gateway.get("checked")),
        _health_text(gateway.get("reachable"), checked=gateway.get("checked")),
        _value(gateway.get("status")),
        _value(gateway.get("error") or ("MCP ok" if gateway.get("mcp_ok") else "")),
    )
    for upstream in _sequence(result.get("upstreams")):
        if not isinstance(upstream, Mapping):
            continue
        table.add_row(
            Text(str(upstream.get("name") or "upstream"), style="cyan"),
            _value(upstream.get("url")),
            _bool_text(upstream.get("checked")),
            _health_text(upstream.get("reachable"), checked=upstream.get("checked")),
            _value(upstream.get("status")),
            _value(upstream.get("error") or upstream.get("health") or ""),
        )
    return table


def _policy_table(result: Mapping[str, Any]) -> Table:
    policy = _mapping(result.get("policy"))
    leases = _mapping(result.get("leases"))
    recordings = _mapping(result.get("recordings"))
    contract = _mapping(result.get("contract"))
    record_log = _mapping(recordings.get("record_log"))
    audit_log = _mapping(recordings.get("audit_log"))
    table = Table(title="Policy And Artifacts", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Item", style="bold")
    table.add_column("Value", overflow="fold")
    table.add_row("Bundle", _value(policy.get("bundle")))
    table.add_row("Active policy", _value(policy.get("active_policy")))
    table.add_row("Lifecycle", _policy_text(policy.get("lifecycle_state")))
    table.add_row("Signed", _bool_text(policy.get("lifecycle_signed")))
    table.add_row("Lease file", _value(leases.get("file")))
    table.add_row("Replay log", _artifact_text(record_log))
    table.add_row("Audit log", _artifact_text(audit_log))
    table.add_row("Share contract", _contract_text(contract))
    return table


def _traffic_table(result: Mapping[str, Any]) -> Table:
    traffic = _mapping(result.get("traffic"))
    table = Table(title="Traffic", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")
    for key, label in (
        ("event_count", "Events"),
        ("allowed", "Allowed"),
        ("blocked", "Blocked"),
        ("confirmed", "Confirmed"),
        ("confirmation_approved", "Confirmed approved"),
        ("confirmation_denied", "Confirmed denied"),
        ("redacted_events", "Secrets redacted"),
        ("response_redacted", "Response redactions"),
    ):
        style = "red" if key == "blocked" and int(traffic.get(key, 0) or 0) else None
        table.add_row(label, Text(str(traffic.get(key, 0)), style=style))
    return table


def _tools_table(result: Mapping[str, Any]) -> Table:
    traffic = _mapping(result.get("traffic"))
    tools = [item for item in _sequence(traffic.get("tools")) if isinstance(item, Mapping)]
    clients = [item for item in _sequence(traffic.get("clients")) if isinstance(item, Mapping)]
    sources = [item for item in _sequence(traffic.get("source_ips")) if isinstance(item, Mapping)]
    table = Table(title="Observed Traffic Keys", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Kind", style="bold")
    table.add_column("Value", overflow="fold")
    table.add_column("Count", justify="right")
    rows = []
    rows.extend(("tool", item.get("value"), item.get("count")) for item in tools[:5])
    rows.extend(("client", item.get("value"), item.get("count")) for item in clients[:3])
    rows.extend(("source ip", item.get("value"), item.get("count")) for item in sources[:3])
    if not rows:
        table.add_row("none", "-", "0")
        return table
    for kind, value, count in rows:
        table.add_row(kind, _value(value), _value(count))
    return table


def _findings_panel(result: Mapping[str, Any]) -> Panel:
    findings = [item for item in _sequence(result.get("findings")) if isinstance(item, Mapping)]
    if not findings:
        return Panel(Text("No findings", style="green"), title="Findings", border_style="green")
    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Severity", style="bold")
    table.add_column("Type", overflow="fold")
    table.add_column("Message", overflow="fold")
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        style = {"error": "red", "warning": "yellow", "info": "blue"}.get(severity, "white")
        table.add_row(
            Text(severity, style=style),
            _value(finding.get("type")),
            _value(finding.get("message") or finding.get("count") or ""),
        )
    return Panel(table, title="Findings", border_style="yellow")


def _commands_panel(result: Mapping[str, Any]) -> Panel:
    commands = _mapping(result.get("commands"))
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")
    added = False
    for name in ("run", "doctor", "client", "close", "inspect_audit", "inspect_session"):
        command = commands.get(name)
        if isinstance(command, str) and command:
            _add_kv(table, name, Text(command))
            added = True
    if not added:
        table.add_row(Text("none", style="dim"), Text("-"))
    return Panel(table, title="Next Commands", border_style="blue")


def _add_kv(table: Table, key: str, value: Any) -> None:
    table.add_row(Text(key), value if isinstance(value, Text) else _value(value))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) else []


def _value(value: Any) -> Text:
    if value in (None, ""):
        return Text("-", style="dim")
    return Text(str(value))


def _bool_text(value: Any) -> Text:
    if value is True:
        return Text("yes", style="green")
    if value is False:
        return Text("no", style="red")
    return Text("unknown", style="yellow")


def _health_text(value: Any, *, checked: Any = True) -> Text:
    if checked is False:
        return Text("not checked", style="yellow")
    if value is True:
        return Text("reachable", style="green")
    if value is False:
        return Text("unreachable", style="red")
    return Text("unknown", style="yellow")


def _state_text(value: Any) -> Text:
    text = str(value or "unknown")
    style = {
        "created": "cyan",
        "running": "green",
        "closed": "dim",
        "close_failed": "red",
    }.get(text, "yellow")
    return Text(text, style=style)


def _policy_text(value: Any) -> Text:
    text = str(value or "observed")
    style = {
        "active": "green",
        "approved": "blue",
        "proposed": "yellow",
        "observed": "cyan",
    }.get(text, "yellow")
    return Text(text, style=style)


def _artifact_text(artifact: Mapping[str, Any]) -> Text:
    path = artifact.get("path") or "-"
    exists = artifact.get("exists")
    suffix = "exists" if exists is True else "missing" if exists is False else "unknown"
    style = "green" if exists is True else "red" if exists is False else "yellow"
    text = Text(str(path))
    text.append(f" ({suffix})", style=style)
    return text


def _contract_text(contract: Mapping[str, Any]) -> Text:
    if not contract:
        return Text("-", style="dim")
    required = "required" if contract.get("required") is True else "optional"
    drifted = contract.get("drifted")
    style = "red" if drifted is True else "green" if contract.get("signed") is True else "yellow"
    text = Text(required, style=style)
    if contract.get("binding_digest") or contract.get("digest"):
        text.append(" ")
        text.append(str(contract.get("binding_digest") or contract.get("digest")), style="dim")
    return text

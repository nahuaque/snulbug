from __future__ import annotations

import http.client
import json
import os
import re
import shutil
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .config import DEFAULT_CONFIG_PATH, load_mcp_fabric_config
from .manifests import load_manifest, verify_upstream_manifest

_FABRIC_DOCTOR_REQUEST = {
    "jsonrpc": "2.0",
    "id": "snulbug-fabric-doctor-tools-list",
    "method": "tools/list",
    "params": {},
}


def fabric_status(config: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Summarize the declared MCP fabric without probing network endpoints."""

    fabric = load_mcp_fabric_config(config)
    proxy = _mapping(fabric.get("proxy"))
    upstreams = [_upstream_status(upstream) for upstream in _upstreams(proxy)]
    summary = _fabric_summary(fabric, proxy, upstreams)
    recommendations = _fabric_recommendations(fabric, upstreams)
    return {
        "ok": summary["missing_required_manifests"] == 0,
        "name": fabric["name"],
        "description": fabric.get("description", ""),
        "config": str(config),
        "gateway_url": fabric.get("gateway_url"),
        "require_manifests": fabric["require_manifests"],
        "probe_gateway": fabric["probe_gateway"],
        "probe_upstreams": fabric["probe_upstreams"],
        "timeout": fabric["timeout"],
        "proxy": _proxy_status(proxy),
        "upstreams": upstreams,
        "summary": summary,
        "recommendations": recommendations,
    }


def build_fabric_audit_metadata(fabric: Mapping[str, Any]) -> dict[str, Any]:
    """Build an audit-safe static topology summary from normalized fabric config."""

    proxy = _mapping(fabric.get("proxy"))
    upstreams = [_topology_upstream(upstream) for upstream in _upstreams(proxy)]
    summary = _fabric_summary(fabric, proxy, upstreams)
    return _drop_empty(
        {
            "fabric": _drop_empty(
                {
                    "name": fabric.get("name"),
                    "description": fabric.get("description"),
                    "gateway_url": _audit_url(fabric.get("gateway_url")),
                    "require_manifests": fabric.get("require_manifests"),
                }
            ),
            "gateway": _drop_empty(
                {
                    "url": _audit_url(fabric.get("gateway_url")),
                    "host": proxy.get("host"),
                    "port": proxy.get("port"),
                    "tunnel_provider": proxy.get("tunnel_provider"),
                    "tunnel_public_url": _audit_url(proxy.get("tunnel_public_url")),
                    "lease_required": proxy.get("lease_required"),
                    "cloudflare_access": proxy.get("cloudflare_access"),
                    "facade": bool(proxy.get("upstreams")),
                }
            ),
            "summary": summary,
            "upstreams": upstreams,
        }
    )


def annotate_topology_audit(
    topology: Mapping[str, Any] | None,
    proxy_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Attach the request-specific route to static topology metadata."""

    if not topology:
        return {}
    annotated = _copy_jsonish(topology)
    route = _topology_route(proxy_metadata)
    if route:
        annotated["route"] = route
    return annotated


def learn_fabric_profile(
    log: str | Path,
    output: str | Path,
    *,
    kind: str = "auto",
    force: bool = False,
) -> dict[str, Any]:
    """Compile topology-aware MCP audit/replay logs into a reviewable fabric profile."""

    from .inspection import _load_events

    events = _load_events(log, kind=kind)
    model = _LearnedFabric.from_events(events)
    output_path = Path(output)
    if output_path.exists() and not force:
        raise FileExistsError(f"fabric learn output already exists: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)

    profile_path = output_path / "fabric.json"
    config_path = output_path / "snulbug.fabric.toml"
    report_path = output_path / "FABRIC.md"
    profile = model.profile(log)
    profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    config_path.write_text(model.to_toml(), encoding="utf-8")
    report_path.write_text(model.report(log), encoding="utf-8")
    ok = bool(model.upstreams) and model.route_event_count > 0
    return {
        "ok": ok,
        "log": str(log),
        "output": str(output_path),
        "profile": str(profile_path),
        "config": str(config_path),
        "report": str(report_path),
        "event_count": model.event_count,
        "topology_event_count": model.topology_event_count,
        "route_event_count": model.route_event_count,
        "missing_topology_count": model.missing_topology_count,
        "upstreams": sorted(model.upstreams),
        "tools": sorted(model.tools),
        "conflicts": model.conflicts,
        "next_steps": [
            f"review {report_path}",
            f"review and merge {config_path} into snulbug.toml",
            f"uv run snulbug mcp fabric doctor --config {config_path}",
        ],
    }


def doctor_fabric(
    config: str | Path = DEFAULT_CONFIG_PATH,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float | None = None,
    probe_gateway: bool | None = None,
    probe_upstreams: bool | None = None,
) -> dict[str, Any]:
    """Run static and active checks against a declared MCP fabric."""

    checks: list[dict[str, Any]] = []
    probes: dict[str, Any] = {}
    try:
        status = fabric_status(config)
        fabric = load_mcp_fabric_config(config)
    except Exception as exc:
        _add_check(checks, "config.loaded", False, f"failed to load fabric config: {exc}")
        summary = _checks_summary(checks)
        return {
            "ok": False,
            "config": str(config),
            "checks": checks,
            "summary": summary,
            "recommendations": ["Fix the snulbug.toml syntax or [mcp.fabric]/[mcp.proxy] configuration."],
            "probes": probes,
        }

    headers = dict(headers or {})
    timeout_value = float(timeout if timeout is not None else fabric["timeout"])
    if timeout_value <= 0:
        raise ValueError("timeout must be positive")
    do_probe_gateway = fabric["probe_gateway"] if probe_gateway is None else probe_gateway
    do_probe_upstreams = fabric["probe_upstreams"] if probe_upstreams is None else probe_upstreams
    proxy = _mapping(fabric.get("proxy"))
    upstreams = _upstreams(proxy)

    _add_check(checks, "config.loaded", True, f"loaded fabric config {config}", details={"config": str(config)})
    _add_check(
        checks,
        "fabric.gateway_url_present",
        bool(fabric.get("gateway_url")),
        "gateway URL is configured or inferred" if fabric.get("gateway_url") else "gateway URL is missing",
        details={"gateway_url": fabric.get("gateway_url")},
    )
    _add_check(
        checks,
        "proxy.facade_enabled",
        bool(upstreams),
        f"facade declares {len(upstreams)} upstream(s)" if upstreams else "no facade upstreams are declared",
        severity="warning",
    )
    _add_check(
        checks,
        "logs.record_out_configured",
        bool(proxy.get("record_out")),
        "record_out is configured" if proxy.get("record_out") else "record_out is not configured",
        severity="warning",
        details={"record_out": str(proxy.get("record_out")) if proxy.get("record_out") else None},
    )
    _add_check(
        checks,
        "logs.audit_out_configured",
        bool(proxy.get("audit_out")),
        "audit_out is configured" if proxy.get("audit_out") else "audit_out is not configured",
        severity="warning",
        details={"audit_out": str(proxy.get("audit_out")) if proxy.get("audit_out") else None},
    )

    for upstream in upstreams:
        _run_manifest_checks(checks, upstream, require_manifest=bool(fabric["require_manifests"]))

    if do_probe_gateway and fabric.get("gateway_url"):
        _run_mcp_endpoint_checks(
            checks,
            probes,
            check_prefix="gateway",
            url=str(fabric["gateway_url"]),
            headers=headers,
            timeout=timeout_value,
            label="gateway",
        )
    elif not do_probe_gateway:
        _add_check(checks, "gateway.probe_enabled", None, "gateway probing is disabled")

    for upstream in upstreams:
        if not do_probe_upstreams:
            _add_check(checks, f"upstream.{_check_name(upstream)}.probe_enabled", None, "upstream probing is disabled")
            continue
        _run_upstream_probe_checks(checks, probes, upstream, headers=headers, timeout=timeout_value)

    summary = _checks_summary(checks)
    recommendations = _doctor_recommendations(checks, headers=headers)
    return {
        **status,
        "ok": summary["failed"] == 0,
        "checks": checks,
        "summary": {**status["summary"], **summary},
        "recommendations": recommendations or status["recommendations"],
        "probes": probes,
    }


def format_fabric_status_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric status",
        "",
        f"Fabric: {result.get('name')}",
        f"Config: {result.get('config')}",
        f"Gateway: {result.get('gateway_url') or '(missing)'}",
        f"Require manifests: {str(bool(result.get('require_manifests'))).lower()}",
        "",
        "## Proxy",
    ]
    proxy = _mapping(result.get("proxy"))
    for key in ("host", "port", "policy", "state", "tunnel_provider", "lease_required", "facade"):
        lines.append(f"- {key}: `{proxy.get(key)}`")

    lines.extend(["", "## Upstreams"])
    upstreams = list(result.get("upstreams", []))
    if not upstreams:
        lines.append("- none")
    for upstream in upstreams:
        manifest = _mapping(upstream.get("manifest"))
        manifest_text = "none"
        if manifest:
            manifest_text = f"{manifest.get('path')} ({'exists' if manifest.get('exists') else 'missing'})"
        lines.append(
            "- "
            f"{upstream.get('name')} [{upstream.get('transport')}] "
            f"prefix=`{upstream.get('tool_prefix')}` "
            f"url=`{upstream.get('url') or '-'}` "
            f"manifest=`{manifest_text}`"
        )

    summary = _mapping(result.get("summary"))
    lines.extend(
        [
            "",
            "## Summary",
            f"- upstreams: {summary.get('upstream_count', 0)}",
            f"- manifests: {summary.get('manifest_count', 0)}",
            f"- missing required manifests: {summary.get('missing_required_manifests', 0)}",
        ]
    )
    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip()


def format_fabric_doctor_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric doctor",
        "",
        f"Fabric: {result.get('name')}",
        f"Gateway: {result.get('gateway_url') or '(missing)'}",
        "",
        "## Checks",
    ]
    for check in result.get("checks", []):
        lines.append(f"- [{check.get('status')}] {check.get('id')}: {check.get('message')}")

    summary = _mapping(result.get("summary"))
    lines.extend(
        [
            "",
            "## Summary",
            (
                f"Passed: {summary.get('passed', 0)} | Failed: {summary.get('failed', 0)} | "
                f"Warnings: {summary.get('warnings', 0)} | Skipped: {summary.get('skipped', 0)}"
            ),
        ]
    )
    recommendations = result.get("recommendations", [])
    if recommendations:
        lines.extend(["", "## Recommendations"])
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    return "\n".join(lines).rstrip()


def format_fabric_learn_report(result: Mapping[str, Any]) -> str:
    lines = [
        "# snulbug fabric learn",
        "",
        f"Log: {result.get('log')}",
        f"Output: {result.get('output')}",
        "",
        "## Summary",
        f"- events: {result.get('event_count', 0)}",
        f"- topology events: {result.get('topology_event_count', 0)}",
        f"- routed events: {result.get('route_event_count', 0)}",
        f"- missing topology: {result.get('missing_topology_count', 0)}",
        "",
        "## Artifacts",
        f"- profile: `{result.get('profile')}`",
        f"- config: `{result.get('config')}`",
        f"- report: `{result.get('report')}`",
    ]
    conflicts = result.get("conflicts", [])
    if conflicts:
        lines.extend(["", "## Conflicts"])
        for conflict in conflicts:
            if isinstance(conflict, Mapping):
                lines.append(
                    "- "
                    f"{conflict.get('scope')} {conflict.get('name')} field `{conflict.get('field')}` "
                    f"changed from `{conflict.get('old')}` to `{conflict.get('new')}`"
                )
    next_steps = result.get("next_steps", [])
    if next_steps:
        lines.extend(["", "## Next steps"])
        for step in next_steps:
            lines.append(f"- {step}")
    return "\n".join(lines).rstrip()


@dataclass
class _LearnedFabricUpstream:
    name: str
    transport: str | None = None
    tool_prefix: str | None = None
    url: str | None = None
    command: str | None = None
    cwd: str | None = None
    bridge: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    declared_count: int = 0
    route_count: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    operations: Counter[str] = field(default_factory=Counter)
    tools: Counter[str] = field(default_factory=Counter)
    upstream_tools: Counter[str] = field(default_factory=Counter)

    def merge_static(
        self,
        data: Mapping[str, Any],
        *,
        conflicts: list[dict[str, Any]],
        conflict_keys: set[tuple[str, str, str, str, str]],
        line: Any = None,
    ) -> None:
        for field_name in ("transport", "tool_prefix", "url", "command", "cwd"):
            _merge_attr(
                self,
                field_name,
                data.get(field_name),
                scope="upstream",
                name=self.name,
                conflicts=conflicts,
                conflict_keys=conflict_keys,
                line=line,
            )
        bridge = _mapping(data.get("bridge"))
        for field_name in ("transport", "peer", "local_port", "config", "command", "private", "ready_timeout"):
            _merge_dict_value(
                self.bridge,
                field_name,
                bridge.get(field_name),
                scope="upstream.bridge",
                name=self.name,
                conflicts=conflicts,
                conflict_keys=conflict_keys,
                line=line,
            )
        manifest = _mapping(data.get("manifest"))
        for field_name in (
            "path",
            "required",
            "exists",
            "identity",
            "digest",
            "key_id",
            "algorithm",
            "schema",
            "transport",
            "tool_prefix",
            "tool_count",
        ):
            _merge_dict_value(
                self.manifest,
                field_name,
                manifest.get(field_name),
                scope="upstream.manifest",
                name=self.name,
                conflicts=conflicts,
                conflict_keys=conflict_keys,
                line=line,
            )
        if data:
            self.declared_count += 1

    def observe_route(self, route: Mapping[str, Any], event: Mapping[str, Any], *, fanout: bool = False) -> None:
        self.route_count += 1
        if _event_allowed(event):
            self.allowed_count += 1
        else:
            self.blocked_count += 1
        operation = route.get("operation") or _mapping(event.get("mcp")).get("method")
        if operation:
            self.operations[str(operation)] += 1
        if fanout:
            return
        tool = route.get("tool") or _mapping(event.get("mcp")).get("tool")
        upstream_tool = route.get("upstream_tool")
        if tool:
            self.tools[str(tool)] += 1
        if upstream_tool:
            self.upstream_tools[str(upstream_tool)] += 1

    def to_dict(self) -> dict[str, Any]:
        return _drop_empty(
            {
                "name": self.name,
                "transport": self.transport,
                "tool_prefix": self.tool_prefix,
                "url": self.url,
                "command": self.command,
                "cwd": self.cwd,
                "bridge": self.bridge,
                "manifest": self.manifest,
                "declared_count": self.declared_count,
                "route_count": self.route_count,
                "allowed_count": self.allowed_count,
                "blocked_count": self.blocked_count,
                "operations": _counter_counts(self.operations),
                "tools": sorted(self.tools),
                "tool_counts": _counter_counts(self.tools),
                "upstream_tools": sorted(self.upstream_tools),
                "upstream_tool_counts": _counter_counts(self.upstream_tools),
                "review": self.review_notes(),
            }
        )

    def review_notes(self) -> list[str]:
        notes = []
        if self.transport in {"http", "holepunch"} and not self.url:
            notes.append("upstream URL was not observed; fill in url before using generated config")
        if self.transport == "stdio" and not self.command:
            notes.append("stdio command was not observed; fill in command before using generated config")
        if not self.tool_prefix:
            notes.append("tool prefix was not observed; confirm namespacing before public use")
        if self.manifest and not self.manifest.get("path"):
            notes.append("manifest identity was observed without a manifest path; attach a signed manifest file")
        if not self.manifest:
            notes.append("no signed manifest metadata was observed for this upstream")
        return notes


@dataclass
class _LearnedFabric:
    event_count: int = 0
    topology_event_count: int = 0
    route_event_count: int = 0
    missing_topology_count: int = 0
    allowed_event_count: int = 0
    blocked_event_count: int = 0
    fabric: dict[str, Any] = field(default_factory=dict)
    gateway: dict[str, Any] = field(default_factory=dict)
    upstreams: dict[str, _LearnedFabricUpstream] = field(default_factory=dict)
    tools: Counter[str] = field(default_factory=Counter)
    operations: Counter[str] = field(default_factory=Counter)
    route_modes: Counter[str] = field(default_factory=Counter)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    _conflict_keys: set[tuple[str, str, str, str, str]] = field(default_factory=set)

    @classmethod
    def from_events(cls, events: Iterable[Mapping[str, Any]]) -> _LearnedFabric:
        model = cls()
        for event in events:
            model.add(event)
        return model

    def add(self, event: Mapping[str, Any]) -> None:
        self.event_count += 1
        if _event_allowed(event):
            self.allowed_event_count += 1
        else:
            self.blocked_event_count += 1

        topology = _topology_from_event(event)
        if topology:
            self.topology_event_count += 1
            if not self._observe_topology(topology, event):
                self._count_mcp_event(event)
            return

        if self._observe_legacy_facade(event):
            return
        self._count_mcp_event(event)
        self.missing_topology_count += 1

    def profile(self, log: str | Path) -> dict[str, Any]:
        return {
            "generated_by": "snulbug mcp fabric learn",
            "generated_from": str(log),
            "event_count": self.event_count,
            "topology_event_count": self.topology_event_count,
            "route_event_count": self.route_event_count,
            "missing_topology_count": self.missing_topology_count,
            "allowed_event_count": self.allowed_event_count,
            "blocked_event_count": self.blocked_event_count,
            "fabric": self.fabric,
            "gateway": self.gateway,
            "upstreams": [upstream.to_dict() for upstream in self._sorted_upstreams()],
            "traffic": {
                "operations": _counter_counts(self.operations),
                "tools": _counter_counts(self.tools),
                "route_modes": _counter_counts(self.route_modes),
            },
            "conflicts": self.conflicts,
            "review_required": self._review_required(),
        }

    def report(self, log: str | Path) -> str:
        upstream_rows = []
        for upstream in self._sorted_upstreams():
            manifest_identity = _mapping(upstream.manifest).get("identity") or "-"
            upstream_rows.append(
                [
                    upstream.name,
                    upstream.transport or "-",
                    upstream.tool_prefix or "-",
                    upstream.route_count,
                    ", ".join(sorted(upstream.tools)) or "-",
                    manifest_identity,
                    upstream.url or upstream.command or "TODO",
                ]
            )

        conflict_rows = [
            [
                conflict.get("line") or "-",
                conflict.get("scope"),
                conflict.get("name"),
                conflict.get("field"),
                conflict.get("old"),
                conflict.get("new"),
            ]
            for conflict in self.conflicts
        ]
        lines = [
            "# Learned MCP Fabric Profile",
            "",
            f"- Source log: `{log}`",
            f"- Events inspected: {self.event_count}",
            f"- Topology events: {self.topology_event_count}",
            f"- Routed events: {self.route_event_count}",
            f"- Missing topology: {self.missing_topology_count}",
            f"- Allowed decisions: {self.allowed_event_count}",
            f"- Blocked decisions: {self.blocked_event_count}",
            "",
            "## Fabric",
            "",
            _markdown_table(
                ["Field", "Value"],
                [
                    ["Name", self.fabric.get("name") or "learned-fabric"],
                    ["Gateway URL", self._gateway_url() or "TODO"],
                    ["Require manifests", self._require_manifests()],
                ],
            ),
            "",
            "## Upstreams",
            "",
            _markdown_table(
                ["Name", "Transport", "Prefix", "Routes", "Observed tools", "Manifest identity", "Target"],
                upstream_rows,
            ),
            "",
            "## Traffic",
            "",
            _counter_table("Operations", self.operations),
            "",
            _counter_table("Tools", self.tools),
            "",
            _counter_table("Route modes", self.route_modes),
            "",
            "## Review Required",
            "",
            _markdown_list("Checks", self._review_required()),
            "",
            "## Conflicts",
            "",
            _markdown_table(["Line", "Scope", "Name", "Field", "Old", "New"], conflict_rows),
            "",
        ]
        return "\n".join(lines)

    def to_toml(self) -> str:
        return _render_learned_fabric_toml(self)

    def _observe_topology(self, topology: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
        line = event.get("line")
        fabric = _mapping(topology.get("fabric"))
        self._merge_static(
            "fabric", "fabric", self.fabric, fabric, ("name", "description", "gateway_url", "require_manifests"), line
        )
        gateway = _mapping(topology.get("gateway"))
        self._merge_static(
            "gateway",
            "gateway",
            self.gateway,
            gateway,
            (
                "url",
                "host",
                "port",
                "tunnel_provider",
                "tunnel_public_url",
                "lease_required",
                "cloudflare_access",
                "facade",
            ),
            line,
        )
        for upstream_data in _sequence_mappings(topology.get("upstreams")):
            name = upstream_data.get("name")
            if isinstance(name, str) and name:
                self._upstream(name).merge_static(
                    upstream_data,
                    conflicts=self.conflicts,
                    conflict_keys=self._conflict_keys,
                    line=line,
                )
        route = _mapping(topology.get("route"))
        if route:
            self._observe_route(route, event)
            return True
        return False

    def _count_mcp_event(self, event: Mapping[str, Any]) -> None:
        mcp = _mapping(event.get("mcp"))
        operation = mcp.get("method")
        tool = mcp.get("tool")
        if operation:
            self.operations[str(operation)] += 1
        if tool:
            self.tools[str(tool)] += 1

    def _observe_legacy_facade(self, event: Mapping[str, Any]) -> bool:
        facade = _legacy_facade(event)
        if not facade:
            return False
        for upstream_data in _sequence_mappings(facade.get("upstream_transports")):
            name = upstream_data.get("name")
            if isinstance(name, str) and name:
                self._upstream(name).merge_static(
                    upstream_data,
                    conflicts=self.conflicts,
                    conflict_keys=self._conflict_keys,
                    line=event.get("line"),
                )
        route = _legacy_route(event, facade)
        if not route:
            return False
        self._observe_route(route, event)
        return True

    def _observe_route(self, route: Mapping[str, Any], event: Mapping[str, Any]) -> None:
        self.route_event_count += 1
        mode = route.get("mode")
        if mode:
            self.route_modes[str(mode)] += 1
        operation = route.get("operation")
        if operation:
            self.operations[str(operation)] += 1
        tool = route.get("tool")
        if tool:
            self.tools[str(tool)] += 1

        upstream_name = route.get("upstream")
        if isinstance(upstream_name, str) and upstream_name:
            upstream = self._upstream(upstream_name)
            upstream.merge_static(
                _route_static_upstream(route),
                conflicts=self.conflicts,
                conflict_keys=self._conflict_keys,
                line=event.get("line"),
            )
            upstream.observe_route(route, event)
            return

        upstream_names = [name for name in _string_sequence(route.get("upstreams")) if name]
        for name in upstream_names:
            self._upstream(name).observe_route(route, event, fanout=True)

    def _merge_static(
        self,
        scope: str,
        name: str,
        target: dict[str, Any],
        source: Mapping[str, Any],
        fields: Sequence[str],
        line: Any,
    ) -> None:
        for field_name in fields:
            _merge_dict_value(
                target,
                field_name,
                source.get(field_name),
                scope=scope,
                name=name,
                conflicts=self.conflicts,
                conflict_keys=self._conflict_keys,
                line=line,
            )

    def _upstream(self, name: str) -> _LearnedFabricUpstream:
        if name not in self.upstreams:
            self.upstreams[name] = _LearnedFabricUpstream(name=name)
        return self.upstreams[name]

    def _sorted_upstreams(self) -> list[_LearnedFabricUpstream]:
        return [self.upstreams[name] for name in sorted(self.upstreams)]

    def _gateway_url(self) -> str | None:
        value = self.gateway.get("url") or self.fabric.get("gateway_url")
        return str(value) if value else None

    def _require_manifests(self) -> bool:
        if isinstance(self.fabric.get("require_manifests"), bool):
            return bool(self.fabric["require_manifests"])
        return any(bool(upstream.manifest) for upstream in self.upstreams.values())

    def _review_required(self) -> list[str]:
        notes = []
        if not self.upstreams:
            notes.append("no upstreams were learned")
        if self.route_event_count == 0:
            notes.append("no routed facade events were learned")
        if not self._gateway_url():
            notes.append("gateway URL was not observed")
        if self.missing_topology_count:
            notes.append(f"{self.missing_topology_count} event(s) lacked topology/facade metadata")
        for upstream in self._sorted_upstreams():
            for note in upstream.review_notes():
                notes.append(f"{upstream.name}: {note}")
        if self.conflicts:
            notes.append(f"{len(self.conflicts)} conflicting topology value(s) need review")
        return notes


def _topology_from_event(event: Mapping[str, Any]) -> Mapping[str, Any]:
    topology = _mapping(event.get("topology"))
    if topology:
        return topology
    metadata = _mapping(event.get("metadata"))
    return _mapping(metadata.get("topology"))


def _legacy_facade(event: Mapping[str, Any]) -> Mapping[str, Any]:
    facade = _mapping(event.get("facade"))
    if facade:
        return facade
    metadata = _mapping(event.get("metadata"))
    if metadata.get("facade"):
        return metadata
    return {}


def _legacy_route(event: Mapping[str, Any], facade: Mapping[str, Any]) -> dict[str, Any]:
    mcp = _mapping(event.get("mcp"))
    upstream_metadata = _mapping(facade.get("upstream_metadata"))
    manifest = _mapping(upstream_metadata.get("manifest"))
    bridge = _mapping(upstream_metadata.get("bridge"))
    route = _drop_empty(
        {
            "mode": "facade",
            "operation": facade.get("operation") or mcp.get("method"),
            "upstream": facade.get("upstream"),
            "upstream_transport": facade.get("upstream_transport") or upstream_metadata.get("transport"),
            "tool_prefix": upstream_metadata.get("tool_prefix"),
            "tool": facade.get("tool") or mcp.get("tool"),
            "upstream_tool": facade.get("upstream_tool"),
            "url": _audit_url(upstream_metadata.get("url")),
            "upstream_identity": manifest.get("identity"),
            "manifest_digest": manifest.get("digest"),
            "manifest_key_id": manifest.get("key_id"),
            "bridge": _drop_empty(
                {
                    "transport": bridge.get("transport"),
                    "peer": bridge.get("peer"),
                    "local_port": bridge.get("local_port"),
                    "config": bridge.get("config"),
                    "command": bridge.get("command"),
                    "private": bridge.get("private"),
                    "ready_timeout": bridge.get("ready_timeout"),
                }
            ),
        }
    )
    upstreams = facade.get("upstreams")
    if (
        not route.get("upstream")
        and isinstance(upstreams, Sequence)
        and not isinstance(upstreams, str | bytes | bytearray)
    ):
        route["fanout"] = True
        route["upstreams"] = _string_sequence(upstreams)
        route["upstream_count"] = len(route["upstreams"])
    return route


def _route_static_upstream(route: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "name": route.get("upstream"),
            "transport": route.get("upstream_transport"),
            "tool_prefix": route.get("tool_prefix"),
            "url": _audit_url(route.get("url")),
            "bridge": _mapping(route.get("bridge")),
            "manifest": _drop_empty(
                {
                    "identity": route.get("upstream_identity"),
                    "digest": route.get("manifest_digest"),
                    "key_id": route.get("manifest_key_id"),
                }
            ),
        }
    )


def _event_allowed(event: Mapping[str, Any]) -> bool:
    decision = _mapping(event.get("decision"))
    allowed = decision.get("allowed")
    if isinstance(allowed, bool):
        return allowed
    action = decision.get("action")
    return action in {"continue", "set_context", "rewrite", "rate_limit"}


def _sequence_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            if isinstance(item, Mapping):
                yield item


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [str(item) for item in value if item is not None and item != ""]


def _merge_attr(
    target: object,
    field_name: str,
    value: Any,
    *,
    scope: str,
    name: str,
    conflicts: list[dict[str, Any]],
    conflict_keys: set[tuple[str, str, str, str, str]],
    line: Any,
) -> None:
    if not _has_value(value):
        return
    current = getattr(target, field_name)
    normalized = _copy_jsonish(value)
    if not _has_value(current):
        setattr(target, field_name, normalized)
        return
    if current != normalized:
        _add_conflict(conflicts, conflict_keys, scope, name, field_name, current, normalized, line=line)


def _merge_dict_value(
    target: dict[str, Any],
    field_name: str,
    value: Any,
    *,
    scope: str,
    name: str,
    conflicts: list[dict[str, Any]],
    conflict_keys: set[tuple[str, str, str, str, str]],
    line: Any,
) -> None:
    if not _has_value(value):
        return
    normalized = _copy_jsonish(value)
    current = target.get(field_name)
    if not _has_value(current):
        target[field_name] = normalized
        return
    if current != normalized:
        _add_conflict(conflicts, conflict_keys, scope, name, field_name, current, normalized, line=line)


def _add_conflict(
    conflicts: list[dict[str, Any]],
    conflict_keys: set[tuple[str, str, str, str, str]],
    scope: str,
    name: str,
    field_name: str,
    old: Any,
    new: Any,
    *,
    line: Any,
) -> None:
    key = (
        scope,
        name,
        field_name,
        json.dumps(old, sort_keys=True, default=str),
        json.dumps(new, sort_keys=True, default=str),
    )
    if key in conflict_keys:
        return
    conflict_keys.add(key)
    conflicts.append(
        _drop_empty(
            {
                "line": line,
                "scope": scope,
                "name": name,
                "field": field_name,
                "old": _copy_jsonish(old),
                "new": _copy_jsonish(new),
            }
        )
    )


def _has_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def _counter_counts(counter: Counter[str], *, limit: int = 20) -> list[dict[str, Any]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def _counter_table(title: str, counter: Counter[str]) -> str:
    rows = [[value, count] for value, count in counter.most_common(20)]
    return "\n".join([f"### {title}", "", _markdown_table(["Value", "Count"], rows)])


def _markdown_list(title: str, values: Sequence[Any]) -> str:
    lines = [f"### {title}"]
    if not values:
        lines.append("- none")
        return "\n".join(lines)
    for value in values:
        lines.append(f"- {value}")
    return "\n".join(lines)


def _markdown_table(headers: Sequence[Any], rows: Sequence[Sequence[Any]]) -> str:
    if not rows:
        rows = [["-" for _header in headers]]
    header = "| " + " | ".join(str(value) for value in headers) + " |"
    separator = "| " + " | ".join("---" for _header in headers) + " |"
    body = ["| " + " | ".join(_markdown_cell(value) for value in row) + " |" for row in rows]
    return "\n".join([header, separator, *body])


def _markdown_cell(value: Any) -> str:
    text = "-" if value in (None, "") else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _render_learned_fabric_toml(model: _LearnedFabric) -> str:
    gateway_url = model._gateway_url() or "http://127.0.0.1:8080/mcp"
    host, port = _gateway_host_port(gateway_url, model.gateway)
    lines = [
        "# Generated by snulbug mcp fabric learn. Review TODO values before use.",
        "",
        "[mcp.fabric]",
        _toml_kv("name", model.fabric.get("name") or "learned-fabric"),
        _toml_kv("description", model.fabric.get("description") or "Learned from topology-aware audit logs"),
        _toml_kv("gateway_url", gateway_url),
        _toml_kv("require_manifests", model._require_manifests()),
        _toml_kv("probe_gateway", True),
        _toml_kv("probe_upstreams", True),
        _toml_kv("timeout", 5.0),
        "",
        "[mcp.proxy]",
        _toml_kv("policy", "policy.snulbug/policy.lua"),
        _toml_kv("host", host),
        _toml_kv("port", port),
        _toml_kv("record_out", "traces/session.jsonl"),
        _toml_kv("audit_out", "traces/audit.jsonl"),
        _toml_kv("decision_console", True),
    ]
    for upstream in model._sorted_upstreams():
        lines.extend(["", "[[mcp.proxy.upstreams]]"])
        lines.extend(_upstream_toml(upstream))
    return "\n".join(lines).rstrip() + "\n"


def _upstream_toml(upstream: _LearnedFabricUpstream) -> list[str]:
    transport = upstream.transport or "http"
    lines = [
        _toml_kv("name", upstream.name),
        _toml_kv("transport", transport),
        _toml_kv("tool_prefix", upstream.tool_prefix or f"{upstream.name}."),
    ]
    if transport in {"http", "holepunch"}:
        lines.append(_toml_kv("url", upstream.url or _holepunch_local_url(upstream) or "TODO"))
    if transport == "stdio":
        lines.append(_toml_kv("command", upstream.command or "TODO"))
        if upstream.cwd:
            lines.append(_toml_kv("cwd", upstream.cwd))
    if transport == "holepunch":
        bridge = _mapping(upstream.bridge)
        local_port = bridge.get("local_port")
        if local_port:
            lines.append(_toml_kv("local_port", local_port))
        if bridge.get("peer"):
            lines.append(_toml_kv("peer", bridge["peer"]))
        elif not bridge.get("config"):
            lines.append(_toml_kv("peer", "TODO"))
        if bridge.get("config"):
            lines.append(_toml_kv("bridge_config", bridge["config"]))
        if bridge.get("command"):
            lines.append(_toml_kv("bridge_command", bridge["command"]))
        if isinstance(bridge.get("private"), bool):
            lines.append(_toml_kv("bridge_private", bridge["private"]))
        if bridge.get("ready_timeout"):
            lines.append(_toml_kv("bridge_ready_timeout", bridge["ready_timeout"]))
    manifest = _mapping(upstream.manifest)
    if manifest.get("path"):
        lines.append(_toml_kv("manifest", manifest["path"]))
        lines.append(_toml_kv("manifest_secret_env", "SNULBUG_MANIFEST_SECRET"))
    if manifest.get("identity"):
        lines.append(_toml_kv("manifest_identity", manifest["identity"]))
    if manifest.get("key_id"):
        lines.append(_toml_kv("manifest_key_id", manifest["key_id"]))
    return lines


def _holepunch_local_url(upstream: _LearnedFabricUpstream) -> str | None:
    local_port = _mapping(upstream.bridge).get("local_port")
    if isinstance(local_port, int) and local_port > 0:
        return f"http://127.0.0.1:{local_port}/mcp"
    return None


def _gateway_host_port(url: str, gateway: Mapping[str, Any]) -> tuple[str, int]:
    parsed = urlsplit(url)
    host = gateway.get("host") if isinstance(gateway.get("host"), str) else None
    port = gateway.get("port") if isinstance(gateway.get("port"), int) else None
    return host or parsed.hostname or "127.0.0.1", port or parsed.port or 8080


def _toml_kv(key: str, value: Any) -> str:
    return f"{key} = {_toml_value(value)}"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return json.dumps(str(value))


def _proxy_status(proxy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "host": proxy.get("host"),
        "port": proxy.get("port"),
        "policy": str(proxy.get("policy")) if proxy.get("policy") is not None else None,
        "state": proxy.get("state"),
        "record_out": str(proxy.get("record_out")) if proxy.get("record_out") is not None else None,
        "audit_out": str(proxy.get("audit_out")) if proxy.get("audit_out") is not None else None,
        "tunnel_provider": proxy.get("tunnel_provider"),
        "tunnel_public_url": proxy.get("tunnel_public_url"),
        "lease_required": proxy.get("lease_required"),
        "cloudflare_access": proxy.get("cloudflare_access"),
        "facade": bool(proxy.get("upstreams")),
    }


def _upstream_status(upstream: Mapping[str, Any]) -> dict[str, Any]:
    status: dict[str, Any] = {
        "name": upstream.get("name"),
        "transport": upstream.get("transport"),
        "tool_prefix": upstream.get("tool_prefix"),
        "default": upstream.get("default", False),
    }
    for field_name in ("url", "command", "cwd", "peer", "local_port", "bridge_command", "bridge_config"):
        if upstream.get(field_name) is not None:
            status[field_name] = str(upstream[field_name])
    if upstream.get("args"):
        status["args"] = list(upstream["args"])
    if upstream.get("bridge_args"):
        status["bridge_args"] = list(upstream["bridge_args"])
    manifest = _manifest_status(upstream)
    if manifest:
        status["manifest"] = manifest
    return status


def _topology_upstream(upstream: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _manifest_status(upstream)
    transport = upstream.get("transport")
    command = None
    if transport == "stdio" and upstream.get("command"):
        command = Path(str(upstream["command"])).name
    manifest_summary = _drop_empty(
        {
            "path": manifest.get("path"),
            "required": manifest.get("required"),
            "exists": manifest.get("exists"),
            "identity": manifest.get("declared_identity"),
            "digest": manifest.get("digest"),
            "key_id": manifest.get("signature_key_id") or manifest.get("configured_key_id"),
            "algorithm": manifest.get("algorithm"),
            "schema": manifest.get("declared_schema"),
            "transport": manifest.get("declared_transport"),
            "tool_prefix": manifest.get("declared_tool_prefix"),
            "tool_count": manifest.get("declared_tool_count"),
        }
    )
    return _drop_empty(
        {
            "name": upstream.get("name"),
            "transport": transport,
            "tool_prefix": upstream.get("tool_prefix"),
            "default": upstream.get("default", False),
            "url": _audit_url(upstream.get("url")) if transport in {"http", "holepunch"} else None,
            "command": command,
            "cwd": str(upstream.get("cwd")) if upstream.get("cwd") is not None else None,
            "bridge": _holepunch_topology(upstream) if transport == "holepunch" else None,
            "manifest": manifest_summary,
        }
    )


def _holepunch_topology(upstream: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "transport": "hypertele",
            "peer": upstream.get("peer"),
            "local_port": upstream.get("local_port"),
            "config": upstream.get("bridge_config"),
            "command": Path(str(upstream.get("bridge_command"))).name if upstream.get("bridge_command") else None,
            "private": upstream.get("bridge_private"),
            "ready_timeout": upstream.get("bridge_ready_timeout"),
        }
    )


def _manifest_status(upstream: Mapping[str, Any]) -> dict[str, Any]:
    path = upstream.get("manifest")
    if path is None:
        return {}
    manifest_path = Path(path)
    status: dict[str, Any] = {
        "path": str(manifest_path),
        "required": bool(upstream.get("manifest_required", True)),
        "exists": manifest_path.is_file(),
        "expected_identity": upstream.get("manifest_identity"),
        "configured_key_id": upstream.get("manifest_key_id"),
        "secret_env": upstream.get("manifest_secret_env"),
        "secret_env_set": bool(os.environ.get(str(upstream.get("manifest_secret_env"))))
        if upstream.get("manifest_secret_env")
        else None,
        "inline_secret_configured": bool(upstream.get("manifest_secret")),
    }
    if not manifest_path.is_file():
        return _drop_empty(status)
    try:
        document = load_manifest(manifest_path)
    except Exception as exc:
        status["load_error"] = str(exc)
        return _drop_empty(status)
    signature = document.get("snulbug_signature")
    if isinstance(signature, Mapping):
        status["signed"] = True
        status["signature_key_id"] = signature.get("key_id")
        status["digest"] = signature.get("digest")
        status["algorithm"] = signature.get("algorithm")
    else:
        status["signed"] = False
    for field_name in ("schema", "identity", "transport", "tool_prefix"):
        if document.get(field_name) is not None:
            status[f"declared_{field_name}"] = document[field_name]
    tools = document.get("tools")
    if isinstance(tools, list):
        status["declared_tool_count"] = len(tools)
    return _drop_empty(status)


def _fabric_summary(
    fabric: Mapping[str, Any],
    proxy: Mapping[str, Any],
    upstreams: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    transports: dict[str, int] = {}
    for upstream in upstreams:
        transport = str(upstream.get("transport", "unknown"))
        transports[transport] = transports.get(transport, 0) + 1
    missing_required_manifests = sum(
        1
        for upstream in upstreams
        if bool(fabric.get("require_manifests")) and not _mapping(upstream.get("manifest")).get("exists")
    )
    default_upstream = next((upstream.get("name") for upstream in upstreams if upstream.get("default")), None)
    return {
        "upstream_count": len(upstreams),
        "transports": transports,
        "manifest_count": sum(1 for upstream in upstreams if upstream.get("manifest")),
        "missing_required_manifests": missing_required_manifests,
        "default_upstream": default_upstream,
        "facade": bool(proxy.get("upstreams")),
        "tunnel_provider": proxy.get("tunnel_provider"),
    }


def _fabric_recommendations(fabric: Mapping[str, Any], upstreams: Sequence[Mapping[str, Any]]) -> list[str]:
    recommendations = []
    if not upstreams:
        recommendations.append("Declare [[mcp.proxy.upstreams]] entries to run snulbug as a fabric facade.")
    if fabric.get("require_manifests") and any(
        not _mapping(upstream.get("manifest")).get("exists") for upstream in upstreams
    ):
        recommendations.append("Add signed manifests for every upstream or set require_manifests = false.")
    if not fabric.get("gateway_url"):
        recommendations.append("Set mcp.fabric.gateway_url or configure mcp.proxy.host and mcp.proxy.port.")
    return recommendations


def _run_manifest_checks(
    checks: list[dict[str, Any]],
    upstream: Mapping[str, Any],
    *,
    require_manifest: bool,
) -> None:
    name = _check_name(upstream)
    manifest = upstream.get("manifest")
    if manifest is None:
        _add_check(
            checks,
            f"upstream.{name}.manifest_present",
            False if require_manifest else None,
            "manifest is required but missing" if require_manifest else "no manifest configured",
        )
        return
    manifest_path = Path(manifest)
    exists = manifest_path.is_file()
    _add_check(
        checks,
        f"upstream.{name}.manifest_present",
        exists,
        f"manifest exists at {manifest_path}" if exists else f"manifest file is missing: {manifest_path}",
        details={"path": str(manifest_path)},
    )
    if not exists:
        return
    try:
        document = load_manifest(manifest_path)
        signature = document.get("snulbug_signature")
        signature_key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
        key_id = upstream.get("manifest_key_id") or signature_key_id
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("manifest key_id is required")
        secret = upstream.get("manifest_secret")
        secret_env = upstream.get("manifest_secret_env")
        if not secret and isinstance(secret_env, str):
            secret = os.environ.get(secret_env)
        if not secret:
            source = f"environment variable {secret_env!r}" if secret_env else "manifest_secret"
            raise ValueError(f"manifest secret is required from {source}")
        expected_identity = upstream.get("manifest_identity")
        verified = verify_upstream_manifest(
            document,
            secrets={key_id: str(secret)},
            expected_identity=expected_identity if isinstance(expected_identity, str) else None,
        )
        _add_check(
            checks,
            f"upstream.{name}.manifest_verified",
            True,
            f"manifest verified for {verified.get('identity', upstream.get('name'))}",
            details=verified,
        )
    except Exception as exc:
        _add_check(checks, f"upstream.{name}.manifest_verified", False, f"manifest verification failed: {exc}")


def _run_upstream_probe_checks(
    checks: list[dict[str, Any]],
    probes: dict[str, Any],
    upstream: Mapping[str, Any],
    *,
    headers: Mapping[str, str],
    timeout: float,
) -> None:
    name = _check_name(upstream)
    transport = upstream.get("transport")
    if transport in {"http", "holepunch"}:
        url = upstream.get("url")
        if not isinstance(url, str) or not url:
            _add_check(checks, f"upstream.{name}.url_present", False, "upstream URL is missing")
            return
        _run_mcp_endpoint_checks(
            checks,
            probes,
            check_prefix=f"upstream.{name}",
            url=url,
            headers=headers,
            timeout=timeout,
            label=f"upstream {upstream.get('name')}",
        )
        return
    if transport == "stdio":
        command = upstream.get("command")
        command_ok = isinstance(command, str) and bool(_resolve_command(command))
        _add_check(
            checks,
            f"upstream.{name}.stdio_command",
            command_ok,
            f"stdio command is available: {command}" if command_ok else f"stdio command is not on PATH: {command}",
            details={"command": command},
        )
        return
    _add_check(checks, f"upstream.{name}.transport_supported", False, f"unsupported transport: {transport!r}")


def _run_mcp_endpoint_checks(
    checks: list[dict[str, Any]],
    probes: dict[str, Any],
    *,
    check_prefix: str,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    label: str,
) -> None:
    probe = _probe_mcp_tools_list(url, headers=headers, timeout=timeout)
    probes[check_prefix] = probe
    reachable = probe.get("error") is None and probe.get("status") is not None
    reachable_message = (
        f"{label} responded with HTTP {probe.get('status')}"
        if reachable
        else f"{label} did not respond: {probe.get('error')}"
    )
    _add_check(
        checks,
        f"{check_prefix}.reachable",
        reachable,
        reachable_message,
        details={"url": url, "status": probe.get("status"), "error": probe.get("error")},
    )
    json_body = probe.get("json")
    tools = json_body.get("result", {}).get("tools") if isinstance(json_body, Mapping) else None
    round_trip = probe.get("status") == 200 and isinstance(tools, list)
    _add_check(
        checks,
        f"{check_prefix}.tools_list",
        round_trip,
        f"{label} returned tools/list with {len(tools)} tool(s)"
        if round_trip
        else f"{label} did not return a valid tools/list response",
        details={"status": probe.get("status"), "body_sample": probe.get("body_sample")},
    )


def _probe_mcp_tools_list(url: str, *, headers: Mapping[str, str], timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return _probe_error(url, "invalid URL")
    body = json.dumps(_FABRIC_DOCTOR_REQUEST, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "Host": parsed.netloc,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "User-Agent": "snulbug-fabric-doctor",
        **dict(headers),
    }
    connection = _connection(parsed, timeout)
    try:
        connection.request("POST", _exact_target(parsed), body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        text = response_body.decode("utf-8", errors="replace")
        json_body = None
        try:
            json_body = json.loads(text) if text else None
        except json.JSONDecodeError:
            json_body = None
        return {
            "url": url,
            "status": int(response.status),
            "headers": {name.lower(): value for name, value in response.getheaders()},
            "body_size": len(response_body),
            "body_sample": text[:300],
            "json": json_body,
            "error": None,
        }
    except Exception as exc:
        return _probe_error(url, str(exc))
    finally:
        connection.close()


def _probe_error(url: str, error: str) -> dict[str, Any]:
    return {
        "url": url,
        "status": None,
        "headers": {},
        "body_size": 0,
        "body_sample": "",
        "json": None,
        "error": error,
    }


def _connection(upstream: SplitResult, timeout: float) -> http.client.HTTPConnection:
    host = upstream.hostname
    if host is None:
        raise ValueError("upstream host is required")
    port = upstream.port
    if upstream.scheme == "https":
        return http.client.HTTPSConnection(host, port=port, timeout=timeout)
    return http.client.HTTPConnection(host, port=port, timeout=timeout)


def _exact_target(upstream: SplitResult) -> str:
    path = upstream.path or "/"
    return f"{path}?{upstream.query}" if upstream.query else path


def _resolve_command(command: str) -> str | None:
    if "/" in command or "\\" in command:
        return command if Path(command).exists() else None
    return shutil.which(command)


def _doctor_recommendations(checks: Sequence[Mapping[str, Any]], *, headers: Mapping[str, str]) -> list[str]:
    recommendations = []
    statuses = {str(check.get("id")): str(check.get("status")) for check in checks}
    if statuses.get("gateway.tools_list") == "fail" and not any(name.lower() == "authorization" for name in headers):
        recommendations.append("Pass --token or --header Authorization:Bearer... so doctor can verify the gateway.")
    manifest_failed = any(
        str(check.get("id", "")).endswith(".manifest_verified") and check.get("status") == "fail" for check in checks
    )
    tools_list_failed = any(
        str(check.get("id", "")).endswith(".tools_list") and check.get("status") == "fail" for check in checks
    )
    if manifest_failed:
        recommendations.append(
            "Fix manifest signatures, expected identities, or manifest secret environment variables."
        )
    if tools_list_failed:
        recommendations.append(
            "Start the gateway/upstream servers, or disable the corresponding probe for static checks."
        )
    if statuses.get("proxy.facade_enabled") == "warn":
        recommendations.append("Declare [[mcp.proxy.upstreams]] entries to expose multiple MCP servers as one fabric.")
    return recommendations


def _topology_route(proxy_metadata: Mapping[str, Any]) -> dict[str, Any]:
    operation = proxy_metadata.get("operation")
    if proxy_metadata.get("facade"):
        route: dict[str, Any] = {
            "mode": "facade",
            "operation": operation,
        }
        if proxy_metadata.get("upstream"):
            upstream_metadata = _mapping(proxy_metadata.get("upstream_metadata"))
            manifest = _mapping(upstream_metadata.get("manifest"))
            bridge = _mapping(upstream_metadata.get("bridge"))
            route.update(
                _drop_empty(
                    {
                        "upstream": proxy_metadata.get("upstream"),
                        "upstream_transport": proxy_metadata.get("upstream_transport"),
                        "tool_prefix": upstream_metadata.get("tool_prefix"),
                        "tool": proxy_metadata.get("tool"),
                        "upstream_tool": proxy_metadata.get("upstream_tool"),
                        "upstream_identity": manifest.get("identity"),
                        "manifest_digest": manifest.get("digest"),
                        "manifest_key_id": manifest.get("key_id"),
                        "bridge": _drop_empty(
                            {
                                "transport": bridge.get("transport"),
                                "peer": bridge.get("peer"),
                                "local_port": bridge.get("local_port"),
                            }
                        ),
                    }
                )
            )
            return _drop_empty(route)
        upstreams = proxy_metadata.get("upstreams")
        if isinstance(upstreams, list):
            route.update(
                {
                    "fanout": True,
                    "upstreams": list(upstreams),
                    "upstream_count": len(upstreams),
                }
            )
        return _drop_empty(route)
    return _drop_empty(
        {
            "mode": "reverse_proxy",
            "operation": operation,
            "target": proxy_metadata.get("target"),
        }
    )


def _audit_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit(parsed._replace(netloc=host, query="", fragment=""))


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_jsonish(item) for item in value]
    return value


def _checks_summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "skipped": sum(1 for check in checks if check.get("status") == "skip"),
    }


def _add_check(
    checks: list[dict[str, Any]],
    check_id: str,
    passed: bool | None,
    message: str,
    *,
    severity: str = "error",
    details: Mapping[str, Any] | None = None,
) -> None:
    if passed is True:
        status = "pass"
    elif passed is None:
        status = "skip"
    elif severity == "warning":
        status = "warn"
    else:
        status = "fail"
    check = {
        "id": check_id,
        "status": status,
        "message": message,
    }
    if details:
        check["details"] = _json_safe(details)
    checks.append(check)


def _upstreams(proxy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    upstreams = proxy.get("upstreams")
    if not isinstance(upstreams, list):
        return []
    return [upstream for upstream in upstreams if isinstance(upstream, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _check_name(upstream: Mapping[str, Any]) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(upstream.get("name", "upstream"))).strip("_") or "upstream"


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}


def _json_safe(value: Mapping[str, Any]) -> dict[str, Any]:
    result = {}
    for key, item in value.items():
        if isinstance(item, Path):
            result[str(key)] = str(item)
        elif isinstance(item, Mapping):
            result[str(key)] = _json_safe(item)
        elif isinstance(item, list):
            result[str(key)] = [str(part) if isinstance(part, Path) else part for part in item]
        else:
            result[str(key)] = item
    return result

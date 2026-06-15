from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GatewayTemplate:
    """Shared shape for generated snulbug gateway TOML files."""

    proxy: Mapping[str, Any] = field(default_factory=dict)
    upstreams: Sequence[Mapping[str, Any]] = ()
    auth: Mapping[str, Any] | None = None
    event_sinks: Sequence[Mapping[str, Any]] = ()
    fabric: Mapping[str, Any] | None = None
    fabric_credentials: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    fabric_discovery: Mapping[str, Any] | None = None
    fabric_discovery_providers: Sequence[Mapping[str, Any]] = ()


def render_gateway_toml(template: GatewayTemplate, *, header: str | None = None) -> str:
    lines: list[str] = []
    if header:
        lines.extend(header.rstrip().splitlines())

    if template.fabric is not None:
        _append_block(lines, render_toml_table("mcp.fabric", template.fabric))
        for name, values in template.fabric_credentials.items():
            _append_block(lines, render_toml_table(f"mcp.fabric.credentials.{name}", values))
        if template.fabric_discovery is not None:
            _append_block(lines, render_toml_table("mcp.fabric.discovery", template.fabric_discovery))
        for provider in template.fabric_discovery_providers:
            _append_block(lines, render_toml_array_table("mcp.fabric.discovery.providers", provider))

    if template.proxy:
        _append_block(lines, render_toml_table("mcp.proxy", template.proxy))
    for upstream in template.upstreams:
        _append_block(lines, render_toml_array_table("mcp.proxy.upstreams", upstream))
    if template.auth is not None:
        _append_block(lines, render_toml_table("mcp.auth", template.auth))
    for sink in template.event_sinks:
        _append_block(lines, render_toml_array_table("mcp.events.sinks", sink))

    if not lines:
        return ""
    return "\n".join(lines).rstrip() + "\n"


def render_toml_table(name: str, values: Mapping[str, Any]) -> list[str]:
    return [f"[{name}]", *render_toml_values(values)]


def render_toml_array_table(name: str, values: Mapping[str, Any]) -> list[str]:
    return [f"[[{name}]]", *render_toml_values(values)]


def render_toml_values(values: Mapping[str, Any]) -> list[str]:
    return [f"{key} = {toml_literal(value)}" for key, value in values.items()]


def toml_literal(value: Any) -> str:
    if value is None:
        return json.dumps("")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, Path):
        return json.dumps(str(value))
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return json.dumps([_toml_array_value(item) for item in value])
    return json.dumps(str(value))


def _toml_array_value(value: Any) -> Any:
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, Path):
        return str(value)
    return str(value)


def _append_block(lines: list[str], block: Sequence[str]) -> None:
    if lines:
        lines.append("")
    lines.extend(block)

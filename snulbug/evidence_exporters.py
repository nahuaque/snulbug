from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvidenceExportContext:
    """Inputs passed to an evidence exporter."""

    command: str
    result: Mapping[str, Any]
    output: Path
    options: Mapping[str, Any] | None = None


class EvidenceExporter:
    """Extension point for writing evidence reports and machine-readable gates."""

    name = ""
    commands: tuple[str, ...] = ()
    extension: str | None = None

    @property
    def normalized_name(self) -> str:
        return str(self.name).strip().lower()

    def supports(self, command: str) -> bool:
        return not self.commands or command in self.commands

    def render(self, context: EvidenceExportContext) -> str | bytes:
        raise NotImplementedError(f"evidence exporter {self.name!r} must implement render()")


class MarkdownEvidenceExporter(EvidenceExporter):
    name = "markdown"
    commands = ("inspect", "impact", "diff")
    extension = ".md"

    def render(self, context: EvidenceExportContext) -> str:
        if context.command == "inspect":
            from .inspection import format_mcp_inspection_report

            return format_mcp_inspection_report(context.result, output_format="markdown")
        if context.command == "impact":
            from .impact import format_mcp_impact_report

            return format_mcp_impact_report(context.result, output_format="markdown")
        if context.command == "diff":
            from .promotion import format_policy_diff_report

            return format_policy_diff_report(context.result)
        raise ValueError(f"markdown exporter does not support evidence command: {context.command}")


class JsonEvidenceExporter(EvidenceExporter):
    name = "json"
    commands = ("record", "replay", "inspect", "impact", "diff")
    extension = ".json"

    def render(self, context: EvidenceExportContext) -> str:
        compact = bool(_mapping(context.options).get("compact", False))
        if compact:
            return json.dumps(context.result, separators=(",", ":"), sort_keys=True) + "\n"
        return json.dumps(context.result, indent=2, sort_keys=True) + "\n"


class SarifEvidenceExporter(EvidenceExporter):
    name = "sarif"
    commands = ("diff",)
    extension = ".sarif"

    def render(self, context: EvidenceExportContext) -> str:
        from .sarif import sarif_for_policy_diff

        return json.dumps(sarif_for_policy_diff(context.result), indent=2, sort_keys=True) + "\n"


_EVIDENCE_EXPORTER_REGISTRY: dict[str, EvidenceExporter] = {}


def register_evidence_exporter(exporter: EvidenceExporter, *, replace: bool = False) -> EvidenceExporter:
    """Register an evidence exporter plugin."""

    name = exporter.normalized_name
    if not name:
        raise ValueError("evidence exporter name is required")
    if name in _EVIDENCE_EXPORTER_REGISTRY and not replace:
        raise ValueError(f"evidence exporter already registered: {name}")
    _EVIDENCE_EXPORTER_REGISTRY[name] = exporter
    return exporter


def get_evidence_exporter(name: str) -> EvidenceExporter:
    """Return a registered evidence exporter plugin."""

    normalized = str(name).strip().lower()
    try:
        return _EVIDENCE_EXPORTER_REGISTRY[normalized]
    except KeyError as exc:
        known = ", ".join(list_evidence_exporters()) or "<none>"
        raise ValueError(f"unknown evidence exporter {name!r}; known exporters: {known}") from exc


def list_evidence_exporters(*, command: str | None = None) -> tuple[str, ...]:
    """Return registered evidence exporter names in registration order."""

    if command is None:
        return tuple(_EVIDENCE_EXPORTER_REGISTRY)
    return tuple(name for name, exporter in _EVIDENCE_EXPORTER_REGISTRY.items() if exporter.supports(command))


def export_evidence(
    command: str,
    result: Mapping[str, Any],
    output: str | Path,
    *,
    exporter: str,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write an evidence export and return metadata safe to attach to CLI results."""

    plugin = get_evidence_exporter(exporter)
    if not plugin.supports(command):
        raise ValueError(f"evidence exporter {plugin.normalized_name!r} does not support command {command!r}")
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = plugin.render(
        EvidenceExportContext(
            command=command,
            result=result,
            output=output_path,
            options=options or {},
        )
    )
    if isinstance(rendered, bytes):
        output_path.write_bytes(rendered)
    else:
        output_path.write_text(rendered, encoding="utf-8")
    return {
        "exporter": plugin.normalized_name,
        "format": plugin.normalized_name,
        "path": str(output_path),
    }


def parse_evidence_export_specs(specs: Sequence[str]) -> list[dict[str, Any]]:
    """Parse CLI export specs in `format=path` form."""

    exports = []
    for spec in specs:
        exporter, separator, path = str(spec).partition("=")
        if not separator or not exporter.strip() or not path.strip():
            raise ValueError("evidence export specs must use FORMAT=PATH")
        exports.append({"format": exporter.strip(), "path": Path(path.strip())})
    return exports


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


for _exporter in (MarkdownEvidenceExporter(), JsonEvidenceExporter(), SarifEvidenceExporter()):
    register_evidence_exporter(_exporter, replace=True)

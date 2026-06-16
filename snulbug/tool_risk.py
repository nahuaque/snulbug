from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

RISK_LEVELS = ("low", "medium", "high")
RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
RISK_WEIGHTS = {"low": 10, "medium": 30, "high": 60}

SHELL_TERMS = (
    "shell",
    "exec",
    "execute",
    "command",
    "terminal",
    "subprocess",
    "process",
    "spawn",
    "bash",
    "zsh",
    "powershell",
    "cmd",
    "system",
)
WRITE_TERMS = (
    "write",
    "edit",
    "create",
    "delete",
    "remove",
    "rename",
    "move",
    "patch",
    "replace",
    "append",
    "mkdir",
    "rm",
    "save",
    "mutate",
    "update",
)
DESTRUCTIVE_TERMS = ("delete", "remove", "rm", "destroy", "drop", "wipe", "kill", "terminate")
NETWORK_TERMS = ("url", "uri", "host", "http", "https", "fetch", "request", "webhook", "network", "download")
SECRET_TERMS = ("secret", "token", "password", "credential", "apikey", "api_key", "private_key", "ssh_key")
FILESYSTEM_TERMS = (
    "file",
    "files",
    "filesystem",
    "path",
    "directory",
    "dir",
    "read_file",
    "list_project_files",
)
LOW_RISK_READ_TERMS = ("list", "read", "get", "show", "status", "describe", "inspect", "search")


@dataclass(frozen=True)
class ToolRiskSignal:
    code: str
    severity: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity, "reason": self.reason}


@dataclass(frozen=True)
class ToolRiskFinding:
    signal: ToolRiskSignal
    category: str


@dataclass(frozen=True)
class ToolRiskContext:
    tool: str | Mapping[str, Any]
    name: str
    description: str
    annotations: Mapping[str, Any]
    input_schema: Mapping[str, Any]
    count: int = 0
    evidence_sources: tuple[str, ...] = ()
    confidence: str | None = None
    schema_hash: str | None = None
    schema_hashes: tuple[str, ...] = ()
    catalog_hashes: tuple[str, ...] = ()
    catalog_paths: tuple[str, ...] = ()
    schema_variants: int | None = None


class ToolRiskAnalyzer:
    """Extension point for MCP tool/schema risk classification and policy advice."""

    name = ""

    @property
    def normalized_name(self) -> str:
        return str(self.name).strip().lower()

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        return ()

    def suggest_policy(self, context: ToolRiskContext, risk: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return ()

    def suggest_lease(self, context: ToolRiskContext, risk: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        return ()


class ToolNameRiskAnalyzer(ToolRiskAnalyzer):
    name = "tool-name"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        findings: list[ToolRiskFinding] = []
        haystack = f"{context.name} {context.description}".lower().replace("-", "_")
        if _contains_any(haystack, SHELL_TERMS):
            findings.append(_finding("tool.shell_or_process", "high", "tool looks able to run commands", "command"))
        if _contains_any(haystack, SECRET_TERMS):
            findings.append(
                _finding("tool.secret_name", "high", "tool name suggests secret or credential access", "secrets")
            )
        if _contains_any(haystack, DESTRUCTIVE_TERMS):
            findings.append(
                _finding("tool.destructive_name", "high", "tool name suggests destructive mutation", "mutation")
            )
        elif _contains_any(haystack, WRITE_TERMS):
            findings.append(_finding("tool.mutating_name", "medium", "tool name suggests mutation", "mutation"))
        if _contains_any(haystack, NETWORK_TERMS):
            findings.append(_finding("tool.network_name", "medium", "tool name suggests network access", "network"))
        if _contains_any(haystack, FILESYSTEM_TERMS):
            findings.append(
                _finding("tool.filesystem_name", "medium", "tool name suggests filesystem access", "filesystem")
            )
        if _contains_any(haystack, LOW_RISK_READ_TERMS):
            findings.append(
                _finding("tool.read_like_name", "low", "tool name suggests read-only or inspection use", "read")
            )
        return findings


class ToolAnnotationRiskAnalyzer(ToolRiskAnalyzer):
    name = "tool-annotations"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        findings: list[ToolRiskFinding] = []
        if context.annotations.get("destructiveHint") is True:
            findings.append(
                _finding("annotation.destructive", "high", "tool declares destructive behavior", "mutation")
            )
        if context.annotations.get("openWorldHint") is True:
            findings.append(_finding("annotation.open_world", "medium", "tool may affect external systems", "network"))
        if context.annotations.get("readOnlyHint") is True:
            findings.append(_finding("annotation.read_only", "low", "tool declares read-only behavior", "read"))
        return findings


class ToolSchemaArgumentRiskAnalyzer(ToolRiskAnalyzer):
    name = "tool-schema-arguments"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        findings: list[ToolRiskFinding] = []
        for property_name, property_schema in _mapping(context.input_schema.get("properties")).items():
            for signal, category in _schema_property_signals(str(property_name), _mapping(property_schema)):
                findings.append(ToolRiskFinding(signal, category))
        return findings


class ToolSchemaShapeRiskAnalyzer(ToolRiskAnalyzer):
    name = "tool-schema-shape"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        if context.input_schema and context.input_schema.get("type", "object") == "object":
            additional_properties = context.input_schema.get("additionalProperties")
            if additional_properties is not False:
                return (
                    _finding(
                        "schema.open_arguments",
                        "medium",
                        "tool input schema allows undeclared arguments",
                        "open-schema",
                    ),
                )
        return ()


class ToolSchemaDriftRiskAnalyzer(ToolRiskAnalyzer):
    name = "tool-schema-drift"

    def analyze(self, context: ToolRiskContext) -> Sequence[ToolRiskFinding]:
        if context.schema_variants is not None and context.schema_variants > 1:
            return (
                _finding(
                    "schema.variant_conflict",
                    "high",
                    "multiple schema variants were found for this tool",
                    "schema-drift",
                ),
            )
        return ()


_TOOL_RISK_ANALYZER_REGISTRY: dict[str, ToolRiskAnalyzer] = {}


def register_tool_risk_analyzer(analyzer: ToolRiskAnalyzer, *, replace: bool = False) -> ToolRiskAnalyzer:
    """Register an MCP tool risk analyzer plugin."""

    name = analyzer.normalized_name
    if not name:
        raise ValueError("tool risk analyzer name is required")
    if name in _TOOL_RISK_ANALYZER_REGISTRY and not replace:
        raise ValueError(f"tool risk analyzer already registered: {name}")
    _TOOL_RISK_ANALYZER_REGISTRY[name] = analyzer
    return analyzer


def get_tool_risk_analyzer(name: str) -> ToolRiskAnalyzer:
    """Return a registered MCP tool risk analyzer."""

    normalized = str(name).strip().lower()
    try:
        return _TOOL_RISK_ANALYZER_REGISTRY[normalized]
    except KeyError as exc:
        known = ", ".join(list_tool_risk_analyzers()) or "<none>"
        raise ValueError(f"unknown tool risk analyzer {name!r}; known analyzers: {known}") from exc


def list_tool_risk_analyzers() -> tuple[str, ...]:
    """Return registered analyzer names in registration order."""

    return tuple(_TOOL_RISK_ANALYZER_REGISTRY)


def classify_mcp_tool(tool: str | Mapping[str, Any], *, count: int = 0) -> dict[str, Any]:
    """Classify one MCP tool using secret-safe name/schema heuristics."""

    context = _tool_risk_context(tool, count=count)
    findings: list[ToolRiskFinding] = []
    for analyzer in _TOOL_RISK_ANALYZER_REGISTRY.values():
        findings.extend(analyzer.analyze(context))

    signals = [finding.signal for finding in findings]
    categories = {finding.category for finding in findings if finding.category}
    if not signals:
        signals.append(ToolRiskSignal("tool.observed", "low", "tool was observed but has no obvious high-risk signal"))
        categories.add("unknown")

    score = min(100, sum(RISK_WEIGHTS.get(signal.severity, 0) for signal in signals))
    level = _risk_level(score, signals)
    result: dict[str, Any] = {
        "name": context.name,
        "level": level,
        "score": score,
        "count": int(count or 0),
        "categories": sorted(categories),
        "signals": [signal.to_dict() for signal in signals],
    }
    if context.evidence_sources:
        result["evidence_sources"] = sorted(dict.fromkeys(context.evidence_sources))
    if context.confidence:
        result["confidence"] = context.confidence
    schema = _schema_summary(
        context.input_schema,
        schema_hash=context.schema_hash,
        schema_hashes=context.schema_hashes,
        catalog_hashes=context.catalog_hashes,
        catalog_paths=context.catalog_paths,
        schema_variants=context.schema_variants,
    )
    if schema:
        result["schema"] = schema
    advice = _tool_risk_advice(context, result)
    if advice:
        result["advice"] = advice
    return result


def classify_mcp_tool_risks(tools: Sequence[Any] | Mapping[str, Any] | None) -> dict[str, Any]:
    """Classify observed or discovered MCP tools and summarize by risk level."""

    classified: list[dict[str, Any]] = []
    for item in _tool_entries(tools):
        classified.append(classify_mcp_tool(item["tool"], count=item["count"]))

    classified.sort(key=lambda item: (-RISK_ORDER.get(str(item["level"]), 0), -int(item.get("count", 0)), item["name"]))
    summary = Counter(str(item["level"]) for item in classified)
    categories = Counter(category for item in classified for category in _sequence(item.get("categories")))
    return {
        "summary": {level: summary.get(level, 0) for level in RISK_LEVELS},
        "categories": [{"value": value, "count": count} for value, count in categories.most_common()],
        "tools": classified,
        "top_risks": classified[:10],
    }


def _tool_risk_context(tool: str | Mapping[str, Any], *, count: int) -> ToolRiskContext:
    if isinstance(tool, Mapping):
        name = str(tool.get("name") or tool.get("value") or "")
        description = tool.get("description") if isinstance(tool.get("description"), str) else ""
        annotations = _mapping(tool.get("annotations"))
        input_schema = _mapping(tool.get("inputSchema"))
        evidence_sources = tuple(_string_list(tool.get("evidence_sources") or tool.get("evidence")))
        confidence = tool.get("confidence") if isinstance(tool.get("confidence"), str) else None
        schema_hash = tool.get("schema_hash") if isinstance(tool.get("schema_hash"), str) else None
        if schema_hash is None and isinstance(tool.get("hash"), str) and input_schema:
            schema_hash = str(tool.get("hash"))
        schema_hashes = tuple(_string_list(tool.get("schema_hashes")))
        catalog_hashes = tuple(_string_list(tool.get("catalog_hashes")))
        catalog_paths = tuple(_string_list(tool.get("catalog_paths")))
        schema_variants = tool.get("schema_variants") if isinstance(tool.get("schema_variants"), int) else None
    else:
        name = str(tool)
        description = ""
        annotations = {}
        input_schema = {}
        evidence_sources = ()
        confidence = None
        schema_hash = None
        schema_hashes = ()
        catalog_hashes = ()
        catalog_paths = ()
        schema_variants = None
    return ToolRiskContext(
        tool=tool,
        name=name,
        description=description,
        annotations=annotations,
        input_schema=input_schema,
        count=int(count or 0),
        evidence_sources=evidence_sources,
        confidence=confidence,
        schema_hash=schema_hash,
        schema_hashes=schema_hashes,
        catalog_hashes=catalog_hashes,
        catalog_paths=catalog_paths,
        schema_variants=schema_variants,
    )


def _tool_risk_advice(context: ToolRiskContext, risk: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    policy_advice: list[dict[str, Any]] = []
    lease_advice: list[dict[str, Any]] = []
    for analyzer in _TOOL_RISK_ANALYZER_REGISTRY.values():
        policy_advice.extend(dict(item) for item in analyzer.suggest_policy(context, risk))
        lease_advice.extend(dict(item) for item in analyzer.suggest_lease(context, risk))
    advice: dict[str, list[dict[str, Any]]] = {}
    if policy_advice:
        advice["policy"] = policy_advice
    if lease_advice:
        advice["lease"] = lease_advice
    return advice


def _finding(code: str, severity: str, reason: str, category: str) -> ToolRiskFinding:
    return ToolRiskFinding(ToolRiskSignal(code, severity, reason), category)


def _tool_entries(value: Sequence[Any] | Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        if isinstance(value.get("tools"), Sequence) and not isinstance(value.get("tools"), str | bytes | bytearray):
            return _tool_entries(value.get("tools"))  # type: ignore[arg-type]
        tool_name = value.get("name") or value.get("value")
        return [{"tool": value, "count": int(value.get("count") or 0)}] if tool_name else []
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        entries = []
        for item in value:
            if isinstance(item, Mapping):
                tool_name = item.get("name") or item.get("value")
                if tool_name:
                    if "name" in item:
                        entries.append({"tool": item, "count": int(item.get("count") or 0)})
                    else:
                        entries.append({"tool": str(tool_name), "count": int(item.get("count") or 0)})
            elif item is not None:
                entries.append({"tool": str(item), "count": 0})
        return entries
    return [{"tool": str(value), "count": 0}]


def _schema_property_signals(name: str, schema: Mapping[str, Any]) -> list[tuple[ToolRiskSignal, str]]:
    signals: list[tuple[ToolRiskSignal, str]] = []
    haystack = f"{name} {schema.get('description') or ''}".lower().replace("-", "_")
    if _contains_any(haystack, FILESYSTEM_TERMS):
        signals.append((ToolRiskSignal("argument.path", "medium", f"argument `{name}` looks path-like"), "filesystem"))
    if _contains_any(haystack, NETWORK_TERMS):
        signals.append(
            (ToolRiskSignal("argument.network", "medium", f"argument `{name}` looks network-capable"), "network")
        )
    if _contains_any(haystack, SHELL_TERMS):
        signals.append(
            (ToolRiskSignal("argument.command", "high", f"argument `{name}` looks command-capable"), "command")
        )
    if _contains_any(haystack, SECRET_TERMS):
        signals.append(
            (ToolRiskSignal("argument.secret", "high", f"argument `{name}` looks secret-bearing"), "secrets")
        )
    if schema.get("format") in {"uri", "url", "hostname", "ipv4", "ipv6"}:
        signals.append(
            (ToolRiskSignal("argument.network_format", "medium", f"argument `{name}` has network format"), "network")
        )
    return signals


def _schema_summary(
    input_schema: Mapping[str, Any],
    *,
    schema_hash: str | None,
    schema_hashes: Sequence[str],
    catalog_hashes: Sequence[str],
    catalog_paths: Sequence[str],
    schema_variants: int | None,
) -> dict[str, Any]:
    properties = sorted(str(key) for key in _mapping(input_schema.get("properties")).keys())
    required = sorted(str(item) for item in _sequence(input_schema.get("required")))
    summary: dict[str, Any] = {}
    if schema_hash:
        summary["tool_hash"] = schema_hash
    if schema_hashes:
        summary["tool_hashes"] = sorted(dict.fromkeys(schema_hashes))
    if catalog_hashes:
        summary["catalog_hashes"] = sorted(dict.fromkeys(catalog_hashes))
    if catalog_paths:
        summary["catalog_paths"] = sorted(dict.fromkeys(catalog_paths))
    if schema_variants is not None:
        summary["variants"] = schema_variants
    if input_schema:
        summary["input_properties"] = properties
        summary["required"] = required
        summary["additional_properties"] = _additional_properties_summary(input_schema.get("additionalProperties"))
    return summary


def _additional_properties_summary(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, Mapping):
        return "schema"
    if value is None:
        return None
    return str(value)


def _risk_level(score: int, signals: Sequence[ToolRiskSignal]) -> str:
    level = "low"
    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    highest_signal = max(signals, key=lambda signal: RISK_ORDER.get(signal.severity, 0))
    if RISK_ORDER[highest_signal.severity] > RISK_ORDER[level]:
        level = highest_signal.severity
    return level


def _contains_any(value: str, terms: Sequence[str]) -> bool:
    return any(term in value for term in terms)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    return []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in _sequence(value) if item is not None and str(item)]


for _analyzer in (
    ToolNameRiskAnalyzer(),
    ToolAnnotationRiskAnalyzer(),
    ToolSchemaArgumentRiskAnalyzer(),
    ToolSchemaShapeRiskAnalyzer(),
    ToolSchemaDriftRiskAnalyzer(),
):
    register_tool_risk_analyzer(_analyzer, replace=True)

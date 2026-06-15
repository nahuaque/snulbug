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


def classify_mcp_tool(tool: str | Mapping[str, Any], *, count: int = 0) -> dict[str, Any]:
    """Classify one MCP tool using secret-safe name/schema heuristics."""

    evidence_sources: list[str] = []
    confidence: str | None = None
    schema_hash: str | None = None
    schema_hashes: list[str] = []
    catalog_hashes: list[str] = []
    catalog_paths: list[str] = []
    schema_variants: int | None = None
    if isinstance(tool, Mapping):
        name = str(tool.get("name") or tool.get("value") or "")
        description = tool.get("description") if isinstance(tool.get("description"), str) else ""
        annotations = _mapping(tool.get("annotations"))
        input_schema = _mapping(tool.get("inputSchema"))
        evidence_sources = _string_list(tool.get("evidence_sources") or tool.get("evidence"))
        confidence = tool.get("confidence") if isinstance(tool.get("confidence"), str) else None
        schema_hash = tool.get("schema_hash") if isinstance(tool.get("schema_hash"), str) else None
        if schema_hash is None and isinstance(tool.get("hash"), str) and input_schema:
            schema_hash = str(tool.get("hash"))
        schema_hashes = _string_list(tool.get("schema_hashes"))
        catalog_hashes = _string_list(tool.get("catalog_hashes"))
        catalog_paths = _string_list(tool.get("catalog_paths"))
        schema_variants = tool.get("schema_variants") if isinstance(tool.get("schema_variants"), int) else None
    else:
        name = str(tool)
        description = ""
        annotations = {}
        input_schema = {}

    signals: list[ToolRiskSignal] = []
    categories: set[str] = set()
    haystack = f"{name} {description}".lower().replace("-", "_")

    if _contains_any(haystack, SHELL_TERMS):
        signals.append(ToolRiskSignal("tool.shell_or_process", "high", "tool looks able to run commands"))
        categories.add("command")
    if _contains_any(haystack, SECRET_TERMS):
        signals.append(ToolRiskSignal("tool.secret_name", "high", "tool name suggests secret or credential access"))
        categories.add("secrets")
    if _contains_any(haystack, DESTRUCTIVE_TERMS):
        signals.append(ToolRiskSignal("tool.destructive_name", "high", "tool name suggests destructive mutation"))
        categories.add("mutation")
    elif _contains_any(haystack, WRITE_TERMS):
        signals.append(ToolRiskSignal("tool.mutating_name", "medium", "tool name suggests mutation"))
        categories.add("mutation")
    if _contains_any(haystack, NETWORK_TERMS):
        signals.append(ToolRiskSignal("tool.network_name", "medium", "tool name suggests network access"))
        categories.add("network")
    if _contains_any(haystack, FILESYSTEM_TERMS):
        signals.append(ToolRiskSignal("tool.filesystem_name", "medium", "tool name suggests filesystem access"))
        categories.add("filesystem")
    if _contains_any(haystack, LOW_RISK_READ_TERMS):
        signals.append(ToolRiskSignal("tool.read_like_name", "low", "tool name suggests read-only or inspection use"))
        categories.add("read")

    if annotations.get("destructiveHint") is True:
        signals.append(ToolRiskSignal("annotation.destructive", "high", "tool declares destructive behavior"))
        categories.add("mutation")
    if annotations.get("openWorldHint") is True:
        signals.append(ToolRiskSignal("annotation.open_world", "medium", "tool may affect external systems"))
        categories.add("network")
    if annotations.get("readOnlyHint") is True:
        signals.append(ToolRiskSignal("annotation.read_only", "low", "tool declares read-only behavior"))
        categories.add("read")

    for property_name, property_schema in _mapping(input_schema.get("properties")).items():
        for signal, category in _schema_property_signals(str(property_name), _mapping(property_schema)):
            signals.append(signal)
            categories.add(category)
    if input_schema and input_schema.get("type", "object") == "object":
        additional_properties = input_schema.get("additionalProperties")
        if additional_properties is not False:
            signals.append(
                ToolRiskSignal(
                    "schema.open_arguments",
                    "medium",
                    "tool input schema allows undeclared arguments",
                )
            )
            categories.add("open-schema")
    if schema_variants is not None and schema_variants > 1:
        signals.append(
            ToolRiskSignal(
                "schema.variant_conflict",
                "high",
                "multiple schema variants were found for this tool",
            )
        )
        categories.add("schema-drift")

    if not signals:
        signals.append(ToolRiskSignal("tool.observed", "low", "tool was observed but has no obvious high-risk signal"))
        categories.add("unknown")

    score = min(100, sum(RISK_WEIGHTS.get(signal.severity, 0) for signal in signals))
    level = _risk_level(score, signals)
    result: dict[str, Any] = {
        "name": name,
        "level": level,
        "score": score,
        "count": int(count or 0),
        "categories": sorted(categories),
        "signals": [signal.to_dict() for signal in signals],
    }
    if evidence_sources:
        result["evidence_sources"] = sorted(dict.fromkeys(evidence_sources))
    if confidence:
        result["confidence"] = confidence
    schema = _schema_summary(
        input_schema,
        schema_hash=schema_hash,
        schema_hashes=schema_hashes,
        catalog_hashes=catalog_hashes,
        catalog_paths=catalog_paths,
        schema_variants=schema_variants,
    )
    if schema:
        result["schema"] = schema
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

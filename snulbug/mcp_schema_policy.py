from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mcp_policy_bundles import write_mcp_policy_bundle
from .mcp_schemas import MCP_SCHEMA_CATALOG_SCHEMA, discover_mcp_schemas, normalize_mcp_schema_catalog

MCP_SCHEMA_POLICY_SCHEMA = "snulbug.mcp-schema-policy.v1"
MCP_SCHEMA_POLICY_VERSION = 1
DEFAULT_SCHEMA_POLICY_ALLOWED_PATHS = ("README.md", "docs/", "examples/", "src/", "snulbug/", "tests/")
DEFAULT_SCHEMA_POLICY_TOKEN = "local-dev-secret"
SCHEMA_POLICY_HIGH_RISK_ACTIONS = ("allow", "confirm", "reject")

_RISK_WEIGHTS = {"low": 10, "medium": 30, "high": 60}
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
_SHELL_TERMS = (
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
_WRITE_TERMS = (
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
_NETWORK_TERMS = ("url", "uri", "host", "http", "https", "fetch", "request", "webhook", "network", "download")
_SECRET_TERMS = ("secret", "token", "password", "credential", "apikey", "api_key", "private_key", "ssh_key")
_PATH_KEYS = (
    "path",
    "paths",
    "filepath",
    "file",
    "files",
    "filename",
    "directory",
    "dir",
    "root",
    "cwd",
    "source",
    "src",
    "destination",
    "dest",
    "target",
    "targetpath",
    "oldpath",
    "newpath",
    "from",
    "to",
)
_SIMPLE_JSON_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}


@dataclass(frozen=True)
class SchemaPolicyOptions:
    token: str | None = None
    token_env: str | None = None
    allowed_paths: list[str] = field(default_factory=lambda: list(DEFAULT_SCHEMA_POLICY_ALLOWED_PATHS))
    high_risk_action: str = "confirm"

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_paths", list(self.allowed_paths or DEFAULT_SCHEMA_POLICY_ALLOWED_PATHS))
        if self.high_risk_action not in SCHEMA_POLICY_HIGH_RISK_ACTIONS:
            raise ValueError("high_risk_action must be one of " + ", ".join(SCHEMA_POLICY_HIGH_RISK_ACTIONS))
        if self.token_env is not None:
            _lua_identifier(self.token_env)


def generate_mcp_schema_policy(
    catalog: str | Path | Mapping[str, Any],
    output: str | Path,
    *,
    options: SchemaPolicyOptions | None = None,
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Generate a reviewable policy bundle from an MCP schema catalog."""

    policy_options = options or SchemaPolicyOptions()
    normalized_catalog = _load_catalog(catalog)
    model = _SchemaPolicyModel.from_catalog(normalized_catalog, options=policy_options)
    output_path = Path(output)
    fixtures, fixture_files = _fixture_documents(model, policy_options)
    manifest = model.manifest(catalog, fixtures)
    report = model.report()
    bundle = write_mcp_policy_bundle(
        output_path,
        policy=model.to_lua(),
        manifest=manifest,
        report=format_mcp_schema_policy_report(report),
        report_name="SCHEMA_POLICY.md",
        force=force,
        exists_label="schema policy output",
        clean=True,
        extra_files=fixture_files,
        validate=validate,
        run_tests=validate,
    )

    return {
        "ok": bundle.ok,
        "schema": MCP_SCHEMA_POLICY_SCHEMA,
        "version": MCP_SCHEMA_POLICY_VERSION,
        "catalog_hash": normalized_catalog.get("hash"),
        "catalog": report["catalog"],
        "output": str(output_path),
        "policy": str(bundle.policy),
        "manifest": str(bundle.manifest),
        "report": str(bundle.report),
        "tool_count": len(model.tools),
        "resource_count": len(model.resources),
        "prompt_count": len(model.prompts),
        "risk_summary": model.risk_summary(),
        "high_risk_action": policy_options.high_risk_action,
        "lease_suggestions": model.lease_suggestions(),
        "tools": report["tools"],
        "validation": bundle.validation,
        "tests": bundle.tests,
        "next_steps": bundle.next_steps,
    }


def score_mcp_schema_catalog(catalog: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    normalized_catalog = _load_catalog(catalog)
    model = _SchemaPolicyModel.from_catalog(normalized_catalog, options=SchemaPolicyOptions())
    return {
        "schema": MCP_SCHEMA_POLICY_SCHEMA,
        "version": MCP_SCHEMA_POLICY_VERSION,
        "catalog_hash": normalized_catalog.get("hash"),
        "risk_summary": model.risk_summary(),
        "tools": [tool.risk for tool in model.tools],
        "resources": [resource.risk for resource in model.resources],
        "prompts": [prompt.risk for prompt in model.prompts],
    }


def format_mcp_schema_policy_report(report: Mapping[str, Any]) -> str:
    summary = _mapping(report.get("risk_summary"))
    lines = [
        "# Schema-Derived MCP Policy",
        "",
        f"- Catalog: `{report.get('catalog') or '-'}`",
        f"- Catalog hash: `{str(report.get('catalog_hash') or '')[:12]}`",
        f"- Tools: {report.get('tool_count', 0)}",
        f"- Resources: {report.get('resource_count', 0)}",
        f"- Prompts: {report.get('prompt_count', 0)}",
        (
            f"- Risk summary: {summary.get('low', 0)} low, "
            f"{summary.get('medium', 0)} medium, {summary.get('high', 0)} high"
        ),
        "",
        "## Tool Policy",
        "",
        "| Tool | Risk | Action | Required Args | Path Guard | Signals |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    tools = report.get("tools")
    if not isinstance(tools, Sequence) or isinstance(tools, str | bytes | bytearray) or not tools:
        lines.append("| - | - | - | - | - | - |")
    else:
        for tool in tools:
            if not isinstance(tool, Mapping):
                continue
            required = ", ".join(f"`{item}`" for item in tool.get("required", [])) or "-"
            path_keys = ", ".join(f"`{item}`" for item in tool.get("path_keys", [])) or "-"
            signals = ", ".join(f"`{signal.get('code')}`" for signal in tool.get("signals", [])) or "-"
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{_md_cell(tool.get('name'))}`",
                        _md_cell(tool.get("risk_level")),
                        _md_cell(tool.get("action")),
                        required,
                        path_keys,
                        signals,
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "## Suggested Lease Scope",
            "",
            _markdown_list("Allowed tools", report.get("lease_suggestions", {}).get("allow_tools", [])),
            "",
            _markdown_list("Confirm tools", report.get("lease_suggestions", {}).get("confirm_tools", [])),
            "",
            _markdown_list("Blocked tools", report.get("lease_suggestions", {}).get("blocked_tools", [])),
            "",
            _markdown_list("Resources", report.get("lease_suggestions", {}).get("allow_resources", [])),
            "",
            _markdown_list("Prompts", report.get("lease_suggestions", {}).get("allow_prompts", [])),
            "",
            "## Notes",
            "",
            "- Unknown MCP methods and tools are denied by default.",
            (
                "- Tool arguments are checked against discovered `inputSchema` keys, required fields, "
                "simple scalar types, and enums."
            ),
            "- Path-like arguments are constrained to the configured project path allowlist.",
            "- High-risk tools default to `confirm`; review the generated Lua before public tunnel use.",
        ]
    )
    return "\n".join(lines) + "\n"


@dataclass
class _RiskSignal:
    code: str
    severity: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "reason": self.reason}


@dataclass
class _ToolPolicy:
    name: str
    description: str | None
    input_schema: Mapping[str, Any]
    annotations: Mapping[str, Any]
    risk: dict[str, Any]
    required: set[str]
    allowed: set[str]
    closed: bool
    types: dict[str, str]
    enums: dict[str, list[Any]]
    path_keys: set[str]
    action: str


@dataclass
class _SurfacePolicy:
    identifier: str
    description: str | None
    risk: dict[str, Any]


@dataclass
class _SchemaPolicyModel:
    catalog: Mapping[str, Any]
    tools: list[_ToolPolicy]
    resources: list[_SurfacePolicy]
    prompts: list[_SurfacePolicy]
    allowed_methods: set[str]
    allowed_paths: list[str]
    token: str | None
    token_env: str | None
    high_risk_action: str

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, Any], *, options: SchemaPolicyOptions) -> _SchemaPolicyModel:
        surfaces = _mapping(catalog.get("surfaces"))
        tools = []
        for item in _mapping_sequence(surfaces.get("tools")):
            risk = _score_tool(item)
            action = options.high_risk_action if risk["level"] == "high" else "allow"
            input_schema = _mapping(item.get("inputSchema"))
            tools.append(
                _ToolPolicy(
                    name=str(item["name"]),
                    description=item.get("description") if isinstance(item.get("description"), str) else None,
                    input_schema=input_schema,
                    annotations=_mapping(item.get("annotations")),
                    risk=risk,
                    required=set(_string_sequence(input_schema.get("required"))),
                    allowed=set(_schema_properties(input_schema)),
                    closed=input_schema.get("additionalProperties") is False,
                    types=_schema_property_types(input_schema),
                    enums=_schema_property_enums(input_schema),
                    path_keys=_schema_path_keys(input_schema),
                    action=action,
                )
            )
        resources = [
            _SurfacePolicy(
                identifier=str(item["uri"]),
                description=item.get("description") if isinstance(item.get("description"), str) else None,
                risk=_score_resource(item),
            )
            for item in _mapping_sequence(surfaces.get("resources"))
        ]
        prompts = [
            _SurfacePolicy(
                identifier=str(item["name"]),
                description=item.get("description") if isinstance(item.get("description"), str) else None,
                risk=_score_prompt(item),
            )
            for item in _mapping_sequence(surfaces.get("prompts"))
        ]
        methods = {"initialize", "notifications/initialized", "tools/list", "resources/list", "prompts/list"}
        if tools:
            methods.add("tools/call")
        if resources:
            methods.add("resources/read")
        if _mapping_sequence(surfaces.get("resource_templates")):
            methods.add("resources/templates/list")
        if prompts:
            methods.add("prompts/get")
        return cls(
            catalog=catalog,
            tools=sorted(tools, key=lambda tool: tool.name),
            resources=sorted(resources, key=lambda resource: resource.identifier),
            prompts=sorted(prompts, key=lambda prompt: prompt.identifier),
            allowed_methods=methods,
            allowed_paths=options.allowed_paths,
            token=options.token,
            token_env=options.token_env,
            high_risk_action=options.high_risk_action,
        )

    def to_lua(self) -> str:
        return f"""-- Generated by snulbug mcp policy schemas generate. Review before exposing through a public tunnel.
local allowed_methods = {_lua_set(self.allowed_methods)}
local tool_policies = {_lua_tool_policies(self.tools)}
local allowed_resources = {_lua_set({resource.identifier for resource in self.resources})}
local allowed_prompts = {_lua_set({prompt.identifier for prompt in self.prompts})}
local allowed_paths = {_lua_array(self.allowed_paths)}

local function reject(status, body, reason_code, reason)
  return {{
    action = "reject",
    status = status,
    body = body,
    reason = reason or body,
    reason_code = reason_code
  }}
end

local function is_empty(table_value)
  if type(table_value) ~= "table" then
    return true
  end
  return next(table_value) == nil
end

local function is_array(value)
  if type(value) ~= "table" then
    return false
  end
  local count = 0
  local max_index = 0
  for key, _ in pairs(value) do
    if type(key) ~= "number" then
      return false
    end
    count = count + 1
    if key > max_index then
      max_index = key
    end
  end
  return count == max_index
end

local function value_matches_type(value, expected)
  if expected == "string" then
    return type(value) == "string"
  end
  if expected == "number" then
    return type(value) == "number"
  end
  if expected == "integer" then
    return type(value) == "number" and math.floor(value) == value
  end
  if expected == "boolean" then
    return type(value) == "boolean"
  end
  if expected == "object" then
    return type(value) == "table" and not is_array(value)
  end
  if expected == "array" then
    return is_array(value)
  end
  if expected == "null" then
    return value == nil
  end
  return true
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function path_is_allowed(path)
  if type(path) ~= "string" or path == "" then
    return false
  end
  if string.sub(path, 1, 1) == "/" or string.sub(path, 1, 1) == "~" then
    return false
  end
  if string.match(path, "^%a:") ~= nil then
    return false
  end
  if path == ".." or starts_with(path, "../") then
    return false
  end
  if string.find(path, "/../", 1, true) ~= nil or string.sub(path, -3) == "/.." then
    return false
  end
  for _, allowed in ipairs(allowed_paths) do
    if path == allowed or starts_with(path, allowed) then
      return true
    end
  end
  return false
end

local function check_path_value(value)
  if type(value) == "string" then
    if not path_is_allowed(value) then
      return value
    end
  elseif type(value) == "table" then
    for _, item in ipairs(value) do
      if type(item) == "string" and not path_is_allowed(item) then
        return item
      end
    end
  end
  return nil
end

local function target_allowed(method, target)
  if method == "resources/read" then
    return allowed_resources[target] == true
  end
  if method == "prompts/get" then
    return allowed_prompts[target] == true
  end
  return true
end

local function validate_tool_arguments(tool, arguments, policy)
  if type(arguments) ~= "table" then
    if not is_empty(policy.required) then
      return reject(400, "MCP tool arguments are required: " .. tool, "mcp.schema.arguments_required")
    end
    arguments = {{}}
  end

  for key, _ in pairs(policy.required) do
    if arguments[key] == nil then
      return reject(400, "MCP required argument is missing: " .. key, "mcp.schema.required_argument_missing")
    end
  end

  if policy.closed then
    for key, _ in pairs(arguments) do
      if policy.allowed[key] ~= true then
        return reject(
          403,
          "MCP argument is not declared by schema: " .. tostring(key),
          "mcp.schema.argument_not_allowed"
        )
      end
    end
  end

  for key, expected in pairs(policy.types) do
    if arguments[key] ~= nil and not value_matches_type(arguments[key], expected) then
      return reject(400, "MCP argument type mismatch: " .. key, "mcp.schema.argument_type_mismatch")
    end
  end

  for key, values in pairs(policy.enums) do
    if arguments[key] ~= nil and values[arguments[key]] ~= true then
      return reject(400, "MCP argument value is outside schema enum: " .. key, "mcp.schema.argument_enum_mismatch")
    end
  end

  for key, _ in pairs(policy.path_keys) do
    local blocked_path = check_path_value(arguments[key])
    if blocked_path ~= nil then
      return reject(
        403,
        "MCP path argument is outside the project allowlist: " .. blocked_path,
        "mcp.schema.path_not_allowed"
      )
    end
  end

  return nil
end

return function(request, context, state)
  if request.path ~= "/mcp" then
    return reject(404, "unknown MCP endpoint", "mcp.schema.endpoint_not_found")
  end

{_token_check(self)}
  local body = mcp.body(request)
  if body == nil then
    return reject(400, "MCP request body is not valid JSON-RPC", "mcp.schema.invalid_json")
  end
  if body[1] ~= nil then
    return reject(
      400,
      "MCP batch requests are not enabled by the schema-derived policy",
      "mcp.schema.batch_not_allowed"
    )
  end

  local method = mcp.method(request)
  if method == nil or allowed_methods[method] ~= true then
    return reject(403, "MCP method is not declared by schema policy", "mcp.schema.method_not_allowed")
  end

  if method == "tools/call" then
    local tool = mcp.tool_name(request)
    local policy = tool_policies[tool or ""]
    if tool == nil or policy == nil then
      return reject(403, "MCP tool is not declared by schema policy", "mcp.schema.tool_not_allowed")
    end
    local params = mcp.params(request)
    local argument_block = validate_tool_arguments(tool, params.arguments, policy)
    if argument_block ~= nil then
      return argument_block
    end
    if policy.action == "reject" then
      return reject(403, "MCP high-risk tool requires policy review: " .. tool, "mcp.schema.high_risk_rejected")
    end
    if policy.action == "confirm" then
      return {{
        action = "confirm",
        prompt = "Allow high-risk MCP tool " .. tool .. "?",
        reason = "MCP tool was classified high risk from discovered schema",
        reason_code = "mcp.schema.high_risk_confirm",
        context = {{
          policy = "mcp-schema-derived",
          method = method,
          tool = tool,
          risk = policy.risk
        }}
      }}
    end
  end

  local params = mcp.params(request)
  local target = params.name or params.uri
  if target ~= nil and not target_allowed(method, target) then
    return reject(403, "MCP target is not declared by schema policy", "mcp.schema.target_not_allowed")
  end

  return {{
    action = "continue",
    reason = "MCP request matched schema-derived policy",
    reason_code = "mcp.schema.allowed",
    context = {{
      policy = "mcp-schema-derived",
      method = method or "",
      tool = mcp.tool_name(request) or ""
    }}
  }}
end
"""

    def manifest(self, source: Any, fixtures: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        return {
            "name": "schema-derived-mcp-policy",
            "version": "0.1.0",
            "entrypoint": "policy.lua",
            "description": "Generated from MCP schema discovery",
            "required_capabilities": ["mcp"],
            "fixtures": list(fixtures),
            "generated_by": "snulbug mcp policy schemas generate",
            "generated_from": str(source) if isinstance(source, str | Path) else "in-memory catalog",
            "schema_policy": {
                "schema": MCP_SCHEMA_POLICY_SCHEMA,
                "version": MCP_SCHEMA_POLICY_VERSION,
                "catalog_hash": self.catalog.get("hash"),
                "catalog_label": self.catalog.get("label"),
                "high_risk_action": self.high_risk_action,
                "allowed_paths": self.allowed_paths,
                "risk_summary": self.risk_summary(),
                "lease_suggestions": self.lease_suggestions(),
                "tools": [self._tool_report(tool) for tool in self.tools],
            },
        }

    def report(self) -> dict[str, Any]:
        return {
            "catalog": _catalog_source_label(self.catalog),
            "catalog_hash": self.catalog.get("hash"),
            "tool_count": len(self.tools),
            "resource_count": len(self.resources),
            "prompt_count": len(self.prompts),
            "risk_summary": self.risk_summary(),
            "lease_suggestions": self.lease_suggestions(),
            "tools": [self._tool_report(tool) for tool in self.tools],
        }

    def risk_summary(self) -> dict[str, int]:
        counter: Counter[str] = Counter(tool.risk["level"] for tool in self.tools)
        return {level: counter.get(level, 0) for level in ("low", "medium", "high")}

    def lease_suggestions(self) -> dict[str, list[str]]:
        return {
            "allow_tools": [tool.name for tool in self.tools if tool.action == "allow"],
            "confirm_tools": [tool.name for tool in self.tools if tool.action == "confirm"],
            "blocked_tools": [tool.name for tool in self.tools if tool.action == "reject"],
            "allow_resources": [resource.identifier for resource in self.resources],
            "allow_prompts": [prompt.identifier for prompt in self.prompts],
        }

    def _tool_report(self, tool: _ToolPolicy) -> dict[str, Any]:
        return {
            "name": tool.name,
            "description": tool.description,
            "risk_level": tool.risk["level"],
            "risk_score": tool.risk["score"],
            "signals": tool.risk["signals"],
            "action": tool.action,
            "required": sorted(tool.required),
            "allowed": sorted(tool.allowed),
            "closed": tool.closed,
            "path_keys": sorted(tool.path_keys),
            "types": dict(sorted(tool.types.items())),
        }


def _load_catalog(catalog: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(catalog, str | Path):
        return discover_mcp_schemas(source=Path(catalog))
    if catalog.get("schema") != MCP_SCHEMA_CATALOG_SCHEMA:
        raise ValueError("schema policy generation requires an MCP schema catalog")
    return normalize_mcp_schema_catalog(catalog)


def _score_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
    signals: list[_RiskSignal] = []
    name = str(tool.get("name", ""))
    description = tool.get("description") if isinstance(tool.get("description"), str) else ""
    haystack = f"{name} {description}".lower().replace("-", "_")
    _add_term_signal(
        signals,
        haystack,
        _SHELL_TERMS,
        "tool.shell_or_process",
        "high",
        "tool looks able to run commands",
    )
    _add_term_signal(signals, haystack, _WRITE_TERMS, "tool.mutating_name", "medium", "tool name suggests mutation")
    _add_term_signal(
        signals,
        haystack,
        _NETWORK_TERMS,
        "tool.network_name",
        "medium",
        "tool name suggests network access",
    )
    _add_term_signal(signals, haystack, _SECRET_TERMS, "tool.secret_name", "high", "tool name suggests secret access")

    annotations = _mapping(tool.get("annotations"))
    if annotations.get("destructiveHint") is True:
        signals.append(_RiskSignal("annotation.destructive", "high", "tool declares destructive behavior"))
    if annotations.get("openWorldHint") is True:
        signals.append(_RiskSignal("annotation.open_world", "medium", "tool may affect external systems"))
    if annotations.get("readOnlyHint") is True:
        signals.append(_RiskSignal("annotation.read_only", "low", "tool declares read-only behavior"))

    input_schema = _mapping(tool.get("inputSchema"))
    for property_name, property_schema in _mapping(input_schema.get("properties")).items():
        property_risk = _score_schema_property(str(property_name), _mapping(property_schema))
        signals.extend(property_risk)
    return _risk_result("tools", name, signals)


def _score_resource(resource: Mapping[str, Any]) -> dict[str, Any]:
    signals: list[_RiskSignal] = []
    uri = str(resource.get("uri", ""))
    lowered = uri.lower()
    if lowered.startswith("file:"):
        signals.append(_RiskSignal("resource.filesystem", "medium", "resource exposes a filesystem URI"))
    if any(term in lowered for term in ("/.ssh", ".env", "secret", "token", "credential")):
        signals.append(_RiskSignal("resource.secret_path", "high", "resource URI looks secret-bearing"))
    return _risk_result("resources", uri, signals)


def _score_prompt(prompt: Mapping[str, Any]) -> dict[str, Any]:
    signals: list[_RiskSignal] = []
    name = str(prompt.get("name", ""))
    description = prompt.get("description") if isinstance(prompt.get("description"), str) else ""
    haystack = f"{name} {description}".lower()
    if "system" in haystack or "instruction" in haystack:
        signals.append(_RiskSignal("prompt.instructional", "medium", "prompt may alter agent instructions"))
    if any(term in haystack for term in _SECRET_TERMS):
        signals.append(_RiskSignal("prompt.secret_related", "high", "prompt mentions secrets or credentials"))
    return _risk_result("prompts", name, signals)


def _score_schema_property(name: str, schema: Mapping[str, Any]) -> list[_RiskSignal]:
    signals: list[_RiskSignal] = []
    haystack = f"{name} {schema.get('description') or ''}".lower().replace("-", "_")
    if _is_path_key(name):
        signals.append(_RiskSignal("argument.path", "medium", f"argument `{name}` looks path-like"))
    if any(term in haystack for term in _NETWORK_TERMS):
        signals.append(_RiskSignal("argument.network", "medium", f"argument `{name}` looks network-capable"))
    if any(term in haystack for term in _SHELL_TERMS):
        signals.append(_RiskSignal("argument.command", "high", f"argument `{name}` looks command-capable"))
    if any(term in haystack for term in _SECRET_TERMS):
        signals.append(_RiskSignal("argument.secret", "high", f"argument `{name}` looks secret-bearing"))
    if schema.get("format") in {"uri", "url", "hostname", "ipv4", "ipv6"}:
        signals.append(_RiskSignal("argument.network_format", "medium", f"argument `{name}` has network format"))
    return signals


def _risk_result(surface: str, identifier: str, signals: Sequence[_RiskSignal]) -> dict[str, Any]:
    if not signals:
        signals = [_RiskSignal("schema.declared", "low", "declared by MCP schema discovery")]
    score = min(100, sum(_RISK_WEIGHTS.get(signal.severity, 0) for signal in signals))
    level = "low"
    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    highest_signal = max(signals, key=lambda signal: _RISK_ORDER.get(signal.severity, 0))
    if _RISK_ORDER[highest_signal.severity] > _RISK_ORDER[level]:
        level = highest_signal.severity
    return {
        "surface": surface,
        "id": identifier,
        "level": level,
        "score": score,
        "signals": [signal.to_dict() for signal in signals],
    }


def _add_term_signal(
    signals: list[_RiskSignal],
    haystack: str,
    terms: Sequence[str],
    code: str,
    severity: str,
    reason: str,
) -> None:
    if any(term in haystack for term in terms):
        signals.append(_RiskSignal(code, severity, reason))


def _schema_properties(schema: Mapping[str, Any]) -> list[str]:
    return sorted(str(key) for key in _mapping(schema.get("properties")))


def _schema_property_types(schema: Mapping[str, Any]) -> dict[str, str]:
    types = {}
    for name, property_schema in _mapping(schema.get("properties")).items():
        item_type = _first_schema_type(_mapping(property_schema).get("type"))
        if item_type in _SIMPLE_JSON_TYPES:
            types[str(name)] = str(item_type)
    return types


def _schema_property_enums(schema: Mapping[str, Any]) -> dict[str, list[Any]]:
    enums = {}
    for name, property_schema in _mapping(schema.get("properties")).items():
        enum_values = _mapping(property_schema).get("enum")
        if isinstance(enum_values, Sequence) and not isinstance(enum_values, str | bytes | bytearray):
            enums[str(name)] = [value for value in enum_values if isinstance(value, str | int | float | bool)]
    return enums


def _schema_path_keys(schema: Mapping[str, Any]) -> set[str]:
    keys = set()
    for name, property_schema in _mapping(schema.get("properties")).items():
        lowered = str(name).lower().replace("-", "_")
        property_format = _mapping(property_schema).get("format")
        if _is_path_key(lowered) or property_format in {"path", "file-path"}:
            keys.add(str(name))
    return keys


def _first_schema_type(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            if isinstance(item, str) and item != "null":
                return item
    return None


def _is_path_key(value: str) -> bool:
    lowered = value.lower().replace("-", "_")
    return lowered in _PATH_KEYS or lowered.endswith("_path") or lowered.endswith("_paths")


def _fixture_documents(
    model: _SchemaPolicyModel,
    options: SchemaPolicyOptions,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    fixture_files: dict[str, str] = {}
    fixtures = [
        _fixture_document(
            fixture_files,
            "list-tools.json",
            "listed methods are allowed",
            _mcp_request("tools/list", {}, options),
            {"action": "continue", "decision.reason_code": "mcp.schema.allowed"},
        )
    ]
    if model.tools:
        first_tool = model.tools[0]
        expected_action = "confirm" if first_tool.action == "confirm" else "continue"
        expected_reason = "mcp.schema.high_risk_confirm" if first_tool.action == "confirm" else "mcp.schema.allowed"
        if first_tool.action == "reject":
            expected_action = "reject"
            expected_reason = "mcp.schema.high_risk_rejected"
        fixtures.append(
            _fixture_document(
                fixture_files,
                "allowed-tool.json",
                "declared tool follows generated schema policy",
                _mcp_request(
                    "tools/call",
                    {"name": first_tool.name, "arguments": _sample_arguments(first_tool)},
                    options,
                ),
                {"action": expected_action, "decision.reason_code": expected_reason},
            )
        )
        fixtures.append(
            _fixture_document(
                fixture_files,
                "unknown-tool.json",
                "unknown tools are denied",
                _mcp_request("tools/call", {"name": "__snulbug_unknown_tool__", "arguments": {}}, options),
                {"action": "reject", "status": 403, "decision.reason_code": "mcp.schema.tool_not_allowed"},
            )
        )
    return fixtures, fixture_files


def _fixture_document(
    fixture_files: dict[str, str],
    filename: str,
    name: str,
    request: Mapping[str, Any],
    expect: Mapping[str, Any],
) -> dict[str, Any]:
    fixture_files[f"fixtures/{filename}"] = json.dumps(request, indent=2, sort_keys=True) + "\n"
    return {"name": name, "request": f"fixtures/{filename}", "expect": dict(expect)}


def _mcp_request(method: str, params: Mapping[str, Any], options: SchemaPolicyOptions) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if _auth_enabled(options):
        headers["authorization"] = f"Bearer {_fixture_token(options)}"
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": headers,
        "body": json.dumps({"jsonrpc": "2.0", "id": f"fixture-{method}", "method": method, "params": dict(params)}),
    }


def _sample_arguments(tool: _ToolPolicy) -> dict[str, Any]:
    arguments = {}
    for key in sorted(tool.required):
        arguments[key] = _sample_value(key, tool.types.get(key), tool.enums.get(key))
    return arguments


def _sample_value(key: str, expected_type: str | None, enum_values: Sequence[Any] | None) -> Any:
    if enum_values:
        return enum_values[0]
    if _is_path_key(key):
        return "README.md"
    if expected_type == "integer":
        return 1
    if expected_type == "number":
        return 1
    if expected_type == "boolean":
        return False
    if expected_type == "array":
        return []
    if expected_type == "object":
        return {}
    return "example"


def _lua_tool_policies(tools: Sequence[_ToolPolicy]) -> str:
    if not tools:
        return "{}"
    lines = ["{"]
    for tool in tools:
        lines.extend(
            [
                f"  [{json.dumps(tool.name)}] = {{",
                f"    required = {_lua_set(tool.required)},",
                f"    allowed = {_lua_set(tool.allowed)},",
                f"    closed = {_lua_bool(tool.closed)},",
                f"    types = {_lua_string_map(tool.types)},",
                f"    enums = {_lua_enum_map(tool.enums)},",
                f"    path_keys = {_lua_set(tool.path_keys)},",
                f"    risk = {json.dumps(tool.risk['level'])},",
                f"    action = {json.dumps(tool.action)},",
                "  },",
            ]
        )
    lines.append("}")
    return "\n".join(lines)


def _token_check(model: _SchemaPolicyModel) -> str:
    if model.token is None and model.token_env is None:
        return ""
    escaped_token = json.dumps(model.token or DEFAULT_SCHEMA_POLICY_TOKEN)
    if model.token_env:
        token_key = _lua_identifier(model.token_env)
        assignment = f"  local token = context.{token_key} or {escaped_token}"
    else:
        assignment = f"  local token = {escaped_token}"
    return f"""{assignment}
  if request.headers.authorization ~= "Bearer " .. token then
    return {{
      action = "challenge",
      scheme = "Bearer",
      realm = "local-mcp",
      error = "invalid_token",
      body = "MCP bearer token required",
      reason = "Missing or invalid MCP bearer token",
      reason_code = "mcp.schema.auth_required"
    }}
  end
"""


def _lua_set(values: set[str]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for value in sorted(values):
        lines.append(f"  [{json.dumps(value)}] = true,")
    lines.append("}")
    return "\n".join(lines)


def _lua_array(values: Sequence[str]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for value in values:
        lines.append(f"  {json.dumps(value)},")
    lines.append("}")
    return "\n".join(lines)


def _lua_string_map(values: Mapping[str, str]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for key, value in sorted(values.items()):
        lines.append(f"  [{json.dumps(key)}] = {json.dumps(value)},")
    lines.append("}")
    return "\n".join(lines)


def _lua_enum_map(values: Mapping[str, Sequence[Any]]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for key, enum_values in sorted(values.items()):
        lines.append(f"  [{json.dumps(key)}] = {_lua_value_set(enum_values)},")
    lines.append("}")
    return "\n".join(lines)


def _lua_value_set(values: Sequence[Any]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for value in values:
        lines.append(f"  [{json.dumps(value)}] = true,")
    lines.append("}")
    return "\n".join(lines)


def _lua_bool(value: bool) -> str:
    return "true" if value else "false"


def _auth_enabled(options: SchemaPolicyOptions) -> bool:
    return options.token is not None or options.token_env is not None


def _fixture_token(options: SchemaPolicyOptions) -> str:
    return options.token or DEFAULT_SCHEMA_POLICY_TOKEN


def _catalog_source_label(catalog: Mapping[str, Any]) -> str:
    source = _mapping(catalog.get("source"))
    return str(source.get("path") or source.get("url") or catalog.get("label") or "-")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [str(item) for item in value]


def _markdown_list(label: str, values: Any) -> str:
    if not isinstance(values, Sequence) or isinstance(values, str | bytes | bytearray) or not values:
        return f"### {label}\n\n- None"
    return f"### {label}\n\n" + "\n".join(f"- `{value}`" for value in values)


def _md_cell(value: Any) -> str:
    return str(value or "-").replace("|", "\\|")


def _lua_identifier(value: str) -> str:
    normalized = value.lower().replace("-", "_")
    if not normalized or not normalized.replace("_", "").isalnum() or normalized[0].isdigit():
        raise ValueError("token_env must contain only letters, numbers, underscores, or dashes")
    return normalized

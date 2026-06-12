from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .bundle import validate_bundle
from .inspection import _load_events


def learn_mcp_policy(
    log: str | Path,
    output: str | Path,
    *,
    kind: str = "auto",
    force: bool = False,
    validate: bool = True,
) -> dict[str, Any]:
    """Compile observed MCP traffic into a least-privilege policy bundle."""

    events = _load_events(log, kind=kind)
    model = _LearnedPolicy.from_events(events)
    output_path = Path(output)
    if output_path.exists() and not force:
        raise FileExistsError(f"learn output already exists: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)

    policy_path = output_path / "policy.lua"
    manifest_path = output_path / "manifest.json"
    report_path = output_path / "LEARNED.md"
    policy_path.write_text(model.to_lua(), encoding="utf-8")
    manifest_path.write_text(
        json.dumps(model.manifest(log), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(model.report(log), encoding="utf-8")

    validation = validate_bundle(output_path) if validate else None
    return {
        "ok": bool(validation["ok"]) if validation is not None else True,
        "log": str(log),
        "output": str(output_path),
        "policy": str(policy_path),
        "manifest": str(manifest_path),
        "report": str(report_path),
        "event_count": model.event_count,
        "allowed_event_count": model.allowed_event_count,
        "blocked_event_count": model.blocked_event_count,
        "methods": sorted(model.methods),
        "tools": sorted(model.tools),
        "resources": sorted(model.resources),
        "prompts": sorted(model.prompts),
        "validation": validation,
        "next_steps": [
            f"uv run snulbug bundle validate {output_path}",
            f"uv run snulbug bundle test {output_path}",
            f"uv run snulbug mcp proxy --policy {policy_path} --upstream http://127.0.0.1:9000",
        ],
    }


class _LearnedPolicy:
    def __init__(self) -> None:
        self.event_count = 0
        self.allowed_event_count = 0
        self.blocked_event_count = 0
        self.paths: set[str] = set()
        self.methods: set[str] = set()
        self.tools: set[str] = set()
        self.resources: set[str] = set()
        self.prompts: set[str] = set()
        self.tool_argument_keys: dict[str, set[str]] = defaultdict(set)
        self.clients: Counter[str] = Counter()
        self.facade_upstreams: Counter[str] = Counter()
        self.blocked_reason_codes: Counter[str] = Counter()
        self.invalid_json_count = 0
        self.batch_count = 0

    @classmethod
    def from_events(cls, events: Sequence[Mapping[str, Any]]) -> _LearnedPolicy:
        model = cls()
        for event in events:
            model.add(event)
        if not model.paths:
            model.paths.add("/mcp")
        return model

    def add(self, event: Mapping[str, Any]) -> None:
        self.event_count += 1
        decision = _mapping(event.get("decision"))
        mcp = _mapping(event.get("mcp"))
        request = _mapping(event.get("request"))
        metadata = _mapping(event.get("metadata"))

        if mcp.get("valid_json") is False:
            self.invalid_json_count += 1
        if mcp.get("batch") is True:
            self.batch_count += 1
        if metadata.get("upstream"):
            self.facade_upstreams[str(metadata["upstream"])] += 1
        if isinstance(mcp.get("client"), Mapping):
            client = _mapping(mcp["client"])
            client_name = client.get("name")
            if client_name:
                self.clients[str(client_name)] += 1

        if decision.get("allowed") is False:
            self.blocked_event_count += 1
            if decision.get("reason_code"):
                self.blocked_reason_codes[str(decision["reason_code"])] += 1
            return

        self.allowed_event_count += 1
        path = request.get("path")
        if isinstance(path, str) and path:
            self.paths.add(path)
        method = mcp.get("method")
        if isinstance(method, str) and method:
            self.methods.add(method)
        if method == "tools/call":
            tool = mcp.get("tool")
            if isinstance(tool, str) and tool:
                self.tools.add(tool)
                for key in _string_sequence(mcp.get("argument_keys")):
                    self.tool_argument_keys[tool].add(key)
        elif method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}:
            target = mcp.get("target")
            if isinstance(target, str) and target:
                self.resources.add(target)
        elif method == "prompts/get":
            target = mcp.get("target")
            if isinstance(target, str) and target:
                self.prompts.add(target)

    def manifest(self, log: str | Path) -> dict[str, Any]:
        return {
            "name": "learned-mcp-policy",
            "version": "0.1.0",
            "entrypoint": "policy.lua",
            "required_capabilities": ["mcp"],
            "fixtures": [],
            "generated_by": "snulbug mcp learn",
            "generated_from": str(log),
            "learned": {
                "event_count": self.event_count,
                "allowed_event_count": self.allowed_event_count,
                "blocked_event_count": self.blocked_event_count,
                "paths": sorted(self.paths),
                "methods": sorted(self.methods),
                "tools": sorted(self.tools),
                "resources": sorted(self.resources),
                "prompts": sorted(self.prompts),
            },
        }

    def report(self, log: str | Path) -> str:
        lines = [
            "# Learned MCP Policy",
            "",
            f"- Source log: `{log}`",
            f"- Events inspected: {self.event_count}",
            f"- Allowed events learned: {self.allowed_event_count}",
            f"- Blocked events excluded: {self.blocked_event_count}",
            f"- Invalid JSON events observed: {self.invalid_json_count}",
            f"- Batch events observed: {self.batch_count}",
            "",
            "## Learned Surface",
            "",
            _markdown_list("HTTP paths", sorted(self.paths)),
            "",
            _markdown_list("MCP methods", sorted(self.methods)),
            "",
            _markdown_list("Tools", sorted(self.tools)),
            "",
            _markdown_list("Resources", sorted(self.resources)),
            "",
            _markdown_list("Prompts", sorted(self.prompts)),
            "",
            "## Tool Argument Keys",
            "",
            _argument_key_table(self.tool_argument_keys),
            "",
            "## Observed Context",
            "",
            _counter_table("Clients", self.clients),
            "",
            _counter_table("Facade upstreams", self.facade_upstreams),
            "",
            _counter_table("Excluded blocked reason codes", self.blocked_reason_codes),
            "",
        ]
        return "\n".join(lines)

    def to_lua(self) -> str:
        return f"""-- Generated by snulbug mcp learn. Review before exposing through a public tunnel.
local allowed_paths = {_lua_set(self.paths)}
local allowed_methods = {_lua_set(self.methods)}
local allowed_tools = {_lua_set(self.tools)}
local allowed_resources = {_lua_set(self.resources)}
local allowed_prompts = {_lua_set(self.prompts)}
local allowed_tool_argument_keys = {_lua_nested_set(self.tool_argument_keys)}

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

local function target_allowed(method, target)
  if method == "resources/read" or method == "resources/subscribe" or method == "resources/unsubscribe" then
    return allowed_resources[target] == true
  end
  if method == "prompts/get" then
    return allowed_prompts[target] == true
  end
  return true
end

return function(request, context, state)
  if allowed_paths[request.path] ~= true then
    return reject(404, "MCP path was not observed during learn mode", "mcp.learn.path_not_observed")
  end

  local body = mcp.body(request)
  if body == nil then
    return reject(400, "MCP request body is not valid JSON-RPC", "mcp.learn.invalid_json")
  end
  if body[1] ~= nil then
    return reject(400, "MCP batch requests were not included in the learned policy", "mcp.learn.batch_not_observed")
  end

  local method = mcp.method(request)
  if method == nil or allowed_methods[method] ~= true then
    return reject(403, "MCP method was not observed during learn mode", "mcp.learn.method_not_observed")
  end

  if method == "tools/call" then
    local tool = mcp.tool_name(request)
    if tool == nil or allowed_tools[tool] ~= true then
      return reject(403, "MCP tool was not observed during learn mode", "mcp.learn.tool_not_observed")
    end
    local params = mcp.params(request)
    local arguments = params.arguments
    local allowed_arguments = allowed_tool_argument_keys[tool] or {{}}
    if type(arguments) == "table" then
      for key, _ in pairs(arguments) do
        if allowed_arguments[key] ~= true then
          return reject(
            403,
            "MCP tool argument key was not observed during learn mode",
            "mcp.learn.argument_not_observed"
          )
        end
      end
    elseif not is_empty(allowed_arguments) then
      return reject(403, "MCP tool arguments were expected from learn mode", "mcp.learn.arguments_missing")
    end
  end

  local params = mcp.params(request)
  local target = params.name or params.uri
  if target ~= nil and not target_allowed(method, target) then
    return reject(403, "MCP target was not observed during learn mode", "mcp.learn.target_not_observed")
  end

  return {{
    action = "continue",
    reason = "MCP request matched learned policy",
    reason_code = "mcp.learn.allowed",
    context = {{
      method = method or "",
      tool = mcp.tool_name(request) or ""
    }}
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


def _lua_nested_set(values: Mapping[str, set[str]]) -> str:
    if not values:
        return "{}"
    lines = ["{"]
    for key in sorted(values):
        lines.append(f"  [{json.dumps(key)}] = {_lua_set(values[key])},")
    lines.append("}")
    return "\n".join(lines)


def _markdown_list(label: str, values: Sequence[str]) -> str:
    if not values:
        return f"### {label}\n\n- None"
    items = "\n".join(f"- `{value}`" for value in values)
    return f"### {label}\n\n{items}"


def _argument_key_table(values: Mapping[str, set[str]]) -> str:
    if not values:
        return "| Tool | Argument Keys |\n| --- | --- |\n| - | - |"
    lines = ["| Tool | Argument Keys |", "| --- | --- |"]
    for tool in sorted(values):
        keys = ", ".join(f"`{key}`" for key in sorted(values[tool])) or "-"
        lines.append(f"| `{tool}` | {keys} |")
    return "\n".join(lines)


def _counter_table(label: str, counter: Counter[str]) -> str:
    lines = [f"### {label}", "", "| Value | Count |", "| --- | --- |"]
    if not counter:
        lines.append("| - | - |")
        return "\n".join(lines)
    for value, count in counter.most_common():
        lines.append(f"| `{value}` | {count} |")
    return "\n".join(lines)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [str(item) for item in value]

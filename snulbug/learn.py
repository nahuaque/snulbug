from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .bundle import load_bundle
from .inspection import _load_events
from .mcp_policy_bundles import write_mcp_policy_bundle
from .recorder import RECORD_TYPE, load_record_log
from .simulator import simulate_policy


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
    bundle = write_mcp_policy_bundle(
        output_path,
        policy=model.to_lua(),
        manifest=model.manifest(log),
        report=model.report(log),
        report_name="LEARNED.md",
        force=force,
        exists_label="learn output",
        validate=validate,
    )

    return {
        "ok": bundle.ok,
        "log": str(log),
        "output": str(output_path),
        "policy": str(bundle.policy),
        "manifest": str(bundle.manifest),
        "report": str(bundle.report),
        "event_count": model.event_count,
        "allowed_event_count": model.allowed_event_count,
        "blocked_event_count": model.blocked_event_count,
        "methods": sorted(model.methods),
        "tools": sorted(model.tools),
        "resources": sorted(model.resources),
        "prompts": sorted(model.prompts),
        "validation": bundle.validation,
        "next_steps": bundle.next_steps,
    }


def amend_mcp_policy(
    bundle: str | Path,
    log: str | Path,
    output: str | Path,
    *,
    kind: str = "auto",
    source: str = "blocked",
    force: bool = False,
    validate: bool = True,
    allow_risky: bool = False,
) -> dict[str, Any]:
    """Propose a narrow candidate amendment from MCP audit/replay evidence."""

    source_mode = source
    if source_mode not in {"blocked", "approved-confirmations"}:
        raise ValueError("source must be 'blocked' or 'approved-confirmations'")

    source_bundle = load_bundle(bundle)
    model = _LearnedPolicy.from_manifest(source_bundle.manifest)
    events = _load_events(log, kind=kind)
    amendment = _Amendment(allow_risky=allow_risky, source=source_mode)
    for event in events:
        amendment.add_event(model, event)

    output_path = Path(output)
    manifest = model.manifest(source_bundle.manifest.get("generated_from", str(bundle)))
    manifest["generated_by"] = "snulbug mcp policy amend"
    manifest["amended_from"] = str(source_bundle.root)
    manifest["amendment_log"] = str(log)
    manifest["amendment"] = {
        "source": source_mode,
        "event_count": amendment.event_count,
        "candidate_event_count": amendment.candidate_event_count,
        "additions": amendment.additions,
        "rejected": amendment.rejected,
        "ignored": amendment.ignored,
    }
    generated = write_mcp_policy_bundle(
        output_path,
        policy=model.to_lua(),
        manifest=manifest,
        report=amendment.report(source_bundle.root, log, model),
        report_name="AMEND.md",
        force=force,
        exists_label="amend output",
        validate=validate,
    )

    baseline = _verify_baseline_records(generated.policy, source_bundle.manifest.get("generated_from"))
    ok = generated.ok
    ok = ok and bool(baseline["ok"])
    return {
        "ok": ok,
        "bundle": str(source_bundle.root),
        "log": str(log),
        "output": str(output_path),
        "policy": str(generated.policy),
        "manifest": str(generated.manifest),
        "report": str(generated.report),
        "source": source_mode,
        "event_count": amendment.event_count,
        "candidate_event_count": amendment.candidate_event_count,
        "additions": amendment.additions,
        "rejected": amendment.rejected,
        "ignored": amendment.ignored,
        "validation": generated.validation,
        "baseline": baseline,
        "next_steps": generated.next_steps,
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

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> _LearnedPolicy:
        learned = _mapping(manifest.get("learned"))
        if not learned:
            raise ValueError("policy bundle manifest does not contain learned policy metadata")
        model = cls()
        model.event_count = int(learned.get("event_count", 0))
        model.allowed_event_count = int(learned.get("allowed_event_count", 0))
        model.blocked_event_count = int(learned.get("blocked_event_count", 0))
        model.paths = set(_string_sequence(learned.get("paths")))
        model.methods = set(_string_sequence(learned.get("methods")))
        model.tools = set(_string_sequence(learned.get("tools")))
        model.resources = set(_string_sequence(learned.get("resources")))
        model.prompts = set(_string_sequence(learned.get("prompts")))
        for tool, keys in _mapping(learned.get("tool_argument_keys")).items():
            model.tool_argument_keys[str(tool)] = set(_string_sequence(keys))
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
            "generated_by": "snulbug mcp policy learn",
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
                "tool_argument_keys": {
                    tool: sorted(keys)
                    for tool, keys in sorted(self.tool_argument_keys.items())
                    if keys or tool in self.tools
                },
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
        return f"""-- Generated by snulbug mcp policy learn. Review before exposing through a public tunnel.
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


class _Amendment:
    def __init__(self, *, allow_risky: bool, source: str = "blocked") -> None:
        self.allow_risky = allow_risky
        self.source = source
        self.event_count = 0
        self.candidate_event_count = 0
        self.additions: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []
        self.ignored: list[dict[str, Any]] = []
        self._seen_additions: set[tuple[str, str, str | None]] = set()
        self._seen_rejections: set[tuple[str, str, str | None]] = set()
        self._seen_ignored: set[tuple[str, str, str | None]] = set()

    def add_event(self, model: _LearnedPolicy, event: Mapping[str, Any]) -> None:
        self.event_count += 1
        if self.source == "approved-confirmations":
            self._add_approved_confirmation_event(model, event)
            return
        self._add_blocked_event(model, event)

    def _add_blocked_event(self, model: _LearnedPolicy, event: Mapping[str, Any]) -> None:
        decision = _mapping(event.get("decision"))
        if decision.get("allowed") is not False:
            return
        reason_code = str(decision.get("reason_code") or "")
        if not reason_code.startswith("mcp.learn."):
            self._ignore("unsupported_reason_code", reason_code or "missing", event)
            return
        self.candidate_event_count += 1

        request = _mapping(event.get("request"))
        mcp = _mapping(event.get("mcp"))
        path = request.get("path")
        method = mcp.get("method")
        tool = mcp.get("tool")
        target = mcp.get("target")

        if reason_code == "mcp.learn.path_not_observed":
            if isinstance(path, str) and path:
                self._add_scalar(model.paths, "path", path, reason_code)
            else:
                self._ignore("missing_path", reason_code, event)
            return

        if reason_code == "mcp.learn.method_not_observed":
            if isinstance(method, str) and method:
                self._add_scalar(model.methods, "method", method, reason_code)
            else:
                self._ignore("missing_method", reason_code, event)
            return

        if reason_code == "mcp.learn.tool_not_observed":
            if not isinstance(tool, str) or not tool:
                self._ignore("missing_tool", reason_code, event)
                return
            if _risky_tool(tool) and not self.allow_risky:
                self._reject("risky_tool", "tool", tool, reason_code)
                return
            self._add_scalar(model.methods, "method", "tools/call", reason_code)
            self._add_scalar(model.tools, "tool", tool, reason_code)
            for key in _string_sequence(mcp.get("argument_keys")):
                self._add_argument_key(model, tool, key, reason_code)
            return

        if reason_code in {"mcp.learn.argument_not_observed", "mcp.learn.arguments_missing"}:
            if not isinstance(tool, str) or not tool:
                self._ignore("missing_tool", reason_code, event)
                return
            if tool not in model.tools:
                if _risky_tool(tool) and not self.allow_risky:
                    self._reject("risky_tool", "tool", tool, reason_code)
                    return
                self._add_scalar(model.tools, "tool", tool, reason_code)
            keys = _string_sequence(mcp.get("argument_keys"))
            if not keys:
                self._ignore("missing_argument_keys", reason_code, event)
                return
            for key in keys:
                self._add_argument_key(model, tool, key, reason_code)
            return

        if reason_code == "mcp.learn.target_not_observed":
            if not isinstance(method, str) or not isinstance(target, str) or not target:
                self._ignore("missing_target", reason_code, event)
                return
            if method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}:
                self._add_scalar(model.resources, "resource", target, reason_code)
            elif method == "prompts/get":
                self._add_scalar(model.prompts, "prompt", target, reason_code)
            else:
                self._ignore("unsupported_target_method", method, event)
            return

        self._ignore("unsupported_learn_reason_code", reason_code, event)

    def _add_approved_confirmation_event(self, model: _LearnedPolicy, event: Mapping[str, Any]) -> None:
        decision = _mapping(event.get("decision"))
        confirmation = _mapping(decision.get("confirmation"))
        if confirmation.get("approved") is not True:
            return

        self.candidate_event_count += 1
        reason_code = str(decision.get("reason_code") or "mcp.confirm.approved")
        request = _mapping(event.get("request"))
        mcp = _mapping(event.get("mcp"))
        path = request.get("path")
        method = mcp.get("method")
        tool = mcp.get("tool")
        target = mcp.get("target")

        if isinstance(path, str) and path:
            self._add_scalar(model.paths, "path", path, reason_code)
        else:
            self._ignore("missing_path", reason_code, event)

        if isinstance(method, str) and method:
            self._add_scalar(model.methods, "method", method, reason_code)
        else:
            self._ignore("missing_method", reason_code, event)
            return

        if method == "tools/call":
            if not isinstance(tool, str) or not tool:
                self._ignore("missing_tool", reason_code, event)
                return
            if _risky_tool(tool) and not self.allow_risky:
                self._reject("risky_tool", "tool", tool, reason_code)
                return
            self._add_scalar(model.tools, "tool", tool, reason_code)
            for key in _string_sequence(mcp.get("argument_keys")):
                self._add_argument_key(model, tool, key, reason_code)
            return

        if method in {"resources/read", "resources/subscribe", "resources/unsubscribe"}:
            if isinstance(target, str) and target:
                self._add_scalar(model.resources, "resource", target, reason_code)
            else:
                self._ignore("missing_target", reason_code, event)
            return

        if method == "prompts/get":
            if isinstance(target, str) and target:
                self._add_scalar(model.prompts, "prompt", target, reason_code)
            else:
                self._ignore("missing_target", reason_code, event)

    def report(self, source_bundle: Path, log: str | Path, model: _LearnedPolicy) -> str:
        return "\n".join(
            [
                "# MCP Policy Amendment",
                "",
                f"- Source bundle: `{source_bundle}`",
                f"- Amendment log: `{log}`",
                f"- Amendment source: `{self.source}`",
                f"- Events inspected: {self.event_count}",
                f"- Candidate events: {self.candidate_event_count}",
                f"- Additions: {len(self.additions)}",
                f"- Rejected: {len(self.rejected)}",
                f"- Ignored: {len(self.ignored)}",
                "",
                "## Added",
                "",
                _items_table(self.additions, ["kind", "value", "parent", "reason_code"]),
                "",
                "## Rejected",
                "",
                _items_table(self.rejected, ["kind", "value", "parent", "reason_code", "reason"]),
                "",
                "## Ignored",
                "",
                _items_table(self.ignored, ["kind", "value", "parent", "reason_code", "reason"]),
                "",
                "## Candidate Surface",
                "",
                _markdown_list("HTTP paths", sorted(model.paths)),
                "",
                _markdown_list("MCP methods", sorted(model.methods)),
                "",
                _markdown_list("Tools", sorted(model.tools)),
                "",
                _argument_key_table(model.tool_argument_keys),
                "",
            ]
        )

    def _add_scalar(self, values: set[str], kind: str, value: str, reason_code: str) -> None:
        if value not in values:
            values.add(value)
            self._record_addition(kind, value, None, reason_code)

    def _add_argument_key(self, model: _LearnedPolicy, tool: str, key: str, reason_code: str) -> None:
        if key not in model.tool_argument_keys[tool]:
            model.tool_argument_keys[tool].add(key)
            self._record_addition("argument_key", key, tool, reason_code)

    def _record_addition(self, kind: str, value: str, parent: str | None, reason_code: str) -> None:
        key = (kind, value, parent)
        if key in self._seen_additions:
            return
        self._seen_additions.add(key)
        item = {"kind": kind, "value": value, "reason_code": reason_code}
        if parent is not None:
            item["parent"] = parent
        self.additions.append(item)

    def _reject(self, reason: str, kind: str, value: str, reason_code: str, parent: str | None = None) -> None:
        key = (kind, value, parent)
        if key in self._seen_rejections:
            return
        self._seen_rejections.add(key)
        item = {"kind": kind, "value": value, "reason": reason, "reason_code": reason_code}
        if parent is not None:
            item["parent"] = parent
        self.rejected.append(item)

    def _ignore(self, reason: str, value: str, event: Mapping[str, Any]) -> None:
        line = event.get("line")
        parent = str(line) if line is not None else None
        key = (reason, value, parent)
        if key in self._seen_ignored:
            return
        self._seen_ignored.add(key)
        item = {"kind": reason, "value": value, "reason": reason, "reason_code": value}
        if parent is not None:
            item["parent"] = parent
        self.ignored.append(item)


def _verify_baseline_records(policy_path: Path, source_log: Any) -> dict[str, Any]:
    if not isinstance(source_log, str) or not source_log:
        return {"ok": True, "checked": 0, "skipped": True, "reason": "no generated_from log"}
    log_path = Path(source_log)
    if not log_path.is_file():
        return {"ok": True, "checked": 0, "skipped": True, "reason": "generated_from log not found"}

    try:
        records = load_record_log(log_path)
    except Exception as exc:
        return {"ok": True, "checked": 0, "skipped": True, "reason": f"generated_from is not replayable: {exc}"}

    failures = []
    checked = 0
    for index, record in enumerate(records, start=1):
        if record.get("type") != RECORD_TYPE:
            continue
        recorded = _mapping(record.get("result"))
        if recorded.get("action") not in {"continue", "set_context", "rewrite", "rate_limit"}:
            continue
        checked += 1
        result = simulate_policy(
            policy_path,
            _mapping(record.get("request")),
            context=_optional_mapping(record.get("context")),
            state_snapshot=_record_state_input(record),
        )
        if result.get("action") not in {"continue", "set_context", "rewrite", "rate_limit"}:
            failures.append(
                {
                    "line": index,
                    "recorded_action": recorded.get("action"),
                    "actual_action": result.get("action"),
                    "reason_code": _mapping(result.get("decision")).get("reason_code"),
                }
            )
    return {"ok": not failures, "checked": checked, "failures": failures}


def _record_state_input(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    state = record.get("state")
    if not isinstance(state, Mapping):
        return None
    return _optional_mapping(state.get("input"))


def _optional_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _risky_tool(tool: str) -> bool:
    normalized = tool.lower().replace("-", "_")
    risky_terms = ("shell", "exec", "command", "terminal", "subprocess", "process_spawn")
    return any(term in normalized for term in risky_terms)


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


def _items_table(items: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    headers = [field.replace("_", " ").title() for field in fields]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _field in fields) + " |",
    ]
    if not items:
        lines.append("| " + " | ".join("-" for _field in fields) + " |")
        return "\n".join(lines)
    for item in items:
        values = [str(item.get(field, "-")) for field in fields]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    return [str(item) for item in value]

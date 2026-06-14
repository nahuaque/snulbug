from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any


class LuaRuntimeError(RuntimeError):
    """Raised when the Lua engine cannot load or execute a script."""


class LuaDecisionError(ValueError):
    """Raised when a script returns an invalid middleware decision."""


LuaValue = str | int | float | bool | None | list["LuaValue"] | dict[str, "LuaValue"]


@dataclass(frozen=True)
class LuaDecisionTrace:
    """Execution trace for one Lua policy decision."""

    decision: dict[str, Any]
    source_name: str
    duration_ms: float
    instruction_count: int
    state_operations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "duration_ms": self.duration_ms,
            "instruction_count": self.instruction_count,
            "state_operations": self.state_operations,
        }


@dataclass(frozen=True)
class CompiledLuaScript:
    """A compiled Lua policy script."""

    source_name: str
    _runtime: Any = field(repr=False)
    _handler: Any = field(repr=False)

    def decide(self, request: Mapping[str, Any], context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.decide_with_trace(request, context).decision

    def decide_with_trace(
        self,
        request: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
        state: Any = None,
    ) -> LuaDecisionTrace:
        request_table = _to_lua(self._runtime, request)
        context_table = _to_lua(self._runtime, context or {})
        state_table = _to_lua(self._runtime, _state_api(state))

        started_at = perf_counter()
        try:
            result = self._handler(request_table, context_table, state_table)
        except LuaDecisionError:
            raise
        except Exception as exc:  # Lupa raises LuaError, but do not import it at module import time.
            raise LuaRuntimeError(f"Lua script {self.source_name!r} failed: {exc}") from exc
        duration_ms = (perf_counter() - started_at) * 1000

        execution = _from_lua(result)
        if not isinstance(execution, dict):
            raise LuaDecisionError("Lua runtime returned an invalid execution result")

        decision = _normalize_decision(execution.get("decision"))
        instruction_count = execution.get("instruction_count", 0)
        if not isinstance(instruction_count, int):
            raise LuaDecisionError("Lua runtime returned an invalid instruction count")

        return LuaDecisionTrace(
            decision=decision,
            source_name=self.source_name,
            duration_ms=duration_ms,
            instruction_count=instruction_count,
            state_operations=[dict(operation) for operation in getattr(state, "operations", [])],
        )


def _normalize_decision(decision: Any) -> dict[str, Any]:
    if decision is None:
        decision = {"action": "continue"}
    if isinstance(decision, str):
        decision = {"action": decision}
    if not isinstance(decision, dict):
        raise LuaDecisionError("Lua script must return a table, action string, or nil")

    action = decision.get("action", "continue")
    if not isinstance(action, str):
        raise LuaDecisionError("Lua decision field 'action' must be a string")
    decision["action"] = action
    for metadata_field in ("reason", "reason_code"):
        if metadata_field in decision and not isinstance(decision[metadata_field], str):
            raise LuaDecisionError(f"Lua decision field {metadata_field!r} must be a string")
    return decision


def compile_lua_script(
    source: str,
    *,
    source_name: str = "<snulbug>",
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> CompiledLuaScript:
    """Compile a Lua policy script in a narrow sandbox.

    Scripts must return a function with this shape:

        return function(request, context, state)
          return { action = "continue" }
        end

    The script sees only safe standard-library globals and the request/context
    tables passed to the returned function. When configured, the state argument
    contains a narrow capability table. Python objects are recursively converted
    to Lua tables before execution.
    """

    try:
        from lupa import LuaRuntime  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - exercised only without the optional runtime installed.
        raise LuaRuntimeError(
            "snulbug requires the 'lupa' package to execute Lua scripts. "
            "Install this project with its runtime dependencies."
        ) from exc

    runtime_kwargs: dict[str, Any] = {
        "unpack_returned_tuples": True,
        "register_eval": False,
        "register_builtins": False,
    }
    if memory_limit_bytes is not None:
        runtime_kwargs["max_memory"] = memory_limit_bytes

    try:
        runtime = LuaRuntime(**runtime_kwargs)
    except TypeError:
        runtime_kwargs.pop("max_memory", None)
        runtime = LuaRuntime(**runtime_kwargs)
        if memory_limit_bytes is not None and hasattr(runtime, "set_max_memory"):
            runtime.set_max_memory(memory_limit_bytes)

    loader = runtime.execute(_LOADER)
    try:
        handler = loader(source, source_name, int(instruction_limit))
    except Exception as exc:
        raise LuaRuntimeError(f"Could not compile Lua script {source_name!r}: {exc}") from exc

    return CompiledLuaScript(source_name=source_name, _runtime=runtime, _handler=handler)


def compile_lua_file(
    path: str | Path,
    *,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> CompiledLuaScript:
    lua_path = Path(path)
    return compile_lua_script(
        lua_path.read_text(encoding="utf-8"),
        source_name=str(lua_path),
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )


def _to_lua(runtime: Any, value: Any) -> Any:
    if isinstance(value, Mapping):
        return runtime.table_from({str(k): _to_lua(runtime, v) for k, v in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return runtime.table_from([_to_lua(runtime, item) for item in value])
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return value


def _state_api(state: Any) -> Any:
    if state is None:
        return {}
    if hasattr(state, "lua_api"):
        return state.lua_api()
    return state


def _from_lua(value: Any) -> Any:
    if _is_lua_table(value):
        keys = list(value.keys())
        if keys and all(isinstance(key, int) for key in keys):
            max_key = max(keys)
            if sorted(keys) == list(range(1, max_key + 1)):
                return [_from_lua(value[index]) for index in range(1, max_key + 1)]
        return {str(key): _from_lua(value[key]) for key in keys}
    return value


def _is_lua_table(value: Any) -> bool:
    return hasattr(value, "keys") and hasattr(value, "__getitem__") and not isinstance(value, dict)


_LOADER = r"""
return function(source, source_name, instruction_limit)
  local safe_env = {
    assert = assert,
    error = error,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = pcall,
    select = select,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    unpack = unpack or table.unpack,
    math = {
      abs = math.abs,
      ceil = math.ceil,
      floor = math.floor,
      max = math.max,
      min = math.min,
      random = math.random,
      sqrt = math.sqrt,
    },
    string = {
      byte = string.byte,
      char = string.char,
      find = string.find,
      format = string.format,
      gmatch = string.gmatch,
      gsub = string.gsub,
      len = string.len,
      lower = string.lower,
      match = string.match,
      rep = string.rep,
      sub = string.sub,
      upper = string.upper,
    },
    table = {
      concat = table.concat,
      insert = table.insert,
      remove = table.remove,
      sort = table.sort,
    },
  }

  local json_null = {}

  local function json_error(message)
    error("invalid JSON body: " .. message, 0)
  end

  local function json_skip_ws(source, index)
    while true do
      local char = string.sub(source, index, index)
      if char == " " or char == "\n" or char == "\r" or char == "\t" then
        index = index + 1
      else
        return index
      end
    end
  end

  local function json_parse_string(source, index)
    local result = {}
    index = index + 1
    while index <= #source do
      local char = string.sub(source, index, index)
      if char == '"' then
        return table.concat(result), index + 1
      end
      if char == "\\" then
        local escape = string.sub(source, index + 1, index + 1)
        if escape == '"' or escape == "\\" or escape == "/" then
          table.insert(result, escape)
          index = index + 2
        elseif escape == "b" then
          table.insert(result, "\b")
          index = index + 2
        elseif escape == "f" then
          table.insert(result, "\f")
          index = index + 2
        elseif escape == "n" then
          table.insert(result, "\n")
          index = index + 2
        elseif escape == "r" then
          table.insert(result, "\r")
          index = index + 2
        elseif escape == "t" then
          table.insert(result, "\t")
          index = index + 2
        elseif escape == "u" then
          local hex = string.sub(source, index + 2, index + 5)
          if not string.match(hex, "^%x%x%x%x$") then
            json_error("bad unicode escape")
          end
          local codepoint = tonumber(hex, 16)
          if codepoint < 128 then
            table.insert(result, string.char(codepoint))
          else
            table.insert(result, "?")
          end
          index = index + 6
        else
          json_error("bad string escape")
        end
      else
        table.insert(result, char)
        index = index + 1
      end
    end
    json_error("unterminated string")
  end

  local json_parse_value

  local function json_parse_array(source, index)
    local result = {}
    index = json_skip_ws(source, index + 1)
    if string.sub(source, index, index) == "]" then
      return result, index + 1
    end
    while true do
      local value
      value, index = json_parse_value(source, index)
      table.insert(result, value)
      index = json_skip_ws(source, index)
      local char = string.sub(source, index, index)
      if char == "]" then
        return result, index + 1
      end
      if char ~= "," then
        json_error("expected ',' or ']' in array")
      end
      index = json_skip_ws(source, index + 1)
    end
  end

  local function json_parse_object(source, index)
    local result = {}
    index = json_skip_ws(source, index + 1)
    if string.sub(source, index, index) == "}" then
      return result, index + 1
    end
    while true do
      if string.sub(source, index, index) ~= '"' then
        json_error("expected object key")
      end
      local key
      key, index = json_parse_string(source, index)
      index = json_skip_ws(source, index)
      if string.sub(source, index, index) ~= ":" then
        json_error("expected ':' after object key")
      end
      index = json_skip_ws(source, index + 1)
      result[key], index = json_parse_value(source, index)
      index = json_skip_ws(source, index)
      local char = string.sub(source, index, index)
      if char == "}" then
        return result, index + 1
      end
      if char ~= "," then
        json_error("expected ',' or '}' in object")
      end
      index = json_skip_ws(source, index + 1)
    end
  end

  local function json_parse_number(source, index)
    local start = index
    local char = string.sub(source, index, index)
    if char == "-" then
      index = index + 1
    end
    while string.match(string.sub(source, index, index), "%d") do
      index = index + 1
    end
    if string.sub(source, index, index) == "." then
      index = index + 1
      while string.match(string.sub(source, index, index), "%d") do
        index = index + 1
      end
    end
    char = string.sub(source, index, index)
    if char == "e" or char == "E" then
      index = index + 1
      char = string.sub(source, index, index)
      if char == "+" or char == "-" then
        index = index + 1
      end
      while string.match(string.sub(source, index, index), "%d") do
        index = index + 1
      end
    end
    local value = tonumber(string.sub(source, start, index - 1))
    if value == nil then
      json_error("bad number")
    end
    return value, index
  end

  function json_parse_value(source, index)
    index = json_skip_ws(source, index)
    local char = string.sub(source, index, index)
    if char == '"' then
      return json_parse_string(source, index)
    end
    if char == "{" then
      return json_parse_object(source, index)
    end
    if char == "[" then
      return json_parse_array(source, index)
    end
    if string.sub(source, index, index + 3) == "true" then
      return true, index + 4
    end
    if string.sub(source, index, index + 4) == "false" then
      return false, index + 5
    end
    if string.sub(source, index, index + 3) == "null" then
      return json_null, index + 4
    end
    return json_parse_number(source, index)
  end

  local function json_decode(source)
    if type(source) ~= "string" or source == "" then
      return nil
    end
    local value, index = json_parse_value(source, 1)
    index = json_skip_ws(source, index)
    if index <= #source then
      json_error("trailing content")
    end
    return value
  end

  local function options_table(options)
    if type(options) == "table" then
      return options
    end
    return {}
  end

  local function copy_option(result, options, key)
    if options[key] ~= nil then
      result[key] = options[key]
    end
  end

  local function copy_options(options)
    local copied = {}
    options = options_table(options)
    for key, value in pairs(options) do
      copied[key] = value
    end
    return copied
  end

  local function with_options(result, options)
    options = options_table(options)
    copy_option(result, options, "reason")
    copy_option(result, options, "reason_code")
    copy_option(result, options, "context")
    copy_option(result, options, "headers")
    return result
  end

  local function with_confirmation_options(result, options)
    options = options_table(options)
    copy_option(result, options, "confirm")
    copy_option(result, options, "prompt")
    copy_option(result, options, "remember_key")
    copy_option(result, options, "timeout_seconds")
    return result
  end

  local function list_contains(values, needle)
    if type(values) ~= "table" or needle == nil then
      return false
    end
    if values[needle] == true then
      return true
    end
    for _, value in ipairs(values) do
      if value == needle then
        return true
      end
    end
    return false
  end

  local function table_is_array(value)
    if type(value) ~= "table" then
      return false
    end
    return type(value[1]) == "table"
  end

  local function starts_with(value, prefix)
    return string.sub(value, 1, #prefix) == prefix
  end

  local function ends_with(value, suffix)
    return suffix == "" or string.sub(value, -#suffix) == suffix
  end

  local function selector_matches(configured, requested)
    if type(configured) ~= "string" or type(requested) ~= "string" then
      return false
    end
    if configured == requested or configured == "*" then
      return true
    end
    if ends_with(configured, "*") then
      return starts_with(requested, string.sub(configured, 1, #configured - 1))
    end
    return false
  end

  local decision = {}

  decision["continue"] = function(options)
    return with_options({ action = "continue" }, options)
  end

  function decision.allow(reason_code, context)
    if type(reason_code) == "table" then
      return decision["continue"](reason_code)
    end
    return decision["continue"]({
      reason_code = reason_code,
      context = context,
    })
  end

  function decision.set_context(context, options)
    local result = { action = "set_context", context = context or {} }
    return with_options(result, options)
  end

  function decision.respond(status, body, options)
    local result = {
      action = "respond",
      status = status or 200,
      body = body or "",
    }
    return with_options(result, options)
  end

  function decision.reject(status, body, options)
    local message = body or "forbidden"
    local result = {
      action = "reject",
      status = status or 403,
      body = message,
      reason = message,
    }
    return with_confirmation_options(with_options(result, options), options)
  end

  function decision.challenge(options)
    options = options_table(options)
    local result = {
      action = "challenge",
      status = options.status or 401,
      body = options.body or "authentication required",
    }
    copy_option(result, options, "scheme")
    copy_option(result, options, "realm")
    copy_option(result, options, "error")
    copy_option(result, options, "error_description")
    return with_options(result, options)
  end

  function decision.redirect(location, options)
    local result = {
      action = "redirect",
      location = location,
      status = options_table(options).status or 307,
    }
    return with_options(result, options)
  end

  function decision.rate_limit(key, limit, window, options)
    local result = {
      action = "rate_limit",
      key = key,
      limit = limit,
      window = window,
    }
    return with_options(result, options)
  end

  function decision.confirm(prompt, options)
    options = options_table(options)
    local result = {
      action = "confirm",
      prompt = prompt or options.prompt,
      status = options.status or 403,
      body = options.body or "confirmation denied",
    }
    copy_option(result, options, "remember_key")
    copy_option(result, options, "timeout_seconds")
    return with_options(result, options)
  end

  safe_env.decision = decision

  local current_auth = {}

  local function set_auth_context(context)
    if type(context) == "table" and type(context.auth) == "table" then
      current_auth = context.auth
    else
      current_auth = {}
    end
  end

  local auth = {}

  function auth.claims()
    return current_auth
  end

  function auth.subject()
    return current_auth.subject
  end

  function auth.client_id()
    return current_auth.client_id
  end

  function auth.scopes()
    if type(current_auth.scopes) == "table" then
      return current_auth.scopes
    end
    return {}
  end

  function auth.has_scope(scope)
    return list_contains(auth.scopes(), scope)
  end

  function auth.can(selector)
    if type(current_auth.scope_map) ~= "table" then
      return false
    end
    for _, scope in ipairs(auth.scopes()) do
      local selectors = current_auth.scope_map[scope]
      if type(selectors) == "table" then
        for _, configured in ipairs(selectors) do
          if selector_matches(configured, selector) then
            return true
          end
        end
      end
    end
    return false
  end

  function auth.require_scope(scope, options)
    if auth.has_scope(scope) then
      return nil
    end
    options = options_table(options)
    local reason_code = options.reason_code or "oauth.missing_scope"
    local body = options.body or "insufficient scope"
    return decision.challenge({
      error = "insufficient_scope",
      body = body,
      reason = options.reason or body,
      reason_code = reason_code,
      context = {
        missing_scope = scope,
      },
    })
  end

  function auth.require(selector, options)
    if auth.can(selector) then
      return nil
    end
    options = options_table(options)
    local reason_code = options.reason_code or "oauth.scope_map_denied"
    local body = options.body or "insufficient scope"
    return decision.challenge({
      error = "insufficient_scope",
      body = body,
      reason = options.reason or body,
      reason_code = reason_code,
      context = {
        selector = selector,
      },
    })
  end

  safe_env.auth = auth

  local mcp = {}

  function mcp.body(request)
    if request.__mcp_body_cached then
      return request.__mcp_body
    end
    local ok, value = pcall(json_decode, request.body or "")
    request.__mcp_body_cached = true
    if not ok or type(value) ~= "table" then
      return nil
    end
    request.__mcp_body = value
    return value
  end

  function mcp.call(request)
    if request.__mcp_call_cached then
      return request.__mcp_call
    end

    local body = mcp.body(request)
    local call = {
      body = body,
      params = {},
      args = {},
      invalid = false,
      batch = false,
      is_tool_call = false,
      is_read = false,
      is_write = false,
    }
    request.__mcp_call_cached = true
    request.__mcp_call = call

    if type(body) ~= "table" then
      call.invalid = true
      call.error = "invalid MCP JSON-RPC body"
      return call
    end

    if table_is_array(body) then
      call.batch = true
      call.error = "batch JSON-RPC request"
      return call
    end

    call.id = body.id
    if type(body.method) ~= "string" then
      call.invalid = true
      call.error = "missing JSON-RPC method"
      return call
    end

    call.method = body.method
    if type(body.params) == "table" then
      call.params = body.params
    end

    if call.method == "tools/call" then
      call.is_tool_call = true
      call.is_write = true
      if type(call.params.name) == "string" then
        call.tool = call.params.name
      end
      if type(call.params.arguments) == "table" then
        call.args = call.params.arguments
      end
      return call
    end

    if call.method == "resources/read" then
      call.is_read = true
      if type(call.params.uri) == "string" then
        call.resource_uri = call.params.uri
      end
      return call
    end

    if call.method == "prompts/get" then
      call.is_read = true
      if type(call.params.name) == "string" then
        call.prompt = call.params.name
      end
      if type(call.params.arguments) == "table" then
        call.args = call.params.arguments
      end
      return call
    end

    if call.method == "tools/list"
      or call.method == "resources/list"
      or call.method == "resources/templates/list"
      or call.method == "prompts/list" then
      call.is_read = true
    end

    return call
  end

  function mcp.method(request)
    return mcp.call(request).method
  end

  function mcp.params(request)
    return mcp.call(request).params
  end

  local function mcp_call_from(value)
    if type(value) ~= "table" then
      return { args = {} }
    end
    if type(value.args) == "table" and (value.method ~= nil or value.is_tool_call ~= nil or value.params ~= nil) then
      return value
    end
    return mcp.call(value)
  end

  function mcp.arg(request_or_call, key)
    local call = mcp_call_from(request_or_call)
    if type(call.args) ~= "table" then
      return nil
    end
    return call.args[key]
  end

  function mcp.arg_keys(request_or_call)
    local call = mcp_call_from(request_or_call)
    local keys = {}
    if type(call.args) ~= "table" then
      return keys
    end
    for key, _ in pairs(call.args) do
      table.insert(keys, tostring(key))
    end
    table.sort(keys)
    return keys
  end

  function mcp.is_method(request, method)
    return mcp.method(request) == method
  end

  function mcp.is_tool_call(request)
    return mcp.call(request).is_tool_call
  end

  function mcp.tool_name(request)
    return mcp.call(request).tool
  end

  function mcp.tool_allowed(request, allowed)
    local name = mcp.tool_name(request)
    if name == nil then
      return true
    end
    return list_contains(allowed, name)
  end

  function mcp.reject_tool(request_or_name, status, body, options)
    local name = request_or_name
    if type(request_or_name) == "table" then
      name = mcp.tool_name(request_or_name)
    end
    options = options_table(options)
    local message = body or options.body or ("MCP tool not allowed: " .. tostring(name))
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or message
    decision_options.reason_code = options.reason_code or "mcp.tool_not_allowed"
    return decision.reject(status or options.status or 403, message, decision_options)
  end

  function mcp.allow_tools(request, allowed, options)
    local name = mcp.tool_name(request)
    if name == nil or list_contains(allowed, name) then
      return nil
    end
    options = options_table(options)
    return mcp.reject_tool(name, options.status or 403, options.body, options)
  end

  safe_env.mcp = mcp

  local cap = {}

  local function rejection(options, body, reason_code)
    options = options_table(options)
    local decision_options = copy_options(options)
    decision_options.reason = options.reason or body
    decision_options.reason_code = options.reason_code or reason_code
    return decision.reject(options.status or 403, options.body or body, decision_options)
  end

  local function value_allowed(value, allowed)
    return list_contains(allowed, value)
  end

  function cap.allowed(value, allowed)
    return value_allowed(value, allowed)
  end

  function cap.method(request_or_method, allowed, options)
    local method = request_or_method
    if type(request_or_method) == "table" then
      method = mcp.method(request_or_method)
    end
    if value_allowed(method, allowed) then
      return nil
    end
    return rejection(options, "MCP method not allowed: " .. tostring(method), "mcp.method_not_allowed")
  end

  function cap.tool(request_or_name, allowed, options)
    local name = request_or_name
    if type(request_or_name) == "table" then
      if not mcp.is_tool_call(request_or_name) then
        return nil
      end
      name = mcp.tool_name(request_or_name)
    end
    if value_allowed(name, allowed) then
      return nil
    end
    return rejection(options, "MCP tool not allowed: " .. tostring(name), "mcp.tool_not_allowed")
  end

  local function normalize_relative_path(path)
    while starts_with(path, "./") do
      path = string.sub(path, 3)
    end
    return path
  end

  local function contains_parent_segment(path)
    return path == ".."
      or starts_with(path, "../")
      or ends_with(path, "/..")
      or string.find(path, "/../", 1, true) ~= nil
  end

  local function path_under(path, root)
    if type(root) ~= "string" or root == "" then
      return false
    end
    if root == "." or root == "./" then
      return true
    end
    root = normalize_relative_path(root)
    while ends_with(root, "/") and root ~= "" do
      root = string.sub(root, 1, #root - 1)
    end
    if root == "" then
      return false
    end
    return path == root or starts_with(path, root .. "/")
  end

  function cap.path(path, allowed_paths, options)
    if type(path) ~= "string" or path == "" then
      return rejection(options, "path must be a non-empty string", "mcp.path_invalid")
    end
    path = normalize_relative_path(path)
    if starts_with(path, "/") then
      return rejection(options, "absolute paths are not allowed", "mcp.path_absolute")
    end
    if contains_parent_segment(path) then
      return rejection(options, "parent path traversal is not allowed", "mcp.path_traversal")
    end
    if value_allowed(path, allowed_paths) then
      return nil
    end
    if type(allowed_paths) == "table" then
      for _, root in ipairs(allowed_paths) do
        if path_under(path, root) then
          return nil
        end
      end
    end
    return rejection(options, "path not allowed: " .. path, "mcp.path_not_allowed")
  end

  local function argument_value(request_or_call, key)
    return mcp.arg(request_or_call, key)
  end

  local function argument_label(key)
    return "argument " .. tostring(key)
  end

  function cap.arg_string(request_or_call, key, options)
    local value = argument_value(request_or_call, key)
    if type(value) == "string" and value ~= "" then
      return nil
    end
    return rejection(options, argument_label(key) .. " must be a non-empty string", "mcp.argument_invalid")
  end

  function cap.arg_path(request_or_call, key, allowed_paths, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.path(argument_value(request_or_call, key), allowed_paths, options)
  end

  local function extract_host(value)
    if type(value) ~= "string" or value == "" then
      return nil
    end
    local host = string.match(value, "^[%a][%w+.-]*://([^/:/%?#]+)")
    if host == nil then
      host = string.match(value, "^([^/:/%?#]+)")
    end
    if host == nil or host == "" then
      return nil
    end
    return string.lower(host)
  end

  local function host_allowed(host, allowed_hosts)
    if value_allowed(host, allowed_hosts) then
      return true
    end
    if type(allowed_hosts) ~= "table" then
      return false
    end
    for _, allowed in ipairs(allowed_hosts) do
      if type(allowed) == "string" then
        allowed = string.lower(allowed)
        if starts_with(allowed, "*.") and ends_with(host, string.sub(allowed, 2)) then
          return true
        end
      end
    end
    return false
  end

  function cap.host(value, allowed_hosts, options)
    local host = extract_host(value)
    if host ~= nil and host_allowed(host, allowed_hosts) then
      return nil
    end
    return rejection(options, "host not allowed: " .. tostring(host), "mcp.host_not_allowed")
  end

  function cap.arg_host(request_or_call, key, allowed_hosts, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.host(argument_value(request_or_call, key), allowed_hosts, options)
  end

  local function command_name(command)
    if type(command) ~= "string" then
      return nil
    end
    return string.match(command, "^%s*([^%s]+)")
  end

  function cap.command(command, allowed_commands, options)
    local name = command_name(command)
    if value_allowed(name, allowed_commands) then
      return nil
    end
    return rejection(options, "command not allowed: " .. tostring(name), "mcp.command_not_allowed")
  end

  function cap.arg_command(request_or_call, key, allowed_commands, options)
    local invalid = cap.arg_string(request_or_call, key, options)
    if invalid ~= nil then
      return invalid
    end
    return cap.command(argument_value(request_or_call, key), allowed_commands, options)
  end

  safe_env.cap = cap

  local loader = loadstring or load
  local chunk, err
  if loadstring then
    chunk, err = loadstring(source, source_name)
    if chunk then
      setfenv(chunk, safe_env)
    end
  else
    chunk, err = load(source, source_name, "t", safe_env)
  end
  if not chunk then
    error(err)
  end

  local handler = chunk()
  if type(handler) ~= "function" then
    error("Lua script must return a function(request, context)")
  end

  return function(request, context, state)
    local instruction_count = 0
    local function check_instruction_limit()
      instruction_count = instruction_count + 1000
      if instruction_count > instruction_limit then
        error("Lua instruction limit exceeded")
      end
    end

    if debug and debug.sethook then
      debug.sethook(check_instruction_limit, "", 1000)
    end

    set_auth_context(context)
    local ok, result = pcall(handler, request, context, state or {})
    set_auth_context({})

    if debug and debug.sethook then
      debug.sethook()
    end

    if not ok then
      error(result)
    end
    return {
      decision = result,
      instruction_count = instruction_count,
    }
  end
end
"""

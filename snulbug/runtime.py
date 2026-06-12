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

  function mcp.method(request)
    local body = mcp.body(request)
    if type(body) ~= "table" or type(body.method) ~= "string" then
      return nil
    end
    return body.method
  end

  function mcp.params(request)
    local body = mcp.body(request)
    if type(body) ~= "table" or type(body.params) ~= "table" then
      return {}
    end
    return body.params
  end

  function mcp.is_method(request, method)
    return mcp.method(request) == method
  end

  function mcp.is_tool_call(request)
    return mcp.is_method(request, "tools/call")
  end

  function mcp.tool_name(request)
    if not mcp.is_tool_call(request) then
      return nil
    end
    local params = mcp.params(request)
    if type(params.name) ~= "string" then
      return nil
    end
    return params.name
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
    options = options or {}
    local message = body or ("MCP tool not allowed: " .. tostring(name))
    return {
      action = "reject",
      status = status or 403,
      body = message,
      reason = options.reason or message,
      reason_code = options.reason_code or "mcp.tool_not_allowed",
    }
  end

  function mcp.allow_tools(request, allowed, options)
    local name = mcp.tool_name(request)
    if name == nil or list_contains(allowed, name) then
      return nil
    end
    options = options or {}
    return mcp.reject_tool(name, options.status or 403, options.body, {
      reason = options.reason,
      reason_code = options.reason_code,
    })
  end

  safe_env.mcp = mcp

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

    local ok, result = pcall(handler, request, context, state or {})

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

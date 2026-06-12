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
    return decision


def compile_lua_script(
    source: str,
    *,
    source_name: str = "<uvicorn-lua>",
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
            "uvicorn-lua requires the 'lupa' package to execute Lua scripts. "
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

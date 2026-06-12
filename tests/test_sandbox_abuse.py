from __future__ import annotations

import pytest

from snulbug import LuaRuntimeError
from snulbug.runtime import compile_lua_script


def test_lua_sandbox_does_not_expose_common_escape_globals():
    script = compile_lua_script(
        """
        return function(request, context, state)
          local exposed = {}
          if os ~= nil then table.insert(exposed, "os") end
          if io ~= nil then table.insert(exposed, "io") end
          if package ~= nil then table.insert(exposed, "package") end
          if require ~= nil then table.insert(exposed, "require") end
          if debug ~= nil then table.insert(exposed, "debug") end
          if python ~= nil then table.insert(exposed, "python") end
          if _G ~= nil then table.insert(exposed, "_G") end
          if load ~= nil then table.insert(exposed, "load") end
          if loadfile ~= nil then table.insert(exposed, "loadfile") end
          if dofile ~= nil then table.insert(exposed, "dofile") end
          if collectgarbage ~= nil then table.insert(exposed, "collectgarbage") end

          if #exposed > 0 then
            return { action = "reject", body = table.concat(exposed, ",") }
          end
          return { action = "continue" }
        end
        """,
    )

    assert script.decide({}) == {"action": "continue"}


def test_lua_sandbox_require_bypass_attempt_fails_closed():
    script = compile_lua_script(
        """
        return function(request, context, state)
          local ok, value = pcall(function()
            return require("io")
          end)
          if ok then
            return { action = "reject", body = tostring(value) }
          end
          return { action = "continue" }
        end
        """,
    )

    assert script.decide({}) == {"action": "continue"}


def test_lua_sandbox_debug_hook_evasion_attempt_still_hits_instruction_limit():
    script = compile_lua_script(
        """
        return function(request, context, state)
          if debug ~= nil and debug.sethook ~= nil then
            debug.sethook()
          end
          while true do end
          return { action = "continue" }
        end
        """,
        instruction_limit=1_000,
    )

    with pytest.raises(LuaRuntimeError, match="instruction limit"):
        script.decide({})

from __future__ import annotations

from asgi_lua.runtime import compile_lua_script


def test_mcp_helpers_read_json_rpc_method_and_tool_name():
    script = compile_lua_script(
        """
        return function(request, context)
          return {
            action = "respond",
            status = 200,
            context = {
              method = mcp.method(request),
              is_call = mcp.is_tool_call(request),
              tool = mcp.tool_name(request),
              path = mcp.params(request).arguments.path
            }
          }
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"README.md"}}}'
            )
        }
    )

    assert decision["context"] == {
        "method": "tools/call",
        "is_call": True,
        "tool": "safe_read_file",
        "path": "README.md",
    }


def test_mcp_allow_tools_returns_nil_for_non_tool_calls():
    script = compile_lua_script(
        """
        return function(request, context)
          local blocked = mcp.allow_tools(request, { "safe_read_file" })
          if blocked ~= nil then
            return blocked
          end
          return { action = "continue", context = { method = mcp.method(request) } }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'})

    assert decision == {"action": "continue", "context": {"method": "tools/list"}}


def test_mcp_allow_tools_rejects_unlisted_tool():
    script = compile_lua_script(
        """
        return function(request, context)
          return mcp.allow_tools(request, { safe_read_file = true }) or { action = "continue" }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "MCP tool not allowed: shell_exec",
    }


def test_mcp_helpers_treat_malformed_body_as_not_mcp():
    script = compile_lua_script(
        """
        return function(request, context)
          return {
            action = "continue",
            context = {
              body_type = type(mcp.body(request)),
              method_type = type(mcp.method(request)),
              tool_type = type(mcp.tool_name(request))
            }
          }
        end
        """
    )

    decision = script.decide({"body": "not json"})

    assert decision == {
        "action": "continue",
        "context": {"body_type": "nil", "method_type": "nil", "tool_type": "nil"},
    }

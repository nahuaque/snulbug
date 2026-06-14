from __future__ import annotations

from snulbug.runtime import compile_lua_script


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
        "reason": "MCP tool not allowed: shell_exec",
        "reason_code": "mcp.tool_not_allowed",
    }


def test_mcp_allow_tools_can_override_rejection_reason():
    script = compile_lua_script(
        """
        return function(request, context)
          return mcp.allow_tools(request, { safe_read_file = true }, {
            body = "blocked",
            reason = "Tool is outside this session's allowlist",
            reason_code = "session.tool_blocked"
          }) or { action = "continue" }
        end
        """
    )

    decision = script.decide({"body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}'})

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "blocked",
        "reason": "Tool is outside this session's allowlist",
        "reason_code": "session.tool_blocked",
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


def test_mcp_call_normalizes_tool_call_arguments():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return decision.respond(200, "ok", {
            context = {
              method = call.method,
              tool = call.tool,
              path = call.args.path,
              write = call.is_write,
              read = call.is_read,
              batch = call.batch,
              invalid = call.invalid
            }
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"docs/api.md"}}}'
            )
        }
    )

    assert decision == {
        "action": "respond",
        "status": 200,
        "body": "ok",
        "context": {
            "method": "tools/call",
            "tool": "safe_read_file",
            "path": "docs/api.md",
            "write": True,
            "read": False,
            "batch": False,
            "invalid": False,
        },
    }


def test_mcp_call_identifies_batch_requests():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return decision.allow("test.observed", {
            batch = call.batch,
            error = call.error,
            method_type = type(call.method)
          })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '[{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}},'
                '{"jsonrpc":"2.0","id":"2","method":"prompts/list","params":{}}]'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.observed",
        "context": {
            "batch": True,
            "error": "batch JSON-RPC request",
            "method_type": "nil",
        },
    }


def test_decision_helpers_build_supported_actions():
    script = compile_lua_script(
        """
        return function(request, context)
          return decision.reject(451, "blocked by policy", {
            reason_code = "test.blocked",
            context = { source = "decision-helper" }
          })
        end
        """
    )

    decision = script.decide({"body": "{}"})

    assert decision == {
        "action": "reject",
        "status": 451,
        "body": "blocked by policy",
        "reason": "blocked by policy",
        "reason_code": "test.blocked",
        "context": {"source": "decision-helper"},
    }


def test_capability_guards_return_nil_when_all_checks_pass():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.method(request, { "tools/call" })
            or cap.tool(request, { "safe_fetch" })
            or cap.path(call.args.path, { "README.md", "docs" })
            or cap.host(call.args.url, { "api.example.com", "*.trusted.local" })
            or cap.command(call.args.command, { "git" })
            or decision.allow("test.allowed", {
              tool = call.tool,
              path = call.args.path
            })
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_fetch","arguments":{'
                '"path":"docs/api.md",'
                '"url":"https://cache.trusted.local/v1",'
                '"command":"git status"}}}'
            )
        }
    )

    assert decision == {
        "action": "continue",
        "reason_code": "test.allowed",
        "context": {"tool": "safe_fetch", "path": "docs/api.md"},
    }


def test_capability_guards_reject_parent_path_traversal():
    script = compile_lua_script(
        """
        return function(request, context)
          local call = mcp.call(request)
          return cap.path(call.args.path, { "." })
            or decision.allow("test.allowed")
        end
        """
    )

    decision = script.decide(
        {
            "body": (
                '{"jsonrpc":"2.0","id":"1","method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"../secret.txt"}}}'
            )
        }
    )

    assert decision == {
        "action": "reject",
        "status": 403,
        "body": "parent path traversal is not allowed",
        "reason": "parent path traversal is not allowed",
        "reason_code": "mcp.path_traversal",
    }

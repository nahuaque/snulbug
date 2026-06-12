from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from asgi_lua import LuaConfig, LuaDecisionError, LuaMiddleware, LuaRuntimeError, MemoryStateStore, simulate_policy
from asgi_lua.simulator import main as simulator_main


async def app(scope, receive, send):
    assert scope["type"] == "http"
    body = b""
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break

    headers = [(b"content-type", b"text/plain")]
    if "lua" in scope:
        headers.append((b"x-lua-tenant", scope["lua"]["tenant"].encode("latin-1")))

    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send(
        {
            "type": "http.response.body",
            "body": f"{scope['method']} {scope['path']}?{scope.get('query_string', b'').decode()} {body.decode()}".encode(),
            "more_body": False,
        }
    )


def run_asgi(middleware, *, path="/in", headers=None, body=b"", query_string=b"") -> list[dict[str, Any]]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "headers": headers or [],
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent


def test_lua_can_continue_and_set_context():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "continue",
            context = { tenant = request.headers["x-tenant"] }
          }
        end
        """,
    )

    sent = run_asgi(middleware, headers=[(b"x-tenant", b"acme")])

    assert sent[0]["status"] == 200
    assert (b"x-lua-tenant", b"acme") in sent[0]["headers"]


def test_lua_can_reject_request():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          if request.headers.authorization ~= "Bearer ok" then
            return {
              action = "reject",
              status = 401,
              headers = { ["content-type"] = "text/plain" },
              body = "nope"
            }
          end
          return { action = "continue" }
        end
        """,
    )

    sent = run_asgi(middleware)

    assert sent == [
        {"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]},
        {"type": "http.response.body", "body": b"nope", "more_body": False},
    ]


def test_lua_can_issue_auth_challenge():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "challenge",
            scheme = "Bearer",
            realm = "tenant:acme",
            error = "invalid_token",
            body = "token required"
          }
        end
        """,
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 401
    assert (b"www-authenticate", b'Bearer, realm="tenant:acme", error="invalid_token"') in sent[0]["headers"]
    assert sent[1]["body"] == b"token required"


def test_lua_can_redirect_request():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "redirect",
            status = 308,
            location = "https://api.example.test/v2/webhooks/acme"
          }
        end
        """,
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 308
    assert (b"location", b"https://api.example.test/v2/webhooks/acme") in sent[0]["headers"]
    assert sent[1]["body"] == b""


def test_lua_can_rate_limit_with_state_store():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "rate_limit",
            key = "tenant:" .. request.headers["x-tenant"],
            limit = 2,
            window = 60,
            body = "slow down"
          }
        end
        """,
        config=LuaConfig(trace=True),
        state_store=MemoryStateStore(),
    )

    first = run_asgi(middleware, headers=[(b"x-tenant", b"acme")])
    second = run_asgi(middleware, headers=[(b"x-tenant", b"acme")])
    third = run_asgi(middleware, headers=[(b"x-tenant", b"acme")])

    assert first[0]["status"] == 200
    assert second[0]["status"] == 200
    assert third[0]["status"] == 429
    assert (b"x-ratelimit-limit", b"2") in third[0]["headers"]
    assert (b"x-ratelimit-remaining", b"0") in third[0]["headers"]
    assert third[1]["body"] == b"slow down"


def test_lua_rate_limit_requires_state_store():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return { action = "rate_limit", key = "global", limit = 1, window = 60 }
        end
        """,
    )

    with pytest.raises(LuaDecisionError, match="requires a configured state_store"):
        run_asgi(middleware)


def test_lua_can_rewrite_request_and_replay_body():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "rewrite",
            path = "/normalized",
            query = { from = request.path },
            headers = { ["x-added"] = "1" }
          }
        end
        """,
        config=LuaConfig(read_body=True),
    )

    sent = run_asgi(middleware, body=b"hello")

    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"POST /normalized?from=%2Fin hello"


def test_lua_can_rewrite_request_body():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return {
            action = "rewrite",
            path = "/normalized",
            headers = { ["content-type"] = "application/json" },
            body = '{"normalized":true}'
          }
        end
        """,
        config=LuaConfig(read_body=True, trace=True),
    )

    sent = run_asgi(middleware, body=b'{"raw":true}')

    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b'POST /normalized? {"normalized":true}'


def test_lua_body_rewrite_requires_body_reading():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return { action = "rewrite", body = "normalized" }
        end
        """,
    )

    with pytest.raises(LuaDecisionError, match="requires LuaConfig"):
        run_asgi(middleware, body=b"raw")


def test_body_limit_rejects_before_lua_runs():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return { action = "continue" }
        end
        """,
        config=LuaConfig(read_body=True, max_body_bytes=3),
    )

    sent = run_asgi(middleware, body=b"hello")

    assert sent[0]["status"] == 413
    assert sent[1]["body"] == b"request body too large for Lua middleware"


def test_lua_sandbox_does_not_expose_os_library():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          if os == nil then
            return { action = "respond", status = 200, body = "sandboxed" }
          end
          return { action = "respond", status = 500, body = "unsafe" }
        end
        """,
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"sandboxed"


def test_instruction_limit_stops_busy_loop():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          while true do end
          return { action = "continue" }
        end
        """,
        config=LuaConfig(instruction_limit=1_000),
    )

    with pytest.raises(LuaRuntimeError, match="instruction limit"):
        run_asgi(middleware)


def test_invalid_action_is_rejected():
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return { action = "explode" }
        end
        """,
    )

    with pytest.raises(LuaDecisionError, match="Lua action must be one of"):
        run_asgi(middleware)


def test_middleware_can_attach_trace_to_scope():
    captured = {}

    async def traced_app(scope, receive, send):
        captured["trace"] = scope["lua_trace"]
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    middleware = LuaMiddleware(
        traced_app,
        """
        return function(request, context)
          return { action = "continue" }
        end
        """,
        config=LuaConfig(trace=True),
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 204
    assert captured["trace"]["action"] == "continue"
    assert captured["trace"]["decision"] == {"action": "continue"}
    assert captured["trace"]["source_name"] == "<asgi-lua>"
    assert isinstance(captured["trace"]["duration_ms"], float)
    assert isinstance(captured["trace"]["instruction_count"], int)


def test_simulate_policy_returns_decision_trace(tmp_path):
    script_path = tmp_path / "policy.lua"
    script_path.write_text(
        """
        return function(request, context)
          return {
            action = "rewrite",
            path = "/tenant/" .. request.headers["x-tenant"],
            context = { tenant = request.headers["x-tenant"] }
          }
        end
        """,
        encoding="utf-8",
    )

    result = simulate_policy(
        script_path,
        {
            "method": "post",
            "path": "/incoming",
            "headers": {"X-Tenant": "acme"},
            "body": "payload",
        },
    )

    assert result["action"] == "rewrite"
    assert result["decision"]["path"] == "/tenant/acme"
    assert result["decision"]["context"] == {"tenant": "acme"}
    assert result["trace"]["source_name"] == str(script_path)
    assert result["body_read"] is True


def test_simulator_cli_emits_json(tmp_path, capsys):
    script_path = tmp_path / "policy.lua"
    request_path = tmp_path / "request.json"
    script_path.write_text(
        """
        return function(request, context)
          return { action = "respond", status = 202, body = request.path }
        end
        """,
        encoding="utf-8",
    )
    request_path.write_text(json.dumps({"path": "/cli", "headers": []}), encoding="utf-8")

    status = simulator_main(["simulate", str(script_path), str(request_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["action"] == "respond"
    assert output["decision"]["status"] == 202
    assert output["decision"]["body"] == "/cli"

from __future__ import annotations

import asyncio
import json
from typing import Any

from uvicorn_lua import LuaConfig, LuaMiddleware, diff_policies
from uvicorn_lua.simulator import main as simulator_main


def write_policy(path, action: str) -> None:
    path.write_text(
        f"""
        return function(request, context)
          if request.path == "/blocked" then
            return {{ action = "{action}", status = 403, body = "blocked" }}
          end
          return {{
            action = "rewrite",
            path = "/normalized",
            context = {{ policy = "{action}" }}
          }}
        end
        """,
        encoding="utf-8",
    )


def test_diff_policies_reports_regression(tmp_path):
    old_policy = tmp_path / "old.lua"
    new_policy = tmp_path / "new.lua"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    write_policy(old_policy, "rewrite")
    write_policy(new_policy, "reject")
    (fixtures / "blocked.json").write_text(json.dumps({"path": "/blocked", "headers": {}}), encoding="utf-8")

    result = diff_policies(old_policy, new_policy, fixtures)

    assert result["safe_to_promote"] is False
    assert result["changed_decisions"] == 1
    assert result["regression_count"] == 1
    assert result["regressions"][0]["reason"] == "action changed from rewrite to reject"


def test_diff_policies_allows_non_regressive_change(tmp_path):
    old_policy = tmp_path / "old.lua"
    new_policy = tmp_path / "new.lua"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    old_policy.write_text(
        """
        return function(request, context)
          return { action = "rewrite", path = "/v1" }
        end
        """,
        encoding="utf-8",
    )
    new_policy.write_text(
        """
        return function(request, context)
          return { action = "rewrite", path = "/v2" }
        end
        """,
        encoding="utf-8",
    )
    (fixtures / "request.json").write_text(json.dumps({"path": "/in", "headers": {}}), encoding="utf-8")

    result = diff_policies(old_policy, new_policy, fixtures)

    assert result["safe_to_promote"] is True
    assert result["changed_decisions"] == 1
    assert result["regression_count"] == 0
    assert result["results"][0]["differences"] == [{"field": "path", "old": "/v1", "new": "/v2"}]


def test_diff_cli_returns_nonzero_for_regression(tmp_path, capsys):
    old_policy = tmp_path / "old.lua"
    new_policy = tmp_path / "new.lua"
    fixture = tmp_path / "request.json"
    old_policy.write_text(
        """
        return function(request, context)
          return { action = "continue" }
        end
        """,
        encoding="utf-8",
    )
    new_policy.write_text(
        """
        return function(request, context)
          return { action = "reject", status = 403 }
        end
        """,
        encoding="utf-8",
    )
    fixture.write_text(json.dumps({"path": "/in", "headers": {}}), encoding="utf-8")

    status = simulator_main(["diff", str(old_policy), str(new_policy), str(fixture), "--compact"])
    output = json.loads(capsys.readouterr().out)

    assert status == 1
    assert output["safe_to_promote"] is False
    assert output["regression_count"] == 1


def test_middleware_shadow_policy_records_candidate_without_affecting_response():
    captured = {}

    async def app(scope, receive, send):
        captured["shadow"] = scope["lua_shadow_trace"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"active response", "more_body": False})

    middleware = LuaMiddleware(
        app,
        """
        return function(request, context)
          return { action = "continue" }
        end
        """,
        shadow_script="""
        return function(request, context)
          return { action = "reject", status = 403, body = "candidate block" }
        end
        """,
        config=LuaConfig(trace=True),
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"active response"
    assert captured["shadow"]["ok"] is True
    assert captured["shadow"]["active_action"] == "continue"
    assert captured["shadow"]["shadow_action"] == "reject"
    assert captured["shadow"]["changed"] is True
    assert captured["shadow"]["regression"] is True


def run_asgi(middleware) -> list[dict[str, Any]]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/in",
        "raw_path": b"/in",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    messages = [{"type": "http.request", "body": b"", "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent

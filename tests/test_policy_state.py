from __future__ import annotations

import asyncio
import sqlite3
from typing import Any

import pytest

from asgi_lua import LuaConfig, LuaDecisionError, LuaMiddleware, MemoryStateStore, SQLiteStateStore, StateLimits


async def app(scope, receive, send):
    headers = []
    if "lua" in scope:
        headers.append((b"x-lua-seen", str(scope["lua"].get("seen")).encode("latin-1")))
    if "lua_trace" in scope:
        headers.append((b"x-state-ops", str(len(scope["lua_trace"]["state_operations"])).encode("latin-1")))
    await send({"type": "http.response.start", "status": 200, "headers": headers})
    await send({"type": "http.response.body", "body": b"ok", "more_body": False})


def test_lua_policy_can_use_memory_state():
    store = MemoryStateStore()
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context, state)
          local key = "delivery:" .. request.headers["x-delivery"]
          local seen = state.get(key)
          if seen ~= nil then
            return { action = "reject", status = 409, body = "duplicate" }
          end
          state.put(key, "seen", { ttl = 60 })
          return { action = "continue", context = { seen = false } }
        end
        """,
        config=LuaConfig(trace=True),
        state_store=store,
    )

    first = run_asgi(middleware, headers=[(b"x-delivery", b"evt-1")])
    second = run_asgi(middleware, headers=[(b"x-delivery", b"evt-1")])

    assert first[0]["status"] == 200
    assert (b"x-state-ops", b"2") in first[0]["headers"]
    assert second[0]["status"] == 409
    assert second[1]["body"] == b"duplicate"


def test_lua_policy_can_use_sqlite_state(tmp_path):
    db_path = tmp_path / "policy_state.sqlite3"
    store = SQLiteStateStore(db_path)
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context, state)
          local value = state.incr("counter", 1)
          return { action = "continue", context = { seen = value } }
        end
        """,
        config=LuaConfig(trace=True),
        state_store=store,
    )

    run_asgi(middleware)
    run_asgi(middleware)

    with sqlite3.connect(db_path) as conn:
        value = conn.execute("SELECT value FROM policy_state WHERE key = 'counter'").fetchone()[0]
    assert value == "2"


def test_state_limits_reject_excessive_operations_before_mutation():
    store = MemoryStateStore()
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context, state)
          state.put("one", "1")
          state.put("two", "2")
          return { action = "continue" }
        end
        """,
        state_store=store,
        state_limits=StateLimits(max_operations=1),
    )

    with pytest.raises(LuaDecisionError, match="operation limit"):
        run_asgi(middleware)
    assert store.get("one") == "1"
    assert store.get("two") is None


def test_state_value_limits_are_enforced():
    store = MemoryStateStore()
    middleware = LuaMiddleware(
        app,
        """
        return function(request, context, state)
          state.put("key", "too-long")
          return { action = "continue" }
        end
        """,
        state_store=store,
        state_limits=StateLimits(max_value_bytes=3),
    )

    with pytest.raises(LuaDecisionError, match="value exceeds"):
        run_asgi(middleware)
    assert store.get("key") is None


def test_shadow_policy_state_writes_are_dry_run():
    store = MemoryStateStore()
    captured = {}

    async def shadow_app(scope, receive, send):
        captured["shadow"] = scope["lua_shadow_trace"]
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    middleware = LuaMiddleware(
        shadow_app,
        """
        return function(request, context, state)
          return { action = "continue" }
        end
        """,
        shadow_script="""
        return function(request, context, state)
          state.put("candidate", "would-write")
          return { action = "continue" }
        end
        """,
        state_store=store,
    )

    sent = run_asgi(middleware)

    assert sent[0]["status"] == 200
    assert store.get("candidate") is None
    assert captured["shadow"]["shadow"]["state_operations"][0]["op"] == "put"


def run_asgi(middleware, *, headers=None) -> list[dict[str, Any]]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/in",
        "raw_path": b"/in",
        "query_string": b"",
        "headers": headers or [],
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

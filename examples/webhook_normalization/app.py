from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asgi_lua import LuaConfig, LuaMiddleware
from asgi_lua.runtime import CompiledLuaScript, compile_lua_file

BASE_DIR = Path(__file__).parent
POLICY_DIR = BASE_DIR / "policies"

POLICIES = {
    policy_path.stem: compile_lua_file(policy_path)
    for policy_path in POLICY_DIR.glob("*.lua")
}


def policy_for_scope(scope: dict[str, Any]) -> CompiledLuaScript:
    vendor = scope.get("path", "/").rstrip("/").split("/")[-1]
    return POLICIES.get(vendor, POLICIES["unknown"])


async def app(scope, receive, send):
    body = await _read_body(receive)
    response_payload = {
        "received_path": scope["path"],
        "received_headers": _headers(scope.get("headers", [])),
        "normalized_webhook": json.loads(body.decode("utf-8")),
        "normalization_context": scope.get("lua", {}),
        "policy_trace": scope.get("lua_trace", {}),
    }
    response = json.dumps(response_payload, indent=2, sort_keys=True).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": response, "more_body": False})


application = LuaMiddleware(
    app,
    policy_for_scope,
    config=LuaConfig(read_body=True, max_body_bytes=16 * 1024, trace=True),
)


async def _read_body(receive) -> bytes:
    chunks = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {name.decode("latin-1").lower(): value.decode("latin-1") for name, value in raw_headers}

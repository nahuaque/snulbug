from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from uvicorn_lua import LuaConfig, LuaMiddleware
from uvicorn_lua.runtime import CompiledLuaScript, compile_lua_file

BASE_DIR = Path(__file__).parent
POLICY_DIR = BASE_DIR / "policies"
DEFAULT_TENANT = "default"


def load_customer_policies(policy_dir: Path = POLICY_DIR) -> dict[str, CompiledLuaScript]:
    policies: dict[str, CompiledLuaScript] = {}
    for policy_path in policy_dir.glob("*.lua"):
        policies[policy_path.stem] = compile_lua_file(policy_path)
    return policies


CUSTOMER_POLICIES = load_customer_policies()


def policy_for_scope(scope: dict[str, Any]) -> CompiledLuaScript:
    headers = _headers(scope.get("headers", []))
    tenant = headers.get("x-tenant", DEFAULT_TENANT)
    return CUSTOMER_POLICIES.get(tenant, CUSTOMER_POLICIES[DEFAULT_TENANT])


async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    body = await _read_body(receive)
    payload = {
        "method": scope["method"],
        "path": scope["path"],
        "query_string": scope.get("query_string", b"").decode("latin-1"),
        "tenant_context": scope.get("lua", {}),
        "policy_trace": scope.get("lua_trace", {}),
        "body": body.decode("utf-8", errors="replace"),
    }
    response = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
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
    config=LuaConfig(read_body=True, max_body_bytes=8 * 1024, trace=True),
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

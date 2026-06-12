from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from asgi_lua import LuaConfig, LuaMiddleware, MemoryStateStore
from asgi_lua.runtime import compile_lua_file

BASE_DIR = Path(__file__).parent
POLICY_PATH = BASE_DIR.parent / "bundles" / "mcp-gateway.asgi-lua" / "policy.lua"

STATE = MemoryStateStore()
POLICY = compile_lua_file(POLICY_PATH)


async def mcp_app(scope, receive, send):
    body = await _read_body(receive)
    request = json.loads(body.decode("utf-8"))
    response = _handle_json_rpc(request, scope)
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": json.dumps(response, sort_keys=True).encode("utf-8"),
            "more_body": False,
        }
    )


application = LuaMiddleware(
    mcp_app,
    POLICY,
    config=LuaConfig(read_body=True, max_body_bytes=16 * 1024, trace=True),
    state_store=STATE,
)


def _handle_json_rpc(request: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    request_id = request.get("id")
    if method == "tools/list":
        result = {
            "tools": [
                {"name": "safe_read_file"},
                {"name": "list_project_files"},
            ],
            "gateway": scope.get("lua", {}),
            "trace": scope.get("lua_trace", {}),
        }
    elif method == "tools/call":
        tool_name = request.get("params", {}).get("name")
        result = {
            "tool": tool_name,
            "content": f"demo result from {tool_name}",
            "gateway": scope.get("lua", {}),
            "trace": scope.get("lua_trace", {}),
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "method not found"},
        }

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


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

from __future__ import annotations

import asyncio
import json
from typing import Any

from examples.mcp_gateway.app import STATE, application
from snulbug import test_bundle as run_bundle_tests
from snulbug import validate_bundle

BUNDLE = "examples/bundles/mcp-gateway.snulbug"


def test_mcp_gateway_bundle_validates_and_tests():
    validation = validate_bundle(BUNDLE)
    result = run_bundle_tests(BUNDLE)

    assert validation["ok"] is True
    assert result["ok"] is True
    assert result["passed"] == 3


def test_mcp_gateway_allows_safe_tool_call():
    reset_state()

    sent = run_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_read_file", "arguments": {"path": "README.md"}},
        },
        authorization="Bearer local-dev-secret",
    )

    payload = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 200
    assert payload["result"]["tool"] == "safe_read_file"
    assert payload["result"]["gateway"]["gateway"] == "mcp"
    assert payload["result"]["trace"]["rate_limit"]["remaining"] == 4


def test_mcp_gateway_blocks_unsafe_tool_call():
    reset_state()

    sent = run_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "shell_exec", "arguments": {"cmd": "rm -rf /"}},
        },
        authorization="Bearer local-dev-secret",
    )

    assert sent[0]["status"] == 403
    assert sent[1]["body"] == b"MCP tool not allowed: shell_exec"


def test_mcp_gateway_challenges_unauthenticated_request():
    reset_state()

    sent = run_mcp_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {},
        }
    )

    assert sent[0]["status"] == 401
    assert (b"www-authenticate", b'Bearer, realm="local-mcp", error="invalid_token"') in sent[0]["headers"]
    assert sent[1]["body"] == b"MCP gateway token required"


def test_mcp_gateway_rate_limits_allowed_calls():
    reset_state()
    request = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "list_project_files", "arguments": {}},
    }

    responses = [run_mcp_request(request, authorization="Bearer local-dev-secret") for _ in range(6)]

    assert responses[0][0]["status"] == 200
    assert responses[4][0]["status"] == 200
    assert responses[5][0]["status"] == 429
    assert (b"x-ratelimit-limit", b"5") in responses[5][0]["headers"]
    assert (b"x-ratelimit-remaining", b"0") in responses[5][0]["headers"]
    assert responses[5][1]["body"] == b"too many MCP calls"


def run_mcp_request(payload: dict[str, Any], *, authorization: str | None = None) -> list[dict[str, Any]]:
    headers = [(b"content-type", b"application/json")]
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    messages = [{"type": "http.request", "body": json.dumps(payload).encode("utf-8"), "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(application(scope, receive, send))
    return sent


def reset_state() -> None:
    STATE._items.clear()

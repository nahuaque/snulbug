from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

import pytest
from test_mcp_protocol import post, running_gateway

from snulbug.mcp_cache import CACHEABLE_METHODS, McpCacheMiddleware, private_result
from snulbug.mcp_protocol import DEFAULT_MCP_PROTOCOL_VERSION, LATEST_MCP_SPEC_VERSION, mcp_request
from snulbug.proxy import create_proxy_application


@pytest.mark.parametrize("method", sorted(CACHEABLE_METHODS))
@pytest.mark.parametrize(
    "hints",
    [
        {},
        {"ttlMs": 10000, "cacheScope": "public"},
        {"ttlMs": -1, "cacheScope": "private"},
        {"ttlMs": True, "cacheScope": []},
        {"ttlMs": "secret-value", "cacheScope": {"secret": "value"}},
        {"ttlMs": 1.5, "cacheScope": "invalid"},
        {"ttlMs": 0, "cacheScope": "private"},
    ],
)
def test_cacheable_results_are_private_and_stale(method, hints):
    payload = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "contents": [], **hints}}
    body, metadata = private_result(json.dumps(payload).encode(), method)
    result = json.loads(body)["result"]
    assert result == {"resultType": "complete", "contents": [], "ttlMs": 0, "cacheScope": "private"}
    assert "secret-value" not in json.dumps(metadata)
    assert metadata["cache_scope"] == "private"


def test_noncacheable_and_interim_results_do_not_gain_hints():
    for method, result_type in [
        ("tools/call", "complete"),
        ("resources/read", "input_required"),
        ("subscriptions/listen", "complete"),
    ]:
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": result_type, "requestState": "opaque"}}
        original = json.dumps(payload).encode()
        assert private_result(original, method) == (original, {})
        payload["result"].update(ttlMs=5000, cacheScope="public")
        body, _ = private_result(json.dumps(payload).encode(), method)
        assert json.loads(body) == json.loads(original)
    for body in (b"not json", b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}'):
        assert private_result(body, "tools/list") == (body, {})


@pytest.mark.parametrize("facade", [False, True])
@pytest.mark.parametrize("sse", [False, True])
def test_live_resource_results_and_continuations_recheck_upstream(tmp_path, facade, sse):
    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen.append(request)
            result = {
                "resultType": "complete",
                "contents": [{"uri": "file:///project/readme", "text": "hello"}],
                "ttlMs": 60000,
                "cacheScope": "public",
            }
            body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
            if sse:
                body = b"data: " + body + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if sse else "application/json")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("ETag", '"shared"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    policy = tmp_path / "policy.lua"
    policy.write_text(
        'return function(request) if request.headers["x-deny"] then '
        'return {action="reject", status=403, body="{}"} end return {action="continue"} end'
    )
    app = create_proxy_application(
        None if facade else origin,
        policy,
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        lease_required=False,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
        record_out=tmp_path / "records.jsonl",
    )
    try:
        with running_gateway(app) as url:
            for extra in ({}, {"requestState": "opaque", "inputResponses": {}}):
                payload = mcp_request(
                    "resources/read",
                    version=LATEST_MCP_SPEC_VERSION,
                    request_id=1,
                    params={"uri": "file:///project/readme", **extra},
                )
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
                    "Mcp-Method": "resources/read",
                    "Mcp-Name": "file:///project/readme",
                }
                with urlopen(Request(url, data=json.dumps(payload).encode(), headers=headers), timeout=5) as response:
                    assert response.headers["Cache-Control"] == "no-store"
                    assert response.headers.get("ETag") is None
                    body = response.read()
                    result = json.loads(body.removeprefix(b"data: ").strip())["result"]
                    assert result["cacheScope"] == "private"
                    assert result["ttlMs"] == 0
            assert len(seen) == 2
            status, _ = post(url, payload, **{"x-deny": "1"})
            assert status == 403
            assert len(seen) == 2
            headers = {}
            status, discovery = post(
                url,
                mcp_request("server/discover", version=LATEST_MCP_SPEC_VERSION, request_id=2),
                response_headers=headers,
            )
            assert status == 200
            assert discovery["result"]["cacheScope"] == "private"
            assert headers["cache-control"] == "no-store"
        records = [json.loads(line) for line in (tmp_path / "records.jsonl").read_text().splitlines()]
        metadata = records[0]["metadata"]
        cache = metadata["stream"]["cache"] if sse else metadata["cache"]
        assert cache["hints_changed"] is True
        assert cache["hints_valid"] is True
        assert cache["ttl_ms"] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("limit", [1024, 8])
def test_final_json_boundary_handles_chunks_and_local_policy_responses(limit):
    messages, metadata = [], []
    request = mcp_request("tools/list", version=LATEST_MCP_SPEC_VERSION, request_id=1)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resultType": "complete", "tools": [], "ttlMs": 1000, "cacheScope": "public"},
        }
    ).encode()

    async def app(scope, receive, send):
        await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"public"),
                    (b"etag", b"shared"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body[:30], "more_body": True})
        await send({"type": "http.response.body", "body": body[30:], "more_body": False})

    async def receive():
        return {"type": "http.request", "body": json.dumps(request).encode()}

    async def send(message):
        messages.append(message)

    middleware = McpCacheMiddleware(
        app, endpoint="/mcp", limit=limit, metadata_callback=lambda scope, value: metadata.append(value)
    )
    asyncio.run(middleware({"type": "http", "method": "POST", "path": "/mcp"}, receive, send))
    assert len(messages) == 2
    assert messages[0]["status"] == (200 if limit == 1024 else 502)
    headers = dict(messages[0]["headers"])
    assert headers[b"cache-control"] == b"no-store"
    assert b"etag" not in headers
    assert int(headers[b"content-length"]) == len(messages[1]["body"])
    if limit == 1024:
        assert json.loads(messages[1]["body"])["result"]["ttlMs"] == 0
    assert metadata


@pytest.mark.parametrize("version", [DEFAULT_MCP_PROTOCOL_VERSION, LATEST_MCP_SPEC_VERSION])
def test_local_lua_result_is_sealed_only_for_modern_profile(tmp_path, version):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resultType": "complete", "tools": [], "ttlMs": 1000, "cacheScope": "public"},
        }
    )
    policy = tmp_path / "policy.lua"
    policy.write_text(
        'return function(request) return {action="respond", status=200, '
        'headers={["content-type"]="application/json", ["cache-control"]="public, max-age=60", etag="shared"}, body=[=['
        + body
        + "]=]} end"
    )
    app = create_proxy_application(
        "http://127.0.0.1:1", policy, lease_required=False, streamable_http_protocol_version=version
    )
    with running_gateway(app) as url:
        headers = {}
        status, response = post(
            url,
            mcp_request("tools/list", version=version, request_id=1),
            response_headers=headers,
            **{"MCP-Protocol-Version": version},
        )
    assert status == 200
    if version == LATEST_MCP_SPEC_VERSION:
        assert response["result"]["ttlMs"] == 0
        assert response["result"]["cacheScope"] == "private"
        assert headers["cache-control"] == "no-store"
        assert "etag" not in headers
    else:
        assert response == json.loads(body)
        assert headers["cache-control"] == "public, max-age=60"
        assert headers["etag"] == "shared"

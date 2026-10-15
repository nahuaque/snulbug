from __future__ import annotations

import asyncio
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen

import httpx
import pytest
from test_mcp_protocol import running_gateway

from snulbug.config import load_mcp_proxy_config
from snulbug.http_routes import HttpRoutesMiddleware, normalize_http_routes
from snulbug.proxy import create_proxy_application, proxy_config_run_kwargs
from snulbug.simulator import main


@pytest.fixture
def web_backend():
    seen = []
    release = threading.Event()

    class Backend(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.respond()

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_GET

        def respond(self):
            if self.headers.get("transfer-encoding") == "chunked":
                chunks = []
                while size := int(self.rfile.readline().strip(), 16):
                    chunks.append(self.rfile.read(size))
                    self.rfile.read(2)
                self.rfile.read(2)
                body = b"".join(chunks)
            else:
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
            seen.append({"method": self.command, "path": self.path, "headers": self.headers, "body": body})
            self.send_response(200)
            if self.path == "/stream":
                self.send_header("content-type", "text/event-stream")
                self.send_header("transfer-encoding", "chunked")
                self.end_headers()
                try:
                    self.wfile.write(b"5\r\nhello\r\n")
                    self.wfile.flush()
                    release.wait(5)
                    self.wfile.write(b"5\r\nworld\r\n0\r\n\r\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            payload = gzip.compress(b"<html>app secret-token is not MCP content</html>")
            self.send_header("content-type", "text/html")
            self.send_header("content-encoding", "gzip")
            self.send_header("content-length", str(len(payload)))
            self.send_header("set-cookie", "session=one; Path=/app; HttpOnly")
            self.send_header("set-cookie", "other=two; Path=/app")
            self.send_header("connection", "x-hop")
            self.send_header("x-hop", "not end-to-end")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(5)


def gateway(tmp_path, backend, **kwargs):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return {action="reject", status=403, body="MCP policy ran"} end')
    routes = kwargs.pop("http_routes", [{"prefix": "/app", "upstream": backend}])
    facade = kwargs.pop("facade", False)
    return create_proxy_application(
        None if facade else "http://127.0.0.1:1",
        policy,
        http_routes=routes,
        upstreams=[{"name": "mcp", "url": "http://127.0.0.1:1/mcp"}] if facade else None,
        **kwargs,
    )


def request(app, method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://public.test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@pytest.mark.parametrize("facade", [False, True], ids=["proxy", "facade"])
def test_web_routes_bypass_all_mcp_layers_and_preserve_http(tmp_path, web_backend, method, facade):
    backend, seen, _ = web_backend
    records = tmp_path / "records.jsonl"
    audit = tmp_path / "audit.jsonl"
    app = gateway(
        tmp_path,
        backend,
        facade=facade,
        max_body_bytes=10,
        response_max_bytes=10,
        record_out=records,
        event_sinks=[{"type": "audit_jsonl", "path": str(audit)}],
        lease_file=tmp_path / "leases.json",
        lease_header="x-task-lease",
        cloudflare_access="enforce",
        auth_config={
            "mode": "oauth-resource",
            "issuer": "https://issuer.invalid",
            "resource": "https://public.test/mcp",
            "audience": "https://public.test/mcp",
            "jwks_url": "https://issuer.invalid/jwks",
        },
    )
    body = b"name=large+form&value=" + b"x" * 70000
    response = request(
        app,
        method,
        "/app/files/a%2Fb%20c?q=a%2Fb&q=2",
        content=body,
        headers=[
            ("content-type", "application/x-www-form-urlencoded"),
            ("authorization", "Basic app-credential"),
            ("x-task-lease", "lease-secret"),
            ("x-snulbug-invite", "invite-secret"),
            ("dpop", "mcp-proof"),
            ("connection", "x-private"),
            ("x-private", "hop-secret"),
            ("x-forwarded-host", "spoofed.test"),
            ("x-forwarded-for", "spoofed"),
            ("x-test", "first"),
            ("x-test", "second"),
        ],
    )
    assert response.status_code == 200
    if method != "HEAD":
        assert response.content == b"<html>app secret-token is not MCP content</html>"
    assert len(response.headers.get_list("set-cookie")) == 2
    assert "x-hop" not in response.headers
    incoming = seen[0]
    assert incoming["method"] == method
    assert incoming["path"] == "/files/a%2Fb%20c?q=a%2Fb&q=2"
    assert incoming["body"] == body
    assert incoming["headers"]["host"] == backend.removeprefix("http://")
    assert incoming["headers"]["authorization"] == "Basic app-credential"
    assert incoming["headers"].get_all("x-test") == ["first", "second"]
    for name in ("x-task-lease", "x-snulbug-invite", "dpop", "x-private"):
        assert incoming["headers"].get(name) is None
    assert incoming["headers"]["x-forwarded-host"] == "public.test"
    assert incoming["headers"]["x-forwarded-for"] == "127.0.0.1"
    assert incoming["headers"]["x-forwarded-prefix"] == "/app"
    assert not records.exists()
    assert not audit.exists()
    # The same factory still enforces MCP authentication on the MCP endpoint.
    assert request(
        app,
        "POST",
        "/mcp",
        json={},
        headers={
            "accept": "application/json, text/event-stream",
        },
    ).status_code in {401, 403}
    assert len(seen) == 1


@pytest.mark.parametrize("path,expected", [("/app", "/base/"), ("/app/", "/base/"), ("/app/x", "/base/x")])
def test_strip_prefix_and_backend_base_path(tmp_path, web_backend, path, expected):
    backend, seen, _ = web_backend
    app = gateway(tmp_path, backend + "/base")
    assert request(app, "GET", path).status_code == 200
    assert seen[0]["path"] == expected


def test_longest_segment_prefix_wins_and_preserved_prefix_is_supported(tmp_path, web_backend):
    backend, seen, _ = web_backend
    app = gateway(
        tmp_path,
        backend,
        http_routes=[
            {"prefix": "/app", "upstream": backend, "strip_prefix": False},
            {"prefix": "/app/api", "upstream": backend + "/v1"},
        ],
    )
    assert request(app, "GET", "/app/assets/main.js").status_code == 200
    assert request(app, "GET", "/app/api/items").status_code == 200
    assert [item["path"] for item in seen] == ["/app/assets/main.js", "/v1/items"]
    for path in ("/application", "/app-other", "/mcp/tools", "/unknown"):
        assert request(app, "GET", path).status_code == 403
    assert request(app, "GET", "/mcp").status_code == 405
    response = request(
        app,
        "POST",
        "/mcp",
        json={"method": "tools/list"},
        headers={
            "accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 403
    assert response.text == "MCP policy ran"
    assert len(seen) == 2


def test_form_upload_streams_without_mcp_body_limit(tmp_path, web_backend):
    backend, seen, _ = web_backend
    app = gateway(tmp_path, backend, max_body_bytes=10)

    async def chunks():
        for _ in range(4):
            yield b"x" * 65536

    response = request(app, "POST", "/app/upload", content=chunks())
    assert response.status_code == 200
    assert len(seen[0]["body"]) == 4 * 65536


def test_http_stream_is_live_without_mcp_response_buffering(tmp_path, web_backend):
    backend, _, release = web_backend
    app = gateway(tmp_path, backend)
    with running_gateway(app) as mcp_url:
        try:
            with urlopen(mcp_url.removesuffix("/mcp") + "/app/stream", timeout=3) as response:
                assert response.read(5) == b"hello"
                release.set()
                assert response.read() == b"world"
        finally:
            release.set()


def test_disconnect_cancels_stream_and_closes_backend(monkeypatch):
    async def run():
        disconnected = asyncio.Event()
        closed = asyncio.Event()
        request_sent = False
        sent = []

        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"first chunk"
                await asyncio.Event().wait()

            async def aclose(self):
                closed.set()

        async def backend(request):
            return httpx.Response(200, stream=Stream())

        original = httpx.AsyncClient
        monkeypatch.setattr(
            "snulbug.http_routes.httpx.AsyncClient",
            lambda **kw: original(
                transport=httpx.MockTransport(backend),
                **kw,
            ),
        )

        async def fallback(*args):
            pytest.fail("HTTP route entered MCP stack")

        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b""}
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)
            if message.get("body"):
                disconnected.set()

        app = HttpRoutesMiddleware(fallback, [{"prefix": "/app", "upstream": "http://backend.test"}])
        await asyncio.wait_for(app({"type": "http", "method": "GET", "path": "/app/"}, receive, send), 2)
        assert closed.is_set()
        assert sent[1]["body"] == b"first chunk"
        assert len(sent) == 2
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    asyncio.run(run())


def test_upstream_timeout_is_plain_http_504(tmp_path, monkeypatch):
    async def backend(request):
        raise httpx.ReadTimeout("private upstream details")

    original = httpx.AsyncClient

    def client(**kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(backend))
        return original(**kwargs)

    monkeypatch.setattr("snulbug.http_routes.httpx.AsyncClient", client)
    response = request(gateway(tmp_path, "http://backend.test"), "GET", "/app/")
    assert response.status_code == 504
    assert response.text == "HTTP route upstream timed out"


def test_upstream_connection_failure_is_plain_http_502(tmp_path):
    app = gateway(tmp_path, "http://127.0.0.1:1")
    response = request(app, "GET", "/app/")
    assert response.status_code == 502
    assert response.text == "HTTP route upstream unavailable"


@pytest.mark.parametrize(
    "prefix",
    [
        "/",
        "/mcp",
        "/mcp/tools",
        "/.well-known",
        "/.well-known/x",
        "/snulbug",
        "/app/../mcp",
        "/app//api",
        "/app%2fapi",
        "app",
        "/app?x=1",
        "/app#x",
        "/app\\x",
    ],
)
def test_invalid_or_reserved_prefixes_are_rejected(prefix):
    with pytest.raises(ValueError):
        normalize_http_routes([{"prefix": prefix, "upstream": "http://127.0.0.1:3000"}])


@pytest.mark.parametrize(
    "upstream",
    [
        "ftp://localhost",
        "http://user:password@localhost",
        "http://localhost?q=1",
        "http://localhost#fragment",
        "http://localhost:0",
        "http://localhost:bad",
        "http://",
        "//localhost",
    ],
)
def test_invalid_backend_urls_are_rejected(upstream):
    with pytest.raises(ValueError):
        normalize_http_routes([{"prefix": "/app", "upstream": upstream}])


@pytest.mark.parametrize(
    "route",
    [
        {"prefix": "/app", "upstream": "http://localhost", "strip_prefix": "false"},
        {"prefix": "/app", "upstream": "http://localhost", "typo": True},
        "http://localhost",
    ],
)
def test_invalid_route_shapes_are_rejected(route):
    with pytest.raises(ValueError):
        normalize_http_routes([route])


def test_config_validation_preserves_mcp_and_rejects_duplicates(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text("""[mcp.proxy]
streamable_http_endpoint_path = "/rpc/mcp"
[[mcp.proxy.http_routes]]
prefix = "/app/"
upstream = "http://127.0.0.1:3000"
strip_prefix = false
""")
    loaded = load_mcp_proxy_config(config)
    assert proxy_config_run_kwargs(loaded)["http_routes"] == [
        {"prefix": "/app", "upstream": "http://127.0.0.1:3000", "strip_prefix": False}
    ]
    with pytest.raises(ValueError, match="overlaps"):
        normalize_http_routes([{"prefix": "/rpc", "upstream": "http://localhost"}], mcp_path="/rpc/mcp")
    with pytest.raises(ValueError, match="duplicate"):
        normalize_http_routes([loaded["http_routes"][0], {**loaded["http_routes"][0], "prefix": "/app/"}])


def test_share_create_cli_writes_routes_and_ngrok_guards(tmp_path, capsys):
    assert (
        main(
            [
                "mcp",
                "share",
                "create",
                "--directory",
                str(tmp_path),
                "--provider",
                "ngrok",
                "--url",
                "https://share.ngrok-free.dev/mcp",
                "--http-route",
                "/app=http://127.0.0.1:3000",
                "--http-route",
                "/api=http://127.0.0.1:4000",
                "--no-validate",
                "--compact",
            ]
        )
        == 0
    )
    capsys.readouterr()
    config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    assert [item["prefix"] for item in config["http_routes"]] == ["/app", "/api"]
    text = (tmp_path / "tunnel/ngrok-traffic-policy.yml").read_text()
    expressions = [
        json.loads(line.removeprefix("      - ")) for line in text.splitlines() if line.startswith('      - "')
    ]
    assert 'req.url.path.startsWith("/app/")' in expressions[0]
    assert 'req.url.path == "/app"' in expressions[0]
    assert 'req.url.path.startsWith("/api/")' in expressions[0]
    assert expressions.count('req.url.path == "/mcp"') == 4
    assert "!hasReqHeader('Authorization')" in expressions
    assert "type: forward-internal" in text


def test_websocket_routes_fail_explicitly_without_entering_mcp(tmp_path):
    app = gateway(tmp_path, "http://127.0.0.1:3000")
    sent = []

    async def run():
        async def send(message):
            sent.append(message)

        await app({"type": "websocket", "path": "/app/socket"}, None, send)

    asyncio.run(run())
    assert sent[0]["type"] == "websocket.close"
    assert sent[0]["code"] == 1008


@pytest.mark.parametrize("path,raw_path", [("/app/../mcp", b"/app/%2e%2e/mcp"), ("/app/x", b"/%61pp/x")])
def test_ambiguous_paths_cannot_bypass_route_boundaries(tmp_path, path, raw_path):
    app = gateway(tmp_path, "http://backend.test")
    sent = []

    async def run():
        async def send(message):
            sent.append(message)

        await app({"type": "http", "method": "GET", "path": path, "raw_path": raw_path}, None, send)

    asyncio.run(run())
    assert sent[0]["status"] == 400

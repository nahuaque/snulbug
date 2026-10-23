from __future__ import annotations

import asyncio

import pytest

from snulbug.config import normalize_mcp_proxy_config
from snulbug.public_origin import PublicOriginMiddleware, captured_origin_matches, public_origin


@pytest.mark.parametrize(
    "value,expected,port",
    [
        ("https://Share.Example/mcp", "https://share.example", 443),
        ("https://share.example:443/rpc/mcp", "https://share.example", 443),
        ("http://localhost:80/mcp", "http://localhost", 80),
        ("https://share.example:8443/mcp", "https://share.example:8443", 8443),
        ("http://127.0.0.1:8080/mcp", "http://127.0.0.1:8080", 8080),
        ("http://[::1]:8080/mcp", "http://[::1]:8080", 8080),
        ("https://xn--bcher-kva.example/mcp", "https://xn--bcher-kva.example", 443),
    ],
)
def test_public_origin_is_canonical_and_drops_only_the_mcp_path(value, expected, port):
    origin = public_origin(value)
    assert origin.url == expected
    assert origin.port == port
    assert dict(origin.headers())[b"x-forwarded-port"] == str(port).encode()
    assert normalize_mcp_proxy_config({"tunnel_public_url": value})["tunnel_public_url"] == value


@pytest.mark.parametrize(
    "value",
    [
        "https://user:secret@share.example/mcp",
        "https://share.example/mcp?token=secret",
        "https://share.example/mcp#fragment",
        "https://share.example/mcp?",
        "https://share.example/mcp#",
        "https://share.example,evil.test/mcp",
        "https://share.example:0/mcp",
        "https://share.example:/mcp",
        "https://share.example:65536/mcp",
        "https://share.example:bad/mcp",
        "//share.example/mcp",
        "https:///mcp",
        "file:///tmp/mcp",
        "https://share.example\n/mcp",
        "https://share.example\t/mcp",
        "https://share.example\\evil.test/mcp",
        "https://*.example/mcp",
        "https://a..example/mcp",
        "https://-a.example/mcp",
        "https://a%2eexample/mcp",
    ],
)
def test_unsafe_public_urls_fail_at_config_load_without_echoing_values(value):
    with pytest.raises(ValueError, match="tunnel_public_url") as exc:
        normalize_mcp_proxy_config({"tunnel_public_url": value})
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize(
    "headers,expected",
    [
        ([], True),
        ([(b"x-snulbug-original-host", b"Share.Example:443"), (b"x-snulbug-original-proto", b"https")], True),
        ([(b"x-snulbug-original-host", b"evil.test"), (b"x-snulbug-original-proto", b"https")], False),
        ([(b"x-snulbug-original-host", b"share.example")], False),
        ([(b"x-snulbug-original-proto", b"https")], False),
        ([(b"x-snulbug-original-host", b"share.example/path"), (b"x-snulbug-original-proto", b"https")], False),
        ([(b"x-snulbug-original-host", b"share.example, evil.test"), (b"x-snulbug-original-proto", b"https")], False),
        ([(b"x-snulbug-original-host", b"share.example"), (b"x-snulbug-original-proto", b"http")], False),
        ([(b"x-snulbug-original-host", b"share.example:8443"), (b"x-snulbug-original-proto", b"https")], False),
        (
            [
                (b"x-snulbug-original-host", b"share.example"),
                (b"x-snulbug-original-proto", b"https"),
                (b"X-Snulbug-Original-Host", b"share.example"),
            ],
            False,
        ),
    ],
)
def test_captured_origin_is_only_a_consistency_check_not_a_source(headers, expected):
    assert captured_origin_matches(headers, public_origin("https://share.example/mcp")) is expected


def test_middleware_rebuilds_headers_without_changing_auth_resource_or_asgi_origin():
    from snulbug.tunnel import TunnelAuditConfig, build_tunnel_audit_metadata

    scopes = []
    messages = []

    async def app(scope, receive, send):
        scopes.append(scope)

    async def unused():
        pytest.fail("middleware read a request body")

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "scheme": "http",
        "path": "/mcp",
        "client": ("127.0.0.1", 3000),
        "headers": [
            (b"host", b"snulbug-mcp.internal"),
            (b"authorization", b"Bearer client-token"),
            (b"dpop", b"proof"),
            (b"forwarded", b"host=evil.test;proto=http"),
            (b"x-forwarded-host", b"evil.test"),
            (b"x-forwarded-proto", b"http"),
            (b"x-forwarded-port", b"1234"),
            (b"x-forwarded-prefix", b"/evil"),
            (b"x-snulbug-original-host", b"share.example"),
            (b"x-snulbug-original-proto", b"https"),
        ],
    }
    original_headers = list(scope["headers"])
    asyncio.run(PublicOriginMiddleware(app, public_url="https://share.example/mcp")(scope, unused, send))
    result = scopes[0]
    headers = dict(result["headers"])
    assert result["scheme"] == "http"
    assert headers[b"host"] == b"snulbug-mcp.internal"
    assert headers[b"authorization"] == b"Bearer client-token"
    assert headers[b"dpop"] == b"proof"
    assert headers[b"x-forwarded-host"] == b"share.example"
    assert headers[b"x-forwarded-proto"] == b"https"
    assert headers[b"x-forwarded-port"] == b"443"
    assert headers[b"x-forwarded-for"] == b"127.0.0.1"
    for key in (b"forwarded", b"x-forwarded-prefix", b"x-snulbug-original-host", b"x-snulbug-original-proto"):
        assert key not in headers
    assert scope["headers"] == original_headers
    assert not messages
    observation = build_tunnel_audit_metadata(result, config=TunnelAuditConfig(public_url="https://share.example/mcp"))
    assert observation["public_host"] == "share.example"
    assert observation["forwarded_host"] == "evil.test"
    assert headers[b"x-forwarded-host"] != observation["forwarded_host"].encode()


def test_invalid_capture_rejects_before_dispatch_without_reflection_or_body_reads():
    messages = []

    async def unused(*args):
        pytest.fail("invalid origin reached the app or read a body")

    async def send(message):
        messages.append(message)

    asyncio.run(
        PublicOriginMiddleware(unused, public_url="https://share.example/mcp")(
            {"type": "http", "headers": [(b"x-snulbug-original-host", b"secret.evil.test")]}, unused, send
        )
    )
    assert messages[0]["status"] == 400
    assert messages[1]["body"] == b"Invalid captured public origin"


def test_without_public_origin_no_capture_header_is_trusted():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope)

    scope = {"type": "http", "headers": [(b"host", b"localhost"), (b"x-snulbug-original-host", b"evil.test")]}
    asyncio.run(PublicOriginMiddleware(app)(scope, None, None))
    assert seen[0]["headers"] == [(b"host", b"localhost")]


def test_mcp_upstream_receives_canonical_metadata_but_keeps_its_backend_host(tmp_path):
    import json

    from test_proxy import run_asgi, start_upstream, write_policy

    from snulbug.proxy import create_proxy_application

    server, seen = start_upstream()
    try:
        app = create_proxy_application(
            f"http://127.0.0.1:{server.server_port}",
            write_policy(tmp_path, "continue"),
            tunnel_public_url="https://share.example/mcp",
        )
        sent = run_asgi(
            app,
            headers=[
                (b"content-type", b"application/json"),
                (b"host", b"snulbug-mcp.internal"),
                (b"x-snulbug-original-host", b"share.example"),
                (b"x-snulbug-original-proto", b"https"),
                (b"x-forwarded-host", b"evil.test"),
                (b"x-original-host", b"evil.test"),
            ],
            body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        )
        assert sent[0]["status"] == 200
        headers = json.loads(sent[1]["body"])["headers"]
        assert headers["host"] == f"127.0.0.1:{server.server_port}"
        assert headers["x-forwarded-host"] == "share.example"
        assert headers["x-forwarded-proto"] == "https"
        assert headers["x-forwarded-port"] == "443"
        assert "x-snulbug-original-host" not in headers
        assert "x-original-host" not in headers
        assert seen["count"] == 1
    finally:
        server.shutdown()
        server.server_close()

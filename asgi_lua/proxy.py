from __future__ import annotations

import asyncio
import http.client
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .middleware import ASGIApp, LuaConfig, LuaMiddleware, Receive, Scope, Send
from .state import MemoryStateStore, PolicyStateStore, SQLiteStateStore, StateLimits

HOP_BY_HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}


@dataclass(frozen=True)
class ProxyConfig:
    upstream: str
    timeout: float = 30.0


class ReverseProxyApp:
    """Minimal ASGI reverse proxy app for local-dev policy gateways."""

    def __init__(self, upstream: str, *, timeout: float = 30.0) -> None:
        parsed = urlsplit(upstream)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("upstream must be an absolute http:// or https:// URL")
        self.config = ProxyConfig(upstream=upstream.rstrip("/"), timeout=timeout)
        self._upstream = parsed

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await _send_response(send, status=404, headers=[], body=b"unsupported scope type")
            return

        body = await _read_body(receive)
        try:
            response = await asyncio.to_thread(self._forward, scope, body)
        except Exception as exc:
            await _send_response(
                send,
                status=502,
                headers=[(b"content-type", b"text/plain; charset=utf-8")],
                body=f"upstream request failed: {exc}".encode("utf-8", errors="replace"),
            )
            return

        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )

    def _forward(self, scope: Scope, body: bytes) -> dict[str, Any]:
        connection = self._connection()
        try:
            target = self._target(scope)
            headers = _request_headers(scope.get("headers", []), self._upstream)
            connection.request(str(scope.get("method", "GET")), target, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            return {
                "status": int(response.status),
                "headers": _response_headers(response.getheaders()),
                "body": response_body,
            }
        finally:
            connection.close()

    def _connection(self) -> http.client.HTTPConnection:
        host = self._upstream.hostname
        if host is None:
            raise ValueError("upstream host is required")
        port = self._upstream.port
        if self._upstream.scheme == "https":
            return http.client.HTTPSConnection(host, port=port, timeout=self.config.timeout)
        return http.client.HTTPConnection(host, port=port, timeout=self.config.timeout)

    def _target(self, scope: Scope) -> str:
        upstream_path = self._upstream.path.rstrip("/")
        request_path = str(scope.get("path", "/"))
        path = f"{upstream_path}{request_path}" if upstream_path else request_path
        query_string = scope.get("query_string", b"")
        if isinstance(query_string, bytes):
            query = query_string.decode("latin-1")
        else:
            query = str(query_string)
        return f"{path}?{query}" if query else path


def create_proxy_application(
    upstream: str,
    policy: str | Path,
    *,
    state_store: PolicyStateStore | None = None,
    state_limits: StateLimits | None = None,
    trace: bool = True,
    max_body_bytes: int = 64 * 1024,
    timeout: float = 30.0,
) -> ASGIApp:
    """Create an ASGI app that applies Lua policy before proxying to an upstream."""

    proxy = ReverseProxyApp(upstream, timeout=timeout)
    return LuaMiddleware(
        proxy,
        Path(policy),
        config=LuaConfig(read_body=True, max_body_bytes=max_body_bytes, trace=trace),
        state_store=state_store if state_store is not None else MemoryStateStore(),
        state_limits=state_limits,
    )


def run_proxy(
    *,
    upstream: str,
    policy: str | Path,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    trace: bool = True,
    max_body_bytes: int = 64 * 1024,
    timeout: float = 30.0,
) -> None:
    """Run the reverse proxy with uvicorn."""

    try:
        import uvicorn  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError('reverse proxy mode requires uvicorn; install with `pip install "asgi-lua[proxy]"`') from exc

    app = create_proxy_application(
        upstream,
        policy,
        state_store=_state_store(state),
        trace=trace,
        max_body_bytes=max_body_bytes,
        timeout=timeout,
    )
    uvicorn.run(app, host=host, port=port)


def _state_store(value: str) -> PolicyStateStore | None:
    if value == "none":
        return None
    if value == "memory":
        return MemoryStateStore()
    if value.startswith("sqlite:"):
        return SQLiteStateStore(value.removeprefix("sqlite:"))
    raise ValueError("state must be 'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")


def _request_headers(raw_headers: list[tuple[bytes, bytes]], upstream: SplitResult) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw_headers:
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS or lower_name == b"host":
            continue
        headers[name.decode("latin-1")] = value.decode("latin-1")
    headers["Host"] = upstream.netloc
    return headers


def _response_headers(raw_headers: list[tuple[str, str]]) -> list[tuple[bytes, bytes]]:
    headers = []
    for name, value in raw_headers:
        encoded_name = name.encode("latin-1").lower()
        if encoded_name in HOP_BY_HOP_HEADERS:
            continue
        headers.append((name.encode("latin-1"), value.encode("latin-1")))
    return headers


async def _read_body(receive: Receive) -> bytes:
    chunks = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _send_response(send: Send, *, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})

"""Explicit HTTP mounts outside the MCP middleware stack."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit

import httpx

from .public_origin import public_origin

if TYPE_CHECKING:
    from .middleware import ASGIApp, Receive, Scope, Send

HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}
DEFAULT_HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
HTTP_ROUTE_FIELDS = {
    "prefix",
    "upstream",
    "strip_prefix",
    "auth",
    "methods",
    "forward_authorization",
    "forward_cookies",
    "preserve_host",
    "timeout",
    "health_path",
    "health_status",
}


class _ClientDisconnected(Exception):
    pass


def path_matches(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def normalize_http_routes(routes: Any, *, mcp_path: str = "/mcp") -> list[dict[str, Any]]:
    if not isinstance(routes, (list, tuple)):
        raise ValueError("mcp.proxy.http_routes must be an array of tables")
    reserved = (mcp_path.rstrip("/") or "/", "/.well-known", "/snulbug")
    result = []
    prefixes = set()
    for route in routes:
        if not isinstance(route, Mapping) or set(route) - HTTP_ROUTE_FIELDS:
            raise ValueError("HTTP route contains unsupported fields")
        prefix = route.get("prefix")
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or not prefix.isascii()
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in prefix)
            or any(char in prefix for char in ("?", "#", "%", "\\"))
            or quote(prefix, safe="/:@!$&'()*+,;=-._~") != prefix
            or "//" in prefix
            or any(segment in {".", ".."} for segment in prefix.split("/"))
        ):
            raise ValueError("HTTP route prefix must be an absolute, unescaped URL path")
        prefix = prefix.rstrip("/")
        if not prefix or any(
            item == "/" or path_matches(prefix, item) or path_matches(item, prefix) for item in reserved
        ):
            raise ValueError("HTTP route prefix overlaps MCP or reserved gateway paths")
        if prefix in prefixes:
            raise ValueError(f"duplicate HTTP route prefix: {prefix}")
        upstream = route.get("upstream")
        if not isinstance(upstream, str) or any(char.isspace() or ord(char) < 32 for char in upstream):
            raise ValueError("HTTP route upstream must be an absolute http:// or https:// URL")
        try:
            parsed = urlsplit(upstream)
            port = parsed.port
            httpx.URL(upstream)
        except (ValueError, httpx.InvalidURL) as exc:
            raise ValueError("invalid HTTP route upstream URL") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "\\" in upstream
            or port == 0
        ):
            raise ValueError("HTTP route upstream requires HTTP(S), without credentials, query, or fragment")
        strip = route.get("strip_prefix", True)
        if not isinstance(strip, bool):
            raise ValueError("HTTP route strip_prefix must be a boolean")
        prefixes.add(prefix)
        normalized = {"prefix": prefix, "upstream": upstream.rstrip("/"), "strip_prefix": strip}
        normalized.update(_normalize_contract(route))
        result.append(normalized)
    return result


def _normalize_contract(route: Mapping[str, Any]) -> dict[str, Any]:
    contract = {key: value for key, value in route.items() if key not in {"prefix", "upstream", "strip_prefix"}}
    if "auth" in contract and (not isinstance(contract["auth"], str) or contract["auth"] not in {"public", "upstream"}):
        raise ValueError("HTTP route auth must be 'public' or 'upstream'; MCP auth does not protect HTTP mounts")
    for key in ("forward_authorization", "forward_cookies", "preserve_host"):
        if key in contract and not isinstance(contract[key], bool):
            raise ValueError(f"HTTP route {key} must be a boolean")
    if "methods" in contract:
        methods = contract["methods"]
        if (
            not isinstance(methods, list | tuple)
            or not methods
            or any(not isinstance(method, str) or method not in DEFAULT_HTTP_METHODS for method in methods)
            or len(set(methods)) != len(methods)
        ):
            raise ValueError(
                "HTTP route methods must be a nonempty, unique list of GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS"
            )
        contract["methods"] = sorted(methods)
    if "timeout" in contract:
        timeout = contract["timeout"]
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("HTTP route timeout must be positive and finite")
        contract["timeout"] = float(timeout)
    if "health_path" in contract:
        path = contract["health_path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "//" in path
            or quote(path, safe="/:@!$&'()*+,;=-._~") != path
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            raise ValueError("HTTP route health_path must be an absolute, unescaped upstream path without a query")
    if "health_status" in contract:
        status = contract["health_status"]
        if (
            "health_path" not in contract
            or isinstance(status, bool)
            or not isinstance(status, int)
            or not 200 <= status < 300
        ):
            raise ValueError("HTTP route health_status requires health_path and a 2xx status")
    return contract


def http_route_contract(
    route: Mapping[str, Any], *, timeout: float = 30.0, public_url: str | None = None
) -> dict[str, Any]:
    """One effective contract for routing, inspection, and signed share bindings."""

    origin = public_origin(public_url)
    if route.get("preserve_host") and origin is None:
        raise ValueError("HTTP route preserve_host requires mcp.proxy.tunnel_public_url")
    return {
        "prefix": route["prefix"],
        "upstream": route["upstream"],
        "strip_prefix": route.get("strip_prefix", True),
        "auth": route.get("auth", "undeclared"),
        "methods": sorted(route.get("methods", DEFAULT_HTTP_METHODS)),
        "forward_authorization": route.get("forward_authorization", route.get("auth") != "public"),
        "forward_cookies": route.get("forward_cookies", route.get("auth") != "public"),
        "preserve_host": route.get("preserve_host", False),
        "public_origin": origin.url if origin else None,
        "timeout": route.get("timeout", timeout),
        "health_path": route.get("health_path"),
        "health_status": route.get("health_status", 200),
    }


def parse_http_route(value: str) -> dict[str, Any]:
    prefix, separator, upstream = value.partition("=")
    if not separator:
        raise ValueError("--http-route requires PREFIX=URL, for example /app=http://127.0.0.1:3000")
    return normalize_http_routes([{"prefix": prefix, "upstream": upstream}])[0]


def _end_to_end_headers(headers: Sequence[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    connection_tokens = {
        token.strip().lower() for name, value in headers if name.lower() == b"connection" for token in value.split(b",")
    }
    return [(name.lower(), value) for name, value in headers if name.lower() not in HOP_HEADERS | connection_tokens]


class HttpRoutesMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        routes: Sequence[Mapping[str, Any]],
        *,
        mcp_path: str = "/mcp",
        timeout: float = 30.0,
        lease_header: str = "x-snulbug-lease",
        public_url: str | None = None,
    ) -> None:
        self.app = app
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("HTTP route timeout must be positive and finite")
        self.routes = sorted(
            [
                http_route_contract(route, timeout=timeout, public_url=public_url)
                for route in normalize_http_routes(routes, mcp_path=mcp_path)
            ],
            key=lambda r: -len(r["prefix"]),
        )
        self.timeout = timeout
        self.lease_header = lease_header.lower().encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        route = next((route for route in self.routes if path_matches(scope.get("path", ""), route["prefix"])), None)
        if scope["type"] not in {"http", "websocket"} or route is None:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008, "reason": "HTTP routes do not support WebSockets"})
            return
        if scope["method"] not in route["methods"]:
            await self._error(send, 405, b"HTTP method is not allowed for this mount", allow=route["methods"])
            return
        raw_path = scope.get("raw_path", scope["path"].encode("utf-8"))
        prefix = route["prefix"].encode("ascii")
        if any(part in {".", ".."} for part in scope["path"].split("/")) or not (
            raw_path == prefix or raw_path.startswith(prefix + b"/")
        ):
            await self._error(send, 400, b"Invalid route path")
            return
        body_done = asyncio.Event()
        proxy = asyncio.create_task(self._forward(route, scope, raw_path, body_done, receive, send))
        disconnected = asyncio.create_task(self._wait_disconnect(receive, body_done))
        try:
            done, _ = await asyncio.wait({proxy, disconnected}, return_when=asyncio.FIRST_COMPLETED)
            if proxy in done:
                await proxy
        finally:
            for task in (proxy, disconnected):
                if not task.done():
                    task.cancel()
            await asyncio.gather(proxy, disconnected, return_exceptions=True)

    async def _wait_disconnect(self, receive: Receive, body_done: asyncio.Event) -> None:
        await body_done.wait()
        while (await receive())["type"] != "http.disconnect":
            pass

    async def _forward(self, route, scope, raw_path, body_done, receive, send) -> None:
        first = await receive()
        if first["type"] == "http.disconnect":
            return

        async def body():
            message = first
            while True:
                if message["type"] == "http.disconnect":
                    raise _ClientDisconnected
                if not message.get("more_body", False):
                    body_done.set()
                yield message.get("body", b"")
                if not message.get("more_body", False):
                    return
                message = await receive()

        content = body()
        if not first.get("body") and not first.get("more_body", False):
            content = b""
            body_done.set()
        base = httpx.URL(route["upstream"])
        suffix = raw_path[len(route["prefix"]) :] if route["strip_prefix"] else raw_path
        target_path = base.raw_path.rstrip(b"/") + (suffix or b"/")
        query = scope.get("query_string", b"")
        target = base.copy_with(raw_path=target_path + (b"?" + query if query else b""))
        headers = self._request_headers(scope, route)
        started = False
        try:
            async with httpx.AsyncClient(timeout=route["timeout"], trust_env=False, follow_redirects=False) as client:
                async with client.stream(scope["method"], target, headers=headers, content=content) as response:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": response.status_code,
                            "headers": [
                                (name, value)
                                for name, value in _end_to_end_headers(response.headers.raw)
                                if route["forward_cookies"] or name != b"set-cookie"
                            ],
                        }
                    )
                    started = True
                    async for chunk in response.aiter_raw():
                        await send({"type": "http.response.body", "body": chunk, "more_body": True})
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
        except _ClientDisconnected:
            return
        except (httpx.HTTPError, OSError) as exc:
            if started:
                raise
            if isinstance(exc, httpx.TimeoutException):
                await self._error(send, 504, b"HTTP route upstream timed out")
            else:
                await self._error(send, 502, b"HTTP route upstream unavailable")

    def _request_headers(self, scope: Scope, route: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
        headers = []
        original_host = b""
        for name, value in _end_to_end_headers(scope.get("headers", [])):
            if name == b"host":
                original_host = value
            elif not (
                name.startswith((b"x-snulbug-", b"x-forwarded-"))
                or name in {self.lease_header, b"forwarded", b"dpop"}
                or (name == b"authorization" and not route["forward_authorization"])
                or (name == b"cookie" and not route["forward_cookies"])
            ):
                headers.append((name, value))
        origin = public_origin(route["public_origin"])
        if origin:
            headers.extend(origin.headers())
            if route["preserve_host"]:
                headers.append((b"host", origin.authority.encode("ascii")))
        elif original_host:
            headers.append((b"x-forwarded-host", original_host))
        if not origin:
            headers.append((b"x-forwarded-proto", scope.get("scheme", "http").encode("ascii")))
        headers.append((b"x-forwarded-prefix", route["prefix"].encode("ascii")))
        if scope.get("client"):
            headers.append((b"x-forwarded-for", scope["client"][0].encode("ascii")))
        return headers

    @staticmethod
    async def _error(send: Send, status: int, body: bytes, *, allow: Sequence[str] = ()) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    *([(b"allow", ", ".join(allow).encode("ascii"))] if allow else []),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

"""Conservative cache hints at the modern gateway's response boundary."""

from __future__ import annotations

import json
from collections.abc import Mapping

CACHEABLE_METHODS = frozenset(
    {"server/discover", "tools/list", "prompts/list", "resources/list", "resources/templates/list", "resources/read"}
)
_CACHE_HEADERS = {
    b"cache-control",
    b"expires",
    b"age",
    b"etag",
    b"last-modified",
    b"surrogate-control",
    b"cdn-cache-control",
}


def private_result(body: bytes, method: str | None) -> tuple[bytes, dict]:
    """Keep policy-filtered results private, including MRTR continuation results."""
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        return body, {}
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict) or "error" in payload or "method" in payload:
        return body, {}
    complete = result.get("resultType") == "complete" and method in CACHEABLE_METHODS
    if not complete and not ({"ttlMs", "cacheScope"} & result.keys()):
        return body, {}
    ttl, scope = result.get("ttlMs"), result.get("cacheScope")
    metadata = {
        "reason_code": "mcp.cache.policy_boundary",
        "hints_valid": type(ttl) is int and ttl >= 0 and scope in ("private", "public"),
        "hints_changed": not complete or type(ttl) is not int or ttl != 0 or scope != "private",
        "cacheable_method": complete,
    }
    if complete:
        result.update(ttlMs=0, cacheScope="private")
        metadata.update(ttl_ms=0, cache_scope="private")
    else:
        result.pop("ttlMs", None)
        result.pop("cacheScope", None)
    return json.dumps(payload, separators=(",", ":")).encode(), metadata


class McpCacheMiddleware:
    """Seal JSON after Lua; SSE terminals are sealed by the existing stream sender."""

    def __init__(self, app, *, endpoint: str, metadata_callback, limit: int = 2 * 1024 * 1024):
        self.app, self.endpoint, self.metadata_callback, self.limit = app, endpoint, metadata_callback, limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or (str(scope.get("path", "/")).rstrip("/") or "/") != self.endpoint:
            await self.app(scope, receive, send)
            return
        request_body = bytearray()
        request_overflow = False
        response_body = bytearray()
        start = None
        rejected = False

        async def capture_receive():
            nonlocal request_overflow
            message = await receive()
            if message["type"] == "http.request" and not request_overflow:
                body = message.get("body", b"")
                if len(request_body) + len(body) <= self.limit:
                    request_body.extend(body)
                else:
                    request_overflow = True
                    request_body.clear()
            return message

        async def reject_oversized():
            nonlocal rejected
            rejected = True
            response_body.clear()
            self.metadata_callback(scope, {"cache": {"blocked": True, "reason_code": "response.too_large"}})
            body = b'{"error":"MCP JSON result exceeds the gateway response limit"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 502,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"cache-control", b"no-store"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})

        async def cache_safe_send(message):
            nonlocal start
            if rejected:
                return
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in _CACHE_HEADERS]
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
                content_type = next((v.lower().split(b";")[0] for k, v in headers if k.lower() == b"content-type"), b"")
                if content_type == b"application/json":
                    start = message
                    return
            elif message["type"] == "http.response.body" and start is not None:
                body = message.get("body", b"")
                if len(response_body) + len(body) > self.limit:
                    await reject_oversized()
                    return
                response_body.extend(body)
                if message.get("more_body"):
                    return
                try:
                    request = json.loads(request_body)
                except (ValueError, UnicodeError, RecursionError):
                    request = None
                method = request.get("method") if isinstance(request, Mapping) else None
                body, metadata = private_result(bytes(response_body), method if isinstance(method, str) else None)
                if len(body) > self.limit:
                    await reject_oversized()
                    return
                if metadata:
                    self.metadata_callback(scope, {"cache": metadata})
                headers = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
                await send({**start, "headers": [*headers, (b"content-length", str(len(body)).encode())]})
                start = None
                response_body.clear()
                message = {**message, "body": body}
            await send(message)

        await self.app(scope, capture_receive, cache_safe_send)

"""Canonical public-origin forwarding, never inferred from proxy claim headers."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

if TYPE_CHECKING:
    from .middleware import ASGIApp, Receive, Scope, Send

ORIGINAL_HOST = b"x-snulbug-original-host"
ORIGINAL_PROTO = b"x-snulbug-original-proto"
INGRESS_HEADERS_SCOPE_KEY = "snulbug.public_origin.ingress_headers"


@dataclass(frozen=True)
class PublicOrigin:
    scheme: str
    authority: str
    port: int

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}"

    def headers(self) -> list[tuple[bytes, bytes]]:
        return [
            (b"x-forwarded-host", self.authority.encode("ascii")),
            (b"x-forwarded-proto", self.scheme.encode("ascii")),
            (b"x-forwarded-port", str(self.port).encode("ascii")),
        ]


def public_origin(value: str | None) -> PublicOrigin | None:
    if value is None or value == "":
        return None
    error = "mcp.proxy.tunnel_public_url requires an HTTP(S) URL without credentials, query, or fragment"
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError(error)
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or any(c in value for c in ("\\", "?", "#"))
            or any(c in parsed.netloc for c in (",", "%"))
            or parsed.netloc.endswith(":")
        ):
            raise ValueError(error)
        url = httpx.URL(value)
        host = url.raw_host.decode("ascii").lower()
        if ":" in host:
            host = f"[{ipaddress.IPv6Address(host).compressed}]"
        elif len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.rstrip(".").split(".")
        ):
            raise ValueError(error)
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port if parsed.port is not None else default_port
        if not 1 <= port <= 65535:
            raise ValueError(error)
    except (ValueError, httpx.InvalidURL, UnicodeError):
        raise ValueError(error) from None
    return PublicOrigin(parsed.scheme, host + (f":{port}" if port != default_port else ""), port)


def captured_origin_matches(headers: list[tuple[bytes, bytes]], origin: PublicOrigin) -> bool:
    values = {key: [value for name, value in headers if name.lower() == key] for key in (ORIGINAL_HOST, ORIGINAL_PROTO)}
    if not any(values.values()):
        return True
    if any(len(items) != 1 for items in values.values()):
        return False
    try:
        host = values[ORIGINAL_HOST][0].decode("ascii")
        scheme = values[ORIGINAL_PROTO][0].decode("ascii")
        if any(c in host for c in ("/", "?", "#", "@")) or scheme not in {"http", "https"}:
            return False
        return public_origin(f"{scheme}://{host}") == origin
    except (ValueError, UnicodeError):
        return False


class PublicOriginMiddleware:
    def __init__(self, app: ASGIApp, *, public_url: str | None = None) -> None:
        self.app = app
        self.origin = public_origin(public_url)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw = scope.get("headers", [])
        if self.origin and not captured_origin_matches(raw, self.origin):
            body = b"Invalid captured public origin"
            await send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        # Do not rewrite ASGI Host/scheme: OAuth/DPoP must retain their own resource checks.
        headers = [
            (name, value)
            for name, value in raw
            if name.lower() not in {ORIGINAL_HOST, ORIGINAL_PROTO}
            and not (
                self.origin
                and (
                    name.lower() in {b"forwarded", b"x-original-host", b"x-original-proto"}
                    or name.lower().startswith(b"x-forwarded-")
                )
            )
        ]
        if self.origin:
            headers.extend(self.origin.headers())
            if scope.get("client"):
                headers.append((b"x-forwarded-for", str(scope["client"][0]).encode("ascii")))
        # Preserve ingress observations for audit only, never as forwarding authority.
        await self.app(
            {**scope, INGRESS_HEADERS_SCOPE_KEY: scope.get(INGRESS_HEADERS_SCOPE_KEY, raw), "headers": headers},
            receive,
            send,
        )

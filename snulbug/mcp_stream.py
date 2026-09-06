"""Bounded, request-scoped MCP event forwarding with backpressure."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Any

import httpx

from .mcp_cache import private_result
from .mcp_mrtr import mrtr_request_metadata, mrtr_result_metadata
from .mcp_progress import enforce_mcp_progress_request_policy, enforce_mcp_progress_response_policy
from .mcp_protocol import modern_response_issue, protocol_error
from .mcp_resources import ResourcePolicyConfig, enforce_mcp_resource_response_policy
from .mcp_subscriptions import LISTEN, SUBSCRIPTION_ID, Subscription
from .response_policy import enforce_mcp_response_policy
from .state import MemoryStateStore

STREAM_SCOPE_KEY = "snulbug.stream_session"
AUTH_EXPIRY_SCOPE_KEY = "snulbug.auth_expires_at"


def bound_auth_expiry(scope: dict[str, Any], expires_at: Any) -> None:
    """Carry only verified credential expiry through middleware, outside Lua context."""
    if expires_at is None:
        return
    try:
        expiry = float(expires_at)
    except (TypeError, ValueError, OverflowError):
        expiry = 0.0
    if not math.isfinite(expiry):
        expiry = 0.0
    scope[AUTH_EXPIRY_SCOPE_KEY] = min(expiry, scope.get(AUTH_EXPIRY_SCOPE_KEY, expiry))


class McpStreamError(Exception):
    """A safe-to-display stream failure; never contains upstream payload text."""


def json_response(payload: Mapping[str, Any], status: int = 200) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        "body": body,
    }


class SseDecoder:
    """Decode data events incrementally, bounding even comments and unfinished lines."""

    def __init__(self, limit: int):
        self.limit = limit
        self.buffer = bytearray()
        self.data: list[bytes] = []
        self.frame_bytes = 0
        self.first_line = True
        self.scan_offset = 0

    def feed(self, chunk: bytes):
        self.buffer.extend(chunk)
        while self.buffer:
            delimiters = [self.buffer.find(byte, self.scan_offset) for byte in (b"\n", b"\r")]
            end = min((offset for offset in delimiters if offset >= 0), default=-1)
            if end < 0 or (self.buffer[end] == 13 and end == len(self.buffer) - 1):
                if self.frame_bytes + len(self.buffer) > self.limit:
                    raise McpStreamError("MCP SSE frame exceeds the configured limit")
                self.scan_offset = end if end >= 0 else len(self.buffer)
                return
            width = 2 if self.buffer[end : end + 2] == b"\r\n" else 1
            line = bytes(self.buffer[:end])
            del self.buffer[: end + width]
            self.scan_offset = 0
            self.frame_bytes += len(line) + width
            if self.frame_bytes > self.limit:
                raise McpStreamError("MCP SSE frame exceeds the configured limit")
            if self.first_line:
                line = line.removeprefix(b"\xef\xbb\xbf")
                self.first_line = False
            # Validate ignored fields/comments too: MCP messages are UTF-8.
            try:
                line.decode("utf-8")
            except UnicodeError as exc:
                raise McpStreamError("MCP SSE contains invalid UTF-8") from exc
            if not line:
                payload = b"\n".join(self.data) if self.data else None
                self.data = []
                self.frame_bytes = 0
                yield payload
            elif line.startswith(b"data:"):
                value = line[5:]
                self.data.append(value[1:] if value.startswith(b" ") else value)
            elif line == b"data":
                self.data.append(b"")

    def finish(self):
        # A final CR is a line delimiter, not an incomplete CRLF.
        return self.feed(b"\n") if self.buffer.endswith(b"\r") else iter(())


class McpStreamSession:
    def __init__(
        self,
        request: Mapping[str, Any],
        send: Callable,
        *,
        response_policy: Any,
        progress_policy: Any,
        resource_policy: ResourcePolicyConfig | None = None,
        auth_expires_at: Any = None,
    ):
        self.request = request
        self.downstream = send
        self.response_policy = response_policy
        self.progress_policy = progress_policy
        self.resource_policy = resource_policy or ResourcePolicyConfig()
        self.subscription = Subscription(request) if request.get("method") == LISTEN else None
        self.lifetime = None
        if self.subscription is not None:
            self.lifetime = min(3600.0, self.resource_policy.subscription_ttl_seconds)
            if type(auth_expires_at) in (int, float) and math.isfinite(auth_expires_at):
                self.lifetime = min(self.lifetime, max(0.0, auth_expires_at - time.time()))
        self.limit = min(response_policy.max_body_bytes or 2 * 1024 * 1024, 2 * 1024 * 1024)
        self.started = False
        self.finished = False
        self.final_body = bytearray()
        self.metadata: dict[str, Any] = {
            "status": "pending",
            "events": 0,
            "notifications": 0,
            "bytes_received": 0,
            "redacted_events": 0,
        }
        self.mrtr_metadata = mrtr_request_metadata(request)
        self.progress_state = MemoryStateStore()
        enforce_mcp_progress_request_policy(request, config=progress_policy, state_store=self.progress_state)

    async def start(self):
        if not self.started:
            await self.downstream(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/event-stream"),
                        (b"cache-control", b"no-store"),
                        (b"x-accel-buffering", b"no"),
                    ],
                }
            )
            self.started = True

    async def notification(self, message: Mapping[str, Any]):
        self.metadata["events"] += 1
        if self.metadata["events"] > 1024:
            raise McpStreamError("MCP stream event limit exceeded")
        method = message.get("method")
        if (
            message.get("jsonrpc") != "2.0"
            or "id" in message
            or "result" in message
            or "error" in message
            or not isinstance(method, str)
            or (self.subscription is None and method not in ("notifications/progress", "notifications/message"))
            or not isinstance(message.get("params"), Mapping)
        ):
            raise McpStreamError("Unsupported or malformed MCP stream notification")
        if self.subscription is not None:
            issue = self.subscription.notification_issue(message)
            if issue:
                raise McpStreamError(issue)
        if method == "notifications/progress":
            token = self.request.get("params", {}).get("_meta", {}).get("progressToken")
            supplied = message["params"].get("progressToken")
            if type(token) not in (str, int) or type(supplied) is not type(token) or supplied != token:
                raise McpStreamError("MCP progress notification does not belong to this request")
        response = json_response(message)
        if len(response["body"]) > self.limit:
            raise McpStreamError("MCP notification exceeds the configured limit")
        response, progress = enforce_mcp_progress_response_policy(
            response,
            request=None,
            config=self.progress_policy,
            state_store=self.progress_state,
        )
        if progress.get("blocked"):
            raise McpStreamError("MCP notification blocked by progress policy")
        if progress.get("warning"):
            self.metadata["progress_warnings"] = self.metadata.get("progress_warnings", 0) + 1
        if self.subscription is not None:
            # Correlation is enforced by the request-local accepted filter, never a shared URI registry.
            response, resource = enforce_mcp_resource_response_policy(
                response,
                request=None,
                config=self.resource_policy,
                state_store=None,
            )
            if resource.get("blocked"):
                raise McpStreamError("MCP notification blocked by resource policy")
        response, policy = enforce_mcp_response_policy(
            response,
            request={"method": method, "id": self.request["id"]},
            config=replace(self.response_policy, target_methods=(method,)),
        )
        if policy.get("blocked"):
            raise McpStreamError("MCP notification blocked by response policy")
        if method == "notifications/progress":
            # This is the verified client-supplied correlation value, not an upstream credential.
            filtered = json.loads(response["body"])
            filtered["params"]["progressToken"] = message["params"]["progressToken"]
            response = json_response(filtered)
            policy["redacted"] = filtered != message
        if self.subscription is not None:
            filtered = json.loads(response["body"])
            filtered["params"].setdefault("_meta", {})[SUBSCRIPTION_ID] = self.request["id"]
            # Redacting an identifier into a different resource/filter would break subscription semantics.
            for key in ("notifications", "uri"):
                if filtered["params"].get(key) != message["params"].get(key):
                    raise McpStreamError("MCP subscription routing fields rejected by response policy")
            response = json_response(filtered)
            policy["redacted"] = filtered != message
        if policy.get("redacted"):
            self.metadata["redacted_events"] += 1
        if len(response["body"]) > self.limit:
            raise McpStreamError("Filtered MCP notification exceeds the configured limit")
        await self.start()
        await self.downstream(
            {"type": "http.response.body", "body": b"data: " + response["body"] + b"\n\n", "more_body": True}
        )
        self.metadata["notifications"] += 1

    def terminal(self, body: bytes, status: int = 200, headers=None) -> dict[str, Any]:
        if len(body) > self.limit:
            raise McpStreamError("MCP result exceeds the configured limit")
        issue = modern_response_issue(body, self.request)
        if issue:
            raise McpStreamError(issue)
        if self.subscription is not None and "result" in json.loads(body) and self.subscription.accepted is None:
            raise McpStreamError("MCP subscription completed without acknowledgment")
        mrtr = mrtr_result_metadata(json.loads(body))
        if mrtr and status != 200:
            raise McpStreamError("input_required requires a successful HTTP response")
        self.mrtr_metadata.update(mrtr)
        return {"status": status, "headers": headers or [(b"content-type", b"application/json")], "body": body}

    async def event(self, data: bytes | None):
        if data is None:
            return None
        try:
            message = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise McpStreamError("Malformed MCP SSE JSON") from exc
        if not isinstance(message, Mapping):
            raise McpStreamError("MCP streams require individual JSON-RPC messages")
        if "method" in message:
            await self.notification(message)
            return None
        return self.terminal(data)

    async def forward_http(self, url: str, *, headers: Mapping[str, str], body: bytes, timeout: float):
        headers = {**headers, "accept-encoding": "identity"}
        # A quiet subscription is normal; its wall-clock lifetime still bounds the entire operation.
        http_timeout = httpx.Timeout(timeout, read=None) if self.subscription is not None else timeout
        async with httpx.AsyncClient(timeout=http_timeout, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", url, headers=headers, content=body) as response:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise McpStreamError("Compressed MCP upstream responses are not supported")
                if content_type == "application/json":
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > self.limit:
                            raise McpStreamError("MCP result exceeds the configured limit")
                    connection_fields = {
                        name.strip().lower().encode("ascii")
                        for name in response.headers.get("connection", "").split(",")
                    }
                    clean = [
                        (key, value)
                        for key, value in response.headers.raw
                        if key.lower()
                        not in {
                            b"mcp-session-id",
                            b"last-event-id",
                            b"transfer-encoding",
                            b"connection",
                            b"keep-alive",
                            b"proxy-authenticate",
                            b"proxy-authorization",
                            b"te",
                            b"trailer",
                            b"upgrade",
                            b"content-length",
                        }
                        and key.lower() not in connection_fields
                    ]
                    return self.terminal(bytes(data), response.status_code, clean)
                if content_type != "text/event-stream" or response.status_code != 200:
                    raise McpStreamError("MCP upstream must return JSON or a successful SSE response")
                await self.start()
                decoder = SseDecoder(self.limit)
                async for chunk in response.aiter_bytes():
                    self.metadata["bytes_received"] += len(chunk)
                    if self.metadata["bytes_received"] > self.limit * 8:
                        raise McpStreamError("MCP stream byte budget exceeded")
                    for data in decoder.feed(chunk):
                        terminal = await self.event(data)
                        if terminal is not None:
                            return terminal
                for data in decoder.finish():
                    terminal = await self.event(data)
                    if terminal is not None:
                        return terminal
                raise McpStreamError("MCP stream ended without a terminal response")

    async def send(self, message: dict[str, Any]):
        if not self.started:
            await self.downstream(message)
            if message["type"] == "http.response.body" and not message.get("more_body"):
                self.finished = True
            return
        if message["type"] == "http.response.start":
            self.metadata["terminal_status"] = message["status"]
            return
        if message["type"] == "http.response.body":
            self.final_body.extend(message.get("body", b""))
            if len(self.final_body) > self.limit:
                raise McpStreamError("Filtered MCP result exceeds the configured limit")
            if not message.get("more_body"):
                body = bytes(self.final_body)
                if modern_response_issue(body, self.request):
                    body = json_response(
                        protocol_error(self.request["id"], -32000, "MCP response rejected by gateway")
                    )["body"]
                body, cache_metadata = private_result(body, self.request.get("method"))
                if len(body) > self.limit:
                    raise McpStreamError("Filtered MCP result exceeds the configured limit")
                if cache_metadata:
                    self.metadata["cache"] = cache_metadata
                await self.downstream(
                    {"type": "http.response.body", "body": b"data: " + body + b"\n\n", "more_body": False}
                )
                self.finished = True

    async def run(self, app: Callable[[], Awaitable[None]], receive: Callable):
        async def watch_disconnect():
            while True:
                if (await receive())["type"] == "http.disconnect":
                    return
                await asyncio.sleep(0.01)

        async def bounded_app():
            if self.lifetime is not None and self.lifetime <= 0:
                raise McpStreamError("MCP subscription authentication expired; reconnect required")
            await app()

        task = asyncio.create_task(bounded_app())
        disconnected = asyncio.create_task(watch_disconnect())
        try:
            done, _ = await asyncio.wait(
                (task, disconnected), timeout=self.lifetime, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise McpStreamError("MCP subscription lifetime or authentication expiry reached; reconnect required")
            if task not in done:
                self.metadata["status"] = "disconnected"
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                return
            await task
            self.metadata["status"] = "complete"
        except asyncio.CancelledError:
            self.metadata["status"] = "cancelled"
            raise
        except Exception as exc:
            self.metadata["status"] = "failed"
            reason = str(exc) if isinstance(exc, McpStreamError) else "MCP upstream stream failed"
            self.metadata["reason"] = reason
            if not self.finished:
                self.final_body.clear()
                response = json_response(protocol_error(self.request["id"], -32000, reason), status=502)
                try:
                    await self.send({"type": "http.response.start", "status": 502, "headers": response["headers"]})
                    await self.send({"type": "http.response.body", "body": response["body"], "more_body": False})
                except OSError:
                    self.metadata["status"] = "disconnected"
        finally:
            task.cancel()
            disconnected.cancel()
            await asyncio.gather(task, disconnected, return_exceptions=True)
            if self.subscription is not None:
                self.metadata["subscription"] = self.subscription.summary()

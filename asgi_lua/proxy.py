from __future__ import annotations

import asyncio
import http.client
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import SplitResult, urlsplit

from .middleware import ASGIApp, LuaConfig, LuaMiddleware, Receive, Scope, Send
from .recorder import append_record, build_request_record, record_audit_event
from .redaction import append_audit_event
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


class ProxyRecorderMiddleware:
    """Capture live proxy requests as replay records, audit events, and console decisions."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        policy: str | Path,
        record_out: str | Path | None = None,
        audit_out: str | Path | None = None,
        redact_records: bool = True,
        decision_console: bool | TextIO = False,
        decision_console_format: str = "text",
    ) -> None:
        self.app = app
        self.policy = policy
        self.record_out = Path(record_out) if record_out is not None else None
        self.audit_out = Path(audit_out) if audit_out is not None else None
        self.redact_records = redact_records
        self.decision_console = _console_stream(decision_console)
        self.decision_console_format = decision_console_format
        if self.decision_console_format not in {"text", "json"}:
            raise ValueError("decision_console_format must be 'text' or 'json'")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self._enabled():
            await self.app(scope, receive, send)
            return

        body, replay_receive = await _capture_body(receive)
        response: dict[str, Any] = {"headers": {}, "body_bytes": 0}

        async def recording_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                response["status"] = int(message["status"])
                response["headers"] = _headers_to_mapping(message.get("headers", []))
            elif message["type"] == "http.response.body":
                response["body_bytes"] = int(response.get("body_bytes", 0)) + len(message.get("body", b""))
            await send(message)

        await self.app(scope, replay_receive, recording_send)
        record = build_request_record(
            self.policy,
            _scope_to_record_request(scope, body),
            _trace_result(scope),
            response=response,
            metadata={"source": "proxy"},
            redact=self.redact_records,
        )
        if self.record_out is not None:
            append_record(self.record_out, record)
        audit_event = None
        if self.audit_out is not None:
            audit_event = record_audit_event(record)
            append_audit_event(self.audit_out, audit_event)
        if self.decision_console is not None:
            _write_decision_console(
                self.decision_console,
                record,
                audit_event=audit_event,
                output_format=self.decision_console_format,
            )

    def _enabled(self) -> bool:
        return self.record_out is not None or self.audit_out is not None or self.decision_console is not None


def create_proxy_application(
    upstream: str,
    policy: str | Path,
    *,
    state_store: PolicyStateStore | None = None,
    state_limits: StateLimits | None = None,
    trace: bool = True,
    max_body_bytes: int = 64 * 1024,
    timeout: float = 30.0,
    record_out: str | Path | None = None,
    audit_out: str | Path | None = None,
    redact_records: bool = True,
    decision_console: bool | TextIO = False,
    decision_console_format: str = "text",
) -> ASGIApp:
    """Create an ASGI app that applies Lua policy before proxying to an upstream."""

    console_enabled = _console_enabled(decision_console)
    proxy = ReverseProxyApp(upstream, timeout=timeout)
    app = LuaMiddleware(
        proxy,
        Path(policy),
        config=LuaConfig(
            read_body=True,
            max_body_bytes=max_body_bytes,
            trace=trace or record_out is not None or audit_out is not None or console_enabled,
        ),
        state_store=state_store if state_store is not None else MemoryStateStore(),
        state_limits=state_limits,
    )
    if record_out is None and audit_out is None and not console_enabled:
        return app
    return ProxyRecorderMiddleware(
        app,
        policy=policy,
        record_out=record_out,
        audit_out=audit_out,
        redact_records=redact_records,
        decision_console=decision_console,
        decision_console_format=decision_console_format,
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
    record_out: str | Path | None = None,
    audit_out: str | Path | None = None,
    redact_records: bool = True,
    decision_console: bool = False,
    decision_console_format: str = "text",
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
        record_out=record_out,
        audit_out=audit_out,
        redact_records=redact_records,
        decision_console=decision_console,
        decision_console_format=decision_console_format,
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


def _console_enabled(value: bool | TextIO) -> bool:
    return value is not False and value is not None


def _console_stream(value: bool | TextIO) -> TextIO | None:
    if value is True:
        return sys.stderr
    if value is False or value is None:
        return None
    return value


def _write_decision_console(
    output: TextIO,
    record: Mapping[str, Any],
    *,
    audit_event: Mapping[str, Any] | None = None,
    output_format: str,
) -> None:
    event = _decision_console_event(record, audit_event=audit_event)
    if output_format == "json":
        line = json.dumps(event, sort_keys=True, separators=(",", ":"))
    else:
        line = _format_decision_console_line(event)
    output.write(line)
    output.write("\n")
    output.flush()


def _decision_console_event(
    record: Mapping[str, Any],
    *,
    audit_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    event = dict(audit_event) if audit_event is not None else record_audit_event(record)
    result = record.get("result")
    trace = result.get("trace") if isinstance(result, Mapping) else None
    if isinstance(trace, Mapping):
        event["trace"] = {
            "duration_ms": trace.get("duration_ms"),
            "instruction_count": trace.get("instruction_count"),
        }
    return event


def _format_decision_console_line(event: Mapping[str, Any]) -> str:
    request = event.get("request") if isinstance(event.get("request"), Mapping) else {}
    decision = event.get("decision") if isinstance(event.get("decision"), Mapping) else {}
    response = event.get("response") if isinstance(event.get("response"), Mapping) else {}
    mcp = event.get("mcp") if isinstance(event.get("mcp"), Mapping) else {}
    trace = event.get("trace") if isinstance(event.get("trace"), Mapping) else {}

    parts = [
        "asgi-lua",
        f"decision={decision.get('action', 'unknown')}",
        f"allowed={str(bool(decision.get('allowed', False))).lower()}",
        f"status={response.get('status', decision.get('status', '-'))}",
        f"method={request.get('method', '-')}",
        f"path={request.get('path', '-')}",
    ]
    if decision.get("reason_code"):
        parts.append(f"reason_code={decision['reason_code']}")
    if decision.get("reason"):
        parts.append(f"reason={_console_value(decision['reason'])}")
    if request.get("query_string"):
        parts.append(f"query={request['query_string']}")
    if mcp.get("method"):
        parts.append(f"mcp.method={mcp['method']}")
    if mcp.get("tool"):
        parts.append(f"mcp.tool={mcp['tool']}")
    elif mcp.get("target"):
        parts.append(f"mcp.target={mcp['target']}")
    if mcp.get("request_id") is not None:
        parts.append(f"mcp.id={mcp['request_id']}")
    if trace.get("duration_ms") is not None:
        parts.append(f"lua_ms={float(trace['duration_ms']):.3f}")
    if trace.get("instruction_count") is not None:
        parts.append(f"lua_instructions={trace['instruction_count']}")
    return " ".join(parts)


def _console_value(value: Any) -> str:
    return json.dumps(str(value), separators=(",", ":"))


def _request_headers(raw_headers: list[tuple[bytes, bytes]], upstream: SplitResult) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw_headers:
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS or lower_name == b"host":
            continue
        headers[name.decode("latin-1")] = value.decode("latin-1")
    headers["Host"] = upstream.netloc
    return headers


def _headers_to_mapping(headers: list[tuple[bytes, bytes]]) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        existing = result.get(name)
        if existing is None:
            result[name] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            result[name] = [existing, value]
    return result


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


async def _capture_body(receive: Receive) -> tuple[bytes, Receive]:
    messages = []
    chunks = []
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break

    index = 0

    async def replay() -> dict[str, Any]:
        nonlocal index
        if index < len(messages):
            message = messages[index]
            index += 1
            return message
        return {"type": "http.request", "body": b"", "more_body": False}

    return b"".join(chunks), replay


def _scope_to_record_request(scope: Scope, body: bytes) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": str(scope.get("method", "GET")),
        "path": str(scope.get("path", "/")),
        "raw_path": _decode_bytes(scope.get("raw_path", b"")),
        "query_string": _decode_bytes(scope.get("query_string", b"")),
        "headers": _headers_to_mapping(scope.get("headers", [])),
        "client": list(scope["client"]) if scope.get("client") is not None else None,
        "scheme": str(scope.get("scheme", "http")),
    }
    if body:
        request["body"] = body.decode("utf-8", errors="replace")
        request["body_bytes_latin1"] = body.decode("latin-1")
    return request


def _trace_result(scope: Scope) -> dict[str, Any]:
    state = scope.get("state")
    trace = state.get("lua_trace") if isinstance(state, Mapping) else None
    if isinstance(trace, Mapping) and isinstance(trace.get("decision"), Mapping):
        return {
            "action": trace.get("action", trace["decision"].get("action", "continue")),
            "decision": dict(trace["decision"]),
            "trace": dict(trace),
            "body_read": bool(trace.get("body_read", False)),
        }
    return {
        "action": "unknown",
        "decision": {"action": "unknown"},
        "trace": {},
        "body_read": False,
    }


def _decode_bytes(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


async def _send_response(send: Send, *, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})

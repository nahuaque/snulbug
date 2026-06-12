from __future__ import annotations

import asyncio
import http.client
import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import SplitResult, urlsplit

from .confirm import ConfirmationBroker
from .leases import LeasePolicyConfig, enforce_mcp_lease_policy, mcp_lease_error_response
from .middleware import ASGIApp, LuaConfig, LuaMiddleware, Receive, Scope, Send
from .recorder import append_record, build_request_record, record_audit_event
from .redaction import append_audit_event
from .response_policy import ResponsePolicyConfig, enforce_mcp_response_policy
from .schema_policy import (
    SchemaPolicyConfig,
    enforce_mcp_request_schema_policy,
    mcp_schema_error_response,
    observe_mcp_tool_schemas,
)
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


@dataclass(frozen=True)
class FacadeUpstream:
    name: str
    tool_prefix: str
    default: bool = False
    transport: str = "http"
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: Mapping[str, str] | None = None


class ReverseProxyApp:
    """Minimal ASGI reverse proxy app for local-dev policy gateways."""

    def __init__(
        self,
        upstream: str,
        *,
        timeout: float = 30.0,
        response_policy: ResponsePolicyConfig | None = None,
        tool_pin_store: PolicyStateStore | None = None,
        schema_policy: SchemaPolicyConfig | None = None,
        tool_schema_store: PolicyStateStore | None = None,
        lease_policy: LeasePolicyConfig | None = None,
    ) -> None:
        parsed = urlsplit(upstream)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("upstream must be an absolute http:// or https:// URL")
        self.config = ProxyConfig(upstream=upstream.rstrip("/"), timeout=timeout)
        self._upstream = parsed
        self.response_policy = response_policy or ResponsePolicyConfig()
        self.tool_pin_store = tool_pin_store
        self.schema_policy = schema_policy or SchemaPolicyConfig()
        self.tool_schema_store = tool_schema_store
        self.lease_policy = lease_policy or LeasePolicyConfig()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await _send_response(send, status=404, headers=[], body=b"unsupported scope type")
            return

        body = await _read_body(receive)
        request = _jsonrpc_request(body)
        lease_allowed, lease_metadata = enforce_mcp_lease_policy(
            request,
            scope,
            config=self.lease_policy,
        )
        if not lease_allowed and isinstance(request, Mapping):
            response = mcp_lease_error_response(request, lease_metadata)
            _set_proxy_metadata(
                scope,
                {
                    **_mcp_request_metadata(request),
                    "lease": lease_metadata,
                },
            )
            await _send_response(
                send,
                status=response["status"],
                headers=response["headers"],
                body=response["body"],
            )
            return
        schema_allowed, schema_request_metadata = enforce_mcp_request_schema_policy(
            request,
            config=self.schema_policy,
            tool_schema_store=self.tool_schema_store,
        )
        if not schema_allowed and isinstance(request, Mapping):
            response = mcp_schema_error_response(request, schema_request_metadata)
            _set_proxy_metadata(
                scope,
                {
                    **_mcp_request_metadata(request),
                    "schema_validation": schema_request_metadata,
                },
            )
            await _send_response(
                send,
                status=response["status"],
                headers=response["headers"],
                body=response["body"],
            )
            return
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

        response, response_metadata = enforce_mcp_response_policy(
            response,
            request=request,
            config=self.response_policy,
            tool_pin_store=self.tool_pin_store,
        )
        schema_observe_metadata = observe_mcp_tool_schemas(
            response,
            request=request,
            config=self.schema_policy,
            tool_schema_store=self.tool_schema_store,
        )
        _set_proxy_metadata(
            scope,
            {
                **_mcp_request_metadata(request),
                "lease": lease_metadata,
                "schema_validation": _schema_metadata(schema_request_metadata, schema_observe_metadata),
                "response_policy": response_metadata,
            },
        )
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
        return _connection(self._upstream, self.config.timeout)

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


class ManagedStdioMcpClient:
    """Managed line-delimited JSON-RPC client for local stdio MCP servers."""

    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.command = command
        self.args = tuple(args)
        self.cwd = cwd
        self.env = dict(env) if env is not None else None
        self.timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._process_loop: asyncio.AbstractEventLoop | None = None
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    async def request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        lock = self._lock_for_loop()
        async with lock:
            process = await self._ensure_process()
            assert process.stdin is not None
            message = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
            process.stdin.write(message)
            await process.stdin.drain()

            if "id" not in request:
                return {"status": 202, "headers": [(b"content-length", b"0")], "body": b""}

            response = await self._read_response(request.get("id"))
            body = json.dumps(response, separators=(",", ":")).encode("utf-8")
            return {
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
                "body": body,
            }

    async def aclose(self) -> None:
        process = self._process
        self._process = None
        self._process_loop = None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except TimeoutError:
            process.kill()
            await process.wait()

    def _lock_for_loop(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    async def _ensure_process(self) -> asyncio.subprocess.Process:
        loop = asyncio.get_running_loop()
        if self._process is not None and self._process_loop is not loop:
            await self.aclose()
        if self._process is not None and self._process.returncode is None:
            return self._process

        env = None if self.env is None else {**os.environ, **self.env}
        self._process = await asyncio.create_subprocess_exec(
            self.command,
            *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=self.cwd,
            env=env,
        )
        self._process_loop = loop
        return self._process

    async def _read_response(self, request_id: Any) -> Mapping[str, Any]:
        process = await self._ensure_process()
        assert process.stdout is not None
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=self.timeout)
            if not line:
                self._process = None
                self._process_loop = None
                raise RuntimeError("stdio MCP server closed stdout")
            try:
                response = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(response, Mapping):
                continue
            if response.get("id") == request_id:
                return response


class McpFacadeProxyApp:
    """Minimal MCP facade that serves several local MCP HTTP servers as one endpoint."""

    def __init__(
        self,
        upstreams: Sequence[FacadeUpstream | Mapping[str, Any]],
        *,
        timeout: float = 30.0,
        response_policy: ResponsePolicyConfig | None = None,
        tool_pin_store: PolicyStateStore | None = None,
        schema_policy: SchemaPolicyConfig | None = None,
        tool_schema_store: PolicyStateStore | None = None,
        lease_policy: LeasePolicyConfig | None = None,
    ) -> None:
        self.upstreams = [_coerce_facade_upstream(upstream) for upstream in upstreams]
        if not self.upstreams:
            raise ValueError("facade mode requires at least one upstream")
        self.timeout = timeout
        self.response_policy = response_policy or ResponsePolicyConfig()
        self.tool_pin_store = tool_pin_store
        self.schema_policy = schema_policy or SchemaPolicyConfig()
        self.tool_schema_store = tool_schema_store
        self.lease_policy = lease_policy or LeasePolicyConfig()
        self._parsed = {
            upstream.name: _parse_upstream(_required_url(upstream))
            for upstream in self.upstreams
            if upstream.transport == "http"
        }
        self._stdio_clients = {
            upstream.name: ManagedStdioMcpClient(
                _required_command(upstream),
                upstream.args,
                cwd=upstream.cwd,
                env=upstream.env,
                timeout=timeout,
            )
            for upstream in self.upstreams
            if upstream.transport == "stdio"
        }
        self._default = next((upstream for upstream in self.upstreams if upstream.default), self.upstreams[0])
        self._prefixes = sorted(self.upstreams, key=lambda upstream: len(upstream.tool_prefix), reverse=True)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await _send_response(send, status=404, headers=[], body=b"unsupported scope type")
            return

        body = await _read_body(receive)
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            await self._send_jsonrpc_error(send, request_id=None, code=-32700, message="invalid JSON-RPC body")
            return
        if not isinstance(request, Mapping) or isinstance(request, list):
            await self._send_jsonrpc_error(
                send,
                request_id=None,
                code=-32600,
                message="facade mode requires one JSON-RPC request",
            )
            return

        method = request.get("method")
        if method == "tools/list":
            await self._list_tools(scope, request, body, send)
            return
        if method == "tools/call":
            await self._call_tool(scope, request, send)
            return

        await self._forward_to_default(scope, body, send)

    async def _list_tools(self, scope: Scope, request: Mapping[str, Any], body: bytes, send: Send) -> None:
        responses = []
        for upstream in self.upstreams:
            try:
                response = await self._forward(upstream, scope, body, request)
            except Exception as exc:
                await self._send_upstream_failure(send, upstream, exc)
                return
            if response["status"] < 200 or response["status"] >= 300:
                await self._send_jsonrpc_error(
                    send,
                    request_id=request.get("id"),
                    code=-32000,
                    message=f"upstream {upstream.name!r} returned HTTP {response['status']}",
                    status=502,
                )
                return
            responses.append((upstream, response))

        tools = []
        for upstream, response in responses:
            try:
                payload = json.loads(response["body"].decode("utf-8"))
                result = payload.get("result") if isinstance(payload, Mapping) else None
                upstream_tools = result.get("tools") if isinstance(result, Mapping) else None
            except Exception as exc:
                await self._send_upstream_failure(send, upstream, exc)
                return
            if not isinstance(upstream_tools, list):
                await self._send_jsonrpc_error(
                    send,
                    request_id=request.get("id"),
                    code=-32000,
                    message=f"upstream {upstream.name!r} did not return result.tools",
                    status=502,
                )
                return
            for tool in upstream_tools:
                if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
                    continue
                decorated = dict(tool)
                decorated["name"] = f"{upstream.tool_prefix}{tool['name']}"
                tools.append(decorated)

        _set_proxy_metadata(
            scope,
            {
                "facade": True,
                "operation": "tools/list",
                "upstreams": [upstream.name for upstream in self.upstreams],
                "tool_count": len(tools),
            },
        )
        response, response_metadata = enforce_mcp_response_policy(
            _json_response(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {"tools": tools},
                }
            ),
            request=request,
            config=self.response_policy,
            tool_pin_store=self.tool_pin_store,
        )
        schema_observe_metadata = observe_mcp_tool_schemas(
            response,
            request=request,
            config=self.schema_policy,
            tool_schema_store=self.tool_schema_store,
        )
        _set_proxy_metadata(
            scope,
            {
                "schema_validation": schema_observe_metadata,
                "response_policy": response_metadata,
            },
        )
        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )

    async def _call_tool(self, scope: Scope, request: Mapping[str, Any], send: Send) -> None:
        params = request.get("params")
        if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32602,
                message="tools/call params.name is required",
            )
            return

        tool_name = params["name"]
        upstream = self._upstream_for_tool(tool_name)
        if upstream is None:
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32602,
                message=f"unknown facade tool prefix for {tool_name!r}",
                status=404,
            )
            return

        lease_allowed, lease_metadata = enforce_mcp_lease_policy(
            request,
            scope,
            config=self.lease_policy,
        )
        if not lease_allowed:
            response = mcp_lease_error_response(request, lease_metadata)
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "tools/call",
                    "upstream": upstream.name,
                    "tool": tool_name,
                    "lease": lease_metadata,
                },
            )
            await _send_response(
                send,
                status=response["status"],
                headers=response["headers"],
                body=response["body"],
            )
            return

        schema_allowed, schema_request_metadata = enforce_mcp_request_schema_policy(
            request,
            config=self.schema_policy,
            tool_schema_store=self.tool_schema_store,
        )
        if not schema_allowed:
            response = mcp_schema_error_response(request, schema_request_metadata)
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "tools/call",
                    "upstream": upstream.name,
                    "tool": tool_name,
                    "lease": lease_metadata,
                    "schema_validation": schema_request_metadata,
                },
            )
            await _send_response(
                send,
                status=response["status"],
                headers=response["headers"],
                body=response["body"],
            )
            return

        rewritten = dict(request)
        rewritten_params = dict(params)
        rewritten_params["name"] = tool_name.removeprefix(upstream.tool_prefix)
        rewritten["params"] = rewritten_params
        body = json.dumps(rewritten, separators=(",", ":")).encode("utf-8")
        try:
            response = await self._forward(upstream, scope, body, rewritten)
        except Exception as exc:
            await self._send_upstream_failure(send, upstream, exc)
            return

        response, response_metadata = enforce_mcp_response_policy(
            response,
            request=request,
            config=self.response_policy,
            tool_pin_store=self.tool_pin_store,
        )
        _set_proxy_metadata(
            scope,
            {
                "facade": True,
                "operation": "tools/call",
                "upstream": upstream.name,
                "tool": tool_name,
                "upstream_tool": rewritten_params["name"],
                "lease": lease_metadata,
                "schema_validation": schema_request_metadata,
                "response_policy": response_metadata,
            },
        )
        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )

    async def _forward_to_default(self, scope: Scope, body: bytes, send: Send) -> None:
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
            response = await self._forward(self._default, scope, body, request if isinstance(request, Mapping) else {})
        except Exception as exc:
            await self._send_upstream_failure(send, self._default, exc)
            return

        response, response_metadata = enforce_mcp_response_policy(
            response,
            request=request if isinstance(request, Mapping) else None,
            config=self.response_policy,
            tool_pin_store=self.tool_pin_store,
        )
        _set_proxy_metadata(
            scope,
            {
                "facade": True,
                "operation": "default",
                "upstream": self._default.name,
                "response_policy": response_metadata,
            },
        )
        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )

    async def _forward(
        self,
        upstream: FacadeUpstream,
        scope: Scope,
        body: bytes,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if upstream.transport == "stdio":
            return await self._stdio_clients[upstream.name].request(request)
        return await asyncio.to_thread(self._forward_http, upstream, scope, body)

    def _forward_http(self, upstream: FacadeUpstream, scope: Scope, body: bytes) -> dict[str, Any]:
        parsed = self._parsed[upstream.name]
        connection = _connection(parsed, self.timeout)
        try:
            headers = _request_headers(scope.get("headers", []), parsed, content_length=len(body))
            connection.request(str(scope.get("method", "POST")), _exact_target(parsed), body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            return {
                "status": int(response.status),
                "headers": _response_headers(response.getheaders()),
                "body": response_body,
            }
        finally:
            connection.close()

    def _upstream_for_tool(self, tool_name: str) -> FacadeUpstream | None:
        for upstream in self._prefixes:
            if tool_name.startswith(upstream.tool_prefix):
                return upstream
        return None

    async def aclose(self) -> None:
        for client in self._stdio_clients.values():
            await client.aclose()

    async def _send_upstream_failure(self, send: Send, upstream: FacadeUpstream, exc: Exception) -> None:
        await self._send_jsonrpc_error(
            send,
            request_id=None,
            code=-32000,
            message=f"upstream {upstream.name!r} request failed: {exc}",
            status=502,
        )

    async def _send_jsonrpc_error(
        self,
        send: Send,
        *,
        request_id: Any,
        code: int,
        message: str,
        status: int = 400,
    ) -> None:
        await _send_json(
            send,
            status=status,
            payload={
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            },
        )


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
            metadata=_record_metadata(scope),
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
    upstream: str | None,
    policy: str | Path,
    *,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None = None,
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
    response_max_bytes: int | None = 256 * 1024,
    response_redact_secrets: bool = True,
    response_block_instructions: bool = False,
    tool_pinning: bool = True,
    tool_pinning_action: str = "block",
    schema_validation: bool = True,
    schema_validation_action: str = "block",
    lease_file: str | Path | None = None,
    lease_required: bool = False,
    lease_header: str = "x-snulbug-lease",
    confirm: bool = False,
    confirm_handler: Any = None,
) -> ASGIApp:
    """Create an ASGI app that applies Lua policy before proxying to an upstream."""

    console_enabled = _console_enabled(decision_console)
    effective_state_store = state_store if state_store is not None else MemoryStateStore()
    response_policy = ResponsePolicyConfig(
        max_body_bytes=response_max_bytes,
        redact_secrets=response_redact_secrets,
        block_instruction_like_content=response_block_instructions,
        tool_pinning=tool_pinning,
        tool_pinning_action=tool_pinning_action,
    )
    schema_policy = SchemaPolicyConfig(
        enabled=schema_validation,
        action=schema_validation_action,
    )
    lease_policy = LeasePolicyConfig(
        lease_file=Path(lease_file) if lease_file else None,
        required=lease_required,
        header=lease_header,
    )
    proxy = _proxy_app(
        upstream,
        upstreams=upstreams,
        timeout=timeout,
        response_policy=response_policy,
        tool_pin_store=effective_state_store if tool_pinning else None,
        schema_policy=schema_policy,
        tool_schema_store=effective_state_store if schema_validation else None,
        lease_policy=lease_policy,
    )
    app = LuaMiddleware(
        proxy,
        Path(policy),
        config=LuaConfig(
            read_body=True,
            max_body_bytes=max_body_bytes,
            trace=trace or record_out is not None or audit_out is not None or console_enabled,
        ),
        state_store=effective_state_store,
        state_limits=state_limits,
        confirm_handler=confirm_handler or (ConfirmationBroker(enabled=True) if confirm else None),
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
    upstream: str | None,
    policy: str | Path,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None = None,
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
    response_max_bytes: int | None = 256 * 1024,
    response_redact_secrets: bool = True,
    response_block_instructions: bool = False,
    tool_pinning: bool = True,
    tool_pinning_action: str = "block",
    schema_validation: bool = True,
    schema_validation_action: str = "block",
    lease_file: str | Path | None = None,
    lease_required: bool = False,
    lease_header: str = "x-snulbug-lease",
    confirm: bool = False,
) -> None:
    """Run the reverse proxy with uvicorn."""

    try:
        import uvicorn  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError('reverse proxy mode requires uvicorn; install with `pip install "snulbug[proxy]"`') from exc

    app = create_proxy_application(
        upstream,
        policy,
        upstreams=upstreams,
        state_store=_state_store(state),
        trace=trace,
        max_body_bytes=max_body_bytes,
        timeout=timeout,
        record_out=record_out,
        audit_out=audit_out,
        redact_records=redact_records,
        decision_console=decision_console,
        decision_console_format=decision_console_format,
        response_max_bytes=response_max_bytes,
        response_redact_secrets=response_redact_secrets,
        response_block_instructions=response_block_instructions,
        tool_pinning=tool_pinning,
        tool_pinning_action=tool_pinning_action,
        schema_validation=schema_validation,
        schema_validation_action=schema_validation_action,
        lease_file=lease_file,
        lease_required=lease_required,
        lease_header=lease_header,
        confirm=confirm,
    )
    uvicorn.run(app, host=host, port=port)


def _proxy_app(
    upstream: str | None,
    *,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None,
    timeout: float,
    response_policy: ResponsePolicyConfig,
    tool_pin_store: PolicyStateStore | None,
    schema_policy: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore | None,
    lease_policy: LeasePolicyConfig,
) -> ASGIApp:
    if upstreams:
        return McpFacadeProxyApp(
            upstreams,
            timeout=timeout,
            response_policy=response_policy,
            tool_pin_store=tool_pin_store,
            schema_policy=schema_policy,
            tool_schema_store=tool_schema_store,
            lease_policy=lease_policy,
        )
    if upstream is None:
        raise ValueError("upstream is required unless facade upstreams are configured")
    return ReverseProxyApp(
        upstream,
        timeout=timeout,
        response_policy=response_policy,
        tool_pin_store=tool_pin_store,
        schema_policy=schema_policy,
        tool_schema_store=tool_schema_store,
        lease_policy=lease_policy,
    )


def _state_store(value: str) -> PolicyStateStore | None:
    if value == "none":
        return None
    if value == "memory":
        return MemoryStateStore()
    if value.startswith("sqlite:"):
        return SQLiteStateStore(value.removeprefix("sqlite:"))
    raise ValueError("state must be 'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")


def _schema_metadata(request_metadata: Mapping[str, Any], observe_metadata: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(request_metadata)
    if observe_metadata.get("observed") or observe_metadata.get("json_error"):
        merged["tools_list"] = dict(observe_metadata)
    return merged


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
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    lease = metadata.get("lease") if isinstance(metadata.get("lease"), Mapping) else {}
    confirmation = decision.get("confirmation") if isinstance(decision.get("confirmation"), Mapping) else {}

    parts = [
        "snulbug",
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
    if confirmation:
        parts.append(f"confirm.approved={str(bool(confirmation.get('approved', False))).lower()}")
        if confirmation.get("mode"):
            parts.append(f"confirm.mode={confirmation['mode']}")
        if confirmation.get("reason_code"):
            parts.append(f"confirm.reason_code={confirmation['reason_code']}")
    if lease:
        if lease.get("id"):
            parts.append(f"lease.id={lease['id']}")
        if lease.get("task"):
            parts.append(f"lease.task={_console_value(lease['task'])}")
        if lease.get("reason_code"):
            parts.append(f"lease.reason_code={lease['reason_code']}")
        if lease.get("allowed") is not None:
            parts.append(f"lease.allowed={str(bool(lease['allowed'])).lower()}")
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


def _coerce_facade_upstream(upstream: FacadeUpstream | Mapping[str, Any]) -> FacadeUpstream:
    if isinstance(upstream, FacadeUpstream):
        return upstream
    name = upstream.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("facade upstream name must be a non-empty string")
    transport = str(upstream.get("transport") or ("stdio" if upstream.get("command") else "http"))
    if transport not in {"http", "stdio"}:
        raise ValueError(f"facade upstream {name!r} transport must be 'http' or 'stdio'")
    url = upstream.get("url", upstream.get("upstream"))
    command = upstream.get("command")
    if transport == "http" and (not isinstance(url, str) or not url):
        raise ValueError(f"facade upstream {name!r} url must be a non-empty string")
    if transport == "stdio" and (not isinstance(command, str) or not command):
        raise ValueError(f"facade upstream {name!r} command must be a non-empty string")
    tool_prefix = upstream.get("tool_prefix", f"{name}.")
    if not isinstance(tool_prefix, str) or not tool_prefix:
        raise ValueError(f"facade upstream {name!r} tool_prefix must be a non-empty string")
    args = upstream.get("args", [])
    if not isinstance(args, Sequence) or isinstance(args, str | bytes | bytearray):
        raise ValueError(f"facade upstream {name!r} args must be a list of strings")
    if not all(isinstance(arg, str) for arg in args):
        raise ValueError(f"facade upstream {name!r} args must be a list of strings")
    cwd = upstream.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise ValueError(f"facade upstream {name!r} cwd must be a string")
    env = upstream.get("env")
    if env is not None:
        if not isinstance(env, Mapping) or not all(isinstance(key, str) for key in env):
            raise ValueError(f"facade upstream {name!r} env must be a string table")
        if not all(isinstance(value, str) for value in env.values()):
            raise ValueError(f"facade upstream {name!r} env must be a string table")
    return FacadeUpstream(
        name=name,
        tool_prefix=tool_prefix,
        default=bool(upstream.get("default", False)),
        transport=transport,
        url=url if isinstance(url, str) else None,
        command=command if isinstance(command, str) else None,
        args=tuple(args),
        cwd=cwd,
        env=dict(env) if isinstance(env, Mapping) else None,
    )


def _required_url(upstream: FacadeUpstream) -> str:
    if not upstream.url:
        raise ValueError(f"facade upstream {upstream.name!r} url is required")
    return upstream.url


def _required_command(upstream: FacadeUpstream) -> str:
    if not upstream.command:
        raise ValueError(f"facade upstream {upstream.name!r} command is required")
    return upstream.command


def _parse_upstream(upstream: str) -> SplitResult:
    parsed = urlsplit(upstream)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("upstream must be an absolute http:// or https:// URL")
    return parsed


def _connection(upstream: SplitResult, timeout: float) -> http.client.HTTPConnection:
    host = upstream.hostname
    if host is None:
        raise ValueError("upstream host is required")
    port = upstream.port
    if upstream.scheme == "https":
        return http.client.HTTPSConnection(host, port=port, timeout=timeout)
    return http.client.HTTPConnection(host, port=port, timeout=timeout)


def _exact_target(upstream: SplitResult) -> str:
    path = upstream.path or "/"
    return f"{path}?{upstream.query}" if upstream.query else path


def _request_headers(
    raw_headers: list[tuple[bytes, bytes]],
    upstream: SplitResult,
    *,
    content_length: int | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in raw_headers:
        lower_name = name.lower()
        if lower_name in HOP_BY_HOP_HEADERS or lower_name in {b"host", b"content-length"}:
            continue
        headers[name.decode("latin-1")] = value.decode("latin-1")
    headers["Host"] = upstream.netloc
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
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


async def _send_json(send: Send, *, status: int, payload: Mapping[str, Any]) -> None:
    response = _json_response(payload, status=status)
    await _send_response(
        send,
        status=response["status"],
        headers=response["headers"],
        body=response["body"],
    )


def _json_response(payload: Mapping[str, Any], *, status: int = 200) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ],
        "body": body,
    }


def _jsonrpc_request(body: bytes) -> Mapping[str, Any] | None:
    if not body:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) and not isinstance(payload, list) else None


def _mcp_request_metadata(request: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        return {}
    method = request.get("method")
    if not isinstance(method, str):
        return {}
    metadata: dict[str, Any] = {"operation": method}
    operation, _, operation_detail = method.partition("/")
    if operation:
        metadata["mcp_operation"] = operation
    if operation_detail:
        metadata["mcp_operation_detail"] = operation_detail
    params = request.get("params")
    if isinstance(params, Mapping):
        target = params.get("name") or params.get("uri")
        if isinstance(target, str):
            metadata["target"] = target
        arguments = params.get("arguments")
        if isinstance(arguments, Mapping):
            metadata["argument_keys"] = sorted(str(key) for key in arguments)
    return metadata


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


def _record_metadata(scope: Scope) -> dict[str, Any]:
    metadata: dict[str, Any] = {"source": "proxy"}
    state = scope.get("state")
    proxy_metadata = state.get("snulbug_proxy") if isinstance(state, Mapping) else None
    if isinstance(proxy_metadata, Mapping):
        metadata.update(proxy_metadata)
    return metadata


def _set_proxy_metadata(scope: Scope, metadata: Mapping[str, Any]) -> None:
    state = scope.get("state")
    if isinstance(state, dict):
        existing = state.get("snulbug_proxy")
        merged = dict(existing) if isinstance(existing, Mapping) else {}
        merged.update(metadata)
        state["snulbug_proxy"] = merged


def _decode_bytes(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


async def _send_response(send: Send, *, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})

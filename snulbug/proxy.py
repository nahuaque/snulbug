from __future__ import annotations

import asyncio
import hashlib
import http.client
import json
import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .cloudflare_access import CloudflareAccessConfig, evaluate_cloudflare_access
from .config import load_mcp_fabric_config, load_mcp_proxy_config, merge_mcp_proxy_config, normalize_mcp_auth_config
from .confirm import ConfirmationBroker
from .control_events import (
    EVENT_RELOAD_FAILED,
    EVENT_RELOAD_RECOVERED,
    EVENT_ROUTE_CHANGED,
    EVENT_UPSTREAM_DEGRADED,
    EVENT_UPSTREAM_RECOVERED,
    EVENT_UPSTREAM_UNHEALTHY,
    event_types,
    make_control_event,
)
from .credentials import apply_credential_header, credential_metadata, normalize_upstream_credential
from .events import build_event_dispatcher, decision_console_event
from .fabric import annotate_topology_audit, build_fabric_audit_metadata
from .fabric_control import summarize_fabric_control_state
from .leases import LeasePolicyConfig, enforce_mcp_lease_policy, mcp_lease_error_response, preview_mcp_lease_policy
from .manifests import load_manifest, verify_upstream_manifest
from .mcp_auth import (
    OAuthResourceConfig,
    evaluate_oauth_request,
    oauth_resource_metadata_url,
    protected_resource_metadata,
)
from .middleware import ASGIApp, LuaConfig, LuaMiddleware, Receive, Scope, Send
from .recorder import append_record, build_request_record, record_audit_event
from .response_policy import ResponsePolicyConfig, enforce_mcp_response_policy
from .schema_policy import (
    SchemaPolicyConfig,
    enforce_mcp_request_schema_policy,
    mcp_schema_error_response,
    observe_mcp_tool_schemas,
)
from .state import MemoryStateStore, PolicyStateStore, SQLiteStateStore, StateLimits
from .tunnel import TunnelAuditConfig, build_tunnel_audit_metadata

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
    peer: str | None = None
    local_port: int | None = None
    bridge_config: str | None = None
    bridge_command: str | None = None
    bridge_args: tuple[str, ...] = ()
    bridge_cwd: str | None = None
    bridge_env: Mapping[str, str] | None = None
    bridge_private: bool = True
    bridge_ready_timeout: float = 10.0
    manifest: Path | None = None
    manifest_required: bool = False
    manifest_secret_env: str | None = None
    manifest_secret: str | None = None
    manifest_key_id: str | None = None
    manifest_identity: str | None = None
    manifest_metadata: Mapping[str, Any] | None = None
    credential: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class FacadeHealthPolicy:
    enabled: bool = False
    failure_threshold: int = 2
    cooldown_seconds: float = 30.0
    exclude_unhealthy: bool = True

    def __post_init__(self) -> None:
        if self.failure_threshold <= 0:
            raise ValueError("facade health failure_threshold must be positive")
        if self.cooldown_seconds <= 0:
            raise ValueError("facade health cooldown_seconds must be positive")


@dataclass
class FacadeUpstreamHealth:
    name: str
    fingerprint: str
    status: str = "healthy"
    consecutive_failures: int = 0
    failure_count: int = 0
    success_count: int = 0
    reason: str | None = None
    last_error: str | None = None
    last_failure_at: str | None = None
    last_success_at: str | None = None
    unhealthy_since: str | None = None
    retry_after: float | None = None

    def to_dict(self, *, now: float | None = None) -> dict[str, Any]:
        retry_in = None
        if self.retry_after is not None and now is not None:
            retry_in = max(0.0, self.retry_after - now)
        return _drop_empty(
            {
                "name": self.name,
                "status": self.status,
                "consecutive_failures": self.consecutive_failures,
                "failure_count": self.failure_count,
                "success_count": self.success_count,
                "reason": self.reason,
                "last_error": self.last_error,
                "last_failure_at": self.last_failure_at,
                "last_success_at": self.last_success_at,
                "unhealthy_since": self.unhealthy_since,
                "retry_in_seconds": round(retry_in, 3) if retry_in is not None else None,
            }
        )


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
        upstream_credential: Mapping[str, Any] | None = None,
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
        self.upstream_credential = upstream_credential

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
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
                    "access": _composed_access_metadata(scope, lease=lease_metadata),
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
                    "lease": lease_metadata,
                    "access": _composed_access_metadata(scope, lease=lease_metadata),
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
            credential_broker = credential_metadata(self.upstream_credential)
            if credential_broker:
                _set_proxy_metadata(scope, {"upstream_auth": credential_broker})
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
                "access": _composed_access_metadata(scope, lease=lease_metadata),
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
            headers = apply_credential_header(headers, self.upstream_credential)
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

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message_type == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


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


class ManagedHolepunchBridge:
    """Managed local Hypertele bridge for remote Holepunch MCP upstreams."""

    def __init__(
        self,
        command: str,
        args: Sequence[str],
        *,
        url: str,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        ready_timeout: float = 10.0,
        probe_timeout: float = 1.0,
    ) -> None:
        self.command = command
        self.args = tuple(args)
        self.url = url
        self.cwd = cwd
        self.env = dict(env) if env is not None else None
        self.ready_timeout = ready_timeout
        self.probe_timeout = probe_timeout
        self._process: asyncio.subprocess.Process | None = None
        self._process_loop: asyncio.AbstractEventLoop | None = None
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    async def ensure_ready(self) -> None:
        lock = self._lock_for_loop()
        async with lock:
            if await self._is_ready():
                return
            process = await self._ensure_process()
            deadline = asyncio.get_running_loop().time() + self.ready_timeout
            while True:
                if process.returncode is not None:
                    self._process = None
                    self._process_loop = None
                    raise RuntimeError(f"holepunch bridge exited with status {process.returncode}")
                if await self._is_ready():
                    return
                if asyncio.get_running_loop().time() >= deadline:
                    raise RuntimeError(f"holepunch bridge did not become ready at {self.url}")
                await asyncio.sleep(0.1)

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
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=self.cwd,
            env=env,
        )
        self._process_loop = loop
        return self._process

    async def _is_ready(self) -> bool:
        return await asyncio.to_thread(_http_endpoint_reachable, self.url, self.probe_timeout)


@dataclass(eq=False)
class FacadeRouteTable:
    upstreams: tuple[FacadeUpstream, ...]
    parsed: dict[str, SplitResult]
    holepunch_bridges: dict[str, ManagedHolepunchBridge]
    stdio_clients: dict[str, ManagedStdioMcpClient]
    default: FacadeUpstream
    prefixes: tuple[FacadeUpstream, ...]
    fingerprint: str
    revision: int
    active: int = 0
    retired: bool = False

    async def startup(self) -> None:
        if not self.holepunch_bridges:
            return
        await asyncio.gather(*(bridge.ensure_ready() for bridge in self.holepunch_bridges.values()))

    async def aclose(self) -> None:
        for client in self.stdio_clients.values():
            await client.aclose()
        for bridge in self.holepunch_bridges.values():
            await bridge.aclose()

    def upstream_for_tool(self, tool_name: str) -> FacadeUpstream | None:
        for upstream in self.prefixes:
            if tool_name.startswith(upstream.tool_prefix):
                return upstream
        return None


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
        health_policy: FacadeHealthPolicy | None = None,
        control_state_provider: Any = None,
    ) -> None:
        self.timeout = timeout
        self.response_policy = response_policy or ResponsePolicyConfig()
        self.tool_pin_store = tool_pin_store
        self.schema_policy = schema_policy or SchemaPolicyConfig()
        self.tool_schema_store = tool_schema_store
        self.lease_policy = lease_policy or LeasePolicyConfig()
        self.health_policy = health_policy or FacadeHealthPolicy()
        self.control_state_provider = control_state_provider
        self._health: dict[str, FacadeUpstreamHealth] = {}
        self._routes = _build_facade_route_table(upstreams, timeout=timeout, revision=1)
        self._sync_health_upstreams(self._routes)
        self._next_revision = 2
        self._retired_routes: list[FacadeRouteTable] = []

    @property
    def upstreams(self) -> tuple[FacadeUpstream, ...]:
        return self._routes.upstreams

    @property
    def route_fingerprint(self) -> str:
        return self._routes.fingerprint

    @property
    def route_revision(self) -> int:
        return self._routes.revision

    def route_state(self) -> dict[str, Any]:
        routes = self._routes
        return {
            "revision": routes.revision,
            "fingerprint": routes.fingerprint,
            "upstreams": [_upstream_metadata(upstream) for upstream in routes.upstreams],
            "health": self._health_metadata(routes),
        }

    async def reload_upstreams(
        self,
        upstreams: Sequence[FacadeUpstream | Mapping[str, Any]],
        *,
        reason: str = "manual",
        force: bool = False,
    ) -> dict[str, Any]:
        reloaded_at = _utc_timestamp()
        new_routes = _build_facade_route_table(upstreams, timeout=self.timeout, revision=self._next_revision)
        current = self._routes
        if new_routes.fingerprint == current.fingerprint and not force:
            await new_routes.aclose()
            return {
                "ok": True,
                "reloaded": False,
                "reason": reason,
                "revision": current.revision,
                "fingerprint": current.fingerprint,
                "upstream_count": len(current.upstreams),
                "control_events": [],
                "event_types": [],
            }

        self._next_revision += 1
        self._routes = new_routes
        self._sync_health_upstreams(new_routes)
        await self._retire_routes(current)
        control_events = [
            make_control_event(
                EVENT_ROUTE_CHANGED,
                time=reloaded_at,
                severity="info",
                reason_code="fabric.route.reload",
                message="facade route table reloaded",
                subject={"kind": "route_table"},
                previous={
                    "revision": current.revision,
                    "fingerprint": current.fingerprint,
                    "upstreams": [upstream.name for upstream in current.upstreams],
                },
                current={
                    "revision": new_routes.revision,
                    "fingerprint": new_routes.fingerprint,
                    "upstreams": [upstream.name for upstream in new_routes.upstreams],
                },
                details={"reason": reason, "force": force},
            )
        ]
        return {
            "ok": True,
            "reloaded": True,
            "reason": reason,
            "revision": new_routes.revision,
            "previous_revision": current.revision,
            "fingerprint": new_routes.fingerprint,
            "previous_fingerprint": current.fingerprint,
            "upstream_count": len(new_routes.upstreams),
            "upstreams": [upstream.name for upstream in new_routes.upstreams],
            "force": force,
            "control_events": control_events,
            "event_types": event_types(control_events),
        }

    def _sync_health_upstreams(self, routes: FacadeRouteTable) -> None:
        if not self.health_policy.enabled:
            self._health = {}
            return
        active = {upstream.name: _health_upstream_fingerprint(upstream) for upstream in routes.upstreams}
        for name in list(self._health):
            if name not in active:
                del self._health[name]
        for name, fingerprint in active.items():
            current = self._health.get(name)
            if current is None or current.fingerprint != fingerprint:
                self._health[name] = FacadeUpstreamHealth(name=name, fingerprint=fingerprint)

    def _health_metadata(
        self,
        routes: FacadeRouteTable,
        *,
        skipped: Sequence[str] = (),
        failures: Sequence[Mapping[str, Any]] = (),
        control_events: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        if not self.health_policy.enabled:
            return {"enabled": False}
        now = time.monotonic()
        return _drop_empty(
            {
                "enabled": True,
                "failure_threshold": self.health_policy.failure_threshold,
                "cooldown_seconds": self.health_policy.cooldown_seconds,
                "exclude_unhealthy": self.health_policy.exclude_unhealthy,
                "upstreams": {
                    upstream.name: self._health_state(upstream).to_dict(now=now) for upstream in routes.upstreams
                },
                "skipped": list(skipped),
                "failures": list(failures),
                "control_events": list(control_events),
                "event_types": event_types(list(control_events)),
            }
        )

    def _health_metadata_field(
        self,
        routes: FacadeRouteTable,
        *,
        skipped: Sequence[str] = (),
        failures: Sequence[Mapping[str, Any]] = (),
        control_events: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        if not self.health_policy.enabled:
            return {}
        return {
            "upstream_health": self._health_metadata(
                routes,
                skipped=skipped,
                failures=failures,
                control_events=control_events,
            )
        }

    def _health_state(self, upstream: FacadeUpstream) -> FacadeUpstreamHealth:
        state = self._health.get(upstream.name)
        fingerprint = _health_upstream_fingerprint(upstream)
        if state is None or state.fingerprint != fingerprint:
            state = FacadeUpstreamHealth(name=upstream.name, fingerprint=fingerprint)
            if self.health_policy.enabled:
                self._health[upstream.name] = state
        return state

    def _current_operational_controls(self) -> dict[str, Any]:
        if self.control_state_provider is None:
            return summarize_fabric_control_state(None)
        state = self.control_state_provider()
        return summarize_fabric_control_state(state)

    def _should_route_upstream(self, upstream: FacadeUpstream, controls: Mapping[str, Any] | None = None) -> bool:
        if self._upstream_disabled_by_controls(upstream, controls):
            return False
        if not self.health_policy.enabled or not self.health_policy.exclude_unhealthy:
            return True
        state = self._health_state(upstream)
        if state.status != "unhealthy":
            return True
        return state.retry_after is None or time.monotonic() >= state.retry_after

    def _upstream_disabled_by_controls(
        self,
        upstream: FacadeUpstream,
        controls: Mapping[str, Any] | None = None,
    ) -> bool:
        control_summary = _mapping(controls)
        if control_summary.get("paused"):
            return True
        return upstream.name in set(control_summary.get("disabled_upstreams", []))

    def _record_upstream_success(self, upstream: FacadeUpstream, *, operation: str) -> list[dict[str, Any]]:
        if not self.health_policy.enabled:
            return []
        state = self._health_state(upstream)
        previous_status = state.status
        state.success_count += 1
        state.consecutive_failures = 0
        state.status = "healthy"
        state.reason = None
        state.last_error = None
        state.last_success_at = _utc_timestamp()
        state.unhealthy_since = None
        state.retry_after = None
        if previous_status == "healthy":
            return []
        return [
            make_control_event(
                EVENT_UPSTREAM_RECOVERED,
                time=state.last_success_at,
                severity="info",
                reason_code="fabric.upstream.recovered",
                message=f"upstream {upstream.name!r} recovered",
                subject={"kind": "upstream", "name": upstream.name},
                previous={"status": previous_status},
                current=state.to_dict(now=time.monotonic()),
                details={"operation": operation},
            )
        ]

    def _record_upstream_failure(
        self,
        upstream: FacadeUpstream,
        *,
        operation: str,
        reason: str,
        error: str,
    ) -> list[dict[str, Any]]:
        if not self.health_policy.enabled:
            return []
        state = self._health_state(upstream)
        previous_status = state.status
        state.failure_count += 1
        state.consecutive_failures += 1
        state.reason = reason
        state.last_error = error
        state.last_failure_at = _utc_timestamp()
        if state.consecutive_failures >= self.health_policy.failure_threshold:
            state.status = "unhealthy"
            if state.unhealthy_since is None:
                state.unhealthy_since = state.last_failure_at
            state.retry_after = time.monotonic() + self.health_policy.cooldown_seconds
        else:
            state.status = "degraded"
            state.retry_after = None

        if state.status == previous_status:
            return []
        event_type = EVENT_UPSTREAM_UNHEALTHY if state.status == "unhealthy" else EVENT_UPSTREAM_DEGRADED
        reason_code = "fabric.upstream.unhealthy" if state.status == "unhealthy" else "fabric.upstream.degraded"
        return [
            make_control_event(
                event_type,
                time=state.last_failure_at,
                severity="warning",
                reason_code=reason_code,
                message=f"upstream {upstream.name!r} marked {state.status}",
                subject={"kind": "upstream", "name": upstream.name},
                previous={"status": previous_status},
                current=state.to_dict(now=time.monotonic()),
                details={"operation": operation, "reason": reason, "error": error},
            )
        ]

    def _acquire_routes(self) -> FacadeRouteTable:
        routes = self._routes
        routes.active += 1
        return routes

    async def _release_routes(self, routes: FacadeRouteTable) -> None:
        routes.active = max(0, routes.active - 1)
        if routes.retired and routes.active == 0:
            if routes in self._retired_routes:
                self._retired_routes.remove(routes)
            await routes.aclose()

    async def _retire_routes(self, routes: FacadeRouteTable) -> None:
        routes.retired = True
        if routes.active:
            self._retired_routes.append(routes)
            return
        await routes.aclose()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope.get("type") != "http":
            await _send_response(send, status=404, headers=[], body=b"unsupported scope type")
            return

        routes = self._acquire_routes()
        controls = self._current_operational_controls()
        try:
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
                await self._list_tools(routes, scope, request, body, send, controls=controls)
                return
            if method == "tools/call":
                await self._call_tool(routes, scope, request, send, controls=controls)
                return

            await self._forward_to_default(routes, scope, body, send)
        finally:
            await self._release_routes(routes)

    async def _list_tools(
        self,
        routes: FacadeRouteTable,
        scope: Scope,
        request: Mapping[str, Any],
        body: bytes,
        send: Send,
        controls: Mapping[str, Any],
    ) -> None:
        responses = []
        skipped: list[str] = []
        failures: list[dict[str, Any]] = []
        health_events: list[dict[str, Any]] = []
        for upstream in routes.upstreams:
            if not self._should_route_upstream(upstream, controls):
                skipped.append(upstream.name)
                continue
            try:
                response = await self._forward(routes, upstream, scope, body, request)
            except Exception as exc:
                if not self.health_policy.enabled:
                    await self._send_upstream_failure(send, upstream, exc)
                    return
                failures.append({"upstream": upstream.name, "reason": "exception", "error": str(exc)})
                health_events.extend(
                    self._record_upstream_failure(
                        upstream,
                        operation="tools/list",
                        reason="exception",
                        error=str(exc),
                    )
                )
                continue
            if response["status"] < 200 or response["status"] >= 300:
                if self.health_policy.enabled:
                    failures.append(
                        {
                            "upstream": upstream.name,
                            "reason": "http_status",
                            "status": response["status"],
                        }
                    )
                    health_events.extend(
                        self._record_upstream_failure(
                            upstream,
                            operation="tools/list",
                            reason="http_status",
                            error=f"HTTP {response['status']}",
                        )
                    )
                    continue
                await self._send_jsonrpc_error(
                    send,
                    request_id=request.get("id"),
                    code=-32000,
                    message=f"upstream {upstream.name!r} returned HTTP {response['status']}",
                    status=502,
                )
                return
            responses.append((upstream, response))

        if not responses and (skipped or failures):
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "tools/list",
                    "upstreams": [upstream.name for upstream in routes.upstreams],
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
                    "operational_controls": _copy_jsonish(controls),
                    **self._health_metadata_field(
                        routes,
                        skipped=skipped,
                        failures=failures,
                        control_events=health_events,
                    ),
                },
            )
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32000,
                message="no healthy facade upstreams available",
                status=503,
            )
            return

        tools = []
        successful_upstreams = []
        for upstream, response in responses:
            try:
                payload = json.loads(response["body"].decode("utf-8"))
                result = payload.get("result") if isinstance(payload, Mapping) else None
                upstream_tools = result.get("tools") if isinstance(result, Mapping) else None
            except Exception as exc:
                if not self.health_policy.enabled:
                    await self._send_upstream_failure(send, upstream, exc)
                    return
                failures.append({"upstream": upstream.name, "reason": "invalid_tools_list", "error": str(exc)})
                health_events.extend(
                    self._record_upstream_failure(
                        upstream,
                        operation="tools/list",
                        reason="invalid_tools_list",
                        error=str(exc),
                    )
                )
                continue
            if not isinstance(upstream_tools, list):
                if self.health_policy.enabled:
                    failures.append({"upstream": upstream.name, "reason": "missing_result_tools"})
                    health_events.extend(
                        self._record_upstream_failure(
                            upstream,
                            operation="tools/list",
                            reason="missing_result_tools",
                            error="upstream did not return result.tools",
                        )
                    )
                    continue
                await self._send_jsonrpc_error(
                    send,
                    request_id=request.get("id"),
                    code=-32000,
                    message=f"upstream {upstream.name!r} did not return result.tools",
                    status=502,
                )
                return
            successful_upstreams.append(upstream.name)
            health_events.extend(self._record_upstream_success(upstream, operation="tools/list"))
            for tool in upstream_tools:
                if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
                    continue
                decorated = dict(tool)
                decorated["name"] = f"{upstream.tool_prefix}{tool['name']}"
                tools.append(decorated)

        if self.health_policy.enabled and not successful_upstreams and (skipped or failures):
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "tools/list",
                    "upstreams": [upstream.name for upstream in routes.upstreams],
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
                    "operational_controls": _copy_jsonish(controls),
                    **self._health_metadata_field(
                        routes,
                        skipped=skipped,
                        failures=failures,
                        control_events=health_events,
                    ),
                },
            )
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32000,
                message="no healthy facade upstreams available",
                status=503,
            )
            return

        _set_proxy_metadata(
            scope,
            {
                "facade": True,
                "operation": "tools/list",
                "upstreams": [upstream.name for upstream in routes.upstreams],
                "fanout_upstreams": [upstream.name for upstream, _response in responses],
                "available_upstreams": successful_upstreams,
                "upstream_transports": [_upstream_metadata(upstream) for upstream in routes.upstreams],
                "tool_count": len(tools),
                "route_revision": routes.revision,
                "route_fingerprint": routes.fingerprint,
                "operational_controls": _copy_jsonish(controls),
                **self._health_metadata_field(
                    routes,
                    skipped=skipped,
                    failures=failures,
                    control_events=health_events,
                ),
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

    async def _call_tool(
        self,
        routes: FacadeRouteTable,
        scope: Scope,
        request: Mapping[str, Any],
        send: Send,
        controls: Mapping[str, Any],
    ) -> None:
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
        upstream = routes.upstream_for_tool(tool_name)
        if upstream is None:
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32602,
                message=f"unknown facade tool prefix for {tool_name!r}",
                status=404,
            )
            return

        operationally_disabled = self._upstream_disabled_by_controls(upstream, controls)
        if operationally_disabled or not self._should_route_upstream(upstream, controls):
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "tools/call",
                    "upstream": upstream.name,
                    "upstream_transport": upstream.transport,
                    "upstream_metadata": _upstream_metadata(upstream),
                    "tool": tool_name,
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
                    "operational_controls": _copy_jsonish(controls),
                    **self._health_metadata_field(routes, skipped=[upstream.name]),
                },
            )
            await self._send_jsonrpc_error(
                send,
                request_id=request.get("id"),
                code=-32000,
                message=(
                    f"facade upstream {upstream.name!r} is unavailable by operational control"
                    if operationally_disabled
                    else f"facade upstream {upstream.name!r} is unhealthy"
                ),
                status=503,
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
                    "upstream_transport": upstream.transport,
                    "upstream_metadata": _upstream_metadata(upstream),
                    "tool": tool_name,
                    "lease": lease_metadata,
                    "access": _composed_access_metadata(scope, lease=lease_metadata),
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
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
                    "upstream_transport": upstream.transport,
                    "upstream_metadata": _upstream_metadata(upstream),
                    "tool": tool_name,
                    "lease": lease_metadata,
                    "access": _composed_access_metadata(scope, lease=lease_metadata),
                    "schema_validation": schema_request_metadata,
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
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
        health_events: list[dict[str, Any]] = []
        health_failures: list[dict[str, Any]] = []
        try:
            response = await self._forward(routes, upstream, scope, body, rewritten)
        except Exception as exc:
            if self.health_policy.enabled:
                health_failures.append({"upstream": upstream.name, "reason": "exception", "error": str(exc)})
                health_events.extend(
                    self._record_upstream_failure(
                        upstream,
                        operation="tools/call",
                        reason="exception",
                        error=str(exc),
                    )
                )
                _set_proxy_metadata(
                    scope,
                    {
                        "facade": True,
                        "operation": "tools/call",
                        "upstream": upstream.name,
                        "upstream_transport": upstream.transport,
                        "upstream_metadata": _upstream_metadata(upstream),
                        "tool": tool_name,
                        "upstream_tool": rewritten_params["name"],
                        "route_revision": routes.revision,
                        "route_fingerprint": routes.fingerprint,
                        **self._health_metadata_field(
                            routes,
                            failures=health_failures,
                            control_events=health_events,
                        ),
                    },
                )
            await self._send_upstream_failure(send, upstream, exc)
            return
        if response["status"] >= 500:
            health_failures.append({"upstream": upstream.name, "reason": "http_status", "status": response["status"]})
            health_events.extend(
                self._record_upstream_failure(
                    upstream,
                    operation="tools/call",
                    reason="http_status",
                    error=f"HTTP {response['status']}",
                )
            )
        else:
            health_events.extend(self._record_upstream_success(upstream, operation="tools/call"))

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
                "upstream_transport": upstream.transport,
                "upstream_metadata": _upstream_metadata(upstream),
                "tool": tool_name,
                "upstream_tool": rewritten_params["name"],
                "lease": lease_metadata,
                "access": _composed_access_metadata(scope, lease=lease_metadata),
                "schema_validation": schema_request_metadata,
                "response_policy": response_metadata,
                "route_revision": routes.revision,
                "route_fingerprint": routes.fingerprint,
                **self._health_metadata_field(
                    routes,
                    failures=health_failures,
                    control_events=health_events,
                ),
            },
        )
        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )

    async def _forward_to_default(self, routes: FacadeRouteTable, scope: Scope, body: bytes, send: Send) -> None:
        if not self._should_route_upstream(routes.default):
            _set_proxy_metadata(
                scope,
                {
                    "facade": True,
                    "operation": "default",
                    "upstream": routes.default.name,
                    "upstream_transport": routes.default.transport,
                    "upstream_metadata": _upstream_metadata(routes.default),
                    "route_revision": routes.revision,
                    "route_fingerprint": routes.fingerprint,
                    **self._health_metadata_field(routes, skipped=[routes.default.name]),
                },
            )
            await self._send_jsonrpc_error(
                send,
                request_id=None,
                code=-32000,
                message=f"facade upstream {routes.default.name!r} is unhealthy",
                status=503,
            )
            return
        health_events: list[dict[str, Any]] = []
        health_failures: list[dict[str, Any]] = []
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
            response = await self._forward(
                routes,
                routes.default,
                scope,
                body,
                request if isinstance(request, Mapping) else {},
            )
        except Exception as exc:
            if self.health_policy.enabled:
                health_failures.append({"upstream": routes.default.name, "reason": "exception", "error": str(exc)})
                health_events.extend(
                    self._record_upstream_failure(
                        routes.default,
                        operation="default",
                        reason="exception",
                        error=str(exc),
                    )
                )
                _set_proxy_metadata(
                    scope,
                    {
                        "facade": True,
                        "operation": "default",
                        "upstream": routes.default.name,
                        "upstream_transport": routes.default.transport,
                        "upstream_metadata": _upstream_metadata(routes.default),
                        "route_revision": routes.revision,
                        "route_fingerprint": routes.fingerprint,
                        **self._health_metadata_field(
                            routes,
                            failures=health_failures,
                            control_events=health_events,
                        ),
                    },
                )
            await self._send_upstream_failure(send, routes.default, exc)
            return
        if response["status"] >= 500:
            health_failures.append(
                {"upstream": routes.default.name, "reason": "http_status", "status": response["status"]}
            )
            health_events.extend(
                self._record_upstream_failure(
                    routes.default,
                    operation="default",
                    reason="http_status",
                    error=f"HTTP {response['status']}",
                )
            )
        else:
            health_events.extend(self._record_upstream_success(routes.default, operation="default"))

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
                "upstream": routes.default.name,
                "upstream_transport": routes.default.transport,
                "upstream_metadata": _upstream_metadata(routes.default),
                "response_policy": response_metadata,
                "route_revision": routes.revision,
                "route_fingerprint": routes.fingerprint,
                **self._health_metadata_field(
                    routes,
                    failures=health_failures,
                    control_events=health_events,
                ),
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
        routes: FacadeRouteTable,
        upstream: FacadeUpstream,
        scope: Scope,
        body: bytes,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if upstream.transport == "stdio":
            return await routes.stdio_clients[upstream.name].request(request)
        if upstream.transport == "holepunch":
            await routes.holepunch_bridges[upstream.name].ensure_ready()
        return await asyncio.to_thread(self._forward_http, routes, upstream, scope, body)

    def _forward_http(
        self,
        routes: FacadeRouteTable,
        upstream: FacadeUpstream,
        scope: Scope,
        body: bytes,
    ) -> dict[str, Any]:
        parsed = routes.parsed[upstream.name]
        connection = _connection(parsed, self.timeout)
        try:
            headers = _request_headers(scope.get("headers", []), parsed, content_length=len(body))
            headers = apply_credential_header(headers, upstream.credential)
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

    async def aclose(self) -> None:
        await self._routes.aclose()
        for routes in list(self._retired_routes):
            await routes.aclose()
        self._retired_routes.clear()

    async def startup(self) -> None:
        await self._routes.startup()

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "lifespan.startup":
                try:
                    await self.startup()
                except Exception as exc:
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": f"snulbug facade startup failed: {exc}",
                        }
                    )
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message_type == "lifespan.shutdown":
                await self.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

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
        redact_records: bool = True,
        tunnel_audit: TunnelAuditConfig | None = None,
        topology_audit: Mapping[str, Any] | None = None,
        event_dispatcher: Any = None,
    ) -> None:
        self.app = app
        self.policy = policy
        self.record_out = Path(record_out) if record_out is not None else None
        self.redact_records = redact_records
        self.tunnel_audit = tunnel_audit or TunnelAuditConfig()
        self.topology_audit = dict(topology_audit or {})
        self.event_dispatcher = event_dispatcher

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
            metadata=_record_metadata(scope, tunnel_audit=self.tunnel_audit, topology_audit=self.topology_audit),
            redact=self.redact_records,
        )
        if self.record_out is not None:
            append_record(self.record_out, record)
        if self.event_dispatcher is not None:
            audit_event = record_audit_event(record)
            self.event_dispatcher.emit(decision_console_event(record, audit_event=audit_event))

    def _enabled(self) -> bool:
        return self.record_out is not None or self.event_dispatcher is not None


class CloudflareAccessMiddleware:
    """Require Cloudflare Access origin headers before Lua policy and upstream calls."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: CloudflareAccessConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or CloudflareAccessConfig()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or self.config.mode == "off":
            await self.app(scope, receive, send)
            return

        _ensure_scope_state(scope)
        decision = evaluate_cloudflare_access(scope, config=self.config)
        _set_proxy_metadata(scope, {"cloudflare_access": decision.metadata})
        if decision.allowed:
            child_scope = dict(scope)
            child_scope["headers"] = _strip_cloudflare_access_credentials(scope.get("headers", []))
            await self.app(child_scope, receive, send)
            return

        _attach_proxy_reject_trace(
            scope,
            action="reject",
            status=decision.status,
            body=decision.body.decode("utf-8", errors="replace"),
            reason="request failed Cloudflare Access checks",
            reason_code=str(decision.metadata.get("reason_code", "cloudflare_access.rejected")),
            context={"cloudflare_access": decision.metadata},
        )
        await _send_response(
            send,
            status=decision.status,
            headers=[
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(decision.body)).encode("ascii")),
            ],
            body=decision.body,
        )


class LeaseContextMiddleware:
    """Expose non-consuming task lease status to Lua policy context."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: LeasePolicyConfig | None = None,
        context_scope_key: str = "lua",
    ) -> None:
        self.app = app
        self.config = config or LeasePolicyConfig()
        self.context_scope_key = context_scope_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or self.config.lease_file is None:
            await self.app(scope, receive, send)
            return

        body, replay_receive = await _capture_body(receive)
        request = _jsonrpc_request(body)
        _allowed, lease_metadata = preview_mcp_lease_policy(
            request,
            scope,
            config=self.config,
        )
        lease_context = _lease_context_metadata(lease_metadata)
        _set_proxy_metadata(scope, {"lease_preview": lease_context})

        child_scope = dict(scope)
        context = child_scope.get(self.context_scope_key)
        lua_context = dict(context) if isinstance(context, Mapping) else {}
        lua_context["lease"] = lease_context
        child_scope[self.context_scope_key] = lua_context
        await self.app(child_scope, replay_receive, send)


class OAuthResourceMiddleware:
    """Require OAuth bearer tokens before Lua policy and upstream calls."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: OAuthResourceConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or OAuthResourceConfig()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.config.enabled:
            await self.app(scope, receive, send)
            return

        if _is_oauth_resource_metadata_request(scope, self.config):
            await self._send_protected_resource_metadata(scope, send)
            return

        body = None
        replay_receive = receive
        if self.config.mapped_scopes:
            body, replay_receive = await _capture_body(receive)

        _ensure_scope_state(scope)
        decision = evaluate_oauth_request(scope, config=self.config, body=body)
        auth_metadata = dict(decision.metadata)
        if decision.allowed:
            auth_metadata["anti_passthrough"] = _anti_passthrough_metadata(scope, self.config)
        _set_proxy_metadata(scope, {"auth": auth_metadata})
        if decision.allowed:
            child_scope = dict(scope)
            context = child_scope.get("lua")
            lua_context = dict(context) if isinstance(context, Mapping) else {}
            lua_context["auth"] = {
                **decision.context,
                "anti_passthrough": auth_metadata["anti_passthrough"],
            }
            child_scope["lua"] = lua_context
            if self.config.strip_authorization_upstream:
                child_scope["headers"] = _strip_authorization_header(scope.get("headers", []))
            await self.app(child_scope, replay_receive, send)
            return

        body = decision.body.decode("utf-8", errors="replace")
        _attach_proxy_reject_trace(
            scope,
            action="challenge",
            status=decision.status,
            body=body,
            reason="request failed OAuth bearer-token checks",
            reason_code=str(decision.metadata.get("reason_code", "oauth.rejected")),
            context={"auth": decision.metadata},
        )
        await _send_response(
            send,
            status=decision.status,
            headers=decision.headers,
            body=decision.body,
        )

    async def _send_protected_resource_metadata(self, scope: Scope, send: Send) -> None:
        payload = protected_resource_metadata(self.config)
        response = _json_response(payload)
        if str(scope.get("method", "GET")).upper() == "HEAD":
            response["body"] = b""
            response["headers"] = _merge_headers(
                response["headers"],
                [(b"content-length", b"0")],
            )
        await _send_response(
            send,
            status=response["status"],
            headers=response["headers"],
            body=response["body"],
        )


class FabricConfigReloadMiddleware:
    """Refresh facade upstream routes from declarative fabric config while serving traffic."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        facade: McpFacadeProxyApp,
        config: str | Path,
        interval: float = 2.0,
        proxy_overrides: Mapping[str, Any] | None = None,
        topology_audit: Mapping[str, Any] | None = None,
        control_state_provider: Any = None,
    ) -> None:
        if interval <= 0:
            raise ValueError("fabric reload interval must be positive")
        self.app = app
        self.facade = facade
        self.config = Path(config)
        self.interval = float(interval)
        self.proxy_overrides = dict(proxy_overrides or {})
        self.topology_audit = dict(topology_audit or {})
        self.control_state_provider = control_state_provider
        self._next_check = 0.0
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None
        self._last_reload: dict[str, Any] = {
            "ok": True,
            "reloaded": False,
            "config": str(self.config),
            "route_revision": facade.route_revision,
            "route_fingerprint": facade.route_fingerprint,
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            await self._maybe_reload()
            state = _ensure_scope_state(scope)
            if self.topology_audit:
                state["snulbug_topology_audit"] = self.topology_audit
            state["snulbug_fabric_reload"] = dict(self._last_reload)
        await self.app(scope, receive, send)

    async def _maybe_reload(self) -> None:
        now = time.monotonic()
        if now < self._next_check:
            return
        lock = self._lock_for_loop()
        async with lock:
            now = time.monotonic()
            if now < self._next_check:
                return
            self._next_check = now + self.interval
            checked_at = _utc_timestamp()
            previous_reload_ok = bool(self._last_reload.get("ok", True))
            try:
                loaded = await asyncio.to_thread(
                    _load_fabric_reload_config,
                    self.config,
                    self.proxy_overrides,
                    self._load_control_state(),
                )
                result = await self.facade.reload_upstreams(
                    loaded["upstreams"],
                    reason="control:force_reload"
                    if loaded["operational_controls"].get("force_reload")
                    else f"config:{self.config}",
                    force=bool(loaded["operational_controls"].get("force_reload")),
                )
                self.topology_audit = loaded["topology_audit"]
                control_events = list(result.get("control_events", []))
                if not previous_reload_ok:
                    control_events.append(
                        make_control_event(
                            EVENT_RELOAD_RECOVERED,
                            time=checked_at,
                            severity="info",
                            reason_code="fabric.reload.recovered",
                            message="fabric config reload recovered",
                            subject={"kind": "fabric_reload", "config": str(self.config)},
                            current={
                                "route_revision": self.facade.route_revision,
                                "route_fingerprint": self.facade.route_fingerprint,
                            },
                        )
                    )
                self._last_reload = {
                    **result,
                    "config": str(self.config),
                    "checked_at": checked_at,
                    "route_revision": self.facade.route_revision,
                    "route_fingerprint": self.facade.route_fingerprint,
                    "summary": loaded["summary"],
                    "operational_controls": loaded["operational_controls"],
                    "control_events": control_events,
                    "event_types": event_types(control_events),
                }
            except Exception as exc:
                control_events = [
                    make_control_event(
                        EVENT_RELOAD_FAILED,
                        time=checked_at,
                        severity="error",
                        reason_code="fabric.reload.failed",
                        message="fabric config reload failed",
                        subject={"kind": "fabric_reload", "config": str(self.config)},
                        current={
                            "route_revision": self.facade.route_revision,
                            "route_fingerprint": self.facade.route_fingerprint,
                        },
                        details={"error": str(exc)},
                    )
                ]
                self._last_reload = {
                    "ok": False,
                    "reloaded": False,
                    "config": str(self.config),
                    "checked_at": checked_at,
                    "error": str(exc),
                    "route_revision": self.facade.route_revision,
                    "route_fingerprint": self.facade.route_fingerprint,
                    "control_events": control_events,
                    "event_types": event_types(control_events),
                }

    def _lock_for_loop(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _load_control_state(self) -> Mapping[str, Any] | None:
        if self.control_state_provider is None:
            return None
        return self.control_state_provider()


def create_proxy_application(
    upstream: str | None,
    policy: str | Path,
    *,
    upstream_credential: Mapping[str, Any] | None = None,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None = None,
    state_store: PolicyStateStore | None = None,
    state_limits: StateLimits | None = None,
    trace: bool = True,
    max_body_bytes: int = 64 * 1024,
    timeout: float = 30.0,
    record_out: str | Path | None = None,
    redact_records: bool = True,
    response_max_bytes: int | None = 256 * 1024,
    response_redact_secrets: bool = True,
    response_block_instructions: bool = False,
    tool_pinning: bool = True,
    tool_pinning_action: str = "block",
    schema_validation: bool = True,
    schema_validation_action: str = "block",
    facade_health_routing: bool = False,
    facade_health_failure_threshold: int = 2,
    facade_health_cooldown_seconds: float = 30.0,
    facade_health_exclude_unhealthy: bool = True,
    lease_file: str | Path | None = None,
    lease_required: bool = False,
    lease_header: str = "x-snulbug-lease",
    tunnel_provider: str = "auto",
    tunnel_public_url: str | None = None,
    cloudflare_access: str = "off",
    cloudflare_access_require_jwt: bool = True,
    cloudflare_access_require_email: bool = False,
    cloudflare_access_require_cf_ray: bool = True,
    cloudflare_access_allowed_emails: Sequence[str] = (),
    cloudflare_access_allowed_domains: Sequence[str] = (),
    auth_config: Mapping[str, Any] | OAuthResourceConfig | None = None,
    topology_audit: Mapping[str, Any] | None = None,
    event_sinks: Sequence[Mapping[str, Any]] | None = None,
    event_dispatcher: Any = None,
    fabric_reload_config: str | Path | None = None,
    fabric_reload_interval: float = 2.0,
    fabric_reload_overrides: Mapping[str, Any] | None = None,
    fabric_control_state_provider: Any = None,
    confirm: bool = False,
    confirm_handler: Any = None,
) -> ASGIApp:
    """Create an ASGI app that applies Lua policy before proxying to an upstream."""

    if event_dispatcher is None:
        event_dispatcher = build_event_dispatcher(event_sinks=event_sinks)
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
    facade_health_policy = FacadeHealthPolicy(
        enabled=facade_health_routing,
        failure_threshold=facade_health_failure_threshold,
        cooldown_seconds=facade_health_cooldown_seconds,
        exclude_unhealthy=facade_health_exclude_unhealthy,
    )
    lease_policy = LeasePolicyConfig(
        lease_file=Path(lease_file) if lease_file else None,
        required=lease_required,
        header=lease_header,
    )
    proxy = _proxy_app(
        upstream,
        upstream_credential=upstream_credential,
        upstreams=upstreams,
        timeout=timeout,
        response_policy=response_policy,
        tool_pin_store=effective_state_store if tool_pinning else None,
        schema_policy=schema_policy,
        tool_schema_store=effective_state_store if schema_validation else None,
        lease_policy=lease_policy,
        health_policy=facade_health_policy,
        control_state_provider=fabric_control_state_provider,
    )
    facade_proxy = proxy if isinstance(proxy, McpFacadeProxyApp) else None
    lua_config = LuaConfig(
        read_body=True,
        max_body_bytes=max_body_bytes,
        trace=(trace or record_out is not None or event_dispatcher is not None),
    )
    app = LuaMiddleware(
        proxy,
        Path(policy),
        config=lua_config,
        state_store=effective_state_store,
        state_limits=state_limits,
        confirm_handler=confirm_handler or (ConfirmationBroker(enabled=True) if confirm else None),
    )
    if lease_policy.lease_file is not None:
        app = LeaseContextMiddleware(
            app,
            config=lease_policy,
            context_scope_key=lua_config.context_scope_key,
        )
    oauth_config = _oauth_resource_config(auth_config)
    if oauth_config.enabled:
        app = OAuthResourceMiddleware(app, config=oauth_config)
    cloudflare_access_config = CloudflareAccessConfig(
        mode=cloudflare_access,
        require_jwt=cloudflare_access_require_jwt,
        require_email=cloudflare_access_require_email,
        require_cf_ray=cloudflare_access_require_cf_ray,
        allowed_emails=cloudflare_access_allowed_emails,
        allowed_domains=cloudflare_access_allowed_domains,
    )
    if cloudflare_access_config.mode != "off":
        app = CloudflareAccessMiddleware(app, config=cloudflare_access_config)
    if record_out is not None or event_dispatcher is not None:
        app = ProxyRecorderMiddleware(
            app,
            policy=policy,
            record_out=record_out,
            redact_records=redact_records,
            tunnel_audit=TunnelAuditConfig(provider=tunnel_provider, public_url=tunnel_public_url),
            topology_audit=topology_audit,
            event_dispatcher=event_dispatcher,
        )
    if fabric_reload_config is not None:
        if facade_proxy is None:
            raise ValueError("fabric reload requires facade upstreams")
        app = FabricConfigReloadMiddleware(
            app,
            facade=facade_proxy,
            config=fabric_reload_config,
            interval=fabric_reload_interval,
            proxy_overrides=fabric_reload_overrides,
            topology_audit=topology_audit,
            control_state_provider=fabric_control_state_provider,
        )
    return app


def run_proxy(
    *,
    upstream: str | None,
    policy: str | Path,
    upstream_credential: Mapping[str, Any] | None = None,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    state: str = "memory",
    trace: bool = True,
    max_body_bytes: int = 64 * 1024,
    timeout: float = 30.0,
    record_out: str | Path | None = None,
    redact_records: bool = True,
    response_max_bytes: int | None = 256 * 1024,
    response_redact_secrets: bool = True,
    response_block_instructions: bool = False,
    tool_pinning: bool = True,
    tool_pinning_action: str = "block",
    schema_validation: bool = True,
    schema_validation_action: str = "block",
    facade_health_routing: bool = False,
    facade_health_failure_threshold: int = 2,
    facade_health_cooldown_seconds: float = 30.0,
    facade_health_exclude_unhealthy: bool = True,
    lease_file: str | Path | None = None,
    lease_required: bool = False,
    lease_header: str = "x-snulbug-lease",
    tunnel_provider: str = "auto",
    tunnel_public_url: str | None = None,
    cloudflare_access: str = "off",
    cloudflare_access_require_jwt: bool = True,
    cloudflare_access_require_email: bool = False,
    cloudflare_access_require_cf_ray: bool = True,
    cloudflare_access_allowed_emails: Sequence[str] = (),
    cloudflare_access_allowed_domains: Sequence[str] = (),
    auth_config: Mapping[str, Any] | OAuthResourceConfig | None = None,
    topology_audit: Mapping[str, Any] | None = None,
    event_sinks: Sequence[Mapping[str, Any]] | None = None,
    fabric_reload_config: str | Path | None = None,
    fabric_reload_interval: float = 2.0,
    fabric_reload_overrides: Mapping[str, Any] | None = None,
    fabric_control_state_provider: Any = None,
    confirm: bool = False,
) -> None:
    """Run the reverse proxy with uvicorn."""

    try:
        import uvicorn  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError("reverse proxy mode requires uvicorn; run `uv sync` from the source repository") from exc

    app = create_proxy_application(
        upstream,
        policy,
        upstream_credential=upstream_credential,
        upstreams=upstreams,
        state_store=_state_store(state),
        trace=trace,
        max_body_bytes=max_body_bytes,
        timeout=timeout,
        record_out=record_out,
        redact_records=redact_records,
        response_max_bytes=response_max_bytes,
        response_redact_secrets=response_redact_secrets,
        response_block_instructions=response_block_instructions,
        tool_pinning=tool_pinning,
        tool_pinning_action=tool_pinning_action,
        schema_validation=schema_validation,
        schema_validation_action=schema_validation_action,
        facade_health_routing=facade_health_routing,
        facade_health_failure_threshold=facade_health_failure_threshold,
        facade_health_cooldown_seconds=facade_health_cooldown_seconds,
        facade_health_exclude_unhealthy=facade_health_exclude_unhealthy,
        lease_file=lease_file,
        lease_required=lease_required,
        lease_header=lease_header,
        tunnel_provider=tunnel_provider,
        tunnel_public_url=tunnel_public_url,
        cloudflare_access=cloudflare_access,
        cloudflare_access_require_jwt=cloudflare_access_require_jwt,
        cloudflare_access_require_email=cloudflare_access_require_email,
        cloudflare_access_require_cf_ray=cloudflare_access_require_cf_ray,
        cloudflare_access_allowed_emails=cloudflare_access_allowed_emails,
        cloudflare_access_allowed_domains=cloudflare_access_allowed_domains,
        auth_config=auth_config,
        topology_audit=topology_audit,
        event_sinks=event_sinks,
        fabric_reload_config=fabric_reload_config,
        fabric_reload_interval=fabric_reload_interval,
        fabric_reload_overrides=fabric_reload_overrides,
        fabric_control_state_provider=fabric_control_state_provider,
        confirm=confirm,
    )
    uvicorn.run(app, host=host, port=port)


def proxy_config_run_kwargs(
    proxy_config: Mapping[str, Any],
    fabric_config: Mapping[str, Any] | None = None,
    *,
    topology_audit: Mapping[str, Any] | None = None,
    fabric_reload_config: str | Path | None = None,
    fabric_reload_interval: float = 2.0,
    fabric_reload_overrides: Mapping[str, Any] | None = None,
    fabric_control_state_provider: Any = None,
) -> dict[str, Any]:
    """Expand a normalized MCP proxy config into run_proxy keyword arguments."""

    effective_fabric_config = dict(fabric_config or {})
    effective_fabric_config["proxy"] = proxy_config
    effective_topology_audit = topology_audit or build_fabric_audit_metadata(effective_fabric_config)
    return {
        "upstream": proxy_config["upstream"],
        "upstream_credential": proxy_config.get("upstream_credential"),
        "upstreams": proxy_config["upstreams"],
        "policy": proxy_config["policy"],
        "host": proxy_config["host"],
        "port": proxy_config["port"],
        "state": proxy_config["state"],
        "trace": proxy_config["trace"],
        "max_body_bytes": proxy_config["max_body_bytes"],
        "timeout": proxy_config["timeout"],
        "record_out": proxy_config["record_out"],
        "redact_records": proxy_config["redact_records"],
        "confirm": proxy_config["confirm"],
        "response_max_bytes": proxy_config["response_max_bytes"],
        "response_redact_secrets": proxy_config["response_redact_secrets"],
        "response_block_instructions": proxy_config["response_block_instructions"],
        "tool_pinning": proxy_config["tool_pinning"],
        "tool_pinning_action": proxy_config["tool_pinning_action"],
        "schema_validation": proxy_config["schema_validation"],
        "schema_validation_action": proxy_config["schema_validation_action"],
        "facade_health_routing": proxy_config["facade_health_routing"],
        "facade_health_failure_threshold": proxy_config["facade_health_failure_threshold"],
        "facade_health_cooldown_seconds": proxy_config["facade_health_cooldown_seconds"],
        "facade_health_exclude_unhealthy": proxy_config["facade_health_exclude_unhealthy"],
        "lease_file": proxy_config["lease_file"],
        "lease_required": proxy_config["lease_required"],
        "lease_header": proxy_config["lease_header"],
        "tunnel_provider": proxy_config["tunnel_provider"],
        "tunnel_public_url": proxy_config["tunnel_public_url"],
        "cloudflare_access": proxy_config["cloudflare_access"],
        "cloudflare_access_require_jwt": proxy_config["cloudflare_access_require_jwt"],
        "cloudflare_access_require_email": proxy_config["cloudflare_access_require_email"],
        "cloudflare_access_require_cf_ray": proxy_config["cloudflare_access_require_cf_ray"],
        "cloudflare_access_allowed_emails": proxy_config["cloudflare_access_allowed_emails"],
        "cloudflare_access_allowed_domains": proxy_config["cloudflare_access_allowed_domains"],
        "auth_config": proxy_config.get("auth", {}),
        "topology_audit": effective_topology_audit,
        "event_sinks": proxy_config["event_sinks"],
        "fabric_reload_config": fabric_reload_config,
        "fabric_reload_interval": fabric_reload_interval,
        "fabric_reload_overrides": fabric_reload_overrides,
        "fabric_control_state_provider": fabric_control_state_provider,
    }


def run_mcp_proxy_config(
    proxy_config: Mapping[str, Any],
    fabric_config: Mapping[str, Any] | None = None,
    *,
    runner: Any = None,
    topology_audit: Mapping[str, Any] | None = None,
    fabric_reload_config: str | Path | None = None,
    fabric_reload_interval: float = 2.0,
    fabric_reload_overrides: Mapping[str, Any] | None = None,
    fabric_control_state_provider: Any = None,
) -> None:
    """Run an MCP proxy from normalized config."""

    proxy_runner = runner or run_proxy
    proxy_runner(
        **proxy_config_run_kwargs(
            proxy_config,
            fabric_config,
            topology_audit=topology_audit,
            fabric_reload_config=fabric_reload_config,
            fabric_reload_interval=fabric_reload_interval,
            fabric_reload_overrides=fabric_reload_overrides,
            fabric_control_state_provider=fabric_control_state_provider,
        )
    )


def _proxy_app(
    upstream: str | None,
    *,
    upstream_credential: Mapping[str, Any] | None,
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]] | None,
    timeout: float,
    response_policy: ResponsePolicyConfig,
    tool_pin_store: PolicyStateStore | None,
    schema_policy: SchemaPolicyConfig,
    tool_schema_store: PolicyStateStore | None,
    lease_policy: LeasePolicyConfig,
    health_policy: FacadeHealthPolicy,
    control_state_provider: Any = None,
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
            health_policy=health_policy,
            control_state_provider=control_state_provider,
        )
    if upstream is None:
        raise ValueError("upstream is required unless facade upstreams are configured")
    return ReverseProxyApp(
        upstream,
        timeout=timeout,
        upstream_credential=upstream_credential,
        response_policy=response_policy,
        tool_pin_store=tool_pin_store,
        schema_policy=schema_policy,
        tool_schema_store=tool_schema_store,
        lease_policy=lease_policy,
    )


def _oauth_resource_config(value: Mapping[str, Any] | OAuthResourceConfig | None) -> OAuthResourceConfig:
    if isinstance(value, OAuthResourceConfig):
        return value
    normalized = normalize_mcp_auth_config(value or {})
    return OAuthResourceConfig(
        mode=normalized["mode"],
        resource=normalized["resource"],
        issuer=normalized["issuer"],
        authorization_servers=tuple(normalized["authorization_servers"]),
        audience=normalized["audience"],
        required_scopes=tuple(normalized["required_scopes"]),
        scopes_supported=tuple(normalized["scopes_supported"]),
        jwks_path=normalized["jwks_path"],
        resource_metadata_url=normalized["resource_metadata_url"],
        realm=normalized["realm"],
        leeway_seconds=normalized["leeway_seconds"],
        strip_authorization_upstream=normalized["strip_authorization_upstream"],
        scope_map={scope: tuple(selectors) for scope, selectors in normalized["scope_map"].items()},
    )


def _build_facade_route_table(
    upstreams: Sequence[FacadeUpstream | Mapping[str, Any]],
    *,
    timeout: float,
    revision: int,
) -> FacadeRouteTable:
    coerced = tuple(_coerce_facade_upstream(upstream) for upstream in upstreams)
    if not coerced:
        raise ValueError("facade mode requires at least one upstream")
    parsed = {
        upstream.name: _parse_upstream(_required_url(upstream))
        for upstream in coerced
        if upstream.transport in {"http", "holepunch"}
    }
    holepunch_bridges = {
        upstream.name: ManagedHolepunchBridge(
            _required_bridge_command(upstream),
            upstream.bridge_args,
            url=_required_url(upstream),
            cwd=upstream.bridge_cwd,
            env=upstream.bridge_env,
            ready_timeout=upstream.bridge_ready_timeout,
            probe_timeout=min(timeout, 1.0),
        )
        for upstream in coerced
        if upstream.transport == "holepunch"
    }
    stdio_clients = {
        upstream.name: ManagedStdioMcpClient(
            _required_command(upstream),
            upstream.args,
            cwd=upstream.cwd,
            env=upstream.env,
            timeout=timeout,
        )
        for upstream in coerced
        if upstream.transport == "stdio"
    }
    default = next((upstream for upstream in coerced if upstream.default), coerced[0])
    prefixes = tuple(sorted(coerced, key=lambda upstream: len(upstream.tool_prefix), reverse=True))
    return FacadeRouteTable(
        upstreams=coerced,
        parsed=parsed,
        holepunch_bridges=holepunch_bridges,
        stdio_clients=stdio_clients,
        default=default,
        prefixes=prefixes,
        fingerprint=_facade_upstreams_fingerprint(coerced),
        revision=revision,
    )


def _load_fabric_reload_config(
    config: Path,
    proxy_overrides: Mapping[str, Any],
    control_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    proxy_config = load_mcp_proxy_config(config)
    if proxy_overrides:
        proxy_config = merge_mcp_proxy_config(proxy_config, proxy_overrides)
    fabric_config = load_mcp_fabric_config(config)
    fabric_config["proxy"] = proxy_config
    topology_audit = build_fabric_audit_metadata(fabric_config)
    operational_controls = summarize_fabric_control_state(control_state)
    return {
        "upstreams": proxy_config["upstreams"],
        "topology_audit": topology_audit,
        "summary": topology_audit.get("summary", {}),
        "operational_controls": operational_controls,
    }


def _facade_upstreams_fingerprint(upstreams: Sequence[FacadeUpstream]) -> str:
    payload = [_facade_upstream_reload_fingerprint(upstream) for upstream in upstreams]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _facade_upstream_reload_fingerprint(upstream: FacadeUpstream) -> dict[str, Any]:
    return {
        "name": upstream.name,
        "tool_prefix": upstream.tool_prefix,
        "default": upstream.default,
        "transport": upstream.transport,
        "url": upstream.url,
        "command": upstream.command,
        "args": list(upstream.args),
        "cwd": upstream.cwd,
        "env_keys": sorted((upstream.env or {}).keys()),
        "peer": upstream.peer,
        "local_port": upstream.local_port,
        "bridge_config": upstream.bridge_config,
        "bridge_command": upstream.bridge_command,
        "bridge_args": list(upstream.bridge_args),
        "bridge_cwd": upstream.bridge_cwd,
        "bridge_env_keys": sorted((upstream.bridge_env or {}).keys()),
        "bridge_private": upstream.bridge_private,
        "bridge_ready_timeout": upstream.bridge_ready_timeout,
        "manifest": str(upstream.manifest) if upstream.manifest is not None else None,
        "manifest_required": upstream.manifest_required,
        "manifest_key_id": upstream.manifest_key_id,
        "manifest_identity": upstream.manifest_identity,
        "manifest_metadata": _copy_jsonish(upstream.manifest_metadata or {}),
        "credential": credential_metadata(upstream.credential),
    }


def _health_upstream_fingerprint(upstream: FacadeUpstream) -> str:
    payload = _facade_upstream_reload_fingerprint(upstream)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _copy_jsonish(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _copy_jsonish(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, tuple):
        return [_copy_jsonish(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


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


def _lease_context_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "enabled": metadata.get("enabled"),
            "required": metadata.get("required"),
            "header": metadata.get("header"),
            "checked": metadata.get("checked"),
            "method": metadata.get("method"),
            "skipped": metadata.get("skipped"),
            "reason_code": metadata.get("reason_code"),
            "blocked": metadata.get("blocked"),
            "allowed": metadata.get("allowed"),
            "id": metadata.get("id"),
            "task": metadata.get("task"),
            "expires_at": metadata.get("expires_at"),
            "use_count": metadata.get("use_count"),
            "max_calls": metadata.get("max_calls"),
            "last_used_at": metadata.get("last_used_at"),
            "tool": metadata.get("tool"),
            "path": metadata.get("path"),
            "host": metadata.get("host"),
            "command": metadata.get("command"),
            "preview": metadata.get("consume") is False,
        }
    )


def _composed_access_metadata(scope: Scope, *, lease: Mapping[str, Any] | None = None) -> dict[str, Any]:
    state = scope.get("state")
    proxy_metadata = state.get("snulbug_proxy") if isinstance(state, Mapping) else {}
    proxy_metadata = proxy_metadata if isinstance(proxy_metadata, Mapping) else {}
    auth = _mapping(proxy_metadata.get("auth"))
    lease_metadata = _mapping(lease or proxy_metadata.get("lease") or proxy_metadata.get("lease_preview"))
    trace = _trace_result(scope)
    decision = _mapping(trace.get("decision"))

    oauth_enabled = auth.get("enabled") is True
    oauth_allowed = None if not oauth_enabled else auth.get("allowed") is True
    scope_map = _mapping(auth.get("scope_map"))
    scope_map_enabled = scope_map.get("enabled") is True
    scope_allowed = None if not scope_map_enabled else scope_map.get("allowed") is True
    lease_enabled = lease_metadata.get("enabled") is True
    lease_required = lease_metadata.get("required") is True
    lease_required_for_request = lease_required and lease_metadata.get("method") == "tools/call"
    if lease_enabled and lease_metadata.get("checked"):
        lease_allowed = lease_metadata.get("allowed") is True
    else:
        lease_allowed = None
    lua_action = decision.get("action") or trace.get("action")
    lua_allowed = lua_action in {"continue", "set_context", "rewrite", "rate_limit"}

    allowed = (
        (not oauth_enabled or oauth_allowed is True)
        and (not scope_map_enabled or scope_allowed is True)
        and (not lease_required_for_request or lease_allowed is True)
        and lua_allowed
    )
    reason_code = "access.allowed"
    if oauth_enabled and oauth_allowed is not True:
        reason_code = str(auth.get("reason_code") or "oauth.rejected")
    elif scope_map_enabled and scope_allowed is not True:
        reason_code = str(scope_map.get("reason_code") or "oauth.scope_map_denied")
    elif lease_required_for_request and lease_allowed is not True:
        reason_code = str(lease_metadata.get("reason_code") or "lease.required")
    elif not lua_allowed:
        reason_code = str(decision.get("reason_code") or "lua.rejected")
    elif oauth_enabled and lease_required_for_request:
        reason_code = "access.oauth_scope_lease_lua_allowed"

    return _drop_empty(
        {
            "model": "oauth_scope_lease_lua",
            "allowed": allowed,
            "reason_code": reason_code,
            "auth": _drop_empty(
                {
                    "enabled": oauth_enabled,
                    "allowed": oauth_allowed,
                    "subject": auth.get("subject"),
                    "issuer": auth.get("issuer"),
                    "client_id": auth.get("client_id"),
                    "email": auth.get("email"),
                    "tenant": auth.get("tenant"),
                    "groups": auth.get("groups"),
                    "reason_code": auth.get("reason_code"),
                    "scope_match": auth.get("scope_match"),
                }
            ),
            "scope": _drop_empty(
                {
                    "enabled": scope_map_enabled,
                    "allowed": scope_allowed,
                    "matched_scope": scope_map.get("matched_scope"),
                    "matched_selector": scope_map.get("matched_selector"),
                    "matched_request_selector": scope_map.get("matched_request_selector"),
                    "reason_code": scope_map.get("reason_code"),
                }
            ),
            "lease": _drop_empty(
                {
                    "enabled": lease_enabled,
                    "required": lease_required,
                    "required_for_request": lease_required_for_request,
                    "checked": lease_metadata.get("checked"),
                    "allowed": lease_allowed,
                    "id": lease_metadata.get("id"),
                    "task": lease_metadata.get("task"),
                    "tool": lease_metadata.get("tool"),
                    "reason_code": lease_metadata.get("reason_code"),
                }
            ),
            "lua": _drop_empty(
                {
                    "allowed": lua_allowed,
                    "action": lua_action,
                    "reason_code": decision.get("reason_code"),
                }
            ),
        }
    )


def _coerce_facade_upstream(upstream: FacadeUpstream | Mapping[str, Any]) -> FacadeUpstream:
    if isinstance(upstream, FacadeUpstream):
        return upstream
    name = upstream.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("facade upstream name must be a non-empty string")
    transport = str(upstream.get("transport") or ("stdio" if upstream.get("command") else "http"))
    if transport not in {"http", "stdio", "holepunch"}:
        raise ValueError(f"facade upstream {name!r} transport must be 'http', 'stdio', or 'holepunch'")
    url = upstream.get("url", upstream.get("upstream"))
    command = upstream.get("command")
    if transport in {"http", "holepunch"} and (not isinstance(url, str) or not url):
        raise ValueError(f"facade upstream {name!r} url must be a non-empty string")
    if transport == "stdio" and (not isinstance(command, str) or not command):
        raise ValueError(f"facade upstream {name!r} command must be a non-empty string")
    peer = upstream.get("peer")
    if peer is not None and not isinstance(peer, str):
        raise ValueError(f"facade upstream {name!r} peer must be a string")
    local_port = upstream.get("local_port")
    if local_port is not None and (not isinstance(local_port, int) or local_port <= 0):
        raise ValueError(f"facade upstream {name!r} local_port must be a positive integer")
    bridge_config = upstream.get("bridge_config")
    if bridge_config is not None and not isinstance(bridge_config, str):
        raise ValueError(f"facade upstream {name!r} bridge_config must be a string")
    bridge_command = upstream.get("bridge_command")
    if transport == "holepunch" and (not isinstance(bridge_command, str) or not bridge_command):
        raise ValueError(f"facade upstream {name!r} bridge_command must be a non-empty string")
    bridge_args = upstream.get("bridge_args", ())
    if not isinstance(bridge_args, Sequence) or isinstance(bridge_args, str | bytes | bytearray):
        raise ValueError(f"facade upstream {name!r} bridge_args must be a list of strings")
    if not all(isinstance(arg, str) for arg in bridge_args):
        raise ValueError(f"facade upstream {name!r} bridge_args must be a list of strings")
    bridge_cwd = upstream.get("bridge_cwd")
    if bridge_cwd is not None and not isinstance(bridge_cwd, str):
        raise ValueError(f"facade upstream {name!r} bridge_cwd must be a string")
    bridge_env = upstream.get("bridge_env")
    if bridge_env is not None:
        if not isinstance(bridge_env, Mapping) or not all(isinstance(key, str) for key in bridge_env):
            raise ValueError(f"facade upstream {name!r} bridge_env must be a string table")
        if not all(isinstance(value, str) for value in bridge_env.values()):
            raise ValueError(f"facade upstream {name!r} bridge_env must be a string table")
    bridge_private = upstream.get("bridge_private", True)
    if not isinstance(bridge_private, bool):
        raise ValueError(f"facade upstream {name!r} bridge_private must be a boolean")
    bridge_ready_timeout = upstream.get("bridge_ready_timeout", 10.0)
    if not isinstance(bridge_ready_timeout, int | float) or float(bridge_ready_timeout) <= 0:
        raise ValueError(f"facade upstream {name!r} bridge_ready_timeout must be a positive number")
    if transport == "holepunch" and not bridge_args:
        bridge_args = _holepunch_bridge_args(
            url=str(url),
            local_port=local_port,
            peer=peer,
            bridge_config=bridge_config,
            bridge_private=bridge_private,
        )
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
    credential = upstream.get("credential")
    if credential is not None:
        credential = normalize_upstream_credential(credential, field=f"facade upstream {name!r} credential")
    manifest = upstream.get("manifest", upstream.get("manifest_path"))
    if manifest is not None and not isinstance(manifest, str | Path):
        raise ValueError(f"facade upstream {name!r} manifest must be a string path")
    manifest_secret_env = upstream.get("manifest_secret_env")
    manifest_secret = upstream.get("manifest_secret")
    manifest_key_id = upstream.get("manifest_key_id")
    manifest_identity = upstream.get("manifest_identity")
    for manifest_field, manifest_value in (
        ("manifest_secret_env", manifest_secret_env),
        ("manifest_secret", manifest_secret),
        ("manifest_key_id", manifest_key_id),
        ("manifest_identity", manifest_identity),
    ):
        if manifest_value is not None and not isinstance(manifest_value, str):
            raise ValueError(f"facade upstream {name!r} {manifest_field} must be a string")
    raw_manifest_required = upstream.get("manifest_required")
    if raw_manifest_required is None:
        manifest_required = manifest is not None
    elif isinstance(raw_manifest_required, bool):
        manifest_required = raw_manifest_required
    else:
        raise ValueError(f"facade upstream {name!r} manifest_required must be a boolean")
    manifest_metadata = _verify_upstream_manifest_config(
        name=name,
        manifest=manifest,
        manifest_required=manifest_required,
        manifest_secret_env=manifest_secret_env,
        manifest_secret=manifest_secret,
        manifest_key_id=manifest_key_id,
        manifest_identity=manifest_identity,
    )
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
        peer=peer,
        local_port=local_port,
        bridge_config=bridge_config,
        bridge_command=bridge_command if isinstance(bridge_command, str) else None,
        bridge_args=tuple(bridge_args),
        bridge_cwd=bridge_cwd,
        bridge_env=dict(bridge_env) if isinstance(bridge_env, Mapping) else None,
        bridge_private=bridge_private,
        bridge_ready_timeout=float(bridge_ready_timeout),
        manifest=Path(manifest) if manifest is not None else None,
        manifest_required=manifest_required,
        manifest_secret_env=manifest_secret_env,
        manifest_secret=manifest_secret,
        manifest_key_id=manifest_key_id,
        manifest_identity=manifest_identity,
        manifest_metadata=manifest_metadata,
        credential=credential,
    )


def _verify_upstream_manifest_config(
    *,
    name: str,
    manifest: str | Path | None,
    manifest_required: bool,
    manifest_secret_env: str | None,
    manifest_secret: str | None,
    manifest_key_id: str | None,
    manifest_identity: str | None,
) -> dict[str, Any] | None:
    if manifest is None:
        if manifest_required:
            raise ValueError(f"facade upstream {name!r} manifest is required")
        return None
    manifest_path = Path(manifest)
    if not manifest_path.is_file():
        raise ValueError(f"facade upstream {name!r} manifest file does not exist: {manifest_path}")
    manifest_document = load_manifest(manifest_path)
    signature = manifest_document.get("snulbug_signature")
    signature_key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
    key_id = manifest_key_id or signature_key_id
    if not isinstance(key_id, str) or not key_id:
        raise ValueError(f"facade upstream {name!r} manifest key_id is required")
    secret = manifest_secret
    if not secret and manifest_secret_env:
        secret = os.environ.get(manifest_secret_env)
    if not secret:
        secret_source = f"environment variable {manifest_secret_env!r}" if manifest_secret_env else "manifest_secret"
        raise ValueError(f"facade upstream {name!r} manifest secret is required from {secret_source}")
    summary = verify_upstream_manifest(
        manifest_document,
        secrets={key_id: secret},
        expected_identity=manifest_identity,
    )
    return {
        **summary,
        "path": str(manifest_path),
        "required": manifest_required,
    }


def _required_url(upstream: FacadeUpstream) -> str:
    if not upstream.url:
        raise ValueError(f"facade upstream {upstream.name!r} url is required")
    return upstream.url


def _required_command(upstream: FacadeUpstream) -> str:
    if not upstream.command:
        raise ValueError(f"facade upstream {upstream.name!r} command is required")
    return upstream.command


def _required_bridge_command(upstream: FacadeUpstream) -> str:
    if not upstream.bridge_command:
        raise ValueError(f"facade upstream {upstream.name!r} bridge_command is required")
    return upstream.bridge_command


def _holepunch_bridge_args(
    *,
    url: str,
    local_port: int | None,
    peer: str | None,
    bridge_config: str | None,
    bridge_private: bool,
) -> list[str]:
    port = local_port or urlsplit(url).port
    if port is None:
        raise ValueError("holepunch upstream url must include a port when local_port is omitted")
    args = ["-p", str(port)]
    if bridge_config:
        args.extend(["-c", bridge_config])
    elif peer:
        args.extend(["-s", peer])
    if bridge_private:
        args.append("--private")
    return args


def _upstream_metadata(upstream: FacadeUpstream) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "name": upstream.name,
        "transport": upstream.transport,
        "tool_prefix": upstream.tool_prefix,
    }
    if upstream.transport in {"http", "holepunch"}:
        metadata["url"] = upstream.url
    if upstream.transport == "holepunch":
        metadata["bridge"] = {
            "transport": "hypertele",
            "peer": upstream.peer,
            "local_port": upstream.local_port,
            "config": upstream.bridge_config,
            "command": upstream.bridge_command,
            "private": upstream.bridge_private,
            "ready_timeout": upstream.bridge_ready_timeout,
        }
    if upstream.manifest_metadata:
        metadata["manifest"] = dict(upstream.manifest_metadata)
    auth = credential_metadata(upstream.credential)
    if auth:
        metadata["auth"] = auth
    return _drop_empty(metadata)


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


def _http_endpoint_reachable(url: str, timeout: float) -> bool:
    parsed = _parse_upstream(url)
    connection = _connection(parsed, timeout)
    try:
        connection.request("GET", _exact_target(parsed), headers={"host": parsed.netloc})
        response = connection.getresponse()
        response.read()
        return True
    except OSError:
        return False
    finally:
        connection.close()


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


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


def _strip_cloudflare_access_credentials(raw_headers: Any) -> list[tuple[bytes, bytes]]:
    stripped = []
    sensitive = {
        b"cf-access-client-id",
        b"cf-access-client-secret",
        b"cf-access-jwt-assertion",
    }
    for name, value in raw_headers:
        raw_name = name if isinstance(name, bytes) else str(name).encode("latin-1")
        raw_value = value if isinstance(value, bytes) else str(value).encode("latin-1")
        if raw_name.lower() in sensitive:
            continue
        stripped.append((raw_name, raw_value))
    return stripped


def _strip_authorization_header(raw_headers: Any) -> list[tuple[bytes, bytes]]:
    stripped = []
    for name, value in raw_headers or []:
        raw_name = name if isinstance(name, bytes) else str(name).encode("latin-1")
        raw_value = value if isinstance(value, bytes) else str(value).encode("latin-1")
        if raw_name.lower() == b"authorization":
            continue
        stripped.append((raw_name, raw_value))
    return stripped


def _anti_passthrough_metadata(scope: Scope, config: OAuthResourceConfig) -> dict[str, Any]:
    authorization_present = any(
        (name if isinstance(name, bytes) else str(name).encode("latin-1")).lower() == b"authorization"
        for name, _value in scope.get("headers", []) or []
    )
    if config.strip_authorization_upstream:
        disposition = "stripped" if authorization_present else "absent"
        reason_code = (
            "oauth.client_authorization_stripped" if authorization_present else "oauth.client_authorization_absent"
        )
    else:
        disposition = "forwarding_explicitly_allowed" if authorization_present else "absent"
        reason_code = "oauth.client_authorization_forwarding_explicitly_allowed"
    return {
        "enabled": True,
        "authorization_header_present": authorization_present,
        "strip_authorization_upstream": config.strip_authorization_upstream,
        "client_authorization": disposition,
        "reason_code": reason_code,
    }


def _is_oauth_resource_metadata_request(scope: Scope, config: OAuthResourceConfig) -> bool:
    method = str(scope.get("method", "GET")).upper()
    if method not in {"GET", "HEAD"}:
        return False
    metadata_path = urlsplit(oauth_resource_metadata_url(config)).path or "/.well-known/oauth-protected-resource"
    return str(scope.get("path", "/")).rstrip("/") == metadata_path.rstrip("/")


def _merge_headers(
    headers: list[tuple[bytes, bytes]], updates: Sequence[tuple[bytes, bytes]]
) -> list[tuple[bytes, bytes]]:
    update_names = {name.lower() for name, _value in updates}
    merged = [(name, value) for name, value in headers if name.lower() not in update_names]
    merged.extend(updates)
    return merged


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


def _record_metadata(
    scope: Scope,
    *,
    tunnel_audit: TunnelAuditConfig,
    topology_audit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"source": "proxy"}
    state = scope.get("state")
    proxy_metadata = state.get("snulbug_proxy") if isinstance(state, Mapping) else None
    if isinstance(proxy_metadata, Mapping):
        metadata.update(proxy_metadata)
    if "access" not in metadata and (
        isinstance(metadata.get("auth"), Mapping)
        or isinstance(metadata.get("lease"), Mapping)
        or isinstance(metadata.get("lease_preview"), Mapping)
    ):
        metadata["access"] = _composed_access_metadata(
            scope,
            lease=_mapping(metadata.get("lease") or metadata.get("lease_preview")),
        )
    reload_metadata = state.get("snulbug_fabric_reload") if isinstance(state, Mapping) else None
    if isinstance(reload_metadata, Mapping):
        metadata["fabric_reload"] = dict(reload_metadata)
    tunnel_metadata = build_tunnel_audit_metadata(scope, config=tunnel_audit)
    if tunnel_metadata:
        metadata["tunnel"] = tunnel_metadata
    dynamic_topology = state.get("snulbug_topology_audit") if isinstance(state, Mapping) else None
    effective_topology = dynamic_topology if isinstance(dynamic_topology, Mapping) else topology_audit
    topology_metadata = annotate_topology_audit(effective_topology, metadata)
    if topology_metadata:
        metadata["topology"] = topology_metadata
    return metadata


def _ensure_scope_state(scope: Scope) -> dict[str, Any]:
    state = scope.get("state")
    if isinstance(state, dict):
        return state
    state = {}
    scope["state"] = state
    return state


def _set_proxy_metadata(scope: Scope, metadata: Mapping[str, Any]) -> None:
    state = _ensure_scope_state(scope)
    existing = state.get("snulbug_proxy")
    merged = dict(existing) if isinstance(existing, Mapping) else {}
    merged.update(metadata)
    state["snulbug_proxy"] = merged


def _attach_proxy_reject_trace(
    scope: Scope,
    *,
    action: str,
    status: int,
    body: str,
    reason: str,
    reason_code: str,
    context: Mapping[str, Any] | None = None,
) -> None:
    decision = {
        "action": action,
        "status": status,
        "body": body,
        "reason": reason,
        "reason_code": reason_code,
        "context": dict(context or {}),
    }
    trace = {
        "action": action,
        "decision": decision,
        "duration_ms": 0.0,
        "instruction_count": 0,
        "scopes": [],
        "body_read": False,
    }
    state = _ensure_scope_state(scope)
    state["lua_trace"] = trace
    scope["lua_trace"] = trace


def _decode_bytes(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


async def _send_response(send: Send, *, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})

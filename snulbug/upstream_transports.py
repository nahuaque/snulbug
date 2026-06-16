from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit


@dataclass(frozen=True)
class UpstreamHttpTarget:
    url: str


@dataclass(frozen=True)
class UpstreamStdioClientSpec:
    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: Mapping[str, str] | None = None


@dataclass(frozen=True)
class UpstreamBridgeSpec:
    command: str
    args: tuple[str, ...]
    url: str
    cwd: str | None = None
    env: Mapping[str, str] | None = None
    ready_timeout: float = 10.0
    probe_timeout: float = 1.0


@dataclass(frozen=True)
class UpstreamForwardContext:
    upstream: Any
    scope: Mapping[str, Any]
    body: bytes
    request: Mapping[str, Any]
    parsed: Mapping[str, SplitResult]
    stdio_clients: Mapping[str, Any]
    bridges: Mapping[str, Any]
    forward_http: Callable[[], Awaitable[dict[str, Any]]]


class UpstreamTransport:
    """Extension point for facade upstream transport behavior."""

    type = ""
    aliases: tuple[str, ...] = ()

    @property
    def normalized_type(self) -> str:
        return str(self.type).strip().lower()

    @property
    def names(self) -> tuple[str, ...]:
        return (self.normalized_type, *(str(alias).strip().lower() for alias in self.aliases if str(alias).strip()))

    def normalize_config(
        self,
        upstream: Mapping[str, Any],
        *,
        field: str,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del upstream, field, base_dir
        return {}

    def normalize_runtime(self, upstream: Mapping[str, Any], *, field: str) -> Mapping[str, Any]:
        return self.normalize_config(upstream, field=field, base_dir=Path("."))

    def http_target(self, upstream: Any) -> UpstreamHttpTarget | None:
        del upstream
        return None

    def stdio_client(self, upstream: Any, *, timeout: float) -> UpstreamStdioClientSpec | None:
        del upstream, timeout
        return None

    def bridge(self, upstream: Any, *, timeout: float) -> UpstreamBridgeSpec | None:
        del upstream, timeout
        return None

    async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
        raise NotImplementedError(f"upstream transport {self.normalized_type!r} does not implement forwarding")

    def metadata(self, upstream: Any) -> Mapping[str, Any]:
        del upstream
        return {}

    def context(self, upstream: Any) -> Mapping[str, Any]:
        del upstream
        return {}

    def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
        del upstream
        return {}


class HttpUpstreamTransport(UpstreamTransport):
    type = "http"

    def normalize_config(
        self,
        upstream: Mapping[str, Any],
        *,
        field: str,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del base_dir
        url = upstream.get("url", upstream.get("upstream"))
        if not isinstance(url, str) or not url:
            raise ValueError(f"{field}.url must be a non-empty string")
        return {"url": url}

    def http_target(self, upstream: Any) -> UpstreamHttpTarget | None:
        return UpstreamHttpTarget(_required_attr(upstream, "url"))

    async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
        return await context.forward_http()

    def metadata(self, upstream: Any) -> Mapping[str, Any]:
        return {"url": _attr(upstream, "url")}

    def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
        return {"url": _attr(upstream, "url")}


class StdioUpstreamTransport(UpstreamTransport):
    type = "stdio"

    def normalize_config(
        self,
        upstream: Mapping[str, Any],
        *,
        field: str,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del base_dir
        command = upstream.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError(f"{field}.command must be a non-empty string")
        args = _string_sequence(upstream.get("args", []), field=f"{field}.args")
        cwd = upstream.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError(f"{field}.cwd must be a string")
        env = _string_table(upstream.get("env"), field=f"{field}.env")
        return {
            "command": command,
            "args": list(args),
            **({"cwd": cwd} if cwd is not None else {}),
            **({"env": dict(env)} if env is not None else {}),
        }

    def stdio_client(self, upstream: Any, *, timeout: float) -> UpstreamStdioClientSpec | None:
        del timeout
        return UpstreamStdioClientSpec(
            command=_required_attr(upstream, "command"),
            args=tuple(_attr(upstream, "args") or ()),
            cwd=_attr(upstream, "cwd"),
            env=_attr(upstream, "env"),
        )

    async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
        return await context.stdio_clients[_required_attr(context.upstream, "name")].request(context.request)

    def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
        return {
            "command": _attr(upstream, "command"),
            "args": list(_attr(upstream, "args") or ()),
            "cwd": _attr(upstream, "cwd"),
            "env_keys": sorted((_attr(upstream, "env") or {}).keys()),
        }


class HolepunchUpstreamTransport(UpstreamTransport):
    type = "holepunch"

    def normalize_config(
        self,
        upstream: Mapping[str, Any],
        *,
        field: str,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del base_dir
        url = upstream.get("url", upstream.get("upstream"))
        peer = upstream.get("peer")
        local_port = upstream.get("local_port")
        bridge_config = upstream.get("bridge_config")
        bridge_command = upstream.get("bridge_command", "hypertele")
        bridge_args = upstream.get("bridge_args")
        bridge_cwd = upstream.get("bridge_cwd")
        bridge_env = upstream.get("bridge_env")
        bridge_private = upstream.get("bridge_private", True)
        bridge_ready_timeout = upstream.get("bridge_ready_timeout", 10.0)

        if local_port is not None and (not isinstance(local_port, int) or local_port <= 0):
            raise ValueError(f"{field}.local_port must be a positive integer")
        if not isinstance(url, str) or not url:
            if local_port is None:
                raise ValueError(f"{field}.url or local_port is required")
            url = f"http://127.0.0.1:{local_port}/mcp"
        if peer is not None and not isinstance(peer, str):
            raise ValueError(f"{field}.peer must be a string")
        if bridge_config is not None and not isinstance(bridge_config, str):
            raise ValueError(f"{field}.bridge_config must be a string")
        if not isinstance(bridge_command, str) or not bridge_command:
            raise ValueError(f"{field}.bridge_command must be a non-empty string")
        if bridge_args is not None:
            bridge_args = list(_string_sequence(bridge_args, field=f"{field}.bridge_args"))
        if bridge_args is None and not peer and not bridge_config:
            raise ValueError(f"{field}.peer, bridge_config, or bridge_args is required")
        if bridge_cwd is not None and not isinstance(bridge_cwd, str):
            raise ValueError(f"{field}.bridge_cwd must be a string")
        bridge_env = _string_table(bridge_env, field=f"{field}.bridge_env")
        if not isinstance(bridge_private, bool):
            raise ValueError(f"{field}.bridge_private must be a boolean")
        if not isinstance(bridge_ready_timeout, int | float) or float(bridge_ready_timeout) <= 0:
            raise ValueError(f"{field}.bridge_ready_timeout must be a positive number")
        if bridge_args is None:
            bridge_args = holepunch_bridge_args(
                url=str(url),
                local_port=local_port,
                peer=peer,
                bridge_config=bridge_config,
                bridge_private=bridge_private,
            )
        return {
            "url": url,
            **({"peer": peer} if peer is not None else {}),
            **({"local_port": local_port} if local_port is not None else {}),
            **({"bridge_config": bridge_config} if bridge_config is not None else {}),
            "bridge_command": bridge_command,
            "bridge_args": list(bridge_args),
            **({"bridge_cwd": bridge_cwd} if bridge_cwd is not None else {}),
            **({"bridge_env": dict(bridge_env)} if bridge_env is not None else {}),
            "bridge_private": bridge_private,
            "bridge_ready_timeout": float(bridge_ready_timeout),
        }

    def http_target(self, upstream: Any) -> UpstreamHttpTarget | None:
        return UpstreamHttpTarget(_required_attr(upstream, "url"))

    def bridge(self, upstream: Any, *, timeout: float) -> UpstreamBridgeSpec | None:
        return UpstreamBridgeSpec(
            command=_required_attr(upstream, "bridge_command"),
            args=tuple(_attr(upstream, "bridge_args") or ()),
            url=_required_attr(upstream, "url"),
            cwd=_attr(upstream, "bridge_cwd"),
            env=_attr(upstream, "bridge_env"),
            ready_timeout=float(_attr(upstream, "bridge_ready_timeout") or 10.0),
            probe_timeout=min(timeout, 1.0),
        )

    async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
        await context.bridges[_required_attr(context.upstream, "name")].ensure_ready()
        return await context.forward_http()

    def metadata(self, upstream: Any) -> Mapping[str, Any]:
        return {
            "url": _attr(upstream, "url"),
            "bridge": {
                "transport": "hypertele",
                "peer": _attr(upstream, "peer"),
                "local_port": _attr(upstream, "local_port"),
                "config": _attr(upstream, "bridge_config"),
                "command": _attr(upstream, "bridge_command"),
                "private": _attr(upstream, "bridge_private"),
                "ready_timeout": _attr(upstream, "bridge_ready_timeout"),
            },
        }

    def context(self, upstream: Any) -> Mapping[str, Any]:
        return {
            "bridge": {
                "peer": _attr(upstream, "peer"),
                "local_port": _attr(upstream, "local_port"),
                "private": _attr(upstream, "bridge_private"),
            }
        }

    def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
        return {
            "url": _attr(upstream, "url"),
            "peer": _attr(upstream, "peer"),
            "local_port": _attr(upstream, "local_port"),
            "bridge_config": _attr(upstream, "bridge_config"),
            "bridge_command": _attr(upstream, "bridge_command"),
            "bridge_args": list(_attr(upstream, "bridge_args") or ()),
            "bridge_cwd": _attr(upstream, "bridge_cwd"),
            "bridge_env_keys": sorted((_attr(upstream, "bridge_env") or {}).keys()),
            "bridge_private": _attr(upstream, "bridge_private"),
            "bridge_ready_timeout": _attr(upstream, "bridge_ready_timeout"),
        }


_UPSTREAM_TRANSPORT_REGISTRY: dict[str, UpstreamTransport] = {}
_UPSTREAM_TRANSPORT_CANONICAL_NAMES: dict[str, str] = {}


def register_upstream_transport(transport: UpstreamTransport, *, replace: bool = False) -> UpstreamTransport:
    """Register a facade upstream transport plugin."""

    name = transport.normalized_type
    if not name:
        raise ValueError("upstream transport type is required")
    names = transport.names
    if any(existing in _UPSTREAM_TRANSPORT_REGISTRY for existing in names) and not replace:
        conflicts = ", ".join(existing for existing in names if existing in _UPSTREAM_TRANSPORT_REGISTRY)
        raise ValueError(f"upstream transport already registered: {conflicts}")
    for existing, canonical in list(_UPSTREAM_TRANSPORT_CANONICAL_NAMES.items()):
        if canonical == name and existing not in names:
            _UPSTREAM_TRANSPORT_REGISTRY.pop(existing, None)
            _UPSTREAM_TRANSPORT_CANONICAL_NAMES.pop(existing, None)
    for alias in names:
        _UPSTREAM_TRANSPORT_REGISTRY[alias] = transport
        _UPSTREAM_TRANSPORT_CANONICAL_NAMES[alias] = name
    return transport


def get_upstream_transport(transport_type: str) -> UpstreamTransport:
    normalized = str(transport_type).strip().lower()
    try:
        return _UPSTREAM_TRANSPORT_REGISTRY[normalized]
    except KeyError as exc:
        known = ", ".join(list_upstream_transports()) or "<none>"
        raise ValueError(f"unknown upstream transport {transport_type!r}; known transports: {known}") from exc


def list_upstream_transports() -> tuple[str, ...]:
    """Return canonical upstream transport names in registration order."""

    seen: set[str] = set()
    names: list[str] = []
    for canonical in _UPSTREAM_TRANSPORT_CANONICAL_NAMES.values():
        if canonical not in seen:
            seen.add(canonical)
            names.append(canonical)
    return tuple(names)


def holepunch_bridge_args(
    *,
    url: str,
    local_port: int | None,
    peer: str | None,
    bridge_config: str | None,
    bridge_private: bool,
) -> list[str]:
    port = local_port
    if port is None:
        try:
            port = urlsplit(url).port
        except Exception:
            port = None
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


def _string_sequence(value: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        raise ValueError(f"{field} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(value)


def _string_table(value: Any, *, field: str) -> Mapping[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a table of strings")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise ValueError(f"{field} must be a table of strings")
    return value


def _attr(upstream: Any, name: str) -> Any:
    if isinstance(upstream, Mapping):
        return upstream.get(name)
    return getattr(upstream, name, None)


def _required_attr(upstream: Any, name: str) -> Any:
    value = _attr(upstream, name)
    if value in (None, ""):
        raise ValueError(f"upstream {name} is required")
    return value


for _transport in (HttpUpstreamTransport(), StdioUpstreamTransport(), HolepunchUpstreamTransport()):
    register_upstream_transport(_transport, replace=True)

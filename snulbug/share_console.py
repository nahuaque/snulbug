from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from errno import ECONNABORTED, ECONNRESET, EPIPE
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .config import load_mcp_proxy_config
from .redaction import SECRET_REPLACEMENT, build_audit_event
from .runtime import LuaRuntimeError, compile_lua_script
from .share import (
    activate_mcp_share_policy,
    approve_share_capability_request,
    cleanup_mcp_share_invites,
    cleanup_mcp_share_leases,
    create_mcp_share,
    create_mcp_share_invite,
    create_mcp_share_lease,
    deny_share_capability_request,
    doctor_mcp_share,
    list_mcp_share_invites,
    load_mcp_share,
    preview_mcp_share_policy_amendment,
    promote_mcp_share_policy,
    reactivate_mcp_share_lease,
    revoke_mcp_share_invite,
    revoke_mcp_share_lease,
    share_capability_requests,
    share_report,
    share_status,
)
from .share_session import load_share_session_model, share_session_model_path, write_share_session_model

DEFAULT_SHARE_CONSOLE_HOST = "127.0.0.1"
DEFAULT_SHARE_CONSOLE_PORT = 8765
CONSOLE_SECRET_HEADER = "x-snulbug-console-secret"
DEFAULT_TUNNEL_PROVIDER_CONSOLES = {
    "ngrok": {
        "label": "ngrok local web console",
        "url": "http://127.0.0.1:4040",
        "description": "Inspect ngrok tunnel requests, headers, and replay details.",
    }
}
TUNNEL_PROVIDER_LABELS = {
    "generic": "Generic tunnel",
    "ngrok": "ngrok",
    "cloudflare": "Cloudflare Tunnel",
    "tailscale": "Tailscale Funnel",
    "pinggy": "Pinggy",
    "holepunch": "Holepunch / Hypertele",
}
DEFAULT_DECISION_TIMELINE_LIMIT = 20
DEFAULT_AUTH_VISIBILITY_LIMIT = 50
DEFAULT_PROVIDER_CONSOLE_PROBE_TTL_SECONDS = 15.0
MAX_POLICY_SOURCE_BYTES = 256 * 1024
MAX_POLICY_MANIFEST_BYTES = 64 * 1024
POLICY_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(\b[A-Za-z_][A-Za-z0-9_-]*(?:api[_-]?key|credential|password|secret|token)[A-Za-z0-9_-]*\b\s*=\s*)"
    r"(['\"])([^'\"]*)(\2)",
    re.IGNORECASE,
)
POLICY_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
POLICY_STANDALONE_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
]
CONSOLE_ASSET_DIR = Path(__file__).with_name("assets")
CONSOLE_ASSETS = {
    "prism.css": ("text/css; charset=utf-8", CONSOLE_ASSET_DIR / "prism.css"),
    "prism.js": ("application/javascript; charset=utf-8", CONSOLE_ASSET_DIR / "prism.js"),
}
_PROVIDER_CONSOLE_CACHE: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}


def build_share_console_snapshot(
    directory: str | Path,
    *,
    timeout: float = 1.0,
    live_checks: bool = False,
) -> dict[str, Any]:
    """Return the secret-light data needed by the local share console."""

    share_dir = Path(directory)
    status = share_status(share_dir, timeout=timeout, live_checks=live_checks)
    requests = share_capability_requests(share_dir, status="all")
    provider_console = _provider_console(status, timeout=timeout)
    decision_timeline = _decision_timeline(share_dir, status)
    auth_visibility = _auth_visibility(share_dir, status)
    tool_schema_visibility = _tool_schema_visibility(share_dir, status)
    tunnel_provider = _tunnel_provider_visibility(share_dir, status, provider_console)
    policy_visibility = _policy_visibility(share_dir, status, decision_timeline=decision_timeline)
    readiness_gate = _share_readiness_gate(
        share_dir,
        status,
        capability_requests=requests,
        decision_timeline=decision_timeline,
        auth_visibility=auth_visibility,
        tool_schema_visibility=tool_schema_visibility,
        tunnel_provider=tunnel_provider,
    )
    return {
        "ok": bool(status.get("ok")),
        "mode": "share",
        "generated_at": _now_iso(),
        "share": str(share_dir),
        "status": _redact_console_payload(status),
        "capability_requests": _redact_console_payload(requests),
        "decision_timeline": _redact_console_payload(decision_timeline),
        "auth_visibility": _redact_console_payload(auth_visibility),
        "tool_schema_visibility": _redact_console_payload(tool_schema_visibility),
        "tunnel_provider": _redact_console_payload(tunnel_provider),
        "policy_visibility": _redact_console_payload(policy_visibility),
        "readiness_gate": _redact_console_payload(readiness_gate),
        "provider_console": provider_console,
    }


def build_share_setup_console_snapshot(directory: str | Path) -> dict[str, Any]:
    """Return the setup-only console state used before a share session exists."""

    share_dir = Path(directory)
    existing_shares = _setup_existing_shares(share_dir)
    return {
        "ok": True,
        "mode": "setup",
        "generated_at": _now_iso(),
        "share": str(share_dir),
        "setup_defaults": _redact_console_payload(_setup_defaults()),
        "existing_shares": _redact_console_payload(existing_shares),
        "setup_wizard": _redact_console_payload(_bootstrap_setup_wizard(existing_shares)),
    }


def _setup_defaults() -> dict[str, Any]:
    return {
        "directory": ".snulbug/share",
        "provider": "generic",
        "upstream": "http://127.0.0.1:9000",
        "public_url": "http://127.0.0.1:8080/mcp",
        "allowed_tools": "safe_read_file",
        "allowed_paths": ".",
        "host": "127.0.0.1",
        "port": 8080,
        "preset": "tunnel-safe",
        "lease_required": True,
        "validate": True,
        "start_gateway": True,
        "providers": [
            {"name": name, "label": label}
            for name, label in TUNNEL_PROVIDER_LABELS.items()
            if name in {"generic", "ngrok", "cloudflare", "tailscale", "pinggy", "holepunch"}
        ],
    }


def _setup_existing_shares(directory: str | Path) -> list[dict[str, Any]]:
    base = Path(directory)
    candidates: list[Path] = [base, base / ".snulbug" / "share"]
    shares_root = base / ".snulbug" / "shares"
    if shares_root.is_dir():
        candidates.extend(path for path in sorted(shares_root.iterdir()) if path.is_dir())

    seen: set[Path] = set()
    shares: list[dict[str, Any]] = []
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        summary = _setup_share_summary(base, candidate)
        if summary:
            shares.append(summary)
    return shares


def _setup_share_summary(base: Path, directory: Path) -> dict[str, Any] | None:
    model_path = share_session_model_path(directory)
    if not model_path.is_file():
        return None
    try:
        model = json.loads(model_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        model = {}
    share = _mapping(model.get("share"))
    tunnel = _mapping(model.get("tunnel"))
    client = _mapping(model.get("client"))
    status = _mapping(model.get("status"))
    paths = _mapping(model.get("paths"))
    relative = _setup_relative_path(base, directory)
    return {
        "directory": str(directory),
        "relative": relative,
        "label": relative if relative not in {"", "."} else "current directory",
        "state": status.get("state") or "created",
        "provider": tunnel.get("provider") or "generic",
        "public_url": client.get("url") or tunnel.get("public_url") or tunnel.get("client_url"),
        "task": share.get("task"),
        "config": paths.get("config"),
        "session_model": str(model_path),
    }


def _setup_relative_path(base: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(base.resolve(strict=False)).as_posix() or "."
    except ValueError:
        return str(path)


def run_share_console(
    directory: str | Path,
    *,
    host: str = DEFAULT_SHARE_CONSOLE_HOST,
    port: int = DEFAULT_SHARE_CONSOLE_PORT,
    timeout: float = 1.0,
    live_checks: bool = False,
    setup_only: bool = False,
) -> int:
    """Run the blocking local share-session console."""

    server = ShareConsoleServer(
        directory=Path(directory),
        host=host,
        port=port,
        timeout=timeout,
        live_checks=live_checks,
        setup_only=setup_only,
    )
    server.start()
    print(f"snulbug share console: {server.url}", flush=True)
    print(f"snulbug share console secret: {server.console_secret}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()
    return 0


@dataclass
class ShareConsoleServer:
    """Small local HTTP server for one MCP share session."""

    directory: Path
    host: str = DEFAULT_SHARE_CONSOLE_HOST
    port: int = DEFAULT_SHARE_CONSOLE_PORT
    timeout: float = 1.0
    live_checks: bool = False
    setup_only: bool = False
    console_secret: str = field(default_factory=lambda: secrets.token_urlsafe(18), repr=False)
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _run_requested: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _initial_health_share: str | None = field(default=None, init=False, repr=False)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._server is not None:
            return
        console = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                try:
                    console._handle_get(self)
                except Exception as exc:
                    if _is_client_disconnect(exc):
                        return
                    raise

            def do_POST(self) -> None:
                try:
                    console._handle_post(self)
                except Exception as exc:
                    if _is_client_disconnect(exc):
                        return
                    raise

            def log_message(self, format: str, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.host = str(self._server.server_address[0])
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        if self._server is None:
            self.start()
        if self._server is None:
            raise RuntimeError("share console server did not start")
        self._server.serve_forever()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    def wait_for_gateway_start(self, timeout: float | None = None) -> bool:
        return self._run_requested.wait(timeout)

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        try:
            if path in {"/", "/index.html"}:
                _send(handler, 200, _console_html().encode("utf-8"), content_type="text/html; charset=utf-8")
                return
            asset_name = path.removeprefix("/assets/")
            if asset_name != path and asset_name in CONSOLE_ASSETS:
                content_type, asset_path = CONSOLE_ASSETS[asset_name]
                _send(handler, 200, asset_path.read_bytes(), content_type=content_type)
                return
            if path.startswith("/api/") and not self._require_console_secret(handler):
                return
            if path == "/api/snapshot":
                _send_json(handler, 200, self.snapshot())
                return
            if path == "/api/status":
                _send_json(
                    handler,
                    200,
                    share_status(self.directory, timeout=self.timeout, live_checks=self.live_checks),
                )
                return
            if path == "/api/requests":
                query = parse_qs(parsed.query)
                status = _first(query.get("status")) or "all"
                _send_json(handler, 200, share_capability_requests(self.directory, status=status))
                return
            if path == "/api/invites":
                _cleanup_console_stale_invites(self.directory)
                query = parse_qs(parsed.query)
                include_revoked = (_first(query.get("include_revoked")) or "true").lower() not in {"0", "false", "no"}
                result = list_mcp_share_invites(
                    self.directory,
                    include_revoked=include_revoked,
                    include_setup=True,
                )
                _send_json(handler, 200, result)
                return
            if path == "/api/report":
                _send_json(
                    handler,
                    200,
                    share_report(self.directory, timeout=self.timeout, live_checks=self.live_checks),
                )
                return
            if path == "/api/report/download":
                result = share_report(self.directory, timeout=self.timeout, live_checks=self.live_checks)
                _send_download(
                    handler,
                    200,
                    str(result.get("report") or ""),
                    filename=_report_download_filename(self.directory),
                    content_type="text/markdown; charset=utf-8",
                )
                return
            _send(handler, 404, b"not found\n", content_type="text/plain; charset=utf-8")
        except Exception as exc:
            _handle_handler_exception(handler, exc)

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        try:
            if path.startswith("/api/") and not self._require_console_secret(handler):
                return
            body = _read_json_body(handler)
            if path == "/api/setup/create-share":
                share_dir, result = _create_share_from_setup(self.directory, body)
                self.directory = share_dir
                self.setup_only = False
                start_gateway = _bool_or_default(body.get("start_gateway"), True)
                if start_gateway:
                    self._run_requested.set()
                _send_json(
                    handler,
                    200,
                    _redact_console_payload(
                        {
                            "ok": True,
                            "share": str(share_dir),
                            "run_requested": start_gateway,
                            "result": result,
                        }
                    ),
                )
                return
            if path == "/api/setup/select-share":
                share_dir = _resolve_existing_setup_share_directory(self.directory, body.get("directory"))
                self.directory = share_dir
                self.setup_only = False
                start_gateway = _bool_or_default(body.get("start_gateway"), True)
                if start_gateway:
                    self._run_requested.set()
                _send_json(
                    handler,
                    200,
                    _redact_console_payload(
                        {
                            "ok": True,
                            "share": str(share_dir),
                            "run_requested": start_gateway,
                        }
                    ),
                )
                return
            prefix = "/api/requests/"
            if path.startswith(prefix) and path.endswith("/approve"):
                request_id = unquote(path[len(prefix) : -len("/approve")])
                result = approve_share_capability_request(
                    self.directory,
                    request_id=request_id,
                    ttl=_string_or_none(body.get("ttl")),
                    max_calls=_positive_int(body.get("max_calls")),
                    task=_string_or_none(body.get("task")),
                    allow_tools=_string_list(body.get("allow_tools")),
                    allow_paths=_string_list(body.get("allow_paths")),
                    allow_hosts=_string_list(body.get("allow_hosts")),
                    allow_commands=_string_list(body.get("allow_commands")),
                    bind_auth=bool(body.get("bind_auth", True)),
                    reviewer=_string_or_none(body.get("reviewer")),
                )
                _send_json(handler, 200, result)
                return
            if path.startswith(prefix) and path.endswith("/deny"):
                request_id = unquote(path[len(prefix) : -len("/deny")])
                result = deny_share_capability_request(
                    self.directory,
                    request_id=request_id,
                    reason=_string_or_none(body.get("reason")),
                    reviewer=_string_or_none(body.get("reviewer")),
                )
                _send_json(handler, 200, result)
                return
            lease_prefix = "/api/leases/"
            if path.startswith(lease_prefix) and path.endswith("/revoke"):
                lease_id = unquote(path[len(lease_prefix) : -len("/revoke")])
                result = revoke_mcp_share_lease(self.directory, lease_id=lease_id)
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path.startswith(lease_prefix) and path.endswith("/reactivate"):
                lease_id = unquote(path[len(lease_prefix) : -len("/reactivate")])
                result = reactivate_mcp_share_lease(
                    self.directory,
                    lease_id=lease_id,
                    ttl=_string_or_none(body.get("ttl")) or "30m",
                    max_calls=_positive_int(body.get("max_calls")),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/doctor":
                result = doctor_mcp_share(
                    self.directory,
                    timeout=self.timeout,
                    public_url=_string_or_none(body.get("public_url") or body.get("url")),
                    live_checks=_bool_or_default(body.get("live_checks"), self.live_checks),
                    conformance_pack=_string_or_none(body.get("conformance_pack")),
                    require_conformance=bool(body.get("require_conformance", False)),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/health/check":
                _cleanup_console_stale_invites(self.directory)
                snapshot = _with_console_invite_setups(
                    self.directory,
                    build_share_console_snapshot(self.directory, timeout=self.timeout, live_checks=True),
                )
                status = dict(_mapping(snapshot.get("status")))
                status["readiness_gate"] = snapshot.get("readiness_gate")
                status["share"] = snapshot.get("share")
                status["generated_at"] = snapshot.get("generated_at")
                result = status
                _send_json(handler, 200, result)
                return
            if path == "/api/readiness/review":
                result = _record_share_readiness_review(
                    self.directory,
                    body,
                    timeout=self.timeout,
                    live_checks=_bool_or_default(body.get("live_checks"), self.live_checks),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/client/bearer-token":
                result = _client_bearer_token(self.directory)
                _send_json(handler, 200, result)
                return
            if path == "/api/invites/create":
                handoff = _invite_handoff_readiness(
                    self.directory,
                    timeout=self.timeout,
                    live_checks=True,
                )
                if handoff.get("ready") is not True:
                    _send_json(handler, 409, _redact_console_payload(handoff))
                    return
                policy_capabilities = _declared_invite_capabilities(self.directory, timeout=self.timeout)
                capability_ids = {str(item.get("id")) for item in policy_capabilities if item.get("id")}
                requested_capabilities = _string_list(body.get("capabilities"))
                if not capability_ids:
                    _send_json(
                        handler,
                        409,
                        {
                            "ok": False,
                            "error": "active policy does not declare supported invite capabilities",
                            "policy_capabilities": policy_capabilities,
                        },
                    )
                    return
                if not requested_capabilities:
                    requested_capabilities = _default_invite_capability_ids(policy_capabilities)
                unsupported = [item for item in requested_capabilities if item not in capability_ids]
                if unsupported:
                    _send_json(
                        handler,
                        400,
                        {
                            "ok": False,
                            "error": "requested invite capability is not declared by the active policy",
                            "unsupported_capabilities": unsupported,
                            "policy_capabilities": policy_capabilities,
                        },
                    )
                    return
                result = create_mcp_share_invite(
                    self.directory,
                    recipient=_string_or_none(body.get("recipient")) or "share recipient",
                    task=_string_or_none(body.get("task")) or "Temporary MCP access",
                    capabilities=requested_capabilities,
                    allow_tools=_string_list(body.get("allow_tools")),
                    allow_paths=_string_list(body.get("allow_paths")),
                    allow_hosts=_string_list(body.get("allow_hosts")),
                    allow_commands=_string_list(body.get("allow_commands")),
                    ttl=_string_or_none(body.get("ttl")) or "30m",
                    max_calls=_positive_int(body.get("max_calls")),
                    client_name=_string_or_none(body.get("client_name")),
                )
                _send_json(handler, 200, result)
                return
            if path == "/api/invites/cleanup-revoked":
                result = cleanup_mcp_share_invites(self.directory, stale_active=True)
                _send_json(handler, 200, _redact_console_payload(result))
                return
            invite_prefix = "/api/invites/"
            if path.startswith(invite_prefix) and path.endswith("/revoke"):
                invite_id = unquote(path[len(invite_prefix) : -len("/revoke")])
                result = revoke_mcp_share_invite(
                    self.directory,
                    invite_id=invite_id,
                    revoke_lease=_bool_or_default(body.get("revoke_lease"), True),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/leases/cleanup-inactive":
                result = cleanup_mcp_share_leases(self.directory)
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/leases/create":
                result = create_mcp_share_lease(
                    self.directory,
                    task=_string_or_none(body.get("task")) or "Temporary MCP access",
                    allow_tools=_string_list(body.get("allow_tools")),
                    allow_paths=_string_list(body.get("allow_paths")),
                    allow_hosts=_string_list(body.get("allow_hosts")),
                    allow_commands=_string_list(body.get("allow_commands")),
                    ttl=_string_or_none(body.get("ttl")) or "30m",
                    max_calls=_positive_int(body.get("max_calls")),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/policy/amend-preview":
                result = preview_mcp_share_policy_amendment(
                    self.directory,
                    log=_string_or_none(body.get("log")),
                    output=_string_or_none(body.get("output")),
                    kind=_string_or_none(body.get("kind")) or "auto",
                    source=_string_or_none(body.get("source")) or "blocked",
                    force=_bool_or_default(body.get("force"), True),
                    validate=_bool_or_default(body.get("validate"), True),
                    allow_risky=bool(body.get("allow_risky", False)),
                )
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/policy/lifecycle":
                result = _run_policy_lifecycle_action(self.directory, body)
                _send_json(handler, 200, _redact_console_payload(result))
                return
            if path == "/api/report":
                result = share_report(
                    self.directory,
                    timeout=self.timeout,
                    live_checks=self.live_checks,
                    output=_string_or_none(body.get("output")),
                    force=bool(body.get("force", False)),
                )
                _send_json(handler, 200, result)
                return
            _send(handler, 404, b"not found\n", content_type="text/plain; charset=utf-8")
        except Exception as exc:
            _handle_handler_exception(handler, exc)

    def snapshot(self) -> dict[str, Any]:
        if self.setup_only:
            return build_share_setup_console_snapshot(self.directory)
        _cleanup_console_stale_invites(self.directory)
        share_key = str(self.directory.resolve(strict=False))
        if self.live_checks:
            snapshot = build_share_console_snapshot(
                self.directory,
                timeout=self.timeout,
                live_checks=True,
            )
            return _with_console_invite_setups(self.directory, snapshot)
        if self._initial_health_share != share_key:
            snapshot = build_share_console_snapshot(
                self.directory,
                timeout=self.timeout,
                live_checks=True,
            )
            snapshot["initial_health_check"] = True
            self._initial_health_share = share_key
            return _with_console_invite_setups(self.directory, snapshot)
        snapshot = build_share_console_snapshot(
            self.directory,
            timeout=self.timeout,
            live_checks=False,
        )
        return _with_console_invite_setups(self.directory, snapshot)

    def _has_console_secret(self, handler: BaseHTTPRequestHandler) -> bool:
        supplied = handler.headers.get(CONSOLE_SECRET_HEADER, "")
        return hmac.compare_digest(str(supplied), self.console_secret)

    def _require_console_secret(self, handler: BaseHTTPRequestHandler) -> bool:
        if self._has_console_secret(handler):
            return True
        _send_json(
            handler,
            403,
            {
                "ok": False,
                "error": "console secret required",
                "header": CONSOLE_SECRET_HEADER,
            },
        )
        return False


def _with_console_invite_setups(directory: str | Path, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    payload = json.loads(json.dumps(dict(snapshot), default=str))
    status = payload.get("status")
    if not isinstance(status, dict):
        return payload
    try:
        invitations = list_mcp_share_invites(directory, include_revoked=True, include_setup=True)
    except Exception:
        return payload
    status["invitations"] = {
        "items": invitations.get("invitations", []),
        "summary": invitations.get("summary", {}),
    }
    return payload


def _cleanup_console_stale_invites(directory: str | Path) -> None:
    try:
        cleanup_mcp_share_invites(directory, stale_active=True)
    except Exception:
        return


def _send_json(handler: BaseHTTPRequestHandler, status: int, payload: Mapping[str, Any]) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    _send(handler, status, body, content_type="application/json; charset=utf-8")


def _send_error(handler: BaseHTTPRequestHandler, exc: Exception) -> None:
    _send_json(
        handler,
        400,
        {
            "ok": False,
            "error": str(exc),
            "error_type": type(exc).__name__,
        },
    )


def _handle_handler_exception(handler: BaseHTTPRequestHandler, exc: Exception) -> None:
    if _is_client_disconnect(exc):
        return
    try:
        _send_error(handler, exc)
    except Exception as send_exc:
        if _is_client_disconnect(send_exc):
            return
        raise


def _is_client_disconnect(exc: BaseException) -> bool:
    if isinstance(exc, BrokenPipeError | ConnectionResetError | ConnectionAbortedError):
        return True
    return isinstance(exc, OSError) and exc.errno in {EPIPE, ECONNRESET, ECONNABORTED}


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, *, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("cache-control", "no-store")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_download(
    handler: BaseHTTPRequestHandler,
    status: int,
    text: str,
    *,
    filename: str,
    content_type: str,
) -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("cache-control", "no-store")
    handler.send_header("content-disposition", f'attachment; filename="{filename}"')
    handler.send_header("x-content-type-options", "nosniff")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _report_download_filename(directory: str | Path) -> str:
    raw = Path(directory).name or "share"
    safe = "".join(char if char.isascii() and (char.isalnum() or char in "-_.") else "-" for char in raw)
    safe = safe.strip(".-") or "share"
    return f"snulbug-{safe}-report.md"


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")
    return dict(payload)


def _create_share_from_setup(base_directory: str | Path, payload: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    share_dir = _resolve_new_setup_share_directory(
        base_directory,
        _string_or_none(payload.get("directory")) or _setup_defaults()["directory"],
    )
    result = create_mcp_share(
        share_dir,
        provider=_string_or_none(payload.get("provider")) or "generic",
        preset=_string_or_none(payload.get("preset")) or "tunnel-safe",
        upstream=_string_or_none(payload.get("upstream")) or "http://127.0.0.1:9000",
        public_url=_string_or_none(payload.get("public_url")),
        token=_string_or_none(payload.get("token")),
        task=_string_or_none(payload.get("task")) or "Ephemeral MCP share session",
        ttl=_string_or_none(payload.get("ttl")) or "30m",
        allowed_tools=_string_list(payload.get("allowed_tools")) or None,
        allowed_paths=_string_list(payload.get("allowed_paths")) or None,
        allowed_hosts=_string_list(payload.get("allowed_hosts")) or None,
        allowed_commands=_string_list(payload.get("allowed_commands")) or None,
        max_calls=_positive_int(payload.get("max_calls")),
        host=_string_or_none(payload.get("host")) or "127.0.0.1",
        port=_positive_int(payload.get("port")) or 8080,
        state=_string_or_none(payload.get("state")) or "memory",
        lease_required=_bool_or_default(payload.get("lease_required"), True),
        force=bool(payload.get("force", False)),
        validate=_bool_or_default(payload.get("validate"), True),
    )
    return share_dir, result


def _resolve_new_setup_share_directory(base_directory: str | Path, value: str) -> Path:
    base = Path(base_directory).resolve(strict=False)
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise ValueError("setup share directory must stay under the workspace")
    return candidate


def _resolve_existing_setup_share_directory(base_directory: str | Path, value: Any) -> Path:
    raw = _string_or_none(value)
    if raw is None:
        raise ValueError("share directory is required")
    candidate = _resolve_new_setup_share_directory(base_directory, raw)
    model_path = share_session_model_path(candidate)
    if not model_path.is_file():
        raise FileNotFoundError(f"share session model not found: {model_path}")
    return candidate


def _record_share_readiness_review(
    directory: str | Path,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    live_checks: bool,
) -> dict[str, Any]:
    share_dir = Path(directory)
    snapshot = build_share_console_snapshot(share_dir, timeout=timeout, live_checks=live_checks)
    readiness_gate = _mapping(snapshot.get("readiness_gate"))
    summary = _mapping(readiness_gate.get("summary"))
    failed = int(summary.get("failed") or 0)
    if failed:
        raise ValueError("fix failing readiness checks before marking the share reviewed")

    review_digest = _string_or_none(readiness_gate.get("review_digest"))
    if review_digest is None:
        raise ValueError("readiness review digest is unavailable")
    expected_digest = _string_or_none(payload.get("review_digest"))
    if expected_digest and expected_digest != review_digest:
        raise ValueError("readiness changed; refresh the console and review again")

    checks = [_mapping(check) for check in _sequence(readiness_gate.get("checks")) if isinstance(check, Mapping)]
    warning_ids = [str(check.get("id")) for check in checks if check.get("status") == "warn" and check.get("id")]
    review = _drop_empty(
        {
            "schema": "snulbug.share-readiness-review.v1",
            "reviewed_at": _now_iso(),
            "reviewer": _string_or_none(payload.get("reviewer")) or "share-console",
            "decision": readiness_gate.get("decision"),
            "review_digest": review_digest,
            "attestation_digest": _mapping(readiness_gate.get("attestation")).get("digest"),
            "content_digest": _mapping(readiness_gate.get("attestation")).get("content_digest"),
            "warning_ids": warning_ids,
            "failed_ids": [],
            "live_checks": live_checks,
        }
    )

    model = load_share_session_model(share_dir)
    updated_model = json.loads(json.dumps(model, default=str))
    readiness = dict(_mapping(updated_model.get("readiness")))
    readiness["last_review"] = review
    updated_model["readiness"] = readiness
    write_share_session_model(share_dir, updated_model, force=True)

    updated_snapshot = build_share_console_snapshot(share_dir, timeout=timeout, live_checks=live_checks)
    return {
        "ok": True,
        "review": review,
        "readiness_gate": updated_snapshot.get("readiness_gate"),
        "session_model": str(share_session_model_path(share_dir)),
    }


def _invite_handoff_readiness(
    directory: str | Path,
    *,
    timeout: float,
    live_checks: bool,
) -> dict[str, Any]:
    snapshot = build_share_console_snapshot(Path(directory), timeout=timeout, live_checks=live_checks)
    readiness_gate = _mapping(snapshot.get("readiness_gate"))
    handoff = _mapping(readiness_gate.get("handoff"))
    if handoff.get("ready") is True:
        return {"ok": True, "ready": True, "handoff": handoff}
    blocking = list(_sequence(handoff.get("blocking_checks")))
    return {
        "ok": False,
        "ready": False,
        "error": "share is not handoff-ready for invites",
        "reason_code": "share.handoff_not_ready",
        "blocking_checks": blocking,
        "handoff": handoff,
        "readiness": {
            "decision": readiness_gate.get("decision"),
            "label": readiness_gate.get("label"),
            "summary": readiness_gate.get("summary"),
        },
    }


def _client_bearer_token(directory: str | Path) -> dict[str, Any]:
    manifest = load_mcp_share(directory)
    client = _mapping(manifest.get("client"))
    headers = _mapping(client.get("headers"))
    auth_value = None
    for name, value in headers.items():
        if str(name).lower() == "authorization":
            auth_value = str(value)
            break
    if not auth_value:
        raise ValueError("share client does not include an Authorization bearer token")
    match = re.match(r"Bearer\s+(.+)", auth_value.strip(), flags=re.IGNORECASE)
    if not match:
        raise ValueError("share client Authorization header is not a bearer token")
    token = match.group(1).strip()
    if not token or token.startswith("${"):
        raise ValueError("bearer token is not stored in this share; mint or resolve it client-side")
    return {
        "ok": True,
        "scheme": "Bearer",
        "token": token,
        "authorization": f"Bearer {token}",
        "header": "Authorization",
        "client_url": client.get("url"),
    }


def _run_policy_lifecycle_action(directory: str | Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    action = _string_or_none(payload.get("action")) or "promote"
    key_id = _string_or_none(payload.get("key_id")) or "local-review"
    secret_env = _string_or_none(payload.get("secret_env")) or "SNULBUG_BUNDLE_SECRET"
    secret = os.environ.get(secret_env)
    if not secret:
        raise ValueError(f"set {secret_env} before starting the share console to sign policy lifecycle changes")
    memory_limit = _positive_int(payload.get("memory_limit_bytes"))
    if memory_limit is None and payload.get("memory_limit_bytes") not in (0, "0"):
        memory_limit = 8 * 1024 * 1024
    kwargs = {
        "secret": secret,
        "key_id": key_id,
        "actor": _string_or_none(payload.get("actor")) or "share-console",
        "note": _string_or_none(payload.get("note")),
        "instruction_limit": _positive_int(payload.get("instruction_limit")) or 100_000,
        "memory_limit_bytes": memory_limit,
    }
    if action == "activate":
        result = activate_mcp_share_policy(directory, **kwargs)
    else:
        to_state = _string_or_none(payload.get("to_state") or payload.get("to"))
        if to_state not in {"proposed", "approved"}:
            raise ValueError("policy lifecycle promotion target must be proposed or approved")
        result = promote_mcp_share_policy(directory, to_state=to_state, **kwargs)
    result["secret_env"] = secret_env
    return result


def _first(values: Sequence[str] | None) -> str | None:
    if not values:
        return None
    return values[0]


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _string_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def _sequence(value: Any) -> Sequence[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return value
    return [value]


def _positive_int(value: Any) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _bool_or_default(value: Any, default: bool) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _provider_console(status: Mapping[str, Any], *, timeout: float) -> dict[str, Any] | None:
    tunnel = _mapping(status.get("tunnel_doctor"))
    session = _mapping(status.get("session"))
    provider = str(tunnel.get("provider") or session.get("provider") or "").strip().lower()
    if not provider:
        return None
    template = DEFAULT_TUNNEL_PROVIDER_CONSOLES.get(provider)
    if template is None:
        return None
    probe = _cached_provider_console_probe(provider, str(template["url"]), timeout=timeout)
    return {"provider": provider, **template, **probe}


def _tunnel_provider_visibility(
    share_dir: Path,
    status: Mapping[str, Any],
    provider_console: Mapping[str, Any] | None,
) -> dict[str, Any]:
    session = _mapping(status.get("session"))
    tunnel = _mapping(status.get("tunnel_doctor"))
    client = _mapping(status.get("client"))
    gateway = _mapping(status.get("gateway"))
    config = _provider_proxy_config_visibility(share_dir, status)
    provider = (
        str(
            tunnel.get("provider")
            or session.get("provider")
            or config.get("provider")
            or config.get("tunnel_provider")
            or "generic"
        )
        .strip()
        .lower()
    )
    public_url = tunnel.get("public_url") or client.get("url") or config.get("public_url")
    local_url = tunnel.get("local_url") or gateway.get("url") or config.get("local_url")
    return {
        "ok": True,
        "provider": provider,
        "label": TUNNEL_PROVIDER_LABELS.get(provider, provider.replace("-", " ").title()),
        "public_url": public_url,
        "client_url": client.get("url"),
        "local_url": local_url,
        "gateway_url": gateway.get("url"),
        "config": config,
        "auth": _provider_auth_visibility(status, config),
        "local_console": _provider_local_console_visibility(provider, provider_console),
        "doctor": _provider_doctor_visibility(tunnel),
        "commands": _provider_command_rows(_mapping(status.get("commands"))),
    }


def _provider_proxy_config_visibility(share_dir: Path, status: Mapping[str, Any]) -> dict[str, Any]:
    session_model = _mapping(status.get("session_model"))
    files = _mapping(session_model.get("files"))
    config_value = files.get("config")
    if not isinstance(config_value, str) or not config_value:
        return {}
    config_path = _resolve_console_path(share_dir, config_value)
    if not config_path.is_file():
        return {"path": str(config_path), "exists": False}
    try:
        proxy_config = load_mcp_proxy_config(config_path)
    except Exception as exc:
        return {"path": str(config_path), "exists": True, "error": str(exc)}
    auth = _mapping(proxy_config.get("auth"))
    return _drop_empty(
        {
            "path": str(config_path),
            "exists": True,
            "provider": proxy_config.get("tunnel_provider"),
            "public_url": proxy_config.get("tunnel_public_url"),
            "auth_mode": auth.get("mode"),
            "lease_required": proxy_config.get("lease_required"),
            "cloudflare_access": proxy_config.get("cloudflare_access"),
            "cloudflare_access_profile": proxy_config.get("cloudflare_access_profile"),
            "tailscale_profile": proxy_config.get("tailscale_profile"),
        }
    )


def _provider_auth_visibility(status: Mapping[str, Any], config: Mapping[str, Any]) -> dict[str, Any]:
    session = _mapping(status.get("session"))
    client_headers = _mapping(_mapping(status.get("client")).get("headers"))
    header_names = sorted(str(name) for name in client_headers)
    mode = config.get("auth_mode")
    if not mode:
        mode = "bearer" if any(name.lower() == "authorization" for name in header_names) else "none"
    return _drop_empty(
        {
            "mode": mode,
            "lease_required": config.get("lease_required", session.get("lease_required")),
            "lease_header": session.get("lease_header"),
            "client_header_names": header_names,
            "cloudflare_access": config.get("cloudflare_access"),
            "cloudflare_access_profile": config.get("cloudflare_access_profile")
            or session.get("cloudflare_access_profile"),
            "tailscale_profile": config.get("tailscale_profile") or session.get("tailscale_profile"),
        }
    )


def _provider_local_console_visibility(
    provider: str,
    provider_console: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if provider_console:
        return dict(provider_console)
    return {
        "provider": provider,
        "configured": False,
        "checked": False,
        "reachable": None,
        "label": "No default local console",
        "description": "No standard local inspection UI is configured for this provider.",
    }


def _cached_provider_console_probe(provider: str, url: str, *, timeout: float) -> dict[str, Any]:
    key = (provider, url)
    now = monotonic()
    cached = _PROVIDER_CONSOLE_CACHE.get(key)
    if cached is not None:
        checked_at, payload = cached
        if now - checked_at < DEFAULT_PROVIDER_CONSOLE_PROBE_TTL_SECONDS:
            result = dict(payload)
            result["cached"] = True
            result["cache_ttl_seconds"] = DEFAULT_PROVIDER_CONSOLE_PROBE_TTL_SECONDS
            return result
    result = _probe_provider_console(url, timeout=timeout)
    result["cached"] = False
    result["cache_ttl_seconds"] = DEFAULT_PROVIDER_CONSOLE_PROBE_TTL_SECONDS
    _PROVIDER_CONSOLE_CACHE[key] = (now, dict(result))
    return result


def _provider_doctor_visibility(tunnel: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "checked": bool(tunnel.get("checked")),
            "ok": tunnel.get("ok"),
            "last_checked_at": tunnel.get("last_checked_at"),
            "summary": _mapping(tunnel.get("summary")),
            "recommendations": _string_list(tunnel.get("recommendations")),
        }
    )


def _provider_command_rows(commands: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    labels = {
        "run": "Run snulbug",
        "provider": "Run provider",
        "doctor": "Run doctor",
        "share_doctor": "Run doctor",
        "client": "Show client config",
        "close": "Close session",
    }
    for key in ("run", "provider", "doctor", "share_doctor", "client", "close"):
        if key == "share_doctor" and commands.get("share_doctor") == commands.get("doctor"):
            continue
        value = commands.get(key)
        for index, command in enumerate(_sequence(value), start=1):
            if not isinstance(command, str) or not command.strip():
                continue
            if command in seen:
                continue
            seen.add(command)
            label = labels.get(key, key.replace("_", " ").title())
            if key == "provider" and len(_sequence(value)) > 1:
                label = f"{label} {index}"
            rows.append({"kind": key, "label": label, "command": command})
    return rows


def _probe_provider_console(url: str, *, timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"checked": False, "reachable": None, "status": None, "error": "unsupported provider console URL"}
    conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        connection = conn_class(
            parsed.hostname,
            parsed.port,
            timeout=max(0.05, min(float(timeout or 0.25), 0.35)),
        )
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            response.read(256)
            status = int(response.status)
        finally:
            connection.close()
    except OSError as exc:
        return {"checked": True, "reachable": False, "status": None, "error": str(exc)}
    return {"checked": True, "reachable": status < 500, "status": status, "error": None}


def _decision_timeline(
    share_dir: Path,
    status: Mapping[str, Any],
    *,
    limit: int = DEFAULT_DECISION_TIMELINE_LIMIT,
) -> dict[str, Any]:
    source = _decision_timeline_source(share_dir, status)
    result: dict[str, Any] = {
        "source": str(source) if source is not None else None,
        "source_kind": _mapping(status.get("traffic")).get("source_kind"),
        "exists": bool(source and source.exists()),
        "limit": limit,
        "events": [],
        "summary": {
            "shown": 0,
            "allowed": 0,
            "blocked": 0,
            "confirmed": 0,
            "capability_requested": 0,
            "redacted": 0,
            "upstream_failed": 0,
        },
    }
    if source is None or not source.exists():
        return result
    try:
        events = [
            _decision_timeline_item(event, source=source, line=line)
            for line, event in _recent_jsonl_events(source, limit)
        ]
    except OSError as exc:
        result["error"] = str(exc)
        return result
    items = [item for item in events if item is not None]
    result["events"] = list(reversed(items))
    result["compacted_events"] = _compact_decision_timeline_events(result["events"])
    result["summary"] = _decision_timeline_summary(result["events"])
    return result


def _decision_timeline_source(share_dir: Path, status: Mapping[str, Any]) -> Path | None:
    traffic = _mapping(status.get("traffic"))
    for value in (
        traffic.get("source"),
        _mapping(_mapping(status.get("recordings")).get("audit_log")).get("path"),
        _mapping(_mapping(status.get("recordings")).get("record_log")).get("path"),
    ):
        if value in (None, ""):
            continue
        path = Path(str(value))
        if path.is_absolute():
            return path
        if path.exists():
            return path
        return share_dir / path
    return None


def _recent_jsonl_events(path: Path, limit: int) -> list[tuple[int, dict[str, Any]]]:
    events: deque[tuple[int, dict[str, Any]]] = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(value, Mapping):
                continue
            event = build_audit_event(value) if value.get("type") == "snulbug.request_record" else dict(value)
            if _event_is_internal_probe(event):
                continue
            events.append((line_number, event))
    return list(events)


def _event_is_internal_probe(event: Mapping[str, Any]) -> bool:
    metadata = _mapping(event.get("metadata"))
    return isinstance(metadata.get("internal_probe"), Mapping)


def _decision_timeline_item(event: Mapping[str, Any], *, source: Path, line: int) -> dict[str, Any] | None:
    decision = _mapping(event.get("decision"))
    mcp = _mapping(event.get("mcp"))
    request = _mapping(event.get("request"))
    response = _mapping(event.get("response"))
    metadata = _mapping(event.get("metadata"))
    if not decision and not mcp and not request:
        return None
    confirmation = _mapping(decision.get("confirmation"))
    auth = _timeline_auth(event)
    facade = _mapping(event.get("facade")) or _mapping(metadata.get("facade"))
    topology = _mapping(event.get("topology")) or _mapping(metadata.get("topology"))
    response_policy = _mapping(metadata.get("response_policy"))
    item = {
        "time": event.get("time") or event.get("recorded_at"),
        "outcome": _timeline_outcome(event, decision=decision),
        "action": decision.get("action"),
        "allowed": decision.get("allowed"),
        "status": response.get("status") or decision.get("status"),
        "reason_code": decision.get("reason_code"),
        "reason": decision.get("reason"),
        "http_method": request.get("method"),
        "path": request.get("path"),
        "mcp_method": mcp.get("method"),
        "tool": mcp.get("tool") or mcp.get("target"),
        "request_id": mcp.get("request_id"),
        "auth_subject": auth.get("subject"),
        "auth_tenant": auth.get("tenant"),
        "auth_issuer": auth.get("issuer"),
        "auth_profile": auth.get("profile_id"),
        "upstream": facade.get("upstream") or topology.get("upstream") or metadata.get("upstream"),
        "source_ip": _mapping(event.get("tunnel")).get("source_ip")
        or _mapping(metadata.get("tunnel")).get("source_ip"),
        "confirmed": bool(confirmation),
        "confirmation_approved": confirmation.get("approved"),
        "redacted": _event_has_redaction_marker(event),
        "response_redacted": response_policy.get("redacted"),
        "source": str(source),
        "line": line,
    }
    return _drop_empty(item)


def _timeline_auth(event: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = _mapping(event.get("metadata"))
    auth = dict(_mapping(event.get("auth")) or _mapping(metadata.get("auth")))
    access_auth = _mapping(_mapping(metadata.get("access")).get("auth"))
    for key in ("subject", "issuer", "tenant", "client_id", "groups", "profile_id"):
        if auth.get(key) in (None, "", []):
            value = access_auth.get(key)
            if value not in (None, "", []):
                auth[key] = value
    return auth


def _timeline_outcome(event: Mapping[str, Any], *, decision: Mapping[str, Any]) -> str:
    metadata = _mapping(event.get("metadata"))
    response = _mapping(event.get("response"))
    confirmation = _mapping(decision.get("confirmation"))
    capability = _mapping(metadata.get("capability_request")) or _mapping(
        _mapping(decision.get("context")).get("capability_request")
    )
    if capability:
        return "capability_requested"
    if confirmation:
        return "confirmed" if confirmation.get("approved") is True else "blocked"
    if decision.get("allowed") is False:
        return "blocked"
    status = response.get("status") or decision.get("status")
    if isinstance(status, int) and status >= 500:
        return "upstream_failed"
    response_policy = _mapping(metadata.get("response_policy"))
    if response_policy.get("redacted") is True:
        return "redacted"
    return "allowed"


def _decision_timeline_summary(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    summary = {
        "shown": len(events),
        "allowed": 0,
        "blocked": 0,
        "confirmed": 0,
        "capability_requested": 0,
        "redacted": 0,
        "upstream_failed": 0,
    }
    for event in events:
        outcome = str(event.get("outcome") or "")
        if outcome in {"allowed", "blocked", "capability_requested", "upstream_failed"}:
            summary[outcome] += 1
        if event.get("confirmed"):
            summary["confirmed"] += 1
        if event.get("redacted") or event.get("response_redacted"):
            summary["redacted"] += 1
    return summary


def _compact_decision_timeline_events(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    current_signature: tuple[Any, ...] | None = None
    for event in events:
        signature = _decision_timeline_compaction_signature(event)
        if compacted and signature == current_signature:
            current = compacted[-1]
            current["count"] = int(current.get("count") or 1) + 1
            current["earliest_time"] = event.get("time") or current.get("earliest_time")
            if event.get("line"):
                current["earliest_line"] = event.get("line")
            continue
        item = dict(event)
        item["count"] = 1
        item["latest_time"] = event.get("time")
        item["earliest_time"] = event.get("time")
        item["latest_line"] = event.get("line")
        item["earliest_line"] = event.get("line")
        compacted.append(_drop_empty(item))
        current_signature = signature
    return compacted


def _decision_timeline_compaction_signature(event: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        event.get("outcome"),
        event.get("action"),
        event.get("allowed"),
        event.get("status"),
        event.get("reason_code"),
        event.get("http_method"),
        event.get("path"),
        event.get("mcp_method"),
        event.get("tool"),
        event.get("auth_subject"),
        event.get("auth_tenant"),
        event.get("auth_issuer"),
        event.get("upstream"),
        event.get("source_ip"),
    )


def _auth_visibility(share_dir: Path, status: Mapping[str, Any]) -> dict[str, Any]:
    config = _auth_config_visibility(share_dir)
    source = _decision_timeline_source(share_dir, status)
    result: dict[str, Any] = {
        "configured": bool(config),
        "config": config,
        "source": str(source) if source is not None else None,
        "exists": bool(source and source.exists()),
        "summary": {
            "auth_events": 0,
            "allowed": 0,
            "denied": 0,
            "subjects": 0,
            "issuers": 0,
            "tenants": 0,
            "scope_map_events": 0,
        },
        "current": {},
        "subjects": [],
        "issuers": [],
        "tenants": [],
        "groups": [],
        "scopes": [],
        "scope_match": {},
        "runtime": {},
        "jwks": {},
        "denials": {"total": 0, "reason_codes": [], "scope_denials": []},
        "events": [],
    }
    if source is None or not source.exists():
        return result

    try:
        raw_events = _recent_jsonl_events(source, DEFAULT_AUTH_VISIBILITY_LIMIT)
    except OSError as exc:
        result["error"] = str(exc)
        return result

    subject_counts: dict[str, int] = {}
    issuer_counts: dict[str, int] = {}
    tenant_counts: dict[str, int] = {}
    group_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    scope_denial_counts: dict[str, int] = {}
    auth_events: list[dict[str, Any]] = []
    latest_auth: Mapping[str, Any] = {}
    latest_scope_match: Mapping[str, Any] = {}
    latest_runtime: Mapping[str, Any] = {}

    for line, event in raw_events:
        auth = _auth_event_metadata(event)
        if not auth:
            continue
        latest_auth = auth
        summary = result["summary"]
        summary["auth_events"] += 1
        if auth.get("allowed") is False:
            summary["denied"] += 1
            reason = str(auth.get("reason_code") or "unknown")
            _count(reason_counts, reason)
        else:
            summary["allowed"] += 1
        _count_value(subject_counts, auth.get("subject"))
        _count_value(issuer_counts, auth.get("issuer"))
        _count_value(tenant_counts, auth.get("tenant"))
        for group in _string_list(auth.get("groups")):
            _count(group_counts, group)
        for scope in _string_list(auth.get("scopes")):
            _count(scope_counts, scope)
        scope_match = _auth_scope_match(auth)
        if scope_match:
            latest_scope_match = scope_match
            summary["scope_map_events"] += 1
            if scope_match.get("allowed") is False:
                _count(scope_denial_counts, _auth_scope_denial_key(scope_match))
        runtime = _mapping(auth.get("runtime"))
        if runtime:
            latest_runtime = runtime
        auth_events.append(_auth_visibility_event(event, auth=auth, scope_match=scope_match, source=source, line=line))

    result["current"] = _auth_current_visibility(latest_auth)
    result["subjects"] = _counter_rows(subject_counts)
    result["issuers"] = _counter_rows(issuer_counts)
    result["tenants"] = _counter_rows(tenant_counts)
    result["groups"] = _counter_rows(group_counts)
    result["scopes"] = _counter_rows(scope_counts)
    result["scope_match"] = _auth_scope_match_visibility(latest_scope_match)
    result["runtime"] = _auth_runtime_visibility(latest_runtime)
    result["jwks"] = _mapping(_mapping(result["runtime"].get("caches")).get("jwks"))
    result["denials"] = {
        "total": int(result["summary"]["denied"]),
        "reason_codes": _counter_rows(reason_counts),
        "scope_denials": _counter_rows(scope_denial_counts),
    }
    result["summary"]["subjects"] = len(subject_counts)
    result["summary"]["issuers"] = len(issuer_counts)
    result["summary"]["tenants"] = len(tenant_counts)
    result["events"] = list(reversed(auth_events[-10:]))
    return result


def _auth_config_visibility(share_dir: Path) -> dict[str, Any]:
    manifest_path = share_dir / "share.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    files = _mapping(_mapping(manifest).get("files"))
    config_value = files.get("config")
    if not isinstance(config_value, str) or not config_value:
        return {}
    config_path = _resolve_console_path(share_dir, config_value)
    if not config_path.is_file():
        return {"config": str(config_path), "exists": False}
    try:
        proxy_config = load_mcp_proxy_config(config_path)
    except Exception as exc:
        return {"config": str(config_path), "exists": True, "error": str(exc)}
    auth = _mapping(proxy_config.get("auth"))
    scope_map = _mapping(auth.get("scope_map"))
    return _drop_empty(
        {
            "config": str(config_path),
            "exists": True,
            "mode": auth.get("mode"),
            "resource": auth.get("resource"),
            "issuer": auth.get("issuer"),
            "audience": auth.get("audience"),
            "required_scopes": _string_list(auth.get("required_scopes")),
            "scope_map_count": len(scope_map),
            "scope_map": {str(scope): _string_list(selectors) for scope, selectors in scope_map.items()},
            "jwks_path": str(auth.get("jwks_path")) if auth.get("jwks_path") else None,
            "jwks_url": auth.get("jwks_url"),
            "token_validation": auth.get("token_validation"),
        }
    )


def _resolve_console_path(base: Path, value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    share_relative = base / path
    if share_relative.exists():
        return share_relative
    if path.exists():
        return path
    return share_relative


def _auth_event_metadata(event: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = _mapping(event.get("metadata"))
    auth = dict(_mapping(event.get("auth")) or _mapping(metadata.get("auth")))
    access_auth = _mapping(_mapping(metadata.get("access")).get("auth"))
    for key in ("subject", "issuer", "tenant", "client_id", "groups", "profile_id", "scopes"):
        if auth.get(key) in (None, "", []):
            value = access_auth.get(key)
            if value not in (None, "", []):
                auth[key] = value
    return auth


def _auth_scope_match(auth: Mapping[str, Any]) -> Mapping[str, Any]:
    scope_match = _mapping(auth.get("scope_match"))
    if scope_match:
        return scope_match
    return _mapping(auth.get("scope_map"))


def _auth_scope_denial_key(scope_match: Mapping[str, Any]) -> str:
    target = _mapping(scope_match.get("target"))
    if target.get("tool"):
        return f"tools/call:{target['tool']}"
    selectors = _string_list(target.get("selectors"))
    if selectors:
        return selectors[0]
    if target.get("method"):
        return str(target["method"])
    return str(scope_match.get("reason_code") or "oauth.scope_map_denied")


def _auth_current_visibility(auth: Mapping[str, Any]) -> dict[str, Any]:
    return _drop_empty(
        {
            "allowed": auth.get("allowed"),
            "reason_code": auth.get("reason_code"),
            "subject": auth.get("subject"),
            "issuer": auth.get("issuer"),
            "tenant": auth.get("tenant"),
            "client_id": auth.get("client_id"),
            "profile_id": auth.get("profile_id"),
            "email": auth.get("email"),
            "scopes": _string_list(auth.get("scopes")),
            "groups": _string_list(auth.get("groups")),
        }
    )


def _auth_scope_match_visibility(scope_match: Mapping[str, Any]) -> dict[str, Any]:
    target = _mapping(scope_match.get("target"))
    return _drop_empty(
        {
            "enabled": scope_match.get("enabled"),
            "allowed": scope_match.get("allowed"),
            "reason_code": scope_match.get("reason_code"),
            "matched_scope": scope_match.get("matched_scope"),
            "matched_selector": scope_match.get("matched_selector"),
            "matched_request_selector": scope_match.get("matched_request_selector"),
            "accepted_scopes": _string_list(scope_match.get("accepted_scopes")),
            "candidate_selectors": _string_list(scope_match.get("candidate_selectors")),
            "target_method": target.get("method"),
            "target_tool": target.get("tool"),
            "target_selectors": _string_list(target.get("selectors")),
        }
    )


def _auth_runtime_visibility(runtime: Mapping[str, Any]) -> dict[str, Any]:
    caches = _mapping(runtime.get("caches"))
    return _drop_empty(
        {
            "caches": {str(name): dict(_mapping(cache)) for name, cache in caches.items()},
            "decisions": dict(_mapping(runtime.get("decisions"))),
        }
    )


def _auth_visibility_event(
    event: Mapping[str, Any],
    *,
    auth: Mapping[str, Any],
    scope_match: Mapping[str, Any],
    source: Path,
    line: int,
) -> dict[str, Any]:
    return _drop_empty(
        {
            "time": event.get("time") or event.get("recorded_at"),
            "allowed": auth.get("allowed"),
            "reason_code": auth.get("reason_code"),
            "subject": auth.get("subject"),
            "issuer": auth.get("issuer"),
            "tenant": auth.get("tenant"),
            "scopes": _string_list(auth.get("scopes")),
            "groups": _string_list(auth.get("groups")),
            "scope_match": _auth_scope_match_visibility(scope_match),
            "source": str(source),
            "line": line,
        }
    )


def _count_value(counter: dict[str, int], value: Any) -> None:
    if value not in (None, "", []):
        _count(counter, str(value))


def _count(counter: dict[str, int], value: str) -> None:
    if value:
        counter[value] = counter.get(value, 0) + 1


def _counter_rows(counter: Mapping[str, int]) -> list[dict[str, Any]]:
    return [{"value": key, "count": counter[key]} for key in sorted(counter, key=lambda item: (-counter[item], item))]


def _tool_schema_visibility(share_dir: Path, status: Mapping[str, Any]) -> dict[str, Any]:
    tool_risks = _mapping(status.get("tool_risks"))
    schemas = _mapping(status.get("schemas"))
    source = _decision_timeline_source(share_dir, status)
    tools = [_tool_schema_row(tool) for tool in _sequence(tool_risks.get("tools")) if isinstance(tool, Mapping)]
    drift_alerts = _tool_schema_drift_alerts(share_dir, status, tools=tools)
    schema_source_count = int(schemas.get("source_count", 0) or 0)
    schema_tool_count = int(schemas.get("tool_count", 0) or 0)
    return {
        "ok": bool(tools or drift_alerts or schema_source_count or schema_tool_count),
        "source": str(source) if source is not None else None,
        "summary": {
            "tool_count": len(tools),
            "catalog_count": int(schemas.get("catalog_count", 0) or 0),
            "schema_tool_count": schema_tool_count,
            "schema_errors": int(schemas.get("errors", 0) or 0),
            "high_risk": int(_mapping(tool_risks.get("summary")).get("high", 0) or 0),
            "medium_risk": int(_mapping(tool_risks.get("summary")).get("medium", 0) or 0),
            "low_risk": int(_mapping(tool_risks.get("summary")).get("low", 0) or 0),
            "drift_alerts": len(drift_alerts),
        },
        "schemas": {
            "catalog_count": int(schemas.get("catalog_count", 0) or 0),
            "source_count": schema_source_count,
            "tool_count": schema_tool_count,
            "errors": int(schemas.get("errors", 0) or 0),
            "sources": [dict(_mapping(source_item)) for source_item in _sequence(schemas.get("sources"))],
        },
        "tools": tools,
        "drift_alerts": drift_alerts,
    }


def _tool_schema_row(tool: Mapping[str, Any]) -> dict[str, Any]:
    schema = _mapping(tool.get("schema"))
    signals = [
        str(_mapping(signal).get("code")) for signal in _sequence(tool.get("signals")) if _mapping(signal).get("code")
    ]
    drift_signals = [signal for signal in signals if "drift" in signal or "variant" in signal]
    return _drop_empty(
        {
            "name": tool.get("name"),
            "risk": tool.get("level"),
            "score": tool.get("score"),
            "count": tool.get("count"),
            "categories": _string_list(tool.get("categories")),
            "signals": signals,
            "drift_signals": drift_signals,
            "evidence_sources": _string_list(tool.get("evidence_sources")),
            "schema_hash": schema.get("tool_hash"),
            "schema_hashes": _string_list(schema.get("tool_hashes")),
            "catalog_hashes": _string_list(schema.get("catalog_hashes")),
            "catalog_paths": _string_list(schema.get("catalog_paths")),
            "schema_variants": schema.get("variants"),
            "properties": _string_list(schema.get("input_properties")),
            "required": _string_list(schema.get("required")),
            "additional_properties": schema.get("additional_properties"),
        }
    )


def _tool_schema_drift_alerts(
    share_dir: Path,
    status: Mapping[str, Any],
    *,
    tools: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for tool in tools:
        if int(tool.get("schema_variants") or 0) > 1:
            alerts.append(
                _drop_empty(
                    {
                        "kind": "schema_variants",
                        "tool": tool.get("name"),
                        "severity": "high",
                        "message": "multiple schema variants discovered for this tool",
                        "schema_hashes": tool.get("schema_hashes"),
                    }
                )
            )
        for signal in _string_list(tool.get("drift_signals")):
            alerts.append(
                _drop_empty(
                    {
                        "kind": signal,
                        "tool": tool.get("name"),
                        "severity": "high",
                        "message": "schema drift risk signal",
                    }
                )
            )
    source = _decision_timeline_source(share_dir, status)
    if source is None or not source.exists():
        return alerts
    try:
        events = _recent_jsonl_events(source, DEFAULT_AUTH_VISIBILITY_LIMIT)
    except OSError:
        return alerts
    for line, event in events:
        response_policy = _event_response_policy(event)
        tool_pinning = _mapping(response_policy.get("tool_pinning"))
        for item in _sequence(tool_pinning.get("changed")):
            changed = _mapping(item)
            alerts.append(
                _drop_empty(
                    {
                        "kind": "tool_pinning_changed",
                        "tool": changed.get("tool"),
                        "severity": "high" if response_policy.get("reason_code") else "medium",
                        "message": "pinned tool description or schema changed",
                        "previous_hash": changed.get("previous_hash") or changed.get("old_hash"),
                        "current_hash": changed.get("current_hash") or changed.get("new_hash"),
                        "source": str(source),
                        "line": line,
                    }
                )
            )
        for item in _sequence(tool_pinning.get("pinned")):
            pinned = _mapping(item)
            if pinned.get("tool"):
                alerts.append(
                    _drop_empty(
                        {
                            "kind": "tool_pinning_observed",
                            "tool": pinned.get("tool"),
                            "severity": "info",
                            "message": "tool description/schema pinned from tools/list",
                            "current_hash": pinned.get("hash") or pinned.get("current_hash"),
                            "source": str(source),
                            "line": line,
                        }
                    )
                )
        reason_code = response_policy.get("reason_code")
        if reason_code in {"response.tool_description_changed", "response.tool_schema_changed"}:
            alerts.append(
                _drop_empty(
                    {
                        "kind": str(reason_code),
                        "severity": "high",
                        "message": response_policy.get("reason") or str(reason_code),
                        "source": str(source),
                        "line": line,
                    }
                )
            )
    return alerts[-20:]


def _policy_visibility(
    share_dir: Path,
    status: Mapping[str, Any],
    *,
    decision_timeline: Mapping[str, Any],
) -> dict[str, Any]:
    session_model = _mapping(status.get("session_model"))
    policy = _mapping(status.get("policy")) or _mapping(session_model.get("policy"))
    paths = _mapping(session_model.get("paths"))
    runtime_paths = _mapping(_mapping(session_model.get("runtime")).get("resolved_paths"))
    active_value = (
        policy.get("active_policy") or policy.get("path") or runtime_paths.get("policy") or paths.get("active_policy")
    )
    bundle_value = policy.get("bundle") or runtime_paths.get("policy_bundle") or paths.get("policy_bundle")
    active_path = _resolve_console_path(share_dir, active_value) if isinstance(active_value, str | Path) else None
    bundle_path = _resolve_console_path(share_dir, bundle_value) if isinstance(bundle_value, str | Path) else None
    source = _policy_source_visibility(active_path, share_dir=share_dir, bundle_path=bundle_path)
    manifest = _policy_bundle_manifest_visibility(bundle_path, share_dir=share_dir)
    reason_codes = _policy_reason_code_visibility(decision_timeline)
    source_text = str(source.get("source") or "")
    return {
        "ok": bool(source.get("exists") or manifest.get("exists") or policy),
        "policy": _drop_empty(
            {
                "active_policy": str(active_path) if active_path is not None else None,
                "bundle": str(bundle_path) if bundle_path is not None else None,
                "lifecycle_state": policy.get("lifecycle_state"),
                "lifecycle_signed": policy.get("lifecycle_signed"),
                "lifecycle_signature_key_id": _mapping(policy.get("lifecycle_signature")).get("key_id"),
                "last_lifecycle": policy.get("last_lifecycle"),
                "last_amendment": policy.get("last_amendment"),
            }
        ),
        "source": source,
        "bundle_manifest": manifest,
        "helper_usage": _policy_helper_usage(source_text),
        "reason_codes": reason_codes,
    }


def _declared_invite_capabilities(directory: str | Path, *, timeout: float) -> list[dict[str, Any]]:
    share_dir = Path(directory)
    status = share_status(share_dir, timeout=timeout, live_checks=False)
    visibility = _policy_visibility(share_dir, status, decision_timeline={})
    source = _mapping(visibility.get("source"))
    capabilities = source.get("capabilities")
    if not isinstance(capabilities, Sequence) or isinstance(capabilities, str | bytes | bytearray):
        return []
    return [dict(item) for item in capabilities if isinstance(item, Mapping) and item.get("id")]


def _default_invite_capability_ids(capabilities: Sequence[Mapping[str, Any]]) -> list[str]:
    defaults = [str(item.get("id")) for item in capabilities if item.get("default") is True and item.get("id")]
    if defaults:
        return defaults
    first = next((str(item.get("id")) for item in capabilities if item.get("id")), "")
    return [first] if first else []


def _policy_source_visibility(
    path: Path | None,
    *,
    share_dir: Path,
    bundle_path: Path | None,
) -> dict[str, Any]:
    if path is None:
        return {"exists": False, "displayable": False, "reason": "no active policy path is configured"}
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "displayable": False,
        "language": "lua",
        "max_bytes": MAX_POLICY_SOURCE_BYTES,
    }
    if not path.exists():
        result["reason"] = "active policy file is missing"
        return result
    if not path.is_file():
        result["reason"] = "active policy path is not a file"
        return result
    if path.suffix != ".lua":
        result["reason"] = "active policy is not a Lua source file"
        return result
    if not _policy_path_allowed(path, share_dir=share_dir, bundle_path=bundle_path):
        result["reason"] = "active policy is outside the share policy roots"
        return result

    stat = path.stat()
    raw = _read_bounded_bytes(path, MAX_POLICY_SOURCE_BYTES)
    source = raw["data"].decode("utf-8", errors="replace")
    redacted = _redact_policy_source(source)
    declared_capabilities = _policy_declared_capabilities(source, source_name=str(path))
    result.update(
        {
            "displayable": True,
            "size": stat.st_size,
            "sha256": _file_sha256(path),
            "truncated": raw["truncated"],
            "source": redacted,
            "redacted": redacted != source,
            "line_count": _line_count(str(redacted)),
            **declared_capabilities,
        }
    )
    return result


def _policy_declared_capabilities(source: str, *, source_name: str) -> dict[str, Any]:
    try:
        script = compile_lua_script(source, source_name=source_name)
    except LuaRuntimeError as exc:
        return {
            "capabilities": [],
            "capabilities_ok": False,
            "capabilities_error": str(exc),
        }
    return {
        "capabilities": script.capabilities,
        "capabilities_ok": True,
    }


def _policy_bundle_manifest_visibility(bundle_path: Path | None, *, share_dir: Path) -> dict[str, Any]:
    if bundle_path is None:
        return {"exists": False}
    manifest_path = bundle_path / "manifest.json"
    result: dict[str, Any] = {
        "bundle": str(bundle_path),
        "path": str(manifest_path),
        "exists": manifest_path.is_file(),
    }
    if not manifest_path.exists():
        return result
    if not _policy_path_allowed(manifest_path, share_dir=share_dir, bundle_path=bundle_path):
        result["displayable"] = False
        result["reason"] = "bundle manifest is outside the share policy roots"
        return result
    stat = manifest_path.stat()
    result["size"] = stat.st_size
    result["sha256"] = _file_sha256(manifest_path)
    if stat.st_size > MAX_POLICY_MANIFEST_BYTES:
        result["displayable"] = False
        result["reason"] = "bundle manifest is too large to display"
        return result
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["displayable"] = False
        result["reason"] = str(exc)
        return result
    if not isinstance(manifest, Mapping):
        result["displayable"] = False
        result["reason"] = "bundle manifest must be a JSON object"
        return result
    fixtures = _sequence(manifest.get("fixtures"))
    result.update(
        _drop_empty(
            {
                "displayable": True,
                "id": manifest.get("id"),
                "name": manifest.get("name"),
                "version": manifest.get("version"),
                "description": manifest.get("description"),
                "entrypoint": manifest.get("entrypoint"),
                "fixture_count": len(fixtures),
                "lifecycle": manifest.get("lifecycle"),
            }
        )
    )
    return result


def _redact_policy_source(source: str) -> str:
    redacted = POLICY_SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{SECRET_REPLACEMENT}{match.group(2)}",
        source,
    )
    redacted = POLICY_BEARER_PATTERN.sub("Bearer " + SECRET_REPLACEMENT, redacted)
    for pattern in POLICY_STANDALONE_SECRET_PATTERNS:
        redacted = pattern.sub(SECRET_REPLACEMENT, redacted)
    return redacted


def _policy_path_allowed(path: Path, *, share_dir: Path, bundle_path: Path | None) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return False
    roots = [share_dir.resolve(strict=False)]
    if bundle_path is not None:
        roots.append(bundle_path.resolve(strict=False))
    return any(_path_is_relative_to(resolved, root) for root in roots)


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _read_bounded_bytes(path: Path, limit: int) -> dict[str, Any]:
    with path.open("rb") as file:
        data = file.read(limit + 1)
    return {"data": data[:limit], "truncated": len(data) > limit}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _line_count(value: str) -> int:
    if not value:
        return 0
    return value.count("\n") + (0 if value.endswith("\n") else 1)


def _policy_helper_usage(source: str) -> list[dict[str, Any]]:
    helpers = {
        "mcp": "mcp.",
        "auth": "auth.",
        "lease": "lease.",
        "workspace": "workspace.",
        "state": "state.",
        "request": "request.",
        "context": "context.",
    }
    rows = []
    for name, needle in helpers.items():
        count = source.count(needle)
        if count:
            rows.append({"family": name, "pattern": needle, "count": count})
    for keyword in ("reject(", "respond(", "confirm(", "capability_request(", "rate_limit("):
        count = source.count(keyword)
        if count:
            rows.append({"family": "decision", "pattern": keyword, "count": count})
    return rows


def _policy_reason_code_visibility(decision_timeline: Mapping[str, Any]) -> dict[str, Any]:
    events = [_mapping(event) for event in _sequence(decision_timeline.get("events")) if isinstance(event, Mapping)]
    counts: dict[str, int] = {}
    recent = []
    for event in events:
        reason_code = str(event.get("reason_code") or "")
        if reason_code:
            _count(counts, reason_code)
        recent.append(
            _drop_empty(
                {
                    "time": event.get("time"),
                    "outcome": event.get("outcome"),
                    "action": event.get("action"),
                    "reason_code": reason_code or None,
                    "tool": event.get("tool"),
                    "mcp_method": event.get("mcp_method"),
                    "source": event.get("source"),
                    "line": event.get("line"),
                }
            )
        )
    return {
        "summary": _counter_rows(counts),
        "recent": recent[:10],
    }


def _share_readiness_gate(
    share_dir: Path,
    status: Mapping[str, Any],
    *,
    capability_requests: Mapping[str, Any],
    decision_timeline: Mapping[str, Any],
    auth_visibility: Mapping[str, Any],
    tool_schema_visibility: Mapping[str, Any],
    tunnel_provider: Mapping[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    session = _mapping(status.get("session"))
    gateway = _mapping(status.get("gateway"))
    upstreams = [_mapping(item) for item in _sequence(status.get("upstreams")) if isinstance(item, Mapping)]
    tunnel = _mapping(status.get("tunnel_doctor"))
    provider_auth = _mapping(tunnel_provider.get("auth"))
    policy = _mapping(status.get("policy"))
    leases = _mapping(status.get("leases"))
    invitations = _mapping(status.get("invitations"))
    findings = [_mapping(item) for item in _sequence(status.get("findings")) if isinstance(item, Mapping)]
    traffic = _mapping(status.get("traffic"))
    contract = _mapping(status.get("contract"))
    tool_summary = _mapping(_mapping(status.get("tool_risks")).get("summary"))
    schema_summary = _mapping(tool_schema_visibility.get("summary"))
    public_url = (
        tunnel.get("public_url") or tunnel_provider.get("public_url") or _mapping(status.get("client")).get("url")
    )

    state = status.get("state")
    _add_readiness_check(
        checks,
        "share.state",
        "pass" if state in {"verified", "running", "active"} else "warn",
        "share",
        (
            "share session has been verified"
            if state in {"verified", "running", "active"}
            else "share session has not been verified yet"
        ),
        details={"state": state, "directory": str(share_dir)},
    )
    _add_readiness_check(
        checks,
        "gateway.reachable",
        _readiness_reachability_status(gateway),
        "gateway",
        _readiness_reachability_message("local gateway", gateway),
        details={"url": gateway.get("url"), "checked": gateway.get("checked"), "reachable": gateway.get("reachable")},
    )
    _add_readiness_check(
        checks,
        "upstreams.reachable",
        _readiness_upstream_status(upstreams),
        "upstreams",
        _readiness_upstream_message(upstreams),
        details={
            "count": len(upstreams),
            "checked": sum(1 for upstream in upstreams if upstream.get("checked")),
            "unreachable": [
                upstream.get("name") or upstream.get("url")
                for upstream in upstreams
                if upstream.get("checked") and upstream.get("reachable") is not True
            ],
        },
    )
    public_url_status, public_url_message = _readiness_public_url(public_url)
    _add_readiness_check(
        checks,
        "tunnel.public_url",
        public_url_status,
        "tunnel",
        public_url_message,
        details={"provider": tunnel_provider.get("provider") or tunnel.get("provider"), "public_url": public_url},
    )
    _add_readiness_check(
        checks,
        "tunnel.doctor",
        _readiness_tunnel_doctor_status(tunnel),
        "tunnel",
        _readiness_tunnel_doctor_message(tunnel),
        details={
            "checked": tunnel.get("checked"),
            "ok": tunnel.get("ok"),
            "summary": tunnel.get("summary"),
            "last_checked_at": tunnel.get("last_checked_at"),
        },
    )
    auth_mode = provider_auth.get("mode")
    _add_readiness_check(
        checks,
        "auth.configured",
        "pass" if auth_mode and auth_mode != "none" else "fail",
        "auth",
        f"auth mode is {auth_mode}" if auth_mode and auth_mode != "none" else "no client auth mode is configured",
        details={"mode": auth_mode, "client_header_names": provider_auth.get("client_header_names")},
    )
    lease_required = provider_auth.get("lease_required", session.get("lease_required"))
    active_lease_count = int(leases.get("active_count") or 0)
    active_invite_count = _active_invite_count(invitations, leases)
    _add_readiness_check(
        checks,
        "leases.active",
        _readiness_lease_status(lease_required, active_lease_count, active_invite_count),
        "leases",
        _readiness_lease_message(lease_required, active_lease_count, active_invite_count),
        details={
            "required": lease_required,
            "active_count": active_lease_count,
            "active_invite_count": active_invite_count,
            "file": leases.get("file"),
        },
    )
    _add_readiness_check(
        checks,
        "policy.active",
        _readiness_policy_status(policy),
        "policy",
        _readiness_policy_message(policy),
        details={
            "path": policy.get("path"),
            "bundle": policy.get("bundle"),
            "lifecycle_state": policy.get("lifecycle_state"),
        },
    )
    request_summary = _mapping(capability_requests.get("summary")) or _mapping(status.get("capability_requests"))
    pending_requests = int(request_summary.get("pending") or 0)
    _add_readiness_check(
        checks,
        "capability_requests.pending",
        "warn" if pending_requests else "pass",
        "review",
        f"{pending_requests} pending capability requests need review"
        if pending_requests
        else "no pending capability requests",
        details={"pending": pending_requests, "summary": request_summary},
    )
    finding_counts = _finding_severity_counts(findings)
    _add_readiness_check(
        checks,
        "findings.severity",
        "fail" if finding_counts["error"] else ("warn" if finding_counts["warning"] else "pass"),
        "evidence",
        _readiness_findings_message(finding_counts),
        details=finding_counts,
    )
    drift_alerts = [
        _mapping(item) for item in _sequence(tool_schema_visibility.get("drift_alerts")) if isinstance(item, Mapping)
    ]
    high_drift = sum(1 for alert in drift_alerts if alert.get("severity") == "high")
    schema_errors = int(schema_summary.get("schema_errors") or 0)
    _add_readiness_check(
        checks,
        "schemas.drift",
        "fail" if high_drift else ("warn" if drift_alerts or schema_errors else "pass"),
        "schemas",
        _readiness_schema_message(drift_alerts, schema_errors),
        details={
            "drift_alerts": len(drift_alerts),
            "high_drift_alerts": high_drift,
            "schema_errors": schema_errors,
            "tool_count": schema_summary.get("tool_count"),
            "catalog_count": schema_summary.get("catalog_count"),
        },
    )
    high_risk_tools = int(tool_summary.get("high") or 0)
    _add_readiness_check(
        checks,
        "tools.high_risk",
        "warn" if high_risk_tools else "pass",
        "tools",
        f"{high_risk_tools} high-risk tools require review" if high_risk_tools else "no high-risk tools detected",
        details=dict(tool_summary),
    )
    _add_readiness_check(
        checks,
        "contract.bound",
        _readiness_contract_status(contract),
        "contract",
        _readiness_contract_message(contract),
        details={
            "configured": contract.get("configured"),
            "required": contract.get("required"),
            "signed": contract.get("signed"),
            "verified": contract.get("verified"),
            "drifted": contract.get("drifted"),
            "binding_digest": contract.get("binding_digest"),
            "path": contract.get("path"),
        },
    )
    _add_readiness_check(
        checks,
        "evidence.recorded",
        "pass" if traffic.get("exists") and int(traffic.get("event_count") or 0) else "warn",
        "evidence",
        "request evidence has been recorded"
        if traffic.get("exists") and int(traffic.get("event_count") or 0)
        else "no recorded request evidence found yet",
        details={
            "source": traffic.get("source"),
            "event_count": traffic.get("event_count"),
            "shown": _mapping(decision_timeline.get("summary")).get("shown"),
        },
    )
    auth_denials = int(_mapping(auth_visibility.get("denials")).get("total") or 0)
    _add_readiness_check(
        checks,
        "auth.denials",
        "warn" if auth_denials else "pass",
        "auth",
        f"{auth_denials} auth denials observed" if auth_denials else "no auth denials observed in recent evidence",
        details={"denials": auth_denials, "source": auth_visibility.get("source")},
    )

    summary = _readiness_summary(checks)
    handoff = _share_handoff_readiness(checks)
    base_decision = "blocked" if summary["failed"] else ("review" if summary["warnings"] else "ready")
    labels = {
        "ready": "Ready to share",
        "review": "Needs review before sharing",
        "blocked": "Do not share yet",
    }
    base_label = labels[base_decision]
    recommendations = _readiness_recommendations(checks, status)
    base_attestation = _share_readiness_attestation(
        share_dir,
        status,
        decision=base_decision,
        label=base_label,
        summary=summary,
        checks=checks,
        tunnel_provider=tunnel_provider,
        auth_visibility=auth_visibility,
        tool_schema_visibility=tool_schema_visibility,
    )
    review_digest = _share_readiness_review_digest(base_attestation)
    review = _matching_readiness_review(status, review_digest)
    reviewed = bool(review) and base_decision == "review"
    decision = "ready" if reviewed else base_decision
    label = "Reviewed and ready to share" if reviewed else base_label
    attestation = _share_readiness_attestation(
        share_dir,
        status,
        decision=decision,
        label=label,
        summary=summary,
        checks=checks,
        tunnel_provider=tunnel_provider,
        auth_visibility=auth_visibility,
        tool_schema_visibility=tool_schema_visibility,
    )
    return {
        "schema": "snulbug.share-readiness-gate.v1",
        "ok": decision == "ready",
        "decision": decision,
        "label": label,
        "summary": summary,
        "handoff": handoff,
        "checks": checks,
        "recommendations": recommendations,
        "review_digest": review_digest,
        "reviewed": reviewed,
        "review": review if reviewed else None,
        "attestation": attestation,
    }


def _setup_wizard(
    status: Mapping[str, Any],
    *,
    readiness_gate: Mapping[str, Any],
    tunnel_provider: Mapping[str, Any],
    capability_requests: Mapping[str, Any],
    tool_schema_visibility: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the human share setup path from existing console state."""

    checks = {str(check.get("id")): _mapping(check) for check in _sequence(readiness_gate.get("checks"))}
    commands = _mapping(status.get("commands"))
    request_summary = _mapping(capability_requests.get("summary")) or _mapping(status.get("capability_requests"))
    pending_requests = int(request_summary.get("pending") or 0)
    schema_summary = _mapping(tool_schema_visibility.get("summary"))
    tool_summary = _mapping(_mapping(status.get("tool_risks")).get("summary"))
    public_url = tunnel_provider.get("public_url") or _mapping(status.get("client")).get("url")

    steps = [
        _wizard_step(
            "upstream",
            "Validate Upstream",
            _wizard_status(checks, ("gateway.reachable", "upstreams.reachable")),
            _wizard_message(
                checks,
                ("gateway.reachable", "upstreams.reachable"),
                "Local gateway and upstream MCP servers are reachable.",
            ),
            _wizard_action("run_doctor", "Run doctor", disabled=False),
        ),
        _wizard_step(
            "tunnel",
            "Choose Tunnel",
            _wizard_status(checks, ("tunnel.public_url", "tunnel.doctor")),
            _wizard_tunnel_message(checks, public_url),
            _wizard_tunnel_action(checks, commands),
        ),
        _wizard_step(
            "auth_leases",
            "Auth And Leases",
            _wizard_status(checks, ("auth.configured", "leases.active")),
            _wizard_message(checks, ("auth.configured", "leases.active"), "Auth and lease controls are configured."),
            _wizard_auth_lease_action(checks, pending_requests),
        ),
        _wizard_step(
            "tools",
            "Inspect Tools",
            _wizard_status(checks, ("schemas.drift", "tools.high_risk")),
            _wizard_tools_message(checks, schema_summary, tool_summary),
            _wizard_tools_action(checks),
        ),
        _wizard_step(
            "policy",
            "Generate Policy",
            _wizard_status(checks, ("policy.active", "capability_requests.pending")),
            _wizard_message(
                checks,
                ("policy.active", "capability_requests.pending"),
                "Policy is active and no capability requests are pending.",
            ),
            _wizard_policy_action(checks, pending_requests),
        ),
        _wizard_step(
            "share",
            "Ready To Share",
            _wizard_final_status(readiness_gate),
            _wizard_final_message(readiness_gate),
            _wizard_final_action(readiness_gate),
        ),
    ]
    active_index = next((index for index, step in enumerate(steps) if step["status"] != "pass"), len(steps) - 1)
    for index, step in enumerate(steps):
        step["active"] = index == active_index
        step["index"] = index + 1
    completed = sum(1 for step in steps if step["status"] == "pass")
    next_step = steps[active_index] if steps else None
    return {
        "schema": "snulbug.share-setup-wizard.v1",
        "label": readiness_gate.get("label") or "Share setup",
        "decision": readiness_gate.get("decision") or "unknown",
        "completed": completed,
        "total": len(steps),
        "next_step": next_step,
        "steps": steps,
    }


def _bootstrap_setup_wizard(existing_shares: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    create_message = "Create a share session from this browser, or select one already present in this workspace."
    if existing_shares:
        create_message = "Create a new share session, or start from one of the existing sessions listed above."
    steps = [
        _wizard_step(
            "create_share",
            "Create Or Select Share",
            "warn",
            create_message,
            _wizard_action("create_share", "Create share"),
        ),
        _wizard_step(
            "set_upstream",
            "Set Upstream",
            "skip",
            "Point the share at your local MCP server or facade upstream.",
            _wizard_action("create_share", "Edit setup form"),
        ),
        _wizard_step(
            "run_gateway",
            "Run Gateway",
            "skip",
            "Start the gateway directly from setup after creating or selecting a share.",
            _wizard_action("create_share", "Create and run"),
        ),
        _wizard_step(
            "expose_tunnel",
            "Expose Tunnel",
            "skip",
            "Run your tunnel provider against the local snulbug gateway port.",
            _wizard_action("copy_command", "Copy ngrok example", command="ngrok http 8080"),
        ),
        _wizard_step(
            "validate_share",
            "Validate Share",
            "skip",
            "After the share is running, use share doctor from the console.",
            _wizard_action("run_doctor", "Run doctor"),
        ),
        _wizard_step(
            "review_report",
            "Review Report",
            "skip",
            "Generate a session report once traffic has passed through the gateway.",
            _wizard_action("download_report", "Download report"),
        ),
    ]
    for index, step in enumerate(steps):
        step["index"] = index + 1
        step["active"] = index == 0
    return {
        "schema": "snulbug.share-setup-wizard.v1",
        "label": "Create or select a share session",
        "decision": "setup",
        "completed": 0,
        "total": len(steps),
        "next_step": steps[0],
        "steps": steps,
    }


def _wizard_step(
    step_id: str,
    label: str,
    status: str,
    message: str,
    action: Mapping[str, Any],
) -> dict[str, Any]:
    return _drop_empty(
        {
            "id": step_id,
            "label": label,
            "status": status,
            "message": message,
            "primary_action": dict(action),
        }
    )


def _wizard_status(checks: Mapping[str, Mapping[str, Any]], ids: Sequence[str]) -> str:
    statuses = [str(_mapping(checks.get(check_id)).get("status") or "warn") for check_id in ids]
    if any(status == "fail" for status in statuses):
        return "fail"
    if any(status == "warn" for status in statuses):
        return "warn"
    return "pass"


def _wizard_message(checks: Mapping[str, Mapping[str, Any]], ids: Sequence[str], success: str) -> str:
    messages = [
        str(check.get("message"))
        for check_id in ids
        for check in [_mapping(checks.get(check_id))]
        if check.get("status") != "pass" and check.get("message")
    ]
    return " ".join(messages) if messages else success


def _wizard_action(kind: str, label: str, **extra: Any) -> dict[str, Any]:
    return _drop_empty({"kind": kind, "label": label, **extra})


def _wizard_tunnel_message(checks: Mapping[str, Mapping[str, Any]], public_url: Any) -> str:
    if public_url:
        return _wizard_message(checks, ("tunnel.public_url", "tunnel.doctor"), f"Public URL is {public_url}.")
    return _wizard_message(checks, ("tunnel.public_url", "tunnel.doctor"), "Tunnel provider is configured.")


def _wizard_tunnel_action(checks: Mapping[str, Mapping[str, Any]], commands: Mapping[str, Any]) -> dict[str, Any]:
    if _mapping(checks.get("tunnel.public_url")).get("status") == "fail":
        provider_command = _first_command(commands.get("provider"))
        if provider_command:
            return _wizard_action("copy_command", "Copy provider command", command=provider_command)
        return _wizard_action("anchor", "Review provider", target="#providerSection")
    if _mapping(checks.get("tunnel.doctor")).get("status") != "pass":
        return _wizard_action("run_doctor", "Run doctor")
    return _wizard_action("anchor", "Review provider", target="#providerSection")


def _wizard_auth_lease_action(checks: Mapping[str, Mapping[str, Any]], pending_requests: int) -> dict[str, Any]:
    if _mapping(checks.get("auth.configured")).get("status") == "fail":
        return _wizard_action("anchor", "Review auth", target="#authSection")
    if pending_requests > 0:
        return _wizard_action("anchor", "Review requests", target="#requestsSection")
    return _wizard_action("anchor", "Review leases", target="#leasesSection")


def _wizard_tools_message(
    checks: Mapping[str, Mapping[str, Any]],
    schema_summary: Mapping[str, Any],
    tool_summary: Mapping[str, Any],
) -> str:
    success = (
        f"{int(schema_summary.get('tool_count') or 0)} tools discovered; "
        f"{int(tool_summary.get('high') or 0)} high-risk tools."
    )
    return _wizard_message(checks, ("schemas.drift", "tools.high_risk"), success)


def _wizard_tools_action(checks: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if _mapping(checks.get("schemas.drift")).get("status") != "pass":
        return _wizard_action("anchor", "Inspect schemas", target="#schemaSection")
    return _wizard_action("anchor", "Inspect risk", target="#riskSection")


def _wizard_policy_action(checks: Mapping[str, Mapping[str, Any]], pending_requests: int) -> dict[str, Any]:
    if pending_requests > 0:
        return _wizard_action("preview_amendment", "Preview amendment")
    if _mapping(checks.get("policy.active")).get("status") != "pass":
        return _wizard_action("preview_amendment", "Preview amendment")
    return _wizard_action("anchor", "Review policy", target="#policySection")


def _wizard_final_status(readiness_gate: Mapping[str, Any]) -> str:
    decision = readiness_gate.get("decision")
    if decision == "ready":
        return "pass"
    if decision == "blocked":
        return "fail"
    return "warn"


def _wizard_final_message(readiness_gate: Mapping[str, Any]) -> str:
    if readiness_gate.get("decision") == "ready":
        return "Share is ready; capture the report and client commands before handing out the URL."
    return str(readiness_gate.get("label") or "Share needs review before handing out the URL.")


def _wizard_final_action(readiness_gate: Mapping[str, Any]) -> dict[str, Any]:
    if readiness_gate.get("decision") == "ready":
        return _wizard_action("download_report", "Download report")
    return _wizard_action("run_doctor", "Run doctor")


def _first_command(value: Any) -> str | None:
    for item in _sequence(value):
        if isinstance(item, str) and item.strip():
            return item
    return None


def _add_readiness_check(
    checks: list[dict[str, Any]],
    check_id: str,
    status: str,
    component: str,
    message: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> None:
    check = {
        "id": check_id,
        "status": status,
        "component": component,
        "message": message,
    }
    if details:
        check["details"] = _drop_empty(dict(details))
    checks.append(check)


def _readiness_reachability_status(target: Mapping[str, Any]) -> str:
    if target.get("checked") is not True:
        return "warn"
    return "pass" if target.get("reachable") is True else "fail"


def _readiness_reachability_message(label: str, target: Mapping[str, Any]) -> str:
    if target.get("checked") is not True:
        return f"{label} reachability has not been checked"
    if target.get("reachable") is True:
        return f"{label} is reachable"
    return f"{label} is not reachable"


def _readiness_upstream_status(upstreams: Sequence[Mapping[str, Any]]) -> str:
    if not upstreams:
        return "fail"
    if any(upstream.get("checked") and upstream.get("reachable") is not True for upstream in upstreams):
        return "fail"
    if all(upstream.get("checked") for upstream in upstreams):
        return "pass"
    return "warn"


def _readiness_upstream_message(upstreams: Sequence[Mapping[str, Any]]) -> str:
    if not upstreams:
        return "no upstream MCP servers are configured"
    unreachable = [
        upstream.get("name") or upstream.get("url")
        for upstream in upstreams
        if upstream.get("checked") and upstream.get("reachable") is not True
    ]
    if unreachable:
        return "unreachable upstreams: " + ", ".join(str(item) for item in unreachable[:5])
    if all(upstream.get("checked") for upstream in upstreams):
        return "all upstreams are reachable"
    return "one or more upstream reachability checks have not run"


def _readiness_public_url(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or not value:
        return "fail", "no public MCP URL is configured"
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.scheme == "https" or host in {"127.0.0.1", "localhost", "::1"}:
        return "pass", "client-facing MCP URL is configured"
    return "warn", "client-facing MCP URL is not HTTPS"


def _readiness_tunnel_doctor_status(tunnel: Mapping[str, Any]) -> str:
    if tunnel.get("checked") is not True:
        return "warn"
    return "pass" if tunnel.get("ok") is True else "fail"


def _readiness_tunnel_doctor_message(tunnel: Mapping[str, Any]) -> str:
    if tunnel.get("checked") is not True:
        return "tunnel doctor has not been run"
    if tunnel.get("ok") is True:
        return "last tunnel doctor passed"
    return "last tunnel doctor failed"


def _active_invite_count(invitations: Mapping[str, Any], leases: Mapping[str, Any]) -> int:
    active_lease_ids = {
        str(lease.get("id"))
        for lease in _sequence(leases.get("leases"))
        if isinstance(lease, Mapping) and lease.get("active") is True and lease.get("id")
    }
    active_invites = [
        _mapping(invite)
        for invite in _sequence(invitations.get("items"))
        if isinstance(invite, Mapping) and not invite.get("revoked_at")
    ]
    return sum(1 for invite in active_invites if str(invite.get("lease_id") or "") in active_lease_ids)


def _readiness_lease_status(required: Any, active_count: int, active_invite_count: int = 0) -> str:
    if required is True:
        return "pass" if active_count > 0 or active_invite_count > 0 else "warn"
    if required is False:
        return "warn"
    return "warn"


def _readiness_lease_message(required: Any, active_count: int, active_invite_count: int = 0) -> str:
    if required is True:
        if active_invite_count > 0:
            suffix = "invite" if active_invite_count == 1 else "invites"
            return f"{active_invite_count} active {suffix} available"
        if active_count > 0:
            return f"{active_count} active leases available"
        return "create a task invite or lease before handing out client access"
    if required is False:
        return "leases are not required for this share"
    return "lease requirement is unknown"


def _readiness_policy_status(policy: Mapping[str, Any]) -> str:
    lifecycle = policy.get("lifecycle_state")
    if lifecycle == "active":
        return "pass"
    if lifecycle:
        return "warn"
    return "pass" if policy else "warn"


def _readiness_policy_message(policy: Mapping[str, Any]) -> str:
    lifecycle = policy.get("lifecycle_state")
    if lifecycle == "active":
        return "active policy bundle is selected"
    if lifecycle:
        return f"policy lifecycle state is {lifecycle}"
    if policy:
        return "policy is configured without lifecycle metadata"
    return "no policy metadata is available"


def _finding_severity_counts(findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"error": 0, "warning": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _readiness_findings_message(counts: Mapping[str, int]) -> str:
    if counts.get("error", 0):
        return f"{counts['error']} error findings block sharing"
    if counts.get("warning", 0):
        return f"{counts['warning']} warning findings need review"
    return "no blocking findings"


def _readiness_schema_message(drift_alerts: Sequence[Mapping[str, Any]], schema_errors: int) -> str:
    high_drift = sum(1 for alert in drift_alerts if alert.get("severity") == "high")
    if high_drift:
        return f"{high_drift} high-severity schema drift alerts block sharing"
    if drift_alerts:
        return f"{len(drift_alerts)} schema drift alerts need review"
    if schema_errors:
        return f"{schema_errors} schema catalog errors need review"
    return "no schema drift alerts"


def _readiness_contract_status(contract: Mapping[str, Any]) -> str:
    if contract.get("drifted") is True or contract.get("file_valid") is False or contract.get("exists") is False:
        return "fail"
    if contract.get("required") is True:
        return "pass"
    if contract.get("configured"):
        return "pass"
    return "pass"


def _readiness_contract_message(contract: Mapping[str, Any]) -> str:
    if contract.get("drifted") is True:
        return "share contract has drifted from current share state"
    if contract.get("file_valid") is False:
        return "share contract file is invalid"
    if contract.get("exists") is False:
        return "share contract file is missing"
    if contract.get("required") is True:
        return "required share contract matches current share state"
    if contract.get("configured"):
        return "share contract metadata is available"
    return "share contract is optional; readiness attestation is generated"


def _readiness_summary(checks: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.get("status") == "pass"),
        "warnings": sum(1 for check in checks if check.get("status") == "warn"),
        "failed": sum(1 for check in checks if check.get("status") == "fail"),
    }


def _share_handoff_readiness(checks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    blocking = [
        _mapping(check)
        for check in checks
        if check.get("status") == "fail" and str(check.get("id") or "") != "leases.active"
    ]
    blocking_ids = [str(check.get("id")) for check in blocking if check.get("id")]
    return {
        "ready": not blocking_ids,
        "reason_code": "share.handoff_ready" if not blocking_ids else "share.handoff_blocked",
        "blocking_checks": blocking_ids,
        "message": (
            "share can create task-scoped invites"
            if not blocking_ids
            else "fix blocking readiness checks before creating invites"
        ),
    }


def _readiness_recommendations(checks: Sequence[Mapping[str, Any]], status: Mapping[str, Any]) -> list[str]:
    recommendations: list[str] = []
    check_status = {str(check.get("id")): str(check.get("status")) for check in checks}
    commands = _mapping(status.get("commands"))
    doctor = commands.get("share_doctor") or commands.get("doctor")
    needs_doctor = any(
        check_status.get(check_id) == "warn"
        for check_id in ("gateway.reachable", "upstreams.reachable", "tunnel.doctor")
    )
    if doctor and needs_doctor:
        recommendations.append(f"Run readiness checks: {doctor}")
    if check_status.get("capability_requests.pending") == "warn":
        recommendations.append("Approve or deny pending capability requests before sharing broadly.")
    if check_status.get("contract.bound") == "warn":
        recommendations.append("Generate a share contract if you need a reviewable attestation for this session.")
    if check_status.get("schemas.drift") == "fail":
        recommendations.append("Review schema drift alerts before exposing changed tool surfaces.")
    if check_status.get("leases.active") == "warn":
        recommendations.append("Create a task invite or lease before handing out client access.")
    if check_status.get("auth.configured") == "fail":
        recommendations.append("Configure bearer, OAuth, or provider auth before exposing the endpoint.")
    if any(value == "fail" for value in check_status.values()):
        recommendations.append("Do not share this endpoint until failed checks are resolved.")
    return _unique_console_strings(recommendations)


def _unique_console_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _share_readiness_attestation(
    share_dir: Path,
    status: Mapping[str, Any],
    *,
    decision: str,
    label: str,
    summary: Mapping[str, int],
    checks: Sequence[Mapping[str, Any]],
    tunnel_provider: Mapping[str, Any],
    auth_visibility: Mapping[str, Any],
    tool_schema_visibility: Mapping[str, Any],
) -> dict[str, Any]:
    session = _mapping(status.get("session"))
    policy = _mapping(status.get("policy"))
    contract = _mapping(status.get("contract"))
    traffic = _mapping(status.get("traffic"))
    leases = _mapping(status.get("leases"))
    invitations = _mapping(status.get("invitations"))
    auth_config = _mapping(auth_visibility.get("config"))
    schema_summary = _mapping(tool_schema_visibility.get("summary"))
    tool_risk = _mapping(_mapping(status.get("tool_risks")).get("summary"))
    payload = _drop_empty(
        {
            "schema": "snulbug.share-readiness-attestation.v1",
            "generated_at": _now_iso(),
            "share": str(share_dir),
            "decision": decision,
            "label": label,
            "summary": dict(summary),
            "session": {
                "state": status.get("state"),
                "provider": session.get("provider") or tunnel_provider.get("provider"),
                "public_url": tunnel_provider.get("public_url") or _mapping(status.get("client")).get("url"),
                "local_url": tunnel_provider.get("local_url") or _mapping(status.get("gateway")).get("url"),
            },
            "auth": {
                "mode": _mapping(tunnel_provider.get("auth")).get("mode") or auth_config.get("mode"),
                "issuer": auth_config.get("issuer"),
                "resource": auth_config.get("resource"),
                "required_scopes": auth_config.get("required_scopes"),
                "denials": _mapping(auth_visibility.get("denials")).get("total"),
            },
            "leases": {
                "required": _mapping(tunnel_provider.get("auth")).get("lease_required", session.get("lease_required")),
                "active_count": leases.get("active_count"),
                "active_invite_count": _active_invite_count(invitations, leases),
                "file": leases.get("file"),
            },
            "policy": {
                "path": policy.get("path"),
                "bundle": policy.get("bundle"),
                "lifecycle_state": policy.get("lifecycle_state"),
            },
            "contract": {
                "configured": contract.get("configured"),
                "required": contract.get("required"),
                "signed": contract.get("signed"),
                "verified": contract.get("verified"),
                "drifted": contract.get("drifted"),
                "binding_digest": contract.get("binding_digest") or contract.get("digest"),
                "key_id": contract.get("key_id"),
            },
            "evidence": {
                "event_count": traffic.get("event_count"),
                "allowed": traffic.get("allowed"),
                "blocked": traffic.get("blocked"),
                "confirmed": traffic.get("confirmed"),
                "response_redacted": traffic.get("response_redacted"),
            },
            "tools": {
                "risk": dict(tool_risk),
                "schemas": dict(schema_summary),
            },
            "checks": [
                {
                    "id": check.get("id"),
                    "status": check.get("status"),
                    "component": check.get("component"),
                    "message": check.get("message"),
                }
                for check in checks
            ],
        }
    )
    payload["content_digest"] = _console_json_digest(_share_readiness_digest_payload(payload))
    payload["digest"] = payload["content_digest"]
    return payload


def _share_readiness_digest_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    auth = dict(_mapping(payload.get("auth")))
    auth.pop("denials", None)
    tools = _mapping(payload.get("tools"))
    leases = dict(_mapping(payload.get("leases")))
    leases.pop("active_count", None)
    leases.pop("active_invite_count", None)
    volatile_non_failing_checks = {
        "gateway.reachable",
        "leases.active",
        "tunnel.doctor",
        "upstreams.reachable",
    }
    checks = [
        _mapping(check)
        for check in _sequence(payload.get("checks"))
        if isinstance(check, Mapping)
        and not (check.get("id") in volatile_non_failing_checks and check.get("status") != "fail")
    ]
    return _drop_empty(
        {
            "schema": payload.get("schema"),
            "share": payload.get("share"),
            "decision": payload.get("decision"),
            "label": payload.get("label"),
            "summary": _readiness_summary(checks),
            "session": payload.get("session"),
            "auth": auth,
            "leases": leases,
            "policy": payload.get("policy"),
            "contract": payload.get("contract"),
            "tools": {"schemas": tools.get("schemas")},
            "checks": checks,
        }
    )


def _share_readiness_review_digest(attestation: Mapping[str, Any]) -> str:
    payload = _share_readiness_digest_payload(attestation)
    payload.pop("decision", None)
    payload.pop("label", None)
    return _console_json_digest(payload)


def _matching_readiness_review(status: Mapping[str, Any], review_digest: str) -> dict[str, Any] | None:
    session_model = _mapping(status.get("session_model"))
    readiness = _mapping(session_model.get("readiness"))
    review = _mapping(readiness.get("last_review"))
    if review.get("review_digest") != review_digest:
        return None
    return dict(review)


def _console_json_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _event_response_policy(event: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = _mapping(event.get("metadata"))
    return _mapping(event.get("response_policy")) or _mapping(metadata.get("response_policy"))


def _redact_console_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if lowered == "headers" and isinstance(item, Mapping):
                redacted[key_text] = {
                    str(header): (
                        "[REDACTED]"
                        if _sensitive_name(str(header)) or _sensitive_value(header_value)
                        else _redact_console_payload(header_value)
                    )
                    for header, header_value in item.items()
                }
                continue
            if _sensitive_name(key_text) or _sensitive_value(item):
                redacted[key_text] = "[REDACTED]"
            else:
                redacted[key_text] = _redact_console_payload(item)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_redact_console_payload(item) for item in value]
    if _sensitive_value(value):
        return "[REDACTED]"
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in ({}, [], None, "")}


def _event_has_redaction_marker(event: Mapping[str, Any]) -> bool:
    try:
        return SECRET_REPLACEMENT in json.dumps(event, sort_keys=True, default=str)
    except TypeError:
        return False


def _sensitive_name(value: str) -> bool:
    lowered = value.lower()
    return (
        lowered == "authorization"
        or lowered.endswith("_token")
        or "secret" in lowered
        or lowered in {"token", "retry_header"}
    )


def _sensitive_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return (
        stripped.startswith("Bearer ")
        or stripped.startswith("sbl_")
        or "SNULBUG_SHARE_TOKEN=" in stripped
        or "x-snulbug-lease: sbl_" in stripped
    )


def _console_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>snulbug share console</title>
  <link rel="stylesheet" href="/assets/prism.css">
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --surface: #ffffff;
      --surface-2: #eef2f6;
      --line: #d7dde5;
      --text: #17202a;
      --muted: #5e6b7a;
      --blue: #2166a5;
      --green: #127a4a;
      --red: #b4232a;
      --yellow: #9a6700;
      --shadow: 0 8px 28px rgba(25, 38, 52, 0.08);
    }
    * {
      box-sizing: border-box;
    }
    html {
      scroll-behavior: smooth;
      scroll-padding-top: 124px;
    }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow-x: hidden;
    }
    button, input, select {
      font: inherit;
    }
    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--text);
      min-height: 34px;
      padding: 0 12px;
      cursor: pointer;
    }
    button.primary {
      background: var(--blue);
      border-color: var(--blue);
      color: #fff;
    }
    button.danger {
      color: var(--red);
      border-color: #e5b8bb;
    }
    a {
      color: var(--blue);
      text-decoration: none;
      font-weight: 650;
    }
    a:hover {
      text-decoration: underline;
    }
    button:disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    input, select {
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 10px;
      background: #fff;
      color: var(--text);
      min-width: 0;
    }
    .shell {
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
      width: 100%;
      max-width: 100vw;
      overflow-x: clip;
    }
    .topbar {
      max-width: min(1320px, 100vw);
      width: 100%;
      min-width: 0;
      margin: 0 auto;
      padding: 12px 20px 10px;
      display: grid;
      grid-template-columns: minmax(180px, 1fr) auto;
      gap: 16px;
      align-items: center;
    }
    .topbar > *, .toolbar {
      min-width: 0;
    }
    h1 {
      margin: 0;
      font-size: 20px;
      font-weight: 720;
      letter-spacing: 0;
    }
    .subtitle {
      margin-top: 2px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    .toolbar {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .toolbar-group {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      padding: 4px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfd;
    }
    .auto {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      color: var(--muted);
      white-space: nowrap;
    }
    .section-nav {
      max-width: min(1320px, 100vw);
      width: 100%;
      min-width: 0;
      margin: 0 auto;
      padding: 0 20px 10px;
      display: flex;
      gap: 6px;
      overflow-x: auto;
      scrollbar-width: thin;
    }
    .section-nav a {
      flex: 0 0 auto;
      min-height: 30px;
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0 10px;
      background: #fbfcfd;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-decoration: none;
    }
    .section-nav a:hover {
      color: var(--blue);
      border-color: #9ec2df;
      text-decoration: none;
    }
    main {
      max-width: min(1320px, 100vw);
      min-width: 0;
      width: 100%;
      margin: 0 auto;
      padding: 16px 20px 28px;
      display: grid;
      gap: 16px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(168px, 1fr));
      gap: 12px;
    }
    .metric, section {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .metric {
      min-height: 118px;
      padding: 13px 14px;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 8px;
      color: var(--text);
      text-decoration: none;
      position: relative;
      overflow: hidden;
      transition: border-color 120ms ease, transform 120ms ease, box-shadow 120ms ease;
    }
    .metric:hover,
    .metric:focus-visible {
      border-color: #9ec2df;
      box-shadow: 0 10px 30px rgba(25, 38, 52, 0.12);
      text-decoration: none;
      transform: translateY(-1px);
    }
    .metric::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 4px;
      background: var(--line);
    }
    .metric.good::before {
      background: var(--green);
    }
    .metric.warn::before {
      background: var(--yellow);
    }
    .metric.bad::before {
      background: var(--red);
    }
    .metric.neutral::before {
      background: var(--blue);
    }
    .metric-head {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      min-width: 0;
    }
    .metric-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      font-weight: 760;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .metric-badge {
      width: 30px;
      height: 30px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
      font-size: 11px;
      font-weight: 760;
      border: 1px solid var(--line);
      background: #fbfcfd;
      color: var(--muted);
    }
    .metric.good .metric-badge {
      color: var(--green);
      border-color: #a8d9bf;
      background: #f0faf5;
    }
    .metric.warn .metric-badge {
      color: var(--yellow);
      border-color: #e7cf8a;
      background: #fff9e8;
    }
    .metric.bad .metric-badge {
      color: var(--red);
      border-color: #e5b8bb;
      background: #fff3f4;
    }
    .metric-value {
      font-size: clamp(20px, 2.1vw, 28px);
      font-weight: 780;
      line-height: 1.1;
      overflow-wrap: anywhere;
      align-self: end;
    }
    .metric-detail {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.25;
      min-height: 30px;
      overflow-wrap: anywhere;
    }
    section {
      overflow: hidden;
      scroll-margin-top: 124px;
    }
    .section-head {
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      background: var(--surface-2);
    }
    h2 {
      margin: 0;
      font-size: 15px;
      font-weight: 720;
    }
    .section-body {
      padding: 14px;
    }
    .tab-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      border-bottom: 1px solid var(--line);
      padding-bottom: 10px;
      margin-bottom: 14px;
    }
    .tab-button {
      min-height: 36px;
      display: inline-flex;
      gap: 8px;
      align-items: center;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fbfcfd;
      color: var(--muted);
      font-weight: 720;
    }
    .tab-button.active {
      border-color: #9ec2df;
      background: #f2f8fd;
      color: var(--blue);
      box-shadow: 0 0 0 2px rgba(33, 102, 165, 0.08);
    }
    .tab-button:disabled {
      opacity: 0.55;
      cursor: not-allowed;
    }
    .tab-button-detail {
      color: var(--muted);
      font-size: 12px;
      font-weight: 620;
    }
    .tab-panel[hidden] {
      display: none;
    }
    .section-subhead {
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .overview-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(0, 0.8fr);
      gap: 16px;
      align-items: start;
    }
    .grid-two {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      gap: 16px;
      align-items: start;
    }
    .wizard-overview {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfd;
    }
    .wizard-grid {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
    }
    .wizard-step {
      min-height: 160px;
      display: grid;
      gap: 10px;
      align-content: start;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
    }
    .wizard-step.active {
      border-color: #9ec2df;
      box-shadow: 0 0 0 2px rgba(33, 102, 165, 0.08);
    }
    .wizard-step-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .wizard-index {
      width: 26px;
      height: 26px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      border-radius: 50%;
      color: var(--muted);
      font-weight: 720;
      background: #fbfcfd;
    }
    .wizard-title {
      font-weight: 720;
    }
    .wizard-action {
      align-self: end;
      margin-top: auto;
    }
    .button-link {
      min-height: 34px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      background: var(--surface);
      color: var(--text);
      font-weight: 400;
      text-decoration: none;
    }
    .button-link:hover {
      border-color: #9ec2df;
      color: var(--blue);
      text-decoration: none;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      text-align: left;
      border-bottom: 1px solid var(--line);
      padding: 9px 8px;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #fbfcfd;
    }
    tr:last-child td {
      border-bottom: 0;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      min-height: 22px;
      font-size: 12px;
      border: 1px solid var(--line);
      background: #fff;
    }
    .ok, .pass, .reachable, .approved, .ready {
      color: var(--green);
      border-color: #a7d8bf;
      background: #f0fbf5;
    }
    .fail, .blocked, .denied, .unreachable {
      color: var(--red);
      border-color: #efb3b8;
      background: #fff5f5;
    }
    .warn, .pending, .unknown, .confirmed, .not-checked, .review, .skip {
      color: var(--yellow);
      border-color: #ecd598;
      background: #fffaf0;
    }
    .muted {
      color: var(--muted);
    }
    .request-actions {
      display: grid;
      grid-template-columns: 72px 88px minmax(92px, 1fr) auto auto;
      gap: 6px;
      align-items: center;
    }
    .request-actions input {
      width: 100%;
    }
    .lease-list {
      display: grid;
      gap: 10px;
    }
    .lease-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      display: grid;
      gap: 10px;
    }
    .lease-card.active {
      border-left: 4px solid var(--green);
    }
    .lease-card.inactive {
      border-left: 4px solid var(--line);
    }
    .lease-card-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: start;
    }
    .lease-title {
      font-weight: 740;
      overflow-wrap: anywhere;
    }
    .lease-meta {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 12px;
    }
    .lease-actions {
      display: grid;
      grid-template-columns: minmax(70px, 0.7fr) minmax(86px, 0.8fr) auto;
      gap: 6px;
      align-items: center;
    }
    .lease-actions input {
      width: 100%;
    }
    .lease-actions button {
      white-space: nowrap;
    }
    .invite-list {
      display: grid;
      gap: 10px;
    }
    .invite-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      display: grid;
      gap: 10px;
    }
    .invite-card.active {
      border-left: 4px solid var(--blue);
    }
    .invite-card.revoked {
      border-left: 4px solid var(--line);
    }
    .invite-card-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: start;
    }
    .invite-title {
      font-weight: 740;
      overflow-wrap: anywhere;
    }
    .invite-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .setup-form {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
    }
    .field-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .form-field {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .form-field.wide {
      grid-column: 1 / -1;
    }
    .form-field label,
    .check-row label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 720;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .form-field input,
    .form-field select {
      width: 100%;
    }
    .field-help {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.25;
    }
    .capability-options {
      grid-column: 1 / -1;
      display: grid;
      gap: 8px;
    }
    .capability-option {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      background: white;
    }
    .capability-option-title {
      font-weight: 720;
    }
    .check-row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }
    .check-row label {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      text-transform: none;
    }
    .setup-share-list {
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      background: #fff;
    }
    .setup-share-row {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }
    .setup-share-row:last-child {
      border-bottom: 0;
    }
    .request-row {
      cursor: pointer;
    }
    .request-row:hover {
      background: #f7fafd;
    }
    .request-open {
      min-width: 72px;
    }
    .drawer {
      position: fixed;
      z-index: 20;
      top: 0;
      right: 0;
      bottom: 0;
      width: min(560px, 100vw);
      background: var(--surface);
      border-left: 1px solid var(--line);
      box-shadow: -16px 0 38px rgba(15, 23, 32, 0.16);
      display: grid;
      grid-template-rows: auto 1fr;
    }
    .drawer[hidden] {
      display: none;
    }
    .drawer-head {
      padding: 14px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 12px;
      background: var(--surface-2);
    }
    .drawer-title {
      display: grid;
      gap: 4px;
      min-width: 0;
    }
    .drawer-body {
      padding: 14px;
      overflow: auto;
      display: grid;
      gap: 16px;
      align-content: start;
    }
    .detail-grid {
      display: grid;
      grid-template-columns: 132px minmax(0, 1fr);
      gap: 8px 12px;
    }
    .detail-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .drawer-actions {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
    }
    .drawer-actions input {
      width: 100%;
    }
    .drawer-actions .wide {
      grid-column: 1 / -1;
    }
    .timeline-target {
      font-weight: 680;
    }
    .timeline-detail {
      color: var(--muted);
      margin-top: 2px;
    }
    .review-panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
      display: grid;
      gap: 12px;
    }
    .review-panel.ready {
      border-color: #a7d8bf;
      background: #f0fbf5;
    }
    .review-panel.review,
    .review-panel.warn {
      border-color: #ecd598;
      background: #fffaf0;
    }
    .review-panel.blocked,
    .review-panel.fail {
      border-color: #efb3b8;
      background: #fff5f5;
    }
    .review-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
    }
    .review-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .copy-status {
      min-height: 34px;
      display: inline-flex;
      align-items: center;
      color: var(--muted);
      font-size: 12px;
    }
    .copy-status.ok {
      color: var(--green);
      font-weight: 720;
    }
    .copy-status.fail {
      color: var(--red);
      font-weight: 720;
    }
    .review-list {
      display: grid;
      gap: 8px;
    }
    .review-item {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      border-top: 1px solid var(--line);
      padding-top: 8px;
    }
    .target-kind {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 2px 8px;
      border-radius: 6px;
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 760;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #fff;
    }
    .target-kind.gateway {
      color: var(--blue);
      border-color: #9ec2df;
      background: #f2f8fd;
    }
    .target-kind.tunnel {
      color: var(--yellow);
      border-color: #e7cf8a;
      background: #fff9e8;
    }
    .target-kind.upstream {
      color: var(--green);
      border-color: #a7d8bf;
      background: #f0fbf5;
    }
    .health-target {
      display: grid;
      gap: 4px;
    }
    .message {
      min-height: 20px;
      color: var(--muted);
    }
    .stack {
      display: grid;
      gap: 12px;
    }
    .recommendations {
      margin: 8px 0 0;
      padding-left: 18px;
    }
    details.compact-details {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfd;
      overflow: hidden;
    }
    details.compact-details summary {
      min-height: 40px;
      padding: 10px 12px;
      cursor: pointer;
      color: var(--text);
      font-weight: 720;
      list-style-position: inside;
    }
    details.compact-details .details-body {
      border-top: 1px solid var(--line);
      padding: 12px;
      background: var(--surface);
    }
    .console-output {
      background: #0f1720;
      color: #e8f1f8;
      border-radius: 8px;
      padding: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .command-code {
      display: block;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #f4f6f8;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      color: #1b2733;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
    }
    .empty {
      color: var(--muted);
      padding: 16px 4px;
    }
    .report-output {
      max-height: 420px;
      overflow: auto;
      white-space: pre-wrap;
      background: #fbfcfd;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
    }
    .policy-source {
      max-height: 520px;
      border: 1px solid var(--line);
    }
    @media (max-width: 980px) {
      .metrics {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .field-grid,
      .setup-share-row,
      .review-item {
        grid-template-columns: 1fr;
      }
      .review-head {
        display: grid;
      }
      .grid-two, .overview-grid, .topbar, .wizard-overview {
        grid-template-columns: 1fr;
      }
      .lease-meta {
        grid-template-columns: 1fr;
      }
      .wizard-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .toolbar {
        justify-content: flex-start;
      }
      .request-actions {
        grid-template-columns: 1fr 1fr;
      }
    }
    @media (max-width: 560px) {
      main, .topbar, .section-nav {
        padding-left: 12px;
        padding-right: 12px;
      }
      .toolbar-group {
        width: 100%;
      }
      .metrics {
        grid-template-columns: 1fr;
      }
      .wizard-grid {
        grid-template-columns: 1fr;
      }
      .section-body {
        padding: 10px;
      }
      table, thead, tbody, th, td, tr {
        display: block;
      }
      th {
        display: none;
      }
      td {
        border-bottom: 0;
        padding: 6px 0;
      }
      tr {
        border-bottom: 1px solid var(--line);
        padding: 8px 0;
      }
      .request-actions {
        grid-template-columns: 1fr;
      }
      .lease-card-head,
      .lease-actions {
        grid-template-columns: 1fr;
      }
      .invite-card-head,
      .invite-actions {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div class="topbar">
        <div>
          <h1>snulbug share console</h1>
          <div id="sharePath" class="subtitle">Loading share session</div>
        </div>
        <div class="toolbar" aria-label="Console actions">
          <div class="toolbar-group" aria-label="Refresh controls">
            <label class="auto"><input id="autoRefresh" type="checkbox" checked> Auto refresh</label>
            <button id="refreshButton" class="primary" type="button">Refresh</button>
          </div>
          <div id="sessionActions" class="toolbar-group" aria-label="Session actions">
            <button id="doctorButton" type="button">Run Doctor</button>
            <button id="amendPreviewButton" type="button">Preview Amendment</button>
            <button id="reportButton" type="button">Download Report</button>
          </div>
        </div>
      </div>
      <nav class="section-nav" aria-label="Console sections">
        <a id="setupNavLink" href="#setupSection" hidden>Setup</a>
        <a href="#shareWorkflowSection" onclick="setShareTab('readiness')">Readiness</a>
        <a href="#policySection">Policy</a>
        <a href="#providerSection">Provider</a>
        <a href="#decisionsSection">Decisions</a>
        <a href="#requestsSection">Requests</a>
        <a href="#leasesSection">Leases</a>
        <a href="#shareWorkflowSection" onclick="setShareTab('invites')">Invites</a>
        <a href="#authSection">Auth</a>
        <a href="#schemaSection">Schemas</a>
        <a href="#riskSection">Risk</a>
        <a href="#evidenceSection">Evidence</a>
      </nav>
    </header>
    <main>
      <div id="message" class="message" aria-live="polite"></div>
      <div class="metrics" id="metrics"></div>
      <section id="setupSection" hidden>
        <div class="section-head"><h2>Share Setup</h2><span id="wizardSummary" class="muted"></span></div>
        <div class="section-body" id="setupWizard"></div>
      </section>
      <section id="shareWorkflowSection">
        <div class="section-head"><h2>Share Handoff</h2><span id="shareWorkflowSummary" class="muted"></span></div>
        <div class="section-body">
          <div class="tab-list" role="tablist" aria-label="Share handoff">
            <button
              id="share-tab-readiness"
              class="tab-button active"
              type="button"
              role="tab"
              aria-selected="true"
              aria-controls="readinessSection"
              onclick="setShareTab('readiness')"
            >
              Readiness
              <span id="share-tab-readiness-detail" class="tab-button-detail"></span>
            </button>
            <button
              id="share-tab-invites"
              class="tab-button"
              type="button"
              role="tab"
              aria-selected="false"
              aria-controls="invitesSection"
              onclick="setShareTab('invites')"
              disabled
            >
              Invites
              <span id="share-tab-invites-detail" class="tab-button-detail"></span>
            </button>
          </div>
          <div id="readinessSection" class="tab-panel" role="tabpanel" aria-labelledby="share-tab-readiness">
            <div class="section-subhead">
              <h2>Share Readiness</h2>
              <span id="readinessSummary" class="muted"></span>
            </div>
            <div id="shareReadiness"></div>
          </div>
          <div id="invitesSection" class="tab-panel" role="tabpanel" aria-labelledby="share-tab-invites" hidden>
            <div class="section-subhead">
              <h2>Share Invitations</h2>
              <span id="inviteSummary" class="muted"></span>
            </div>
            <div id="invitations"></div>
          </div>
        </div>
      </section>
      <section id="policySection">
        <div class="section-head"><h2>Policy Visibility</h2><span id="policySummary" class="muted"></span></div>
        <div class="section-body" id="policyVisibility"></div>
      </section>
      <div class="overview-grid">
        <section id="providerSection">
          <div class="section-head"><h2>Tunnel Provider</h2><span id="providerSummary" class="muted"></span></div>
          <div class="section-body" id="tunnelProvider"></div>
        </section>
        <section id="healthSection">
          <div class="section-head"><h2>Health</h2><span id="healthSummary" class="muted"></span></div>
          <div class="section-body" id="health"></div>
        </section>
      </div>
      <section id="decisionsSection">
        <div class="section-head"><h2>Live Decisions</h2><span id="decisionSummary" class="muted"></span></div>
        <div class="section-body" id="decisionTimeline"></div>
      </section>
      <div class="grid-two">
        <section id="requestsSection">
          <div class="section-head"><h2>Capability Requests</h2><span id="requestSummary" class="muted"></span></div>
          <div class="section-body" id="requests"></div>
        </section>
        <section id="leasesSection">
          <div class="section-head"><h2>Active Leases</h2><span id="leaseSummary" class="muted"></span></div>
          <div class="section-body" id="leases"></div>
        </section>
      </div>
      <section id="authSection">
        <div class="section-head"><h2>Auth Visibility</h2><span id="authSummary" class="muted"></span></div>
        <div class="section-body" id="authVisibility"></div>
      </section>
      <section id="schemaSection">
        <div class="section-head">
          <h2>Tool And Schema Changes</h2><span id="toolSchemaSummary" class="muted"></span>
        </div>
        <div class="section-body" id="toolSchemaVisibility"></div>
      </section>
      <div class="grid-two">
        <section id="riskSection">
          <div class="section-head"><h2>Tool Risk</h2><span id="riskSummary" class="muted"></span></div>
          <div class="section-body" id="toolRisk"></div>
        </section>
        <section id="findingsSection">
          <div class="section-head"><h2>Findings</h2><span id="findingSummary" class="muted"></span></div>
          <div class="section-body" id="findings"></div>
        </section>
      </div>
      <section id="evidenceSection">
        <div class="section-head"><h2>Evidence And Commands</h2><span id="evidenceSummary" class="muted"></span></div>
        <div class="section-body" id="evidence"></div>
      </section>
      <section id="doctorPanel" hidden>
        <div class="section-head"><h2>Share Doctor</h2><span id="doctorSummary" class="muted"></span></div>
        <div class="section-body" id="doctorChecks"></div>
      </section>
      <section id="amendPreviewPanel" hidden>
        <div class="section-head">
          <h2>Policy Amendment Preview</h2><span id="amendPreviewSummary" class="muted"></span>
        </div>
        <div class="section-body" id="amendPreview"></div>
      </section>
      <section id="leasePanel" hidden>
        <div class="section-head"><h2>New Lease Header</h2></div>
        <div class="section-body"><div id="leaseOutput" class="console-output"></div></div>
      </section>
      <section id="reportPanel" hidden>
        <div class="section-head"><h2>Session Report</h2></div>
        <div class="section-body"><div id="reportOutput" class="report-output"></div></div>
      </section>
    </main>
    <aside id="requestDrawer" class="drawer" hidden></aside>
  </div>
  <script src="/assets/prism.js"></script>
  <script>
    const state = {
      snapshot: null,
      timer: null,
      selectedRequestId: null,
      showAllReadiness: false,
      liveHealthStatus: null,
      liveHealthReadiness: null,
      liveHealthShare: null,
      lastInviteSetup: "",
      lastInviteId: "",
      showInactiveLeases: false,
      showRevokedInvites: false,
      activeShareTab: "readiness"
    };
    const scrollPreserveSelectors = [
      ".policy-source",
      "#reportOutput",
      "#doctorChecks",
      "#amendPreview",
      "#inviteSetupOutput",
      ".invite-setup-output",
      "#requestDrawer .drawer-body"
    ];
    const baseSectionIds = [
      "shareWorkflowSection",
      "policySection",
      "providerSection",
      "healthSection",
      "decisionsSection",
      "requestsSection",
      "leasesSection",
      "authSection",
      "schemaSection",
      "riskSection",
      "findingsSection",
      "evidenceSection"
    ];
    const transientPanelIds = [
      "doctorPanel",
      "amendPreviewPanel",
      "leasePanel",
      "reportPanel"
    ];
    const $ = (id) => document.getElementById(id);

    function text(value, fallback = "-") {
      if (value === null || value === undefined || value === "") return fallback;
      return String(value);
    }

    function esc(value) {
      return text(value, "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[char]));
    }

    function pill(value) {
      const raw = text(value, "unknown");
      const cls = raw.toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
      return `<span class="pill ${cls}">${esc(raw)}</span>`;
    }

    async function api(path, options = {}) {
      const { allowFalse = false, ...requestOptions } = options;
      const headers = {
        "content-type": "application/json",
        ...(requestOptions.headers || {})
      };
      if (path.startsWith("/api/")) {
        const secret = consoleSecret();
        if (!secret) throw new Error("console secret required");
        headers["x-snulbug-console-secret"] = secret;
      }
      const response = await fetch(path, {
        ...requestOptions,
        headers
      });
      const payload = await response.json();
      if (response.status === 403 && String(payload.error || "").includes("console secret")) {
        if (window.sessionStorage) window.sessionStorage.removeItem("snulbug-console-secret");
      }
      if (!response.ok || (!allowFalse && payload.ok === false)) throw new Error(payload.error || response.statusText);
      return payload;
    }

    async function loadSnapshot() {
      $("message").textContent = "Refreshing";
      try {
        const snapshot = await api("/api/snapshot");
        const scrollState = captureScrollState();
        if (state.liveHealthShare && state.liveHealthShare !== snapshot.share) {
          state.liveHealthStatus = null;
          state.liveHealthReadiness = null;
          state.liveHealthShare = null;
        }
        if (snapshot.initial_health_check) {
          state.liveHealthStatus = snapshot.status || null;
          state.liveHealthReadiness = snapshot.readiness_gate || null;
          state.liveHealthShare = snapshot.share || null;
        }
        state.snapshot = snapshot;
        render();
        restoreScrollState(scrollState);
        $("message").textContent = `Updated ${new Date().toLocaleTimeString()}`;
      } catch (error) {
        $("message").textContent = `Refresh failed: ${error.message}`;
      }
    }

    async function refreshAfterReadinessMutation() {
      const hadLiveHealth = Boolean(state.liveHealthStatus || state.liveHealthReadiness);
      await loadSnapshot();
      if (!hadLiveHealth) return;
      const scrollState = captureScrollState();
      try {
        await fetchLiveHealth();
        render();
        restoreScrollState(scrollState);
      } catch (error) {
        state.liveHealthStatus = null;
        state.liveHealthReadiness = null;
        state.liveHealthShare = null;
        render();
        restoreScrollState(scrollState);
        $("message").textContent = `Live health refresh failed: ${error.message}`;
      }
    }

    async function fetchLiveHealth() {
      const payload = await api("/api/health/check", {
        method: "POST",
        allowFalse: true,
        body: JSON.stringify({})
      });
      applyLiveHealthPayload(payload);
      return payload;
    }

    function applyLiveHealthPayload(payload) {
      state.liveHealthStatus = payload;
      state.liveHealthReadiness = payload.readiness_gate || null;
      state.liveHealthShare = ((state.snapshot || {}).share || payload.share || payload.directory || null);
      if (state.snapshot && (!state.liveHealthShare || state.snapshot.share === state.liveHealthShare)) {
        state.snapshot = {
          ...state.snapshot,
          share: payload.share || state.snapshot.share,
          generated_at: payload.generated_at || state.snapshot.generated_at,
          status: payload,
          readiness_gate: payload.readiness_gate || state.snapshot.readiness_gate
        };
      }
    }

    function captureScrollState() {
      return {
        windowX: window.scrollX,
        windowY: window.scrollY,
        details: Array.from(document.querySelectorAll("details[data-state-key]")).map((element) => ({
          key: element.dataset.stateKey,
          open: element.open
        })),
        elements: scrollPreserveSelectors.map((selector) => {
          const element = document.querySelector(selector);
          return element ? { selector, left: element.scrollLeft, top: element.scrollTop } : null;
        }).filter(Boolean)
      };
    }

    function restoreScrollState(scrollState) {
      if (!scrollState) return;
      const restore = () => {
        const detailsOpenByKey = new Map(
          (scrollState.details || []).map((item) => [item.key, item.open])
        );
        document.querySelectorAll("details[data-state-key]").forEach((element) => {
          const key = element.dataset.stateKey;
          if (!detailsOpenByKey.has(key)) return;
          element.open = Boolean(detailsOpenByKey.get(key));
        });
        (scrollState.elements || []).forEach((item) => {
          const element = document.querySelector(item.selector);
          if (!element) return;
          element.scrollLeft = item.left || 0;
          element.scrollTop = item.top || 0;
        });
        window.scrollTo(scrollState.windowX || 0, scrollState.windowY || 0);
      };
      if (window.requestAnimationFrame) {
        window.requestAnimationFrame(restore);
      } else {
        restore();
      }
    }

    function render() {
      const snapshot = state.snapshot || {};
      const status = snapshot.status || {};
      $("sharePath").textContent = text(snapshot.share || status.directory);
      const setupOnly = snapshot.mode === "setup";
      setSetupMode(setupOnly);
      if (setupOnly) {
        renderSetupWizard(snapshot.setup_wizard || {}, snapshot);
        return;
      }
      const readiness = activeReadinessGate(snapshot);
      const metricStatus = state.liveHealthStatus || status;
      renderMetrics(metricStatus, readiness);
      renderReadinessGate(readiness);
      renderPolicyVisibility(snapshot.policy_visibility || {});
      renderTunnelProvider(snapshot.tunnel_provider || {});
      renderDecisionTimeline(snapshot.decision_timeline || {});
      renderRequests(snapshot.capability_requests || {});
      renderRequestDrawer(snapshot.capability_requests || {});
      renderLeases(status.leases || {});
      renderInvites(status.invitations || {});
      renderShareTabs(readiness, status.invitations || {});
      renderAuthVisibility(snapshot.auth_visibility || {});
      renderToolSchemaVisibility(snapshot.tool_schema_visibility || {});
      renderHealth(state.liveHealthStatus || status);
      renderToolRisk(status);
      renderFindings(status);
      renderEvidence(status);
    }

    function activeReadinessGate(snapshot = state.snapshot || {}) {
      return state.liveHealthReadiness || snapshot.readiness_gate || {};
    }

    function currentInvitationsPayload() {
      return (((state.snapshot || {}).status || {}).invitations || {});
    }

    function activeInviteCount(invitationsPayload = currentInvitationsPayload()) {
      const summary = invitationsPayload.summary || {};
      const summaryActive = numeric(summary.active);
      if (summaryActive > 0) return summaryActive;
      return (invitationsPayload.items || []).filter((invite) => !invite.revoked_at).length;
    }

    function inviteTabUnlocked(readiness = activeReadinessGate(), invitationsPayload = currentInvitationsPayload()) {
      return (readiness || {}).decision === "ready" || activeInviteCount(invitationsPayload) > 0;
    }

    function setShareTab(tab) {
      const nextTab = tab === "invites" ? "invites" : "readiness";
      const invitationsPayload = currentInvitationsPayload();
      if (nextTab === "invites" && !inviteTabUnlocked(activeReadinessGate(), invitationsPayload)) {
        state.activeShareTab = "readiness";
        $("message").textContent = "Share readiness must be green before opening new invitations.";
        renderShareTabs(activeReadinessGate(), invitationsPayload);
        return false;
      }
      state.activeShareTab = nextTab;
      renderShareTabs(activeReadinessGate(), invitationsPayload);
      return true;
    }

    function renderShareTabs(readiness = activeReadinessGate(), invitationsPayload = {}) {
      const readinessTab = $("share-tab-readiness");
      const invitesTab = $("share-tab-invites");
      const readinessPanel = $("readinessSection");
      const invitesPanel = $("invitesSection");
      if (!readinessTab || !invitesTab || !readinessPanel || !invitesPanel) return;
      const invitesEnabled = inviteTabUnlocked(readiness, invitationsPayload);
      if (!invitesEnabled && state.activeShareTab === "invites") {
        state.activeShareTab = "readiness";
      }
      const activeTab = state.activeShareTab === "invites" ? "invites" : "readiness";
      const readinessReady = (readiness || {}).decision === "ready";
      const summary = readiness.summary || {};
      const invitationSummary = invitationsPayload.summary || {};
      const activeInvites = activeInviteCount(invitationsPayload);
      readinessTab.classList.toggle("active", activeTab === "readiness");
      invitesTab.classList.toggle("active", activeTab === "invites");
      readinessTab.setAttribute("aria-selected", activeTab === "readiness" ? "true" : "false");
      invitesTab.setAttribute("aria-selected", activeTab === "invites" ? "true" : "false");
      invitesTab.disabled = !invitesEnabled;
      readinessPanel.hidden = activeTab !== "readiness";
      invitesPanel.hidden = activeTab !== "invites";
      $("share-tab-readiness-detail").textContent =
        `${summary.failed || 0} failed · ${summary.warnings || 0} warnings`;
      $("share-tab-invites-detail").textContent = invitesEnabled
        ? `${activeInvites} active`
        : "locked";
      $("shareWorkflowSummary").textContent = readinessReady
        ? "Ready for task invites"
        : (activeInvites > 0 ? "Existing invites available" : "Review readiness before inviting");
    }

    function setSetupMode(enabled) {
      $("setupSection").hidden = !enabled;
      $("setupNavLink").hidden = !enabled;
      $("metrics").hidden = enabled;
      $("sessionActions").hidden = enabled;
      baseSectionIds.forEach((id) => {
        const element = $(id);
        if (element) element.hidden = enabled;
      });
      if (enabled) {
        transientPanelIds.forEach((id) => {
          const element = $(id);
          if (element) element.hidden = true;
        });
      }
    }

    function renderSetupWizard(payload, snapshot = {}) {
      const steps = payload.steps || [];
      const next = payload.next_step || {};
      $("wizardSummary").textContent =
        `${payload.completed || 0}/${payload.total || steps.length || 0} complete · ${payload.label || "Share setup"}`;
      if (!steps.length) {
        $("setupWizard").innerHTML = '<div class="empty">No setup data available.</div>';
        return;
      }
      const nextAction = (next.primary_action || {}).label || "Review setup";
      const overview = `<div class="wizard-overview">
        <div>
          <div class="timeline-target">${esc(next.label || payload.label || "Share setup")}</div>
          <div class="timeline-detail">${esc(next.message || payload.label || "")}</div>
        </div>
        <div>${wizardActionHtml(next.primary_action || {
          kind: "anchor",
          label: nextAction,
          target: "#shareWorkflowSection"
        })}</div>
      </div>`;
      const cards = `<div class="wizard-grid">${steps.map((step) => (
        `<div class="wizard-step ${esc(step.status || "unknown")}${step.active ? " active" : ""}">
          <div class="wizard-step-head">
            <span class="wizard-index">${esc(step.index || "")}</span>
            ${pill(step.status || "unknown")}
          </div>
          <div class="wizard-title">${esc(step.label || "-")}</div>
          <div class="timeline-detail">${esc(step.message || "")}</div>
          <div class="wizard-action">${wizardActionHtml(step.primary_action || {})}</div>
        </div>`
      )).join("")}</div>`;
      $("setupWizard").innerHTML =
        `<div class="stack">${setupFormHtml(snapshot)}${existingSharesHtml(snapshot.existing_shares || [])}` +
        `${overview}${cards}</div>`;
    }

    function setupFormHtml(snapshot) {
      const defaults = snapshot.setup_defaults || {};
      const providers = defaults.providers || [];
      const optionHtml = providers.map((provider) => (
        `<option value="${esc(provider.name)}" ${provider.name === defaults.provider ? "selected" : ""}>` +
        `${esc(provider.label || provider.name)}</option>`
      )).join("");
      return `<div class="setup-form stack">
        <div>
          <div class="timeline-target">Create a share session</div>
          <div class="timeline-detail">
            Generate the share directory, config, policy bundle, lease, and client metadata.
          </div>
        </div>
        <div class="field-grid">
          ${setupField("setup-directory", "Share directory", defaults.directory || ".snulbug/share")}
          <div class="form-field">
            <label for="setup-provider">Tunnel provider</label>
            <select id="setup-provider">${optionHtml}</select>
          </div>
          ${setupField("setup-upstream", "Upstream MCP URL", defaults.upstream || "http://127.0.0.1:9000", "wide")}
          ${setupField(
            "setup-public-url",
            "Public MCP URL",
            defaults.public_url || "http://127.0.0.1:8080/mcp",
            "wide"
          )}
          ${setupField("setup-allowed-tools", "Allowed tools", defaults.allowed_tools || "safe_read_file")}
          ${setupField("setup-allowed-paths", "Allowed paths", defaults.allowed_paths || ".")}
          ${setupField("setup-host", "Gateway host", defaults.host || "127.0.0.1")}
          ${setupField("setup-port", "Gateway port", defaults.port || 8080)}
        </div>
        <div class="check-row">
          ${setupCheckbox("setup-lease-required", "Require lease", defaults.lease_required !== false)}
          ${setupCheckbox("setup-validate", "Validate files", defaults.validate !== false)}
          ${setupCheckbox("setup-force", "Overwrite existing", false)}
          ${setupCheckbox("setup-start-gateway", "Start gateway now", defaults.start_gateway !== false)}
        </div>
        <div><button type="button" class="primary" onclick="createShareFromSetup()">Create share session</button></div>
      </div>`;
    }

    function setupField(id, label, value, extraClass = "", help = "") {
      return `<div class="form-field ${esc(extraClass)}">
        <label for="${esc(id)}">${esc(label)}</label>
        <input id="${esc(id)}" value="${esc(value)}">
        ${help ? `<div class="field-help">${esc(help)}</div>` : ""}
      </div>`;
    }

    function setupCheckbox(id, label, checked) {
      return `<label for="${esc(id)}">` +
        `<input id="${esc(id)}" type="checkbox" ${checked ? "checked" : ""}> ${esc(label)}` +
        `</label>`;
    }

    function existingSharesHtml(shares) {
      if (!shares.length) {
        return `<div class="empty">No existing share sessions found under this workspace.</div>`;
      }
      return `<div class="setup-share-list">
        ${shares.map((share) => (
          `<div class="setup-share-row">
            <div>
              <div class="timeline-target">${esc(share.label || share.relative || share.directory)}</div>
              <div class="timeline-detail">${esc(share.directory || "")}</div>
            </div>
            <div>
              ${pill(share.state || "created")}
              <div class="timeline-detail">${esc([share.provider, share.public_url].filter(Boolean).join(" · "))}</div>
            </div>
            <button
              type="button"
              data-directory="${esc(share.directory || "")}"
              onclick="selectExistingShare(this)"
            >Use share</button>
          </div>`
        )).join("")}
      </div>`;
    }

    function wizardActionHtml(action) {
      const label = action.label || "Review";
      if (action.kind === "create_share") {
        return `<button type="button" class="primary" onclick="createShareFromSetup()">${esc(label)}</button>`;
      }
      if (action.kind === "run_doctor") {
        return `<button type="button" class="primary" onclick="runDoctor()">${esc(label)}</button>`;
      }
      if (action.kind === "preview_amendment") {
        return `<button type="button" onclick="previewAmendment()">${esc(label)}</button>`;
      }
      if (action.kind === "download_report") {
        return `<button type="button" onclick="downloadReport()">${esc(label)}</button>`;
      }
      if (action.kind === "copy_command") {
        return `<button type="button" data-command="${esc(action.command || "")}" ` +
          `onclick="copyWizardCommand(this)">${esc(label)}</button>`;
      }
      if (action.kind === "anchor") {
        return `<a class="button-link" href="${esc(action.target || "#shareWorkflowSection")}">${esc(label)}</a>`;
      }
      return `<a class="button-link" href="#shareWorkflowSection">${esc(label)}</a>`;
    }

    function renderMetrics(status, readiness) {
      const traffic = status.traffic || {};
      const requests = status.capability_requests || {};
      const leases = status.leases || {};
      const invitations = status.invitations || {};
      const risk = (status.tool_risks || {}).summary || {};
      const gateway = status.gateway || {};
      const session = status.session || {};
      const readinessSummary = readiness.summary || {};
      const gatewayState = gatewayMetric(gateway);
      const activeLeases = numeric(leases.active_count);
      const activeInvites = numeric((invitations.summary || {}).active);
      const pendingRequests = numeric(requests.pending);
      const blocked = numeric(traffic.blocked);
      const allowed = numeric(traffic.allowed);
      const confirmed = numeric(traffic.confirmed);
      const highRisk = numeric(risk.high);
      const mediumRisk = numeric(risk.medium);
      const lowRisk = numeric(risk.low);
      const leaseRequired = session.lease_required === true;
      const metrics = [
        {
          label: "Readiness",
          value: readiness.label || readiness.decision || "unknown",
          detail: `${numeric(readinessSummary.passed)} passed, ${numeric(readinessSummary.failed)} failed, ` +
            `${numeric(readinessSummary.warnings)} warnings${readiness.reviewed ? " · reviewed" : ""}`,
          status: readinessMetricStatus(readiness),
          glyph: readinessMetricGlyph(readiness),
          href: "#shareWorkflowSection"
        },
        {
          label: "State",
          value: status.state || "unknown",
          detail: `${session.provider || "generic"} provider${session.preset ? ` · ${session.preset}` : ""}`,
          status: stateMetricStatus(status.state),
          glyph: stateMetricGlyph(status.state),
          href: "#shareWorkflowSection"
        },
        {
          label: "Gateway",
          value: gatewayState.value,
          detail: gatewayState.detail,
          status: gatewayState.status,
          glyph: gatewayState.glyph,
          href: "#healthSection"
        },
        {
          label: "Active leases",
          value: String(activeLeases),
          detail: leaseRequired ? "required for this share" : "optional for this share",
          status: leaseRequired && activeLeases === 0 ? "bad" : (activeLeases > 0 ? "good" : "warn"),
          glyph: activeLeases > 0 ? "OK" : "0",
          href: "#leasesSection"
        },
        {
          label: "Active invites",
          value: String(activeInvites),
          detail: activeInvites ? "task-scoped client setup ready" : "no share invites",
          status: activeInvites ? "good" : "neutral",
          glyph: activeInvites ? "OK" : "0",
          href: "#shareWorkflowSection"
        },
        {
          label: "Pending requests",
          value: String(pendingRequests),
          detail: pendingRequests ? "awaiting approve or deny" : "no queued capability asks",
          status: pendingRequests ? "warn" : "good",
          glyph: pendingRequests ? "!" : "OK",
          href: "#requestsSection"
        },
        {
          label: "Blocked",
          value: String(blocked),
          detail: `${allowed} allowed${confirmed ? ` · ${confirmed} confirmed` : ""}`,
          status: blocked ? "warn" : "good",
          glyph: blocked ? "!" : "OK",
          href: "#decisionsSection"
        },
        {
          label: "High risk tools",
          value: String(highRisk),
          detail: `${mediumRisk} medium, ${lowRisk} low risk`,
          status: highRisk ? "warn" : "good",
          glyph: highRisk ? "!" : "OK",
          href: "#riskSection"
        }
      ];
      $("metrics").innerHTML = metrics.map(metricCardHtml).join("");
    }

    function metricCardHtml(metric) {
      const href = esc(metric.href || "#shareWorkflowSection");
      return `<a class="metric ${esc(metric.status || "neutral")}" href="${href}">
        <div class="metric-head">
          <span class="metric-label">${esc(metric.label)}</span>
          <span class="metric-badge" aria-hidden="true">${esc(metric.glyph || "i")}</span>
        </div>
        <div class="metric-value">${esc(metric.value)}</div>
        <div class="metric-detail">${esc(metric.detail || "")}</div>
      </a>`;
    }

    function numeric(value) {
      const parsed = Number(value || 0);
      return Number.isFinite(parsed) ? parsed : 0;
    }

    function readinessMetricStatus(readiness) {
      const decision = readiness.decision || "";
      if (decision === "blocked") return "bad";
      if (decision === "review") return "warn";
      if (decision === "ready") return "good";
      return "neutral";
    }

    function readinessMetricGlyph(readiness) {
      const decision = readiness.decision || "";
      if (decision === "blocked") return "!";
      if (decision === "review") return "!";
      if (decision === "ready") return "OK";
      return "i";
    }

    function stateMetricStatus(value) {
      const stateValue = String(value || "");
      if (["running", "active", "verified"].includes(stateValue)) return "good";
      if (["closed", "failed", "error"].includes(stateValue)) return "bad";
      if (stateValue === "created") return "warn";
      return "neutral";
    }

    function stateMetricGlyph(value) {
      const status = stateMetricStatus(value);
      if (status === "good") return "OK";
      if (status === "bad") return "!";
      return "i";
    }

    function gatewayMetric(gateway) {
      const url = shortUrl(gateway.url || "");
      if (gateway.checked === true && gateway.reachable === true) {
        const status = gateway.status ? `HTTP ${gateway.status}` : "MCP probe passed";
        return { value: "reachable", detail: `${status}${url ? ` · ${url}` : ""}`, status: "good", glyph: "OK" };
      }
      if (gateway.checked === true) {
        return {
          value: "unreachable",
          detail: gateway.error || url || "probe failed",
          status: "bad",
          glyph: "!"
        };
      }
      return {
        value: "not checked",
        detail: url || "run doctor or health check",
        status: "warn",
        glyph: "i"
      };
    }

    function shortUrl(value) {
      if (!value) return "";
      try {
        const url = new URL(value);
        return `${url.host}${url.pathname === "/" ? "" : url.pathname}`;
      } catch (_) {
        return String(value);
      }
    }

    function renderReadinessGate(payload) {
      const summary = payload.summary || {};
      const checks = payload.checks || [];
      const recommendations = payload.recommendations || [];
      const attestation = payload.attestation || {};
      const attestationSession = attestation.session || {};
      const publicUrl = attestationSession.public_url;
      $("readinessSummary").textContent =
        `${payload.label || "Unknown"} · ${summary.passed || 0} passed, ` +
        `${summary.failed || 0} failed, ${summary.warnings || 0} warnings`;
      if (!checks.length) {
        $("shareReadiness").innerHTML = '<div class="empty">No readiness data available.</div>';
        return;
      }
      const overview = `<details class="compact-details" data-state-key="readiness-details">
        <summary>Readiness Details</summary>
        <div class="details-body detail-grid">
          ${detailRowHtml("Decision", pill(payload.decision || "unknown"))}
          ${detailRow("Generated", attestation.generated_at)}
          ${detailRowHtml("Public URL", externalLink(publicUrl, publicUrl))}
          ${detailRow("Auth", (attestation.auth || {}).mode)}
          ${detailRow("Active leases", (attestation.leases || {}).active_count)}
          ${detailRow("Active invites", (attestation.leases || {}).active_invite_count)}
          ${detailRow("Policy", (attestation.policy || {}).lifecycle_state || (attestation.policy || {}).path)}
          ${detailRow("Contract", contractText(attestation.contract || {}))}
          ${detailRow("Content digest", attestation.content_digest || attestation.digest)}
        </div>
      </details>`;
      const recommendationsHtml = recommendations.length ? `<div>
        <h2>Next Steps</h2>
        <ul class="recommendations">${recommendations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      </div>` : "";
      const attestationHtml = `<details class="compact-details" data-state-key="readiness-attestation">
        <summary>Readiness Attestation</summary>
        <div class="details-body stack">
          <button type="button" onclick="copyReadinessAttestation()">Copy Attestation</button>
          <div class="console-output">${esc(JSON.stringify(attestation, null, 2))}</div>
        </div>
      </details>`;
      const filterHtml = `<label class="auto">
        <input
          id="showAllReadiness"
          type="checkbox"
          ${state.showAllReadiness ? "checked" : ""}
          onchange="setShowAllReadiness(this.checked)"
        > Show all
      </label>`;
      $("shareReadiness").innerHTML =
        `<div class="stack">${readinessReviewQueue(payload, checks)}${filterHtml}${readinessChecksTable(checks)}` +
        `${overview}` +
        `${recommendationsHtml}${attestationHtml}</div>`;
    }

    function setShowAllReadiness(value) {
      state.showAllReadiness = Boolean(value);
      renderReadinessGate(activeReadinessGate());
    }

    function readinessChecksTable(checks) {
      const visibleChecks = state.showAllReadiness
        ? checks
        : checks.filter((check) => check.status === "warn" || check.status === "fail");
      const hiddenPasses = checks.length - visibleChecks.length;
      if (!visibleChecks.length) {
        const message = state.showAllReadiness
          ? "No readiness checks available."
          : `No warnings or failures. ${hiddenPasses} passing checks hidden.`;
        return `<div id="readinessChecksList" class="empty">${esc(message)}</div>`;
      }
      const hiddenHtml = !state.showAllReadiness && hiddenPasses
        ? `<div class="timeline-detail">${esc(`${hiddenPasses} passing checks hidden`)}</div>`
        : "";
      return `<div id="readinessChecksList"><table>
        <thead><tr><th>Status</th><th>Component</th><th>Check</th><th>Message</th></tr></thead>
        <tbody>${visibleChecks.map((check) => (
          `<tr>
            <td>${pill(check.status)}</td>
            <td>${esc(check.component || "-")}</td>
            <td>${esc(check.id || "-")}</td>
            <td>${esc(check.message || "-")}</td>
          </tr>`
        )).join("")}</tbody>
      </table>${hiddenHtml}</div>`;
    }

    function readinessReviewQueue(payload, checks) {
      const reviewChecks = checks.filter((check) => check.status === "warn" || check.status === "fail");
      const summary = payload.summary || {};
      if (!reviewChecks.length) {
        return `<div class="review-panel ready">
          <div class="review-head">
            <div>
              <div class="timeline-target">Ready to share</div>
              <div class="timeline-detail">${esc(summary.passed || 0)} checks passed.</div>
            </div>
            ${pill(payload.decision || "ready")}
          </div>
          <div class="review-actions">
            <button type="button" onclick="runDoctor()">Run doctor</button>
            <button type="button" onclick="downloadReport()">Download report</button>
          </div>
        </div>`;
      }
      const failures = reviewChecks.filter((check) => check.status === "fail").length;
      const warnings = reviewChecks.filter((check) => check.status === "warn").length;
      const title = failures
        ? `${failures} failing check${failures === 1 ? "" : "s"}`
        : payload.reviewed
          ? `${warnings} warning${warnings === 1 ? "" : "s"} reviewed`
          : `${warnings} warning${warnings === 1 ? "" : "s"} to review`;
      const detail = payload.reviewed
        ? "Warnings were acknowledged for the current readiness digest. New drift will require another review."
        : "Review these before sharing the public MCP URL. Passing checks are hidden by default.";
      const reviewAction = readinessReviewAction(payload, failures);
      return `<div class="review-panel ${esc(payload.decision || "review")}">
        <div class="review-head">
          <div>
            <div class="timeline-target">${esc(title)}</div>
            <div class="timeline-detail">${esc(detail)}</div>
          </div>
          ${pill(payload.decision || "review")}
        </div>
        <div class="review-actions">
          <a class="button-link" href="#readinessChecksList">Review checks</a>
          <button type="button" onclick="runDoctor()">Run doctor</button>
          ${reviewAction}
          <button type="button" onclick="downloadReport()">Download report</button>
        </div>
        <div class="review-list">
          ${reviewChecks.map((check) => readinessReviewItem(check)).join("")}
        </div>
      </div>`;
    }

    function readinessReviewAction(payload, failures) {
      if (failures > 0) return "";
      if (payload.reviewed) {
        const reviewedAt = (payload.review || {}).reviewed_at;
        return `<span class="timeline-detail">Reviewed${reviewedAt ? ` ${esc(reviewedAt)}` : ""}</span>`;
      }
      return `<button type="button" class="primary" onclick="markReadinessReviewed()">Mark readiness reviewed</button>`;
    }

    function readinessReviewItem(check) {
      const target = readinessReviewTarget(check);
      return `<div class="review-item">
        <div>
          <div class="timeline-target">${pill(check.status)} ${esc(check.id || "readiness check")}</div>
          <div class="timeline-detail">${esc(check.message || "-")}</div>
        </div>
        <a class="button-link" href="${esc(target.href)}">${esc(target.label)}</a>
      </div>`;
    }

    function readinessReviewTarget(check) {
      const id = String(check.id || "");
      const component = String(check.component || "");
      const value = `${component}.${id}`;
      if (value.includes("capability_requests")) return { href: "#requestsSection", label: "Review requests" };
      if (value.includes("lease")) return { href: "#leasesSection", label: "Review leases" };
      if (value.includes("auth")) return { href: "#authSection", label: "Review auth" };
      if (value.includes("schema") || value.includes("tool")) {
        return { href: "#schemaSection", label: "Inspect schemas" };
      }
      if (value.includes("policy") || value.includes("contract")) {
        return { href: "#policySection", label: "Review policy" };
      }
      if (value.includes("tunnel") || value.includes("provider")) {
        return { href: "#providerSection", label: "Review provider" };
      }
      if (value.includes("gateway") || value.includes("upstream") || value.includes("health")) {
        return { href: "#healthSection", label: "Review health" };
      }
      return { href: "#readinessChecksList", label: "Review check" };
    }

    function contractText(contract) {
      if (!contract || !Object.keys(contract).length) return "-";
      const parts = [];
      if (contract.required !== undefined) parts.push(`required ${contract.required}`);
      if (contract.signed !== undefined) parts.push(`signed ${contract.signed}`);
      if (contract.drifted !== undefined) parts.push(`drifted ${contract.drifted}`);
      if (contract.binding_digest) parts.push(shortHash(contract.binding_digest));
      return parts.join(", ") || "-";
    }

    function renderPolicyVisibility(payload) {
      const policy = payload.policy || {};
      const source = payload.source || {};
      const manifest = payload.bundle_manifest || {};
      const helpers = payload.helper_usage || [];
      const reasons = payload.reason_codes || {};
      const capabilities = source.capabilities || [];
      $("policySummary").textContent =
        `${policy.lifecycle_state || "unspecified"} · ${source.displayable ? "source visible" : "source unavailable"}`;
      if (!payload.ok) {
        $("policyVisibility").innerHTML = '<div class="empty">No active policy metadata found.</div>';
        return;
      }
      const metadata = `<div class="detail-grid">
        ${detailRow("Lifecycle", policy.lifecycle_state || "unspecified")}
        ${detailRow("Signed", policy.lifecycle_signed)}
        ${detailRow("Signature key", policy.lifecycle_signature_key_id)}
        ${detailRow("Active policy", policy.active_policy)}
        ${detailRow("Bundle", policy.bundle)}
        ${detailRow("Policy digest", source.sha256)}
        ${detailRow("Source", policySourceStatus(source))}
        ${detailRow("Invite capabilities", capabilities.length ? listText(capabilities.map((item) => item.id)) : "-")}
        ${detailRow("Bundle manifest", bundleManifestText(manifest))}
      </div>`;
      const bundleHtml = manifest.exists ? `<div>
        <h2>Bundle Manifest</h2>
        <div class="detail-grid">
          ${detailRow("ID", manifest.id)}
          ${detailRow("Name", manifest.name)}
          ${detailRow("Version", manifest.version)}
          ${detailRow("Entrypoint", manifest.entrypoint)}
          ${detailRow("Fixtures", manifest.fixture_count)}
          ${detailRow("Digest", manifest.sha256)}
        </div>
      </div>` : "";
      const helpersHtml = `<div>
        <h2>DSL Helper Usage</h2>
        ${helperUsageTable(helpers)}
      </div>`;
      const capabilitiesHtml = `<div>
        <h2>Invite Capabilities</h2>
        ${policyCapabilitiesTable(capabilities, source)}
      </div>`;
      const reasonHtml = `<div class="grid-two">
        <div>
          <h2>Observed Reason Codes</h2>
          ${counterTable(reasons.summary || [], "Reason code")}
        </div>
        ${policyRecentDecisionsDetails(reasons.recent || [])}
      </div>`;
      const sourceHtml = policySourceHtml(source);
      $("policyVisibility").innerHTML =
        `<div class="stack">${metadata}${policyLifecycleHtml(policy)}${bundleHtml}${helpersHtml}` +
        `${capabilitiesHtml}${reasonHtml}${sourceHtml}</div>`;
      if (window.Prism) window.Prism.highlightAllUnder($("policyVisibility"));
    }

    function policyCapabilitiesTable(capabilities, source) {
      if (!capabilities.length) {
        const reason = source.capabilities_ok === false
          ? `Capability declaration unavailable: ${source.capabilities_error || "policy did not compile"}`
          : "No invite capabilities declared by this policy.";
        return `<div class="empty">${esc(reason)}</div>`;
      }
      const rows = capabilities.map((item) => `<tr>
        <td>${esc(item.id)}</td>
        <td>${esc(item.label || item.id)}</td>
        <td>${esc(item.description || "-")}</td>
        <td>${item.default ? pill("default") : ""}</td>
      </tr>`).join("");
      return `<table><thead><tr><th>ID</th><th>Label</th><th>Description</th><th></th></tr></thead>` +
        `<tbody>${rows}</tbody></table>`;
    }

    function policyLifecycleHtml(policy) {
      const action = nextPolicyLifecycleAction(policy.lifecycle_state);
      const last = policy.last_lifecycle || {};
      const lastText = last.action
        ? `${last.action} ${last.from_state || "?"}->${last.to_state || last.state || "?"}`
        : "No lifecycle transition recorded.";
      const actionHtml = action
        ? `<button type="button" class="primary" onclick="${esc(action.onclick)}">${esc(action.label)}</button>`
        : pill("active");
      return `<div class="setup-form stack">
        <div>
          <div class="timeline-target">Policy Lifecycle Review</div>
          <div class="timeline-detail">
            Move the active policy bundle through observed, proposed, approved, and active states.
          </div>
        </div>
        <div class="field-grid">
          ${setupField("policy-lifecycle-key-id", "Signing key id", "local-review")}
          ${setupField("policy-lifecycle-secret-env", "Secret env var", "SNULBUG_BUNDLE_SECRET")}
          ${setupField("policy-lifecycle-actor", "Reviewer", "share-console")}
          ${setupField("policy-lifecycle-note", "Review note", "", "wide")}
        </div>
        <div class="review-actions">${actionHtml}</div>
        <div class="timeline-detail">${esc(lastText)}</div>
      </div>`;
    }

    function nextPolicyLifecycleAction(state) {
      const current = state || "observed";
      if (current === "observed") {
        return {
          label: "Mark reviewed",
          onclick: "promotePolicyLifecycle('proposed')"
        };
      }
      if (current === "proposed") {
        return {
          label: "Approve policy",
          onclick: "promotePolicyLifecycle('approved')"
        };
      }
      if (current === "approved") {
        return {
          label: "Activate policy",
          onclick: "activatePolicyLifecycle()"
        };
      }
      return null;
    }

    function policySourceStatus(source) {
      if (source.displayable) {
        const parts = [`${source.line_count || 0} lines`, `${source.size || 0} bytes`];
        if (source.truncated) parts.push("truncated");
        if (source.redacted) parts.push("redacted");
        return parts.join(", ");
      }
      return source.reason || "not displayable";
    }

    function bundleManifestText(manifest) {
      if (!manifest.exists) return "missing";
      if (manifest.displayable === false) return manifest.reason || "not displayable";
      const parts = [manifest.id, manifest.version, manifest.entrypoint].filter(Boolean);
      return parts.join(" · ") || "available";
    }

    function helperUsageTable(rows) {
      if (!rows.length) {
        return '<div class="empty">No first-class DSL helper calls detected in the displayed source.</div>';
      }
      return `<table>
        <thead><tr><th>Family</th><th>Pattern</th><th>Count</th></tr></thead>
        <tbody>${rows.map((row) => (
          `<tr><td>${esc(row.family)}</td><td><code>${esc(row.pattern)}</code></td><td>${esc(row.count)}</td></tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function policyReasonTable(rows) {
      if (!rows.length) return '<div class="empty">No policy decision evidence recorded yet.</div>';
      return `<table>
        <thead><tr><th>Decision</th><th>Target</th><th>Reason</th></tr></thead>
        <tbody>${rows.slice(0, 8).map((row) => (
          `<tr>
            <td>${pill(row.outcome || row.action || "unknown")}</td>
            <td>
              ${esc(row.tool || row.mcp_method || "-")}
              <div class="timeline-detail">${esc(shortTime(row.time))}</div>
            </td>
            <td>
              ${esc(row.reason_code || "-")}
              <div class="timeline-detail">${esc(row.source ? `${row.source}:${row.line || ""}` : "")}</div>
            </td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function policyRecentDecisionsDetails(rows) {
      const count = rows.length || 0;
      return `<details class="compact-details" data-state-key="policy-recent-decisions">
        <summary>Recent Decisions (${count})</summary>
        <div class="details-body">${policyReasonTable(rows)}</div>
      </details>`;
    }

    function policySourceHtml(source) {
      if (!source.displayable) {
        return `<details class="compact-details" data-state-key="policy-source">
          <summary>Lua Source</summary>
          <div class="details-body"><div class="empty">${esc(source.reason || "Source is not displayable.")}</div></div>
        </details>`;
      }
      const notice = source.redacted
        ? '<div class="timeline-detail">Secrets have been redacted before rendering.</div>'
        : "";
      const sourceLabel = `Lua Source (${source.line_count || 0} lines)`;
      return `<details class="compact-details" data-state-key="policy-source">
        <summary>${esc(sourceLabel)}</summary>
        <div class="details-body stack">
        ${notice}
        <pre class="policy-source language-lua"><code class="language-lua">${esc(source.source || "")}</code></pre>
        </div>
      </details>`;
    }

    function renderDecisionTimeline(payload) {
      const summary = payload.summary || {};
      const events = payload.events || [];
      const visibleEvents = payload.compacted_events || events;
      $("decisionSummary").textContent =
        `${visibleEvents.length || 0} grouped from ${summary.shown || 0}, ` +
        `${summary.allowed || 0} allowed, ${summary.blocked || 0} blocked, ` +
        `${summary.upstream_failed || 0} upstream failed`;
      if (!payload.exists) {
        $("decisionTimeline").innerHTML = `<div class="empty">No audit log found yet.</div>`;
        return;
      }
      if (!visibleEvents.length) {
        $("decisionTimeline").innerHTML = `<div class="empty">No decisions recorded yet.</div>`;
        return;
      }
      $("decisionTimeline").innerHTML = `<table>
        <thead><tr><th>Time</th><th>Outcome</th><th>Request</th><th>Subject</th><th>Status</th><th>Reason</th></tr></thead>
        <tbody>${visibleEvents.map((event) => (
          `<tr>
            <td>${esc(decisionTimeText(event))}</td>
            <td>
              ${pill(event.outcome)}
              <div class="timeline-detail">${esc(decisionCountText(event))}</div>
            </td>
            <td>
              <div class="timeline-target">${esc(decisionTarget(event))}</div>
              <div class="timeline-detail">${esc(decisionDetail(event))}</div>
            </td>
            <td>
              ${esc(event.auth_subject || "-")}
              <div class="timeline-detail">${esc(
                event.auth_tenant || event.auth_profile || event.auth_issuer || ""
              )}</div>
            </td>
            <td>${esc(event.status || "-")}</td>
            <td>
              ${esc(event.reason_code || "-")}
              <div class="timeline-detail">${esc(decisionReasonDetail(event))}</div>
            </td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function shortTime(value) {
      if (!value) return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleTimeString();
    }

    function shortDateTime(value) {
      if (!value) return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString();
    }

    function decisionTarget(event) {
      if (event.tool) return event.tool;
      if (event.mcp_method) return event.mcp_method;
      return event.path || "-";
    }

    function decisionDetail(event) {
      const parts = [event.mcp_method, event.http_method, event.path].filter(Boolean);
      return parts.join(" ");
    }

    function decisionTimeText(event) {
      if ((event.count || 1) <= 1) return shortTime(event.time || event.latest_time);
      const latest = shortTime(event.latest_time || event.time);
      const earliest = shortTime(event.earliest_time || event.time);
      return earliest === latest ? latest : `${earliest} - ${latest}`;
    }

    function decisionCountText(event) {
      const count = Number(event.count || 1);
      return count > 1 ? `${count} repeated` : "";
    }

    function decisionReasonDetail(event) {
      const parts = [event.upstream || event.source_ip || event.reason || ""];
      const count = Number(event.count || 1);
      if (count > 1 && event.source && event.earliest_line && event.latest_line) {
        parts.push(`${event.source}:${event.earliest_line}-${event.latest_line}`);
      }
      return parts.filter(Boolean).join(" · ");
    }

    function renderRequests(payload) {
      const summary = payload.summary || {};
      const requests = payload.requests || [];
      $("requestSummary").textContent =
        `${summary.pending || 0} pending, ${summary.approved || 0} approved, ${summary.denied || 0} denied`;
      if (!requests.length) {
        $("requests").innerHTML = '<div class="empty">No capability requests recorded.</div>';
        return;
      }
      const rows = requests.map((request) => {
        const id = esc(request.id);
        const suggested = request.suggested_lease || {};
        const auth = request.auth || {};
        const ttl = esc(suggested.ttl || "10m");
        const maxCalls = esc(suggested.max_calls || "2");
        const reviewer = "local-review";
        return `<tr class="request-row" onclick="selectRequest('${id}')">
          <td>${pill(request.status)}<br><span class="muted">${id}</span></td>
          <td>
            <strong>${esc(request.tool || request.method)}</strong><br>
            ${esc(request.task || request.reason_code)}
          </td>
          <td>${esc(auth.subject || "-")}<br><span class="muted">${esc(auth.tenant || auth.issuer || "")}</span></td>
          <td>
            <div class="request-actions">
              <input id="ttl-${id}" value="${ttl}" aria-label="TTL" onclick="event.stopPropagation()">
              <input id="calls-${id}" value="${maxCalls}" aria-label="Max calls" onclick="event.stopPropagation()">
              <input id="reviewer-${id}" value="${reviewer}" aria-label="Reviewer" onclick="event.stopPropagation()">
              <button
                class="request-open"
                type="button"
                onclick="event.stopPropagation(); selectRequest('${id}')"
              >Details</button>
              <button
                class="primary"
                type="button"
                onclick="event.stopPropagation(); approveRequest('${id}')"
              >Approve</button>
            </div>
          </td>
        </tr>`;
      }).join("");
      $("requests").innerHTML = `<table>
        <thead><tr><th>Status</th><th>Capability</th><th>Auth</th><th>Review</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderLeases(payload) {
      const leases = payload.leases || [];
      const active = leases.filter((lease) => lease.active === true);
      const inactive = leases.filter((lease) => lease.active !== true);
      const visibleLeases = state.showInactiveLeases ? leases : active;
      $("leaseSummary").textContent =
        `${active.length} active, ${inactive.length} inactive${state.showInactiveLeases ? "" : " hidden"}`;
      const createHtml = `<div class="setup-form stack">
        <div>
          <div class="timeline-target">Create task lease</div>
          <div class="timeline-detail">Grant temporary capability for a specific task.</div>
        </div>
        <div class="field-grid">
          ${setupField("lease-create-task", "Task", "Temporary MCP access")}
          ${setupField(
            "lease-create-tools",
            "Allowed tools",
            "safe_read_file",
            "",
            "MCP tool names this lease may call. Use commas for multiple tools."
          )}
          ${setupField(
            "lease-create-paths",
            "Allowed paths",
            ".",
            "",
            "Path-like tool arguments must stay under these files or directories. Use . for the current project."
          )}
          ${setupField("lease-create-ttl", "TTL", "30m")}
          ${setupField("lease-create-calls", "Max calls", "")}
          ${setupField(
            "lease-create-hosts",
            "Allowed hosts",
            "",
            "",
            "URL-like tool arguments may only target these hostnames. Leave blank when no network targets are expected."
          )}
          ${setupField(
            "lease-create-commands",
            "Allowed commands",
            "",
            "wide",
            "Command-like tool arguments may only name these executables or subcommands. Leave blank unless expected."
          )}
        </div>
        <div><button type="button" class="primary" onclick="createLease()">Create lease</button></div>
      </div>`;
      const controlsHtml = `<div class="review-actions">
        <label class="auto">
          <input
            id="show-inactive-leases"
            type="checkbox"
            onchange="setShowInactiveLeases(this.checked)"
            ${state.showInactiveLeases ? "checked" : ""}
          >
          Show inactive
        </label>
        ${inactive.length ? '<button type="button" onclick="cleanupInactiveLeases()">Clean up inactive</button>' : ""}
      </div>`;
      if (!visibleLeases.length) {
        const emptyText = inactive.length && !state.showInactiveLeases
          ? `${inactive.length} inactive leases hidden.`
          : "No task leases.";
        const emptyHtml = `<div class="empty">${esc(emptyText)}</div>`;
        $("leases").innerHTML = `<div class="stack">${createHtml}${controlsHtml}${emptyHtml}</div>`;
        return;
      }
      const cardsHtml = `<div class="lease-list">${visibleLeases.map(leaseCardHtml).join("")}</div>`;
      $("leases").innerHTML = `<div class="stack">${createHtml}${controlsHtml}${cardsHtml}</div>`;
    }

    function leaseCardHtml(lease) {
      const id = esc(lease.id);
      const status = lease.active ? "active" : "inactive";
      const tools = listText(lease.allow_tools);
      const paths = listText(lease.allow_paths);
      const capabilities = listText(lease.capabilities);
      const accessValue = capabilities || tools || "-";
      const accessDetail = capabilities ? "temporary capability labels" : (paths ? `paths ${paths}` : "");
      const lastUsed = lease.last_used_at ? `last used ${shortDateTime(lease.last_used_at)}` : "";
      return `<div class="lease-card ${esc(status)}">
        <div class="lease-card-head">
          <div>
            <div class="lease-title">${esc(lease.task || "Temporary MCP access")}</div>
            <div class="timeline-detail">${esc(lease.id || "")}</div>
          </div>
          ${pill(status)}
        </div>
        <div class="lease-meta">
          ${leaseMeta("Subject", leaseSubject(lease), leaseAuthDetail(lease))}
          ${leaseMeta(capabilities ? "Capabilities" : "Allowed tools", accessValue, accessDetail)}
          ${leaseMeta("Expiry", shortDateTime(lease.expires_at), lastUsed)}
          ${leaseMeta("Remaining", remainingCalls(lease), lease.last_tool || "")}
        </div>
        <div>${leaseActionHtml(lease, id)}</div>
      </div>`;
    }

    function leaseMeta(label, value, detail = "") {
      return `<div>
        <div class="detail-label">${esc(label)}</div>
        <div>${esc(value || "-")}</div>
        <div class="timeline-detail">${esc(detail || "")}</div>
      </div>`;
    }

    function leaseActionHtml(lease, id) {
      if (lease.active) {
        return `<button class="danger" type="button" onclick="revokeLease('${id}')">Revoke</button>`;
      }
      return `<div class="lease-actions">
        <input id="lease-reactivate-ttl-${id}" value="30m" aria-label="TTL">
        <input
          id="lease-reactivate-calls-${id}"
          value="${esc(lease.max_calls || "")}"
          aria-label="Max calls"
        >
        <button class="primary" type="button" onclick="reactivateLease('${id}')">Reactivate</button>
      </div>`;
    }

    function leaseSubject(lease) {
      if ((lease.allow_subjects || []).length) return (lease.allow_subjects || []).join(", ");
      if ((lease.allow_groups || []).length) return `group: ${(lease.allow_groups || []).join(", ")}`;
      if ((lease.allow_tenants || []).length) return `tenant: ${(lease.allow_tenants || []).join(", ")}`;
      if ((lease.allow_client_ids || []).length) return `client: ${(lease.allow_client_ids || []).join(", ")}`;
      if ((lease.allow_auth_profiles || []).length) return `profile: ${(lease.allow_auth_profiles || []).join(", ")}`;
      return lease.auth_bound ? "auth-bound" : "unbound";
    }

    function leaseAuthDetail(lease) {
      const parts = [];
      if ((lease.allow_tenants || []).length) parts.push(`tenant ${listText(lease.allow_tenants)}`);
      if ((lease.allow_issuers || []).length) parts.push(`issuer ${listText(lease.allow_issuers)}`);
      if ((lease.allow_groups || []).length) parts.push(`groups ${listText(lease.allow_groups)}`);
      return parts.join("; ");
    }

    function remainingCalls(lease) {
      if (lease.max_calls === null || lease.max_calls === undefined || lease.max_calls === "") return "unlimited";
      const maxCalls = Number(lease.max_calls);
      const used = Number(lease.use_count || 0);
      if (!Number.isFinite(maxCalls)) return "unlimited";
      return `${Math.max(0, maxCalls - used)} / ${maxCalls}`;
    }

    function renderInvites(payload) {
      const invitations = payload.items || [];
      const summary = payload.summary || {};
      const activeInvites = invitations.filter((invite) => !invite.revoked_at);
      const revokedInvites = invitations.filter((invite) => invite.revoked_at);
      const active = numeric(summary.active || activeInvites.length);
      const revoked = numeric(summary.revoked || revokedInvites.length);
      const visibleInvites = state.showRevokedInvites ? invitations : activeInvites;
      const handoff = inviteHandoffState();
      const capabilities = policyInviteCapabilities();
      const hasCapabilities = capabilities.length > 0;
      const inviteDisabled = handoff.ready !== true || !hasCapabilities;
      $("inviteSummary").textContent =
        `${active} active, ${revoked} revoked${state.showRevokedInvites ? "" : " hidden"}`;
      const createHtml = `<div class="setup-form stack">
        <div>
          <div class="timeline-target">Create task invite</div>
          <div class="timeline-detail">
            Mint a lease-backed client setup packet for one recipient. Active invite setup snippets stay available
            while the invite remains active.
          </div>
        </div>
        <div class="field-grid">
          ${setupField("invite-create-recipient", "Recipient", "local collaborator")}
          ${setupField("invite-create-client-name", "Client name", "snulbug-share")}
          ${setupField("invite-create-task", "Task", "Temporary MCP access", "wide")}
          ${inviteCapabilityOptionsHtml(capabilities)}
          ${setupField("invite-create-ttl", "TTL", "30m")}
          ${setupField("invite-create-calls", "Max calls", "")}
        </div>
        <div class="review-actions">
          <button type="button" class="primary" onclick="createInvite()" ${inviteDisabled ? "disabled" : ""}>
            Create invite
          </button>
          <span id="inviteCreateStatus" class="copy-status"></span>
        </div>
        <div class="field-help">${esc(inviteHandoffMessage(handoff))}</div>
        ${hasCapabilities ? "" : [
          '<div class="field-help">',
          "The active Lua policy must declare invite capabilities with capabilities.declare(...).",
          "</div>"
        ].join("")}
      </div>`;
      const controlsHtml = `<div class="review-actions">
        <label class="auto">
          <input
            id="show-revoked-invites"
            type="checkbox"
            onchange="setShowRevokedInvites(this.checked)"
            ${state.showRevokedInvites ? "checked" : ""}
          >
          Show revoked
        </label>
        ${revokedInviteCleanupButton(revokedInvites)}
      </div>`;
      const setupHtml = inviteSetupPanelHtml();
      if (!visibleInvites.length) {
        const emptyText = revokedInvites.length && !state.showRevokedInvites
          ? `${revokedInvites.length} revoked invites hidden.`
          : "No share invites yet.";
        const emptyHtml = `<div class="empty">${esc(emptyText)}</div>`;
        $("invitations").innerHTML = `<div class="stack">${createHtml}${controlsHtml}${setupHtml}${emptyHtml}</div>`;
        return;
      }
      const listHtml = `<div class="invite-list">${visibleInvites.map(inviteCardHtml).join("")}</div>`;
      $("invitations").innerHTML = `<div class="stack">${createHtml}${controlsHtml}${setupHtml}${listHtml}</div>`;
    }

    function policyInviteCapabilities() {
      const source = (((state.snapshot || {}).policy_visibility || {}).source || {});
      return (source.capabilities || []).filter((item) => item && item.id);
    }

    function inviteCapabilityOptionsHtml(capabilities) {
      if (!capabilities.length) {
        return `<div class="capability-options">
          <div class="detail-label">Capability labels</div>
          <div class="empty">No invite capabilities declared by the active policy.</div>
        </div>`;
      }
      const hasDefault = capabilities.some((item) => item.default === true);
      const options = capabilities.map((item, index) => {
        const checked = item.default === true || (!hasDefault && index === 0);
        return `<label class="capability-option">
          <input
            class="invite-capability-option"
            type="checkbox"
            value="${esc(item.id)}"
            ${checked ? "checked" : ""}
          >
          <span>
            <span class="capability-option-title">${esc(item.label || item.id)}</span>
            <span class="timeline-detail">${esc(item.description || item.id)}</span>
          </span>
        </label>`;
      }).join("");
      return `<div class="capability-options">
        <div class="detail-label">Capability labels</div>
        ${options}
        <div class="field-help">These labels are declared by the active Lua policy.</div>
      </div>`;
    }

    function selectedInviteCapabilities() {
      return Array.from(document.querySelectorAll(".invite-capability-option:checked"))
        .map((element) => element.value)
        .filter(Boolean);
    }

    function inviteHandoffState() {
      const readiness = activeReadinessGate();
      const handoff = readiness.handoff || {};
      if (handoff.ready === true || handoff.ready === false) return handoff;
      if (readiness.decision) {
        return {
          ready: readiness.decision !== "blocked",
          message: readiness.decision === "blocked"
            ? "fix blocking readiness checks before creating invites"
            : "share can create task-scoped invites",
          blocking_checks: []
        };
      }
      return {
        ready: false,
        message: "load share readiness before creating invites",
        blocking_checks: []
      };
    }

    function inviteHandoffMessage(handoff) {
      if (handoff.ready === true) return handoff.message || "Share is handoff-ready for task-scoped invites.";
      const blocking = handoff.blocking_checks || [];
      if (blocking.length) return `Resolve blocking checks before inviting: ${blocking.join(", ")}`;
      return handoff.message || "Share is not handoff-ready for invites.";
    }

    function revokedInviteCleanupButton(revokedInvites) {
      if (!revokedInvites.length) return "";
      return '<button type="button" onclick="cleanupRevokedInvites()">Clean up revoked</button>';
    }

    function inviteSetupPanelHtml() {
      if (!state.lastInviteSetup) return "";
      return `<div id="inviteSetupPanel" class="review-panel ready">
        <div class="review-head">
          <div>
            <div class="timeline-target">Invite Setup Snippets</div>
            <div class="timeline-detail">
              Use this invite now: copy the setup packet into the downstream MCP client, or run the curl smoke test.
              It contains bearer and lease tokens and is also available from the active invite card.
            </div>
          </div>
          <div class="review-actions">
            <button type="button" class="primary" onclick="copyInviteSetup()">Copy setup packet</button>
          </div>
        </div>
        <div class="detail-grid">
          ${detailRow("Invite", state.lastInviteId || "-")}
          ${detailRow("Next step", "Paste MCP client JSON into your client, or run the curl command.")}
        </div>
        <div id="inviteSetupOutput" class="console-output">${esc(state.lastInviteSetup)}</div>
      </div>`;
    }

    function inviteCardHtml(invite) {
      const id = esc(invite.id);
      const revoked = Boolean(invite.revoked_at);
      const status = revoked ? "revoked" : "active";
      const tools = listText(invite.allow_tools);
      const paths = listText(invite.allow_paths);
      const capabilities = listText(invite.capabilities);
      const capabilityDetail = capabilities ? "interpreted by Lua policy" : (paths ? `paths ${paths}` : "");
      const taskDetail = `client ${invite.client_name || "snulbug-share"}`;
      const expiryDetail = revoked ? `revoked ${shortDateTime(invite.revoked_at)}` : "";
      const hasSetup = !revoked && invite.setup_available === true && Boolean(invite.setup_snippets);
      const setupText = hasSetup
        ? formatInviteSetup({ invite, setup_snippets: invite.setup_snippets, headers: invite.headers || {} })
        : "";
      const guidance = revoked
        ? "This invite was revoked. Create a new invite to generate fresh setup snippets."
        : (hasSetup
          ? "Setup snippets are available while this invite remains active."
          : [
              "Setup snippets are unavailable for invites created before persistent setup packets;",
              "create a new invite if needed."
            ].join(" "));
      const revokeAction = revoked
        ? ""
        : `<button class="danger" type="button" onclick="revokeInvite('${id}')">Revoke invite</button>`;
      const setupHtml = hasSetup
        ? `<details class="compact-details" data-state-key="invite-setup-${id}">
            <summary>Setup snippets</summary>
            <div class="review-actions">
              <button
                type="button"
                class="primary"
                onclick="copyInviteSetupFromCard('${id}')"
              >Copy setup packet</button>
            </div>
            <div id="invite-setup-output-${id}" class="console-output invite-setup-output">${esc(setupText)}</div>
          </details>`
        : "";
      return `<div class="invite-card ${esc(status)}">
        <div class="invite-card-head">
          <div>
            <div class="invite-title">${esc(invite.recipient || "share recipient")}</div>
            <div class="timeline-detail">${esc(invite.id || "")}</div>
          </div>
          ${pill(status)}
        </div>
        <div class="lease-meta">
          ${leaseMeta("Task", invite.task || "Temporary MCP access", taskDetail)}
          ${leaseMeta("Capabilities", capabilities || tools || "-", capabilityDetail)}
          ${leaseMeta("Expiry", shortDateTime(invite.expires_at), expiryDetail)}
          ${leaseMeta("Backing lease", invite.lease_id || "-", invite.lease_header || "")}
        </div>
        <div class="timeline-detail">${esc(guidance)}</div>
        ${setupHtml}
        <div class="invite-actions">
          ${revokeAction}
        </div>
      </div>`;
    }

    function renderAuthVisibility(payload) {
      const summary = payload.summary || {};
      const current = payload.current || {};
      const scopeMatch = payload.scope_match || {};
      const jwks = payload.jwks || {};
      const denials = payload.denials || {};
      const config = payload.config || {};
      $("authSummary").textContent =
        `${summary.auth_events || 0} auth events, ${summary.denied || 0} denied`;
      if (!payload.exists && !payload.configured) {
        $("authVisibility").innerHTML = '<div class="empty">No auth config or audit metadata found yet.</div>';
        return;
      }
      const currentHtml = `<div class="detail-grid">
        ${detailRow("Subject", current.subject)}
        ${detailRow("Issuer", current.issuer || config.issuer)}
        ${detailRow("Scopes", listText(current.scopes || config.required_scopes))}
        ${detailRow("Tenant", current.tenant)}
        ${detailRow("Groups", listText(current.groups))}
        ${detailRow("Profile", current.profile_id)}
        ${detailRow("Scope match", scopeMatchText(scopeMatch))}
        ${detailRow("JWKS/cache", cacheText(jwks))}
      </div>`;
      const configHtml = config.mode ? `<div>
        <h2>Configured Resource</h2>
        <div class="detail-grid">
          ${detailRow("Mode", config.mode)}
          ${detailRow("Resource", config.resource)}
          ${detailRow("Audience", config.audience)}
          ${detailRow("Scope map", config.scope_map_count)}
          ${detailRow("Token validation", config.token_validation)}
          ${detailRow("JWKS", config.jwks_url || config.jwks_path)}
        </div>
      </div>` : "";
      const denialsHtml = `<div class="grid-two">
        <div>
          <h2>Denial Reasons</h2>
          ${counterTable(denials.reason_codes || [], "Reason")}
        </div>
        <div>
          <h2>Scope Denials</h2>
          ${counterTable(denials.scope_denials || [], "Target")}
        </div>
      </div>`;
      const actorsHtml = `<div class="grid-two">
        <div>
          <h2>Actors</h2>
          ${counterTable(payload.subjects || [], "Subject")}
        </div>
        <div>
          <h2>Scopes</h2>
          ${counterTable(payload.scopes || [], "Scope")}
        </div>
      </div>`;
      const events = payload.events || [];
      const eventsHtml = events.length ? `<div>
        <h2>Recent Auth Events</h2>
        <table>
          <thead><tr><th>Time</th><th>Decision</th><th>Subject</th><th>Scopes</th><th>Reason</th></tr></thead>
          <tbody>${events.map((event) => (
            `<tr>
              <td>${esc(shortTime(event.time))}</td>
              <td>${pill(event.allowed === false ? "denied" : "allowed")}</td>
              <td>
                ${esc(event.subject || "-")}
                <div class="timeline-detail">${esc(event.tenant || event.issuer || "")}</div>
              </td>
              <td>${esc(listText(event.scopes))}</td>
              <td>
                ${esc(event.reason_code || "-")}
                <div class="timeline-detail">${esc(scopeMatchText(event.scope_match || {}))}</div>
              </td>
            </tr>`
          )).join("")}</tbody>
        </table>
      </div>` : "";
      $("authVisibility").innerHTML =
        `<div class="stack">${currentHtml}${configHtml}${denialsHtml}${actorsHtml}${eventsHtml}</div>`;
    }

    function scopeMatchText(scopeMatch) {
      if (!scopeMatch || !Object.keys(scopeMatch).length) return "-";
      if (scopeMatch.matched_scope || scopeMatch.matched_selector) {
        return [scopeMatch.matched_scope, scopeMatch.matched_selector].filter(Boolean).join(" -> ");
      }
      if (scopeMatch.target_tool) return `${scopeMatch.reason_code || "scope"} ${scopeMatch.target_tool}`;
      return scopeMatch.reason_code || (scopeMatch.allowed === true ? "allowed" : "denied");
    }

    function cacheText(cache) {
      if (!cache || !Object.keys(cache).length) return "-";
      const parts = [
        `entries ${cache.entries || 0}`,
        `hits ${cache.hits || 0}`,
        `misses ${cache.misses || 0}`,
        `failures ${cache.failures || 0}`
      ];
      return parts.join(", ");
    }

    function counterTable(rows, label) {
      if (!rows.length) return '<div class="empty">No data.</div>';
      return `<table>
        <thead><tr><th>${esc(label)}</th><th>Count</th></tr></thead>
        <tbody>${rows.slice(0, 8).map((row) => (
          `<tr><td>${esc(row.value)}</td><td>${esc(row.count)}</td></tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function renderToolSchemaVisibility(payload) {
      const summary = payload.summary || {};
      const schemas = payload.schemas || {};
      const tools = payload.tools || [];
      const alerts = payload.drift_alerts || [];
      $("toolSchemaSummary").textContent =
        `${summary.tool_count || 0} tools, ${summary.drift_alerts || 0} drift alerts`;
      if (!payload.ok && !tools.length) {
        $("toolSchemaVisibility").innerHTML = '<div class="empty">No discovered tool schema data yet.</div>';
        return;
      }
      const schemaHtml = `<div>
        <h2>Schema Catalogs</h2>
        ${schemaCatalogTable(schemas.sources || [])}
      </div>`;
      const alertsHtml = `<div>
        <h2>Drift Alerts</h2>
        ${toolSchemaAlertTable(alerts)}
      </div>`;
      const toolsHtml = `<div>
        <h2>Discovered Tools</h2>
        ${toolSchemaTable(tools)}
      </div>`;
      $("toolSchemaVisibility").innerHTML = `<div class="stack">${schemaHtml}${alertsHtml}${toolsHtml}</div>`;
    }

    function schemaCatalogTable(sources) {
      if (!sources.length) return '<div class="empty">No schema catalogs loaded.</div>';
      return `<table>
        <thead><tr><th>Source</th><th>Tools</th><th>Hash</th><th>Status</th></tr></thead>
        <tbody>${sources.map((source) => (
          `<tr>
            <td>
              ${esc(source.label || source.source || "catalog")}
              <div class="timeline-detail">${esc(source.path || "")}</div>
            </td>
            <td>${esc(source.tool_count || 0)}</td>
            <td>${esc(shortHash(source.hash))}</td>
            <td>${source.error ? pill("fail") : pill(source.loaded ? "loaded" : "missing")}</td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function toolSchemaAlertTable(alerts) {
      if (!alerts.length) return '<div class="empty">No schema drift or tool pinning alerts.</div>';
      return `<table>
        <thead><tr><th>Severity</th><th>Tool</th><th>Kind</th><th>Hash</th><th>Message</th></tr></thead>
        <tbody>${alerts.map((alert) => (
          `<tr>
            <td>${pill(alert.severity || "info")}</td>
            <td>${esc(alert.tool || "-")}</td>
            <td>${esc(alert.kind || "-")}</td>
            <td>${esc(hashTransition(alert))}</td>
            <td>
              ${esc(alert.message || "-")}
              <div class="timeline-detail">${esc(alert.source ? `${alert.source}:${alert.line || ""}` : "")}</div>
            </td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function toolSchemaTable(tools) {
      if (!tools.length) return '<div class="empty">No discovered tools.</div>';
      return `<table>
        <thead><tr>
          <th>Tool</th><th>Risk</th><th>Pinned Schema Hashes</th>
          <th>Catalog Hashes</th><th>Drift</th><th>Observed</th>
        </tr></thead>
        <tbody>${tools.map((tool) => (
          `<tr>
            <td>
              <strong>${esc(tool.name || "-")}</strong>
              <div class="timeline-detail">${esc(listText(tool.categories))}</div>
            </td>
            <td>${pill(tool.risk || "unknown")}</td>
            <td>
              ${esc(hashList(tool.schema_hashes || tool.schema_hash))}
              <div class="timeline-detail">${esc(schemaShapeText(tool))}</div>
            </td>
            <td>${esc(hashList(tool.catalog_hashes))}</td>
            <td>
              ${esc(tool.schema_variants ? `${tool.schema_variants} variants` : "none")}
              <div class="timeline-detail">${esc(listText(tool.drift_signals))}</div>
            </td>
            <td>
              ${esc(tool.count || 0)}
              <div class="timeline-detail">${esc(listText(tool.evidence_sources))}</div>
            </td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function shortHash(value) {
      if (!value) return "-";
      const textValue = String(value);
      return textValue.length > 16 ? `${textValue.slice(0, 12)}...` : textValue;
    }

    function hashList(value) {
      const values = Array.isArray(value) ? value : (value ? [value] : []);
      return values.length ? values.map(shortHash).join(", ") : "-";
    }

    function hashTransition(alert) {
      if (alert.previous_hash || alert.current_hash) {
        return `${shortHash(alert.previous_hash)} -> ${shortHash(alert.current_hash)}`;
      }
      return shortHash(alert.current_hash || alert.previous_hash);
    }

    function schemaShapeText(tool) {
      const parts = [];
      if ((tool.required || []).length) parts.push(`required ${listText(tool.required)}`);
      if ((tool.properties || []).length) parts.push(`props ${listText(tool.properties)}`);
      if (tool.additional_properties !== undefined) parts.push(`additional ${tool.additional_properties}`);
      return parts.join("; ");
    }

    function selectRequest(id) {
      state.selectedRequestId = id;
      renderRequestDrawer((state.snapshot || {}).capability_requests || {});
    }

    function closeRequestDrawer() {
      state.selectedRequestId = null;
      $("requestDrawer").hidden = true;
      $("requestDrawer").innerHTML = "";
    }

    function renderRequestDrawer(payload) {
      const drawer = $("requestDrawer");
      const requests = payload.requests || [];
      if (!state.selectedRequestId) {
        drawer.hidden = true;
        drawer.innerHTML = "";
        return;
      }
      const request = requests.find((item) => item.id === state.selectedRequestId);
      if (!request) {
        closeRequestDrawer();
        return;
      }
      const suggested = request.suggested_lease || {};
      const auth = request.auth || {};
      const decision = request.decision || {};
      const sources = request.sources || [];
      const source = sources.length ? `${sources[0].path}:${sources[0].line}` : request.source;
      drawer.hidden = false;
      drawer.innerHTML = `
        <div class="drawer-head">
          <div class="drawer-title">
            <h2>${esc(request.tool || request.method || "Capability request")}</h2>
            <div class="muted">${pill(request.status)} ${esc(request.id)}</div>
          </div>
          <button type="button" onclick="closeRequestDrawer()">Close</button>
        </div>
        <div class="drawer-body">
          <div class="detail-grid">
            ${detailRow("Task", request.task || suggested.task)}
            ${detailRow("Method", request.method)}
            ${detailRow("Tool", request.tool)}
            ${detailRow("Argument keys", listText(request.argument_keys))}
            ${detailRow("Reason code", request.reason_code || decision.reason_code)}
            ${detailRow("Observations", request.observations)}
            ${detailRow("First seen", request.first_seen_at)}
            ${detailRow("Last seen", request.last_seen_at)}
            ${detailRow("Source", source)}
          </div>
          <div>
            <h2>Auth</h2>
            <div class="detail-grid">
              ${detailRow("Subject", auth.subject)}
              ${detailRow("Tenant", auth.tenant)}
              ${detailRow("Issuer", auth.issuer)}
              ${detailRow("Client", auth.client_id)}
              ${detailRow("Groups", listText(auth.groups))}
              ${detailRow("Profile", auth.profile_id)}
            </div>
          </div>
          <div>
            <h2>Suggested Lease</h2>
            <div class="detail-grid">
              ${detailRow("TTL", suggested.ttl)}
              ${detailRow("Max calls", suggested.max_calls)}
              ${detailRow("Tools", listText(suggested.allow_tools))}
              ${detailRow("Paths", listText(suggested.allow_paths))}
              ${detailRow("Hosts", listText(suggested.allow_hosts))}
              ${detailRow("Commands", listText(suggested.allow_commands))}
            </div>
          </div>
          <div>
            <h2>Review</h2>
            <div class="drawer-actions">
              <input class="wide" id="drawer-task-${esc(request.id)}" value="${esc(
                suggested.task || request.task || "Temporary MCP access"
              )}" aria-label="Task">
              <input id="drawer-ttl-${esc(request.id)}" value="${esc(suggested.ttl || "10m")}" aria-label="TTL">
              <input id="drawer-calls-${esc(request.id)}" value="${esc(
                suggested.max_calls || "2"
              )}" aria-label="Max calls">
              <input class="wide" id="drawer-tools-${esc(request.id)}" value="${esc(
                listTextOr(suggested.allow_tools, request.tool)
              )}" aria-label="Allowed tools">
              <input class="wide" id="drawer-paths-${esc(request.id)}" value="${esc(
                listText(suggested.allow_paths)
              )}" aria-label="Allowed paths">
              <input class="wide" id="drawer-hosts-${esc(request.id)}" value="${esc(
                listText(suggested.allow_hosts)
              )}" aria-label="Allowed hosts">
              <input class="wide" id="drawer-commands-${esc(request.id)}" value="${esc(
                listText(suggested.allow_commands)
              )}" aria-label="Allowed commands">
              <input id="drawer-reviewer-${esc(request.id)}" value="local-review" aria-label="Reviewer">
              <label class="auto"><input id="drawer-bind-${esc(request.id)}" type="checkbox" checked> Bind auth</label>
              <input
                class="wide"
                id="drawer-deny-${esc(request.id)}"
                value=""
                aria-label="Deny reason"
                placeholder="Deny reason"
              >
              <button
                class="primary"
                type="button"
                onclick="approveRequest('${esc(request.id)}', 'drawer')"
              >Approve</button>
              <button
                class="danger"
                type="button"
                onclick="denyRequest('${esc(request.id)}', 'drawer')"
              >Deny</button>
            </div>
          </div>
        </div>`;
    }

    function detailRow(label, value) {
      return detailRowHtml(label, esc(value));
    }

    function detailRowHtml(label, valueHtml) {
      return `<div class="detail-label">${esc(label)}</div><div>${valueHtml || "-"}</div>`;
    }

    function listText(value) {
      if (Array.isArray(value)) return value.filter(Boolean).join(", ");
      if (value && typeof value === "object") {
        return Object.keys(value).filter((key) => value[key]).join(", ");
      }
      return text(value, "");
    }

    function listTextOr(value, fallback) {
      return listText(value) || text(fallback, "");
    }

    function renderTunnelProvider(payload) {
      const provider = payload.provider || "generic";
      const auth = payload.auth || {};
      const doctor = payload.doctor || {};
      const localConsole = payload.local_console || {};
      const commands = payload.commands || [];
      const doctorLabel = doctor.checked
        ? (doctor.ok === true ? "doctor passed" : "doctor needs review")
        : "not checked";
      const localOrigin = payload.local_url || payload.gateway_url;
      const leaseRequired = auth.lease_required === true ? "yes" : (auth.lease_required === false ? "no" : "-");
      $("providerSummary").textContent = `${payload.label || provider} · ${doctorLabel}`;
      const overview = `<div class="detail-grid">
        ${detailRow("Provider", payload.label || provider)}
        ${detailRowHtml("Public URL", externalLink(payload.public_url, payload.public_url))}
        ${detailRowHtml("Client URL", externalLink(payload.client_url, payload.client_url))}
        ${detailRowHtml("Local Origin", externalLink(localOrigin, localOrigin))}
        ${detailRowHtml("Auth Mode", providerAuthControls(auth))}
        ${detailRow("Lease Required", leaseRequired)}
        ${detailRowHtml("Local Console", providerConsoleHtml(localConsole))}
        ${detailRow("Config", (payload.config || {}).path)}
      </div>`;
      const doctorHtml = providerDoctorHtml(doctor);
      const commandsHtml = providerCommandsTable(commands);
      $("tunnelProvider").innerHTML = `<div class="stack">${overview}${doctorHtml}${commandsHtml}</div>`;
    }

    function providerAuthControls(auth) {
      const controls = [esc(providerAuthText(auth))];
      if ((auth.mode || "") === "bearer") {
        controls.push(
          '<button id="copyBearerTokenButton" type="button" onclick="copyBearerToken()">Copy bearer token</button>' +
          '<span id="bearerCopyStatus" class="copy-status" role="status" aria-live="polite"></span>'
        );
      }
      return `<div class="review-actions">${controls.join("")}</div>`;
    }

    function providerAuthText(auth) {
      const parts = [auth.mode || "none"];
      if (auth.cloudflare_access) parts.push(`cloudflare access ${auth.cloudflare_access}`);
      if (auth.cloudflare_access_profile) parts.push(`cf profile ${auth.cloudflare_access_profile}`);
      if (auth.tailscale_profile) parts.push(`tailscale ${auth.tailscale_profile}`);
      const headers = auth.client_header_names || [];
      if (headers.length) parts.push(`headers ${headers.join(", ")}`);
      return parts.join(" · ");
    }

    function providerConsoleHtml(localConsole) {
      if (!localConsole || localConsole.configured === false || !localConsole.url) {
        return esc((localConsole && localConsole.description) || "No local console configured.");
      }
      const status = localConsole.checked ? healthLabel(localConsole.reachable) : "not checked";
      const detail = localConsole.error || localConsole.description || localConsole.label || "";
      return `${externalLink(localConsole.url, localConsole.label || localConsole.url)} ${pill(status)}
        <div class="timeline-detail">${esc(detail)}</div>`;
    }

    function providerDoctorHtml(doctor) {
      const summary = doctor.summary || {};
      const recommendations = doctor.recommendations || [];
      const doctorRows = [
        ["Checked", doctor.checked ? "yes" : "no"],
        ["Result", doctor.checked ? (doctor.ok === true ? "pass" : "fail") : "not checked"],
        ["Last Checked", doctor.last_checked_at],
        ["Passed", summary.passed],
        ["Failed", summary.failed],
        ["Warnings", summary.warnings],
        ["Skipped", summary.skipped]
      ];
      const table = `<table>
        <thead><tr><th>Doctor Field</th><th>Value</th></tr></thead>
        <tbody>${doctorRows.map(([label, value]) => (
          `<tr><td>${esc(label)}</td><td>${esc(value)}</td></tr>`
        )).join("")}</tbody>
      </table>`;
      const recs = recommendations.length ? `<div>
        <h2>Provider Recommendations</h2>
        <ul class="recommendations">${recommendations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      </div>` : "";
      return `<div><h2>Last Doctor Result</h2>${table}${recs}</div>`;
    }

    function providerCommandsTable(commands) {
      if (!commands.length) return '<div class="empty">No generated provider commands.</div>';
      return `<details class="compact-details" data-state-key="provider-generated-commands">
        <summary>Generated Commands (${commands.length})</summary>
        <div class="details-body"><table>
        <thead><tr><th>Step</th><th>Command</th></tr></thead>
        <tbody>${commands.map((item) => (
          `<tr>
            <td>
              <strong>${esc(item.label || item.kind)}</strong>
              <div class="timeline-detail">${esc(item.kind || "")}</div>
            </td>
            <td><code class="command-code">${esc(item.command)}</code></td>
          </tr>`
        )).join("")}</tbody>
      </table></div></details>`;
    }

    function renderHealth(status) {
      const publicGateway = status.public_gateway || {};
      const gateway = status.gateway || {};
      const upstreams = status.upstreams || [];
      const publicRows = publicGateway.configured ? [{
        kind: "tunnel",
        label: "public tunnel",
        detail: `${publicGateway.provider || "tunnel"} URL exposed to MCP clients`,
        url: publicGateway.url,
        checked: publicGateway.checked,
        reachable: publicGateway.reachable,
        status: publicGateway.status || publicGateway.error || publicGateway.health
      }] : [];
      const rows = publicRows.concat([
        {
          kind: "gateway",
          label: "snulbug gateway",
          detail: "Policy gateway receiving MCP client traffic",
          url: gateway.url,
          checked: gateway.checked,
          reachable: gateway.reachable,
          status: gateway.status || gateway.error || gateway.health
        }
      ]).concat(upstreams.map((item) => ({
        kind: "upstream",
        label: item.name || "upstream",
        detail: "Upstream MCP server behind snulbug",
        url: item.url,
        checked: item.checked,
        reachable: item.reachable,
        status: item.status || item.error || item.health
      })));
      const checked = rows.filter((row) => row.checked).length;
      const reachable = rows.filter((row) => row.reachable === true).length;
      $("healthSummary").textContent = checked
        ? `${reachable}/${checked} checked targets reachable`
        : "reachability not checked";
      const staticNote =
        "Static config is shown. Reachability is checked manually " +
        "to avoid polling the gateway/upstreams every refresh.";
      const note = checked
        ? "Live reachability results from the last health check."
        : staticNote;
      $("health").innerHTML = `<div class="stack">
        <div class="review-actions">
          <button type="button" onclick="runHealthCheck()">Run health check</button>
          <span class="timeline-detail">${esc(note)}</span>
        </div>
        <table>
          <thead><tr><th>Role</th><th>URL</th><th>Reachable</th><th>Status</th></tr></thead>
          <tbody>${rows.map((row) => (
          `<tr>
            <td>
              <div class="health-target">
                <span class="target-kind ${esc(row.kind)}">${esc(row.kind)}</span>
                <strong>${esc(row.label)}</strong>
                <span class="timeline-detail">${esc(row.detail)}</span>
              </div>
            </td>
            <td>${externalLink(row.url, row.url)}</td>
            <td>${pill(healthLabel(row.reachable))}</td>
            <td>
              ${esc(row.checked ? row.status : "not checked")}
              <div class="timeline-detail">${esc(row.checked ? "" : "Click Run health check to probe.")}</div>
            </td>
          </tr>`
        )).join("")}</tbody>
        </table>
      </div>`;
    }

    function healthLabel(value) {
      if (value === true) return "reachable";
      if (value === false) return "unreachable";
      return "not checked";
    }

    function externalLink(url, label) {
      if (!url) return "-";
      return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label || url)}</a>`;
    }

    function renderToolRisk(status) {
      const risks = status.tool_risks || {};
      const summary = risks.summary || {};
      const tools = risks.tools || [];
      $("riskSummary").textContent = `${summary.high || 0} high, ${summary.medium || 0} medium`;
      if (!tools.length) {
        $("toolRisk").innerHTML = '<div class="empty">No tool risk data yet.</div>';
        return;
      }
      $("toolRisk").innerHTML = `<table>
        <thead><tr><th>Tool</th><th>Level</th><th>Count</th><th>Signals</th></tr></thead>
        <tbody>${tools.slice(0, 8).map((tool) => (
          `<tr>
            <td>${esc(tool.name)}</td>
            <td>${pill(tool.level)}</td>
            <td>${esc(tool.count || 0)}</td>
            <td>${esc((tool.categories || []).join(", "))}</td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function renderFindings(status) {
      const findings = status.findings || [];
      $("findingSummary").textContent = `${findings.length} findings`;
      if (!findings.length) {
        $("findings").innerHTML = '<div class="empty">No findings.</div>';
        return;
      }
      $("findings").innerHTML = `<table>
        <thead><tr><th>Severity</th><th>Type</th><th>Message</th></tr></thead>
        <tbody>${findings.map((finding) => (
          `<tr>
            <td>${pill(finding.severity || "info")}</td>
            <td>${esc(finding.type)}</td>
            <td>${esc(finding.message || finding.count)}</td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
    }

    function renderEvidence(status) {
      const recordings = status.recordings || {};
      const commands = status.commands || {};
      const rows = [
        ["Audit log", (recordings.audit_log || {}).path],
        ["Replay log", (recordings.record_log || {}).path],
        ["Share report", (recordings.share_report || {}).path],
        ["Run", commands.run],
        ["Doctor", commands.share_doctor || commands.doctor],
        ["Close", commands.close]
      ];
      $("evidenceSummary").textContent = text((status.traffic || {}).event_count, 0) + " events";
      $("evidence").innerHTML = `<table>
        <thead><tr><th>Item</th><th>Value</th></tr></thead>
        <tbody>${rows.map(([label, value]) => (
          `<tr><td>${esc(label)}</td><td>${esc(value)}</td></tr>`
        )).join("")}</tbody>
      </table>`;
    }

    async function approveRequest(id, source = "") {
      try {
        const payload = await api(`/api/requests/${encodeURIComponent(id)}/approve`, {
          method: "POST",
          body: JSON.stringify({
            task: requestField(id, "task", source, ""),
            ttl: requestField(id, "ttl", source, "10m"),
            max_calls: requestField(id, "calls", source, "2"),
            allow_tools: requestField(id, "tools", source, ""),
            allow_paths: requestField(id, "paths", source, ""),
            allow_hosts: requestField(id, "hosts", source, ""),
            allow_commands: requestField(id, "commands", source, ""),
            reviewer: requestField(id, "reviewer", source, "local-review"),
            bind_auth: requestChecked(id, "bind", source, true)
          })
        });
        $("leaseOutput").textContent = payload.retry_header || JSON.stringify(payload.headers, null, 2);
        $("leasePanel").hidden = false;
        state.selectedRequestId = id;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Approve failed: ${error.message}`;
      }
    }

    async function denyRequest(id, source = "") {
      const reason = source ? requestField(id, "deny", source, "") : window.prompt("Reason");
      if (reason === null) return;
      try {
        await api(`/api/requests/${encodeURIComponent(id)}/deny`, {
          method: "POST",
          body: JSON.stringify({ reason, reviewer: requestField(id, "reviewer", source, "local-review") })
        });
        state.selectedRequestId = id;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Deny failed: ${error.message}`;
      }
    }

    async function createLease() {
      $("message").textContent = "Creating lease";
      try {
        const payload = await api("/api/leases/create", {
          method: "POST",
          body: JSON.stringify({
            task: setupInputValue("lease-create-task"),
            allow_tools: setupInputValue("lease-create-tools"),
            allow_paths: setupInputValue("lease-create-paths"),
            allow_hosts: setupInputValue("lease-create-hosts"),
            allow_commands: setupInputValue("lease-create-commands"),
            ttl: setupInputValue("lease-create-ttl") || "30m",
            max_calls: setupInputValue("lease-create-calls")
          })
        });
        $("leaseOutput").textContent = payload.retry_header || JSON.stringify(payload.headers || {}, null, 2);
        $("leasePanel").hidden = false;
        $("message").textContent = `Created lease ${(payload.lease || {}).id || ""}`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Create lease failed: ${error.message}`;
      }
    }

    async function reactivateLease(id) {
      $("message").textContent = `Reactivating lease ${id}`;
      try {
        const payload = await api(`/api/leases/${encodeURIComponent(id)}/reactivate`, {
          method: "POST",
          body: JSON.stringify({
            ttl: setupInputValue(`lease-reactivate-ttl-${id}`) || "30m",
            max_calls: setupInputValue(`lease-reactivate-calls-${id}`)
          })
        });
        $("leaseOutput").textContent = payload.retry_header || JSON.stringify(payload.headers || {}, null, 2);
        $("leasePanel").hidden = false;
        $("message").textContent = `Reactivated lease ${id}`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Reactivate failed: ${error.message}`;
      }
    }

    async function revokeLease(id) {
      if (!window.confirm(`Revoke lease ${id}?`)) return;
      try {
        await api(`/api/leases/${encodeURIComponent(id)}/revoke`, { method: "POST" });
        $("message").textContent = `Revoked lease ${id}`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Revoke failed: ${error.message}`;
      }
    }

    function setShowInactiveLeases(value) {
      state.showInactiveLeases = Boolean(value);
      renderLeases(((state.snapshot || {}).status || {}).leases || {});
    }

    async function cleanupInactiveLeases() {
      if (!window.confirm("Remove inactive lease records from this share?")) return;
      try {
        const payload = await api("/api/leases/cleanup-inactive", {
          method: "POST",
          body: JSON.stringify({})
        });
        $("message").textContent = `Removed ${payload.removed_count || 0} inactive leases`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Lease cleanup failed: ${error.message}`;
      }
    }

    function setInviteFeedback(message, kind = "") {
      const status = $("inviteCreateStatus");
      if (status) {
        status.textContent = message || "";
        status.className = `copy-status ${kind}`.trim();
      }
    }

    async function createInvite() {
      const handoff = inviteHandoffState();
      if (handoff.ready !== true) {
        const message = inviteHandoffMessage(handoff);
        setInviteFeedback("Not handoff-ready", "fail");
        $("message").textContent = message;
        return;
      }
      const capabilities = selectedInviteCapabilities();
      if (!capabilities.length) {
        setInviteFeedback("Choose a capability", "fail");
        $("message").textContent = "Choose at least one policy-declared invite capability.";
        return;
      }
      setInviteFeedback("Creating...", "pending");
      $("message").textContent = "Creating invite";
      try {
        const payload = await api("/api/invites/create", {
          method: "POST",
          body: JSON.stringify({
            recipient: setupInputValue("invite-create-recipient"),
            client_name: setupInputValue("invite-create-client-name"),
            task: setupInputValue("invite-create-task"),
            capabilities,
            ttl: setupInputValue("invite-create-ttl") || "30m",
            max_calls: setupInputValue("invite-create-calls"),
            live_checks: Boolean(state.liveHealthReadiness)
          })
        });
        state.lastInviteSetup = formatInviteSetup(payload);
        state.lastInviteId = (payload.invite || {}).id || "";
        setInviteFeedback("Created", "ok");
        $("message").textContent = `Created invite ${(payload.invite || {}).id || ""}`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        setInviteFeedback("Create failed", "fail");
        $("message").textContent = `Create invite failed: ${error.message}`;
      }
    }

    async function revokeInvite(id) {
      if (!window.confirm(`Revoke invite ${id}? This also revokes its backing lease.`)) return;
      try {
        await api(`/api/invites/${encodeURIComponent(id)}/revoke`, {
          method: "POST",
          body: JSON.stringify({ revoke_lease: true })
        });
        $("message").textContent = `Revoked invite ${id}`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Revoke invite failed: ${error.message}`;
      }
    }

    function setShowRevokedInvites(value) {
      state.showRevokedInvites = Boolean(value);
      renderInvites(((state.snapshot || {}).status || {}).invitations || {});
    }

    async function cleanupRevokedInvites() {
      if (!window.confirm("Remove revoked invite records from this share?")) return;
      try {
        const payload = await api("/api/invites/cleanup-revoked", {
          method: "POST",
          body: JSON.stringify({})
        });
        $("message").textContent = `Removed ${payload.removed_count || 0} revoked invites`;
        await refreshAfterReadinessMutation();
      } catch (error) {
        $("message").textContent = `Invite cleanup failed: ${error.message}`;
      }
    }

    function formatInviteSetup(payload) {
      const invite = payload.invite || {};
      const snippets = payload.setup_snippets || {};
      const codex = snippets.codex || {};
      const lines = [
        `Invite: ${invite.id || ""}`,
        `Recipient: ${invite.recipient || ""}`,
        `Task: ${invite.task || ""}`,
        `Client URL: ${snippets.client_url || invite.client_url || ""}`,
        "",
        "Environment:",
        envSnippet(snippets.env || {}),
        "",
        "curl smoke test:",
        (snippets.curl || {}).command || "",
        "",
        "Claude Code:",
        (snippets.claude_code || {}).command || "",
        "",
        "Codex config.toml:",
        (codex.config_toml || ""),
        "",
        "Codex environment:",
        envSnippet(codex.env || {}),
        "",
        "MCP client JSON:",
        JSON.stringify(snippets.mcp_client_json || {}, null, 2),
        "",
        "Headers:",
        JSON.stringify(snippets.headers || payload.headers || {}, null, 2)
      ];
      return lines.join("\\n");
    }

    function envSnippet(env) {
      const keys = Object.keys(env);
      if (!keys.length) return "-";
      return keys.map((key) => `${key}=${shellQuote(env[key])}`).join("\\n");
    }

    function shellQuote(value) {
      const raw = text(value, "");
      if (/^[A-Za-z0-9_./:@-]+$/.test(raw)) return raw;
      return "'" + raw.replace(/'/g, "'\\\\''") + "'";
    }

    async function copyInviteSetup() {
      const textValue = state.lastInviteSetup || ($("inviteSetupOutput") || {}).textContent || "";
      if (!textValue) {
        $("message").textContent = "No invite setup snippets to copy";
        return;
      }
      try {
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(textValue);
        $("message").textContent = "Copied invite setup snippets";
      } catch (error) {
        $("message").textContent = `Copy failed: ${error.message}`;
      }
    }

    async function copyInviteSetupFromCard(id) {
      const output = $(`invite-setup-output-${id}`);
      const textValue = output ? output.textContent : "";
      if (!textValue) {
        $("message").textContent = "No invite setup snippets to copy";
        return;
      }
      try {
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(textValue);
        $("message").textContent = `Copied invite setup snippets for ${id}`;
      } catch (error) {
        $("message").textContent = `Copy failed: ${error.message}`;
      }
    }

    function requestField(id, name, source, fallback) {
      const prefix = source ? `${source}-` : "";
      const element = $(`${prefix}${name}-${id}`);
      if (!element) return fallback;
      return element.value;
    }

    function requestChecked(id, name, source, fallback) {
      const prefix = source ? `${source}-` : "";
      const element = $(`${prefix}${name}-${id}`);
      if (!element) return fallback;
      return Boolean(element.checked);
    }

    async function downloadReport() {
      $("reportButton").disabled = true;
      $("message").textContent = "Generating session report";
      try {
        const secret = consoleSecret();
        if (!secret) throw new Error("console secret required");
        const response = await fetch("/api/report/download", {
          headers: {
            "accept": "text/markdown",
            "x-snulbug-console-secret": secret
          }
        });
        const report = await response.text();
        if (response.status === 403 && report.includes("console secret")) {
          if (window.sessionStorage) window.sessionStorage.removeItem("snulbug-console-secret");
        }
        if (!response.ok) throw new Error(report || response.statusText);
        const filename = reportFilename(response.headers.get("content-disposition"));
        saveTextAsFile(report, filename);
        $("reportOutput").textContent = report;
        $("reportPanel").hidden = false;
        $("message").textContent = `Downloaded ${filename}`;
      } catch (error) {
        $("message").textContent = `Report download failed: ${error.message}`;
      } finally {
        $("reportButton").disabled = false;
      }
    }

    function reportFilename(disposition) {
      const fallback = "snulbug-share-report.md";
      if (!disposition) return fallback;
      const match = disposition.match(/filename="?([^";]+)"?/i);
      return match ? match[1] : fallback;
    }

    function saveTextAsFile(textValue, filename) {
      const blob = new Blob([textValue], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }

    async function copyReadinessAttestation() {
      const attestation = activeReadinessGate().attestation || {};
      try {
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(JSON.stringify(attestation, null, 2));
        $("message").textContent = "Copied readiness attestation";
      } catch (error) {
        $("message").textContent = `Copy failed: ${error.message}`;
      }
    }

    function consoleSecret() {
      const key = "snulbug-console-secret";
      const cached = window.sessionStorage ? window.sessionStorage.getItem(key) : "";
      if (cached) return cached;
      const entered = window.prompt("Enter the snulbug share console secret printed in the terminal:");
      if (entered && window.sessionStorage) window.sessionStorage.setItem(key, entered);
      return entered || "";
    }

    function setBearerCopyFeedback(message, kind = "") {
      const status = $("bearerCopyStatus");
      if (status) {
        status.textContent = message || "";
        status.className = `copy-status ${kind}`.trim();
      }
      const button = $("copyBearerTokenButton");
      if (button) {
        button.textContent = kind === "pending" ? "Copying..." : (kind === "ok" ? "Copied" : "Copy bearer token");
        button.disabled = kind === "pending";
      }
      if (message && kind === "ok") {
        window.setTimeout(() => {
          const current = $("bearerCopyStatus");
          if (current && current.textContent === message) setBearerCopyFeedback("");
        }, 2500);
      }
    }

    async function copyBearerToken() {
      setBearerCopyFeedback("Copying...", "pending");
      try {
        const payload = await api("/api/client/bearer-token", {
          method: "POST",
          body: JSON.stringify({})
        });
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(payload.token || "");
        setBearerCopyFeedback("Copied to clipboard", "ok");
        $("message").textContent = "Copied bearer token";
      } catch (error) {
        setBearerCopyFeedback("Copy failed", "fail");
        $("message").textContent = `Copy bearer token failed: ${error.message}`;
      }
    }

    async function markReadinessReviewed() {
      const readiness = activeReadinessGate();
      const summary = readiness.summary || {};
      if ((summary.failed || 0) > 0) {
        $("message").textContent = "Fix failing readiness checks before marking reviewed";
        return;
      }
      $("message").textContent = "Marking readiness reviewed";
      try {
        const payload = await api("/api/readiness/review", {
          method: "POST",
          body: JSON.stringify({
            review_digest: readiness.review_digest,
            reviewer: "share-console",
            live_checks: Boolean(state.liveHealthReadiness)
          })
        });
        state.liveHealthReadiness = payload.readiness_gate || null;
        if (state.liveHealthReadiness) {
          renderMetrics(state.liveHealthStatus || (state.snapshot || {}).status || {}, state.liveHealthReadiness);
          renderReadinessGate(state.liveHealthReadiness);
          renderShareTabs(state.liveHealthReadiness, currentInvitationsPayload());
        }
        $("message").textContent = "Readiness reviewed";
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Review failed: ${error.message}`;
      }
    }

    async function copyWizardCommand(element) {
      const command = (element && element.dataset && element.dataset.command) || "";
      if (!command) return;
      try {
        if (!navigator.clipboard) throw new Error("clipboard unavailable");
        await navigator.clipboard.writeText(command);
        $("message").textContent = "Copied command";
      } catch (error) {
        $("message").textContent = command;
      }
    }

    function setupInputValue(id) {
      const element = $(id);
      return element ? element.value : "";
    }

    function setupChecked(id) {
      const element = $(id);
      return Boolean(element && element.checked);
    }

    async function createShareFromSetup() {
      $("message").textContent = "Creating share session";
      try {
        const payload = await api("/api/setup/create-share", {
          method: "POST",
          body: JSON.stringify({
            directory: setupInputValue("setup-directory"),
            provider: setupInputValue("setup-provider"),
            upstream: setupInputValue("setup-upstream"),
            public_url: setupInputValue("setup-public-url"),
            allowed_tools: setupInputValue("setup-allowed-tools"),
            allowed_paths: setupInputValue("setup-allowed-paths"),
            host: setupInputValue("setup-host"),
            port: setupInputValue("setup-port"),
            lease_required: setupChecked("setup-lease-required"),
            validate: setupChecked("setup-validate"),
            force: setupChecked("setup-force"),
            start_gateway: setupChecked("setup-start-gateway")
          })
        });
        $("message").textContent = payload.run_requested
          ? "Share created; starting gateway"
          : "Share created";
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Create failed: ${error.message}`;
      }
    }

    async function selectExistingShare(element) {
      const directory = (element && element.dataset && element.dataset.directory) || "";
      if (!directory) return;
      $("message").textContent = "Selecting share session";
      try {
        const payload = await api("/api/setup/select-share", {
          method: "POST",
          body: JSON.stringify({
            directory,
            start_gateway: setupChecked("setup-start-gateway")
          })
        });
        $("message").textContent = payload.run_requested
          ? "Share selected; starting gateway"
          : "Share selected";
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Select failed: ${error.message}`;
      }
    }

    function policyLifecyclePayload(extra = {}) {
      return {
        key_id: setupInputValue("policy-lifecycle-key-id") || "local-review",
        secret_env: setupInputValue("policy-lifecycle-secret-env") || "SNULBUG_BUNDLE_SECRET",
        actor: setupInputValue("policy-lifecycle-actor") || "share-console",
        note: setupInputValue("policy-lifecycle-note"),
        ...extra
      };
    }

    async function promotePolicyLifecycle(toState) {
      $("message").textContent = `Promoting policy to ${toState}`;
      try {
        const payload = await api("/api/policy/lifecycle", {
          method: "POST",
          body: JSON.stringify(policyLifecyclePayload({
            action: "promote",
            to_state: toState
          }))
        });
        $("message").textContent = `Policy lifecycle is now ${payload.state || toState}`;
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Lifecycle update failed: ${error.message}`;
      }
    }

    async function activatePolicyLifecycle() {
      $("message").textContent = "Activating policy";
      try {
        const payload = await api("/api/policy/lifecycle", {
          method: "POST",
          body: JSON.stringify(policyLifecyclePayload({
            action: "activate"
          }))
        });
        $("message").textContent = `Policy lifecycle is now ${payload.state || "active"}`;
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Activation failed: ${error.message}`;
      }
    }

    async function runHealthCheck() {
      $("message").textContent = "Checking gateway and upstream reachability";
      try {
        const payload = await fetchLiveHealth();
        renderHealth(payload);
        if (state.liveHealthReadiness) {
          renderMetrics(payload, state.liveHealthReadiness);
          renderReadinessGate(state.liveHealthReadiness);
          renderShareTabs(state.liveHealthReadiness, currentInvitationsPayload());
        }
        const gateway = payload.gateway || {};
        const upstreams = payload.upstreams || [];
        const publicGateway = payload.public_gateway || {};
        const publicTargets = publicGateway.configured ? [publicGateway] : [];
        const targets = publicTargets.concat([gateway]).concat(upstreams);
        const checked = targets.filter((item) => item.checked).length;
        const reachable = targets.filter((item) => item.reachable === true).length;
        $("message").textContent = `Health checked: ${reachable}/${checked} reachable`;
      } catch (error) {
        $("message").textContent = `Health check failed: ${error.message}`;
      }
    }

    async function runDoctor() {
      $("doctorButton").disabled = true;
      $("message").textContent = "Running share doctor";
      try {
        const payload = await api("/api/doctor", {
          method: "POST",
          allowFalse: true,
          body: JSON.stringify({ live_checks: true })
        });
        renderDoctor(payload);
        $("message").textContent = payload.ok ? "Doctor passed" : "Doctor found failing checks";
      } catch (error) {
        $("message").textContent = `Doctor failed: ${error.message}`;
      } finally {
        $("doctorButton").disabled = false;
      }
    }

    function renderDoctor(payload) {
      const summary = payload.summary || {};
      const checks = payload.checks || [];
      const recommendations = payload.recommendations || [];
      $("doctorPanel").hidden = false;
      $("doctorSummary").textContent =
        `${summary.passed || 0} passed, ${summary.failed || 0} failed, ` +
        `${summary.warnings || 0} warnings, ${summary.skipped || 0} skipped`;
      const metadata = `<div class="detail-grid">
        ${detailRow("Result", payload.ok ? "pass" : "fail")}
        ${detailRow("Provider", payload.provider)}
        ${detailRow("URL", payload.url)}
        ${detailRow("Config", payload.config)}
      </div>`;
      const checksHtml = checks.length ? `<table>
        <thead><tr><th>Status</th><th>Component</th><th>Check</th><th>Message</th></tr></thead>
        <tbody>${checks.map((check) => (
          `<tr>
            <td>${pill(check.status)}</td>
            <td>${esc(check.component || "-")}</td>
            <td>${esc(check.id || "-")}</td>
            <td>${esc(check.message || "-")}</td>
          </tr>`
        )).join("")}</tbody>
      </table>` : '<div class="empty">No doctor checks returned.</div>';
      const recommendationsHtml = recommendations.length ? `<div>
        <h2>Recommendations</h2>
        <ul class="recommendations">${recommendations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>
      </div>` : "";
      $("doctorChecks").innerHTML = `<div class="stack">${metadata}${checksHtml}${recommendationsHtml}</div>`;
    }

    async function previewAmendment() {
      $("amendPreviewButton").disabled = true;
      $("message").textContent = "Generating policy amendment preview";
      try {
        const payload = await api("/api/policy/amend-preview", {
          method: "POST",
          allowFalse: true,
          body: JSON.stringify({ source: "blocked", validate: true })
        });
        renderAmendmentPreview(payload);
        $("message").textContent = payload.ok
          ? "Amendment preview generated"
          : "Amendment preview has validation issues";
      } catch (error) {
        $("message").textContent = `Preview failed: ${error.message}`;
      } finally {
        $("amendPreviewButton").disabled = false;
      }
    }

    function renderAmendmentPreview(payload) {
      const amendment = payload.amendment || {};
      const preview = payload.preview || {};
      const delta = amendment.capability_delta || preview.capability_delta || {};
      const summary = delta.summary || {};
      const additions = amendment.additions || preview.additions || [];
      const rejected = amendment.rejected || preview.rejected || [];
      $("amendPreviewPanel").hidden = false;
      $("amendPreviewSummary").textContent =
        `${summary.newly_allowed_tools || 0} tools, ` +
        `${summary.newly_allowed_path_patterns || 0} paths, ` +
        `${summary.newly_allowed_argument_shapes || 0} argument shapes`;
      const metadata = `<div class="detail-grid">
        ${detailRow("Result", payload.ok ? "valid" : "needs review")}
        ${detailRow("Events", amendment.candidate_event_count || preview.candidate_event_count || 0)}
        ${detailRow("Output", payload.output)}
        ${detailRow("Log", payload.log)}
      </div>`;
      const additionsHtml = additions.length ? `<table>
        <thead><tr><th>Kind</th><th>Value</th><th>Parent</th><th>Reason</th></tr></thead>
        <tbody>${additions.map((item) => (
          `<tr>
            <td>${esc(item.kind || "-")}</td>
            <td>${esc(item.value || "-")}</td>
            <td>${esc(item.parent || "-")}</td>
            <td>${esc(item.reason_code || "-")}</td>
          </tr>`
        )).join("")}</tbody>
      </table>` : '<div class="empty">No policy additions found in current evidence.</div>';
      const rejectedHtml = rejected.length ? `<div>
        <h2>Rejected</h2>
        <table>
          <thead><tr><th>Kind</th><th>Value</th><th>Reason</th></tr></thead>
          <tbody>${rejected.map((item) => (
            `<tr>
              <td>${esc(item.kind || "-")}</td>
              <td>${esc(item.value || "-")}</td>
              <td>${esc(item.reason || item.reason_code || "-")}</td>
            </tr>`
          )).join("")}</tbody>
        </table>
      </div>` : "";
      const reportHtml = payload.report_text ? `<div>
        <h2>AMEND.md</h2>
        <div class="report-output">${esc(payload.report_text)}</div>
      </div>` : "";
      $("amendPreview").innerHTML = `<div class="stack">${metadata}${additionsHtml}${rejectedHtml}${reportHtml}</div>`;
    }

    function configureRefresh() {
      if (state.timer) clearInterval(state.timer);
      state.timer = null;
      if ($("autoRefresh").checked) {
        state.timer = setInterval(loadSnapshot, 5000);
      }
    }

    $("refreshButton").addEventListener("click", loadSnapshot);
    $("doctorButton").addEventListener("click", runDoctor);
    $("amendPreviewButton").addEventListener("click", previewAmendment);
    $("reportButton").addEventListener("click", downloadReport);
    $("autoRefresh").addEventListener("change", configureRefresh);
    configureRefresh();
    loadSnapshot();
  </script>
</body>
</html>
"""

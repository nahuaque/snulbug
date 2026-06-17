from __future__ import annotations

import http.client
import json
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .redaction import SECRET_REPLACEMENT, build_audit_event
from .share import (
    approve_share_capability_request,
    deny_share_capability_request,
    share_capability_requests,
    share_report,
    share_status,
)

DEFAULT_SHARE_CONSOLE_HOST = "127.0.0.1"
DEFAULT_SHARE_CONSOLE_PORT = 8765
DEFAULT_TUNNEL_PROVIDER_CONSOLES = {
    "ngrok": {
        "label": "ngrok local web console",
        "url": "http://127.0.0.1:4040",
        "description": "Inspect ngrok tunnel requests, headers, and replay details.",
    }
}
DEFAULT_DECISION_TIMELINE_LIMIT = 20


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
    return {
        "ok": bool(status.get("ok")),
        "generated_at": _now_iso(),
        "share": str(share_dir),
        "status": _redact_console_payload(status),
        "capability_requests": _redact_console_payload(requests),
        "decision_timeline": _redact_console_payload(_decision_timeline(share_dir, status)),
        "provider_console": _provider_console(status, timeout=timeout),
    }


def run_share_console(
    directory: str | Path,
    *,
    host: str = DEFAULT_SHARE_CONSOLE_HOST,
    port: int = DEFAULT_SHARE_CONSOLE_PORT,
    timeout: float = 1.0,
    live_checks: bool = False,
) -> int:
    """Run the blocking local share-session console."""

    server = ShareConsoleServer(
        directory=Path(directory),
        host=host,
        port=port,
        timeout=timeout,
        live_checks=live_checks,
    )
    server.start()
    print(f"snulbug share console: {server.url}", flush=True)
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
    _server: ThreadingHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self._server is not None:
            return
        console = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                console._handle_get(self)

            def do_POST(self) -> None:
                console._handle_post(self)

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

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        try:
            if path in {"/", "/index.html"}:
                _send(handler, 200, _console_html().encode("utf-8"), content_type="text/html; charset=utf-8")
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
            if path == "/api/report":
                _send_json(
                    handler,
                    200,
                    share_report(self.directory, timeout=self.timeout, live_checks=self.live_checks),
                )
                return
            _send(handler, 404, b"not found\n", content_type="text/plain; charset=utf-8")
        except Exception as exc:
            _send_error(handler, exc)

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        try:
            body = _read_json_body(handler)
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
            _send_error(handler, exc)

    def snapshot(self) -> dict[str, Any]:
        return build_share_console_snapshot(
            self.directory,
            timeout=self.timeout,
            live_checks=self.live_checks,
        )


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


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, *, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("content-type", content_type)
    handler.send_header("cache-control", "no-store")
    handler.send_header("content-length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")
    return dict(payload)


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


def _positive_int(value: Any) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


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
    probe = _probe_provider_console(str(template["url"]), timeout=timeout)
    return {"provider": provider, **template, **probe}


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
    lines: deque[tuple[int, str]] = deque(maxlen=max(limit * 4, limit))
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            stripped = line.strip()
            if stripped:
                lines.append((line_number, stripped))
    events: list[tuple[int, dict[str, Any]]] = []
    for line_number, line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(value, Mapping):
            continue
        event = build_audit_event(value) if value.get("type") == "snulbug.request_record" else dict(value)
        events.append((line_number, event))
    return events[-limit:]


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
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
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
    }
    .topbar {
      max-width: 1320px;
      margin: 0 auto;
      padding: 14px 20px;
      display: grid;
      grid-template-columns: minmax(180px, 1fr) auto;
      gap: 16px;
      align-items: center;
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
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .auto {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      color: var(--muted);
      white-space: nowrap;
    }
    main {
      max-width: 1320px;
      width: 100%;
      margin: 0 auto;
      padding: 18px 20px 28px;
      display: grid;
      gap: 16px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(128px, 1fr));
      gap: 10px;
    }
    .metric, section {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .metric {
      padding: 12px;
      min-height: 82px;
      display: grid;
      align-content: space-between;
    }
    .metric span {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .metric strong {
      font-size: 24px;
      line-height: 1.1;
      overflow-wrap: anywhere;
    }
    section {
      overflow: hidden;
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
    .grid-two {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      gap: 16px;
      align-items: start;
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
    .ok, .pass, .reachable, .approved {
      color: var(--green);
      border-color: #a7d8bf;
      background: #f0fbf5;
    }
    .fail, .blocked, .denied, .unreachable {
      color: var(--red);
      border-color: #efb3b8;
      background: #fff5f5;
    }
    .warn, .pending, .unknown, .confirmed, .not-checked {
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
    .timeline-target {
      font-weight: 680;
    }
    .timeline-detail {
      color: var(--muted);
      margin-top: 2px;
    }
    .message {
      min-height: 20px;
      color: var(--muted);
    }
    .token {
      background: #0f1720;
      color: #e8f1f8;
      border-radius: 8px;
      padding: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
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
    @media (max-width: 980px) {
      .metrics {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .grid-two, .topbar {
        grid-template-columns: 1fr;
      }
      .toolbar {
        justify-content: flex-start;
      }
      .request-actions {
        grid-template-columns: 1fr 1fr;
      }
    }
    @media (max-width: 560px) {
      main, .topbar {
        padding-left: 12px;
        padding-right: 12px;
      }
      .metrics {
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
        <div class="toolbar">
          <label class="auto"><input id="autoRefresh" type="checkbox" checked> Auto refresh</label>
          <button id="refreshButton" class="primary" type="button">Refresh</button>
          <button id="reportButton" type="button">Generate Report</button>
        </div>
      </div>
    </header>
    <main>
      <div id="message" class="message"></div>
      <div class="metrics" id="metrics"></div>
      <section>
        <div class="section-head"><h2>Live Decisions</h2><span id="decisionSummary" class="muted"></span></div>
        <div class="section-body" id="decisionTimeline"></div>
      </section>
      <div class="grid-two">
        <section>
          <div class="section-head"><h2>Capability Requests</h2><span id="requestSummary" class="muted"></span></div>
          <div class="section-body" id="requests"></div>
        </section>
        <section>
          <div class="section-head"><h2>Health</h2><span id="healthSummary" class="muted"></span></div>
          <div class="section-body" id="health"></div>
        </section>
      </div>
      <div class="grid-two">
        <section>
          <div class="section-head"><h2>Tool Risk</h2><span id="riskSummary" class="muted"></span></div>
          <div class="section-body" id="toolRisk"></div>
        </section>
        <section>
          <div class="section-head"><h2>Findings</h2><span id="findingSummary" class="muted"></span></div>
          <div class="section-body" id="findings"></div>
        </section>
      </div>
      <section>
        <div class="section-head"><h2>Evidence And Commands</h2><span id="evidenceSummary" class="muted"></span></div>
        <div class="section-body" id="evidence"></div>
      </section>
      <section id="leasePanel" hidden>
        <div class="section-head"><h2>New Lease Header</h2></div>
        <div class="section-body"><div id="leaseOutput" class="token"></div></div>
      </section>
      <section id="reportPanel" hidden>
        <div class="section-head"><h2>Session Report</h2></div>
        <div class="section-body"><div id="reportOutput" class="report-output"></div></div>
      </section>
    </main>
  </div>
  <script>
    const state = { snapshot: null, timer: null };
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
      const response = await fetch(path, {
        ...options,
        headers: {
          "content-type": "application/json",
          ...(options.headers || {})
        }
      });
      const payload = await response.json();
      if (!response.ok || payload.ok === false) throw new Error(payload.error || response.statusText);
      return payload;
    }

    async function loadSnapshot() {
      $("message").textContent = "Refreshing";
      try {
        state.snapshot = await api("/api/snapshot");
        render();
        $("message").textContent = `Updated ${new Date().toLocaleTimeString()}`;
      } catch (error) {
        $("message").textContent = `Refresh failed: ${error.message}`;
      }
    }

    function render() {
      const snapshot = state.snapshot || {};
      const status = snapshot.status || {};
      $("sharePath").textContent = text(snapshot.share || status.directory);
      renderMetrics(status);
      renderDecisionTimeline(snapshot.decision_timeline || {});
      renderRequests(snapshot.capability_requests || {});
      renderHealth(status, snapshot.provider_console || null);
      renderToolRisk(status);
      renderFindings(status);
      renderEvidence(status);
    }

    function renderMetrics(status) {
      const traffic = status.traffic || {};
      const requests = status.capability_requests || {};
      const leases = status.leases || {};
      const risk = (status.tool_risks || {}).summary || {};
      const gateway = status.gateway || {};
      const metrics = [
        ["State", status.state],
        ["Gateway", gateway.reachable === true ? "reachable" : (gateway.checked === false ? "not checked" : "unknown")],
        ["Active leases", leases.active_count || 0],
        ["Pending requests", requests.pending || 0],
        ["Blocked", traffic.blocked || 0],
        ["High risk tools", risk.high || 0]
      ];
      $("metrics").innerHTML = metrics.map(([label, value]) => (
        `<div class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`
      )).join("");
    }

    function renderDecisionTimeline(payload) {
      const summary = payload.summary || {};
      const events = payload.events || [];
      $("decisionSummary").textContent =
        `${summary.shown || 0} shown, ${summary.allowed || 0} allowed, ${summary.blocked || 0} blocked`;
      if (!payload.exists) {
        $("decisionTimeline").innerHTML = `<div class="empty">No audit log found yet.</div>`;
        return;
      }
      if (!events.length) {
        $("decisionTimeline").innerHTML = `<div class="empty">No decisions recorded yet.</div>`;
        return;
      }
      $("decisionTimeline").innerHTML = `<table>
        <thead><tr><th>Time</th><th>Outcome</th><th>Request</th><th>Subject</th><th>Status</th><th>Reason</th></tr></thead>
        <tbody>${events.map((event) => (
          `<tr>
            <td>${esc(shortTime(event.time))}</td>
            <td>${pill(event.outcome)}</td>
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
              <div class="timeline-detail">${esc(event.upstream || event.source_ip || event.reason || "")}</div>
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

    function decisionTarget(event) {
      if (event.tool) return event.tool;
      if (event.mcp_method) return event.mcp_method;
      return event.path || "-";
    }

    function decisionDetail(event) {
      const parts = [event.mcp_method, event.http_method, event.path].filter(Boolean);
      return parts.join(" ");
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
        return `<tr>
          <td>${pill(request.status)}<br><span class="muted">${id}</span></td>
          <td>
            <strong>${esc(request.tool || request.method)}</strong><br>
            ${esc(request.task || request.reason_code)}
          </td>
          <td>${esc(auth.subject || "-")}<br><span class="muted">${esc(auth.tenant || auth.issuer || "")}</span></td>
          <td>
            <div class="request-actions">
              <input id="ttl-${id}" value="${ttl}" aria-label="TTL">
              <input id="calls-${id}" value="${maxCalls}" aria-label="Max calls">
              <input id="reviewer-${id}" value="${reviewer}" aria-label="Reviewer">
              <button class="primary" type="button" onclick="approveRequest('${id}')">Approve</button>
              <button class="danger" type="button" onclick="denyRequest('${id}')">Deny</button>
            </div>
          </td>
        </tr>`;
      }).join("");
      $("requests").innerHTML = `<table>
        <thead><tr><th>Status</th><th>Capability</th><th>Auth</th><th>Review</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderHealth(status, providerConsole) {
      const gateway = status.gateway || {};
      const upstreams = status.upstreams || [];
      $("healthSummary").textContent = gateway.url || "";
      const rows = [["gateway", gateway.url, gateway.reachable, gateway.status, false]]
        .concat(upstreams.map((item) => [
          item.name || "upstream",
          item.url,
          item.reachable,
          item.status || item.health,
          false
        ]));
      if (providerConsole) {
        rows.push([
          `${providerConsole.provider} console`,
          providerConsole.url,
          providerConsole.checked ? providerConsole.reachable : null,
          providerConsole.error || providerConsole.description || providerConsole.label,
          true
        ]);
      }
      $("health").innerHTML = `<table>
        <thead><tr><th>Target</th><th>URL</th><th>Reachable</th><th>Status</th></tr></thead>
        <tbody>${rows.map(([name, url, reachable, detail, isLink]) => (
          `<tr>
            <td>${esc(name)}</td>
            <td>${isLink ? externalLink(url, url) : esc(url)}</td>
            <td>${pill(healthLabel(reachable))}</td>
            <td>${esc(detail)}</td>
          </tr>`
        )).join("")}</tbody>
      </table>`;
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

    async function approveRequest(id) {
      try {
        const payload = await api(`/api/requests/${encodeURIComponent(id)}/approve`, {
          method: "POST",
          body: JSON.stringify({
            ttl: $(`ttl-${id}`).value,
            max_calls: $(`calls-${id}`).value,
            reviewer: $(`reviewer-${id}`).value,
            bind_auth: true
          })
        });
        $("leaseOutput").textContent = payload.retry_header || JSON.stringify(payload.headers, null, 2);
        $("leasePanel").hidden = false;
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Approve failed: ${error.message}`;
      }
    }

    async function denyRequest(id) {
      const reason = window.prompt("Reason");
      if (reason === null) return;
      try {
        await api(`/api/requests/${encodeURIComponent(id)}/deny`, {
          method: "POST",
          body: JSON.stringify({ reason, reviewer: "local-review" })
        });
        await loadSnapshot();
      } catch (error) {
        $("message").textContent = `Deny failed: ${error.message}`;
      }
    }

    async function generateReport() {
      try {
        const payload = await api("/api/report");
        $("reportOutput").textContent = payload.report || "";
        $("reportPanel").hidden = false;
      } catch (error) {
        $("message").textContent = `Report failed: ${error.message}`;
      }
    }

    function configureRefresh() {
      if (state.timer) clearInterval(state.timer);
      state.timer = null;
      if ($("autoRefresh").checked) {
        state.timer = setInterval(loadSnapshot, 2000);
      }
    }

    $("refreshButton").addEventListener("click", loadSnapshot);
    $("reportButton").addEventListener("click", generateReport);
    $("autoRefresh").addEventListener("change", configureRefresh);
    configureRefresh();
    loadSnapshot();
  </script>
</body>
</html>
"""

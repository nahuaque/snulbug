from __future__ import annotations

import asyncio
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from asgi_lua import create_proxy_application, load_record_log


def test_reverse_proxy_forwards_allowed_request_to_upstream(tmp_path):
    server, seen = start_upstream()
    policy = write_policy(tmp_path, "continue")
    record_log = tmp_path / "records.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    app = create_proxy_application(
        f"http://127.0.0.1:{server.server_port}/api",
        policy,
        record_out=record_log,
        audit_out=audit_log,
    )

    try:
        sent = run_asgi(
            app,
            path="/mcp",
            query_string=b"x=1",
            headers=[(b"content-type", b"application/json"), (b"authorization", b"Bearer local-dev-secret")],
            body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        )
    finally:
        server.shutdown()
        server.server_close()

    payload = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 200
    assert payload["method"] == "POST"
    assert payload["path"] == "/api/mcp?x=1"
    assert payload["body"] == '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    assert payload["headers"]["host"] == f"127.0.0.1:{server.server_port}"
    assert seen["count"] == 1
    records = load_record_log(record_log)
    audit = json.loads(audit_log.read_text(encoding="utf-8"))
    assert records[0]["request"]["headers"]["authorization"] == "Bearer local-dev-secret"
    assert records[0]["request"]["query_string"] == "x=1"
    assert records[0]["result"]["action"] == "continue"
    assert records[0]["response"]["status"] == 200
    assert records[0]["metadata"] == {"source": "proxy"}
    assert audit["request"]["headers"]["authorization"] == "[REDACTED]"
    assert audit["mcp"]["method"] == "tools/list"


def test_reverse_proxy_does_not_call_upstream_when_policy_rejects(tmp_path):
    server, seen = start_upstream()
    policy = write_policy(tmp_path, "reject")
    record_log = tmp_path / "records.jsonl"
    app = create_proxy_application(f"http://127.0.0.1:{server.server_port}", policy, record_out=record_log)

    try:
        sent = run_asgi(app, path="/mcp", body=b"{}")
    finally:
        server.shutdown()
        server.server_close()

    assert sent[0]["status"] == 403
    assert sent[1]["body"] == b"blocked by policy"
    assert seen["count"] == 0
    records = load_record_log(record_log)
    assert records[0]["result"]["action"] == "reject"
    assert records[0]["response"]["status"] == 403


def test_reverse_proxy_returns_bad_gateway_for_unreachable_upstream(tmp_path):
    policy = write_policy(tmp_path, "continue")
    app = create_proxy_application("http://127.0.0.1:9", policy, timeout=0.05)

    sent = run_asgi(app, path="/mcp", body=b"{}")

    assert sent[0]["status"] == 502
    assert b"upstream request failed" in sent[1]["body"]


def test_reverse_proxy_writes_live_decision_console_text(tmp_path):
    server, _seen = start_upstream()
    policy = write_policy(tmp_path, "continue")
    console = io.StringIO()
    app = create_proxy_application(
        f"http://127.0.0.1:{server.server_port}",
        policy,
        decision_console=console,
    )

    try:
        run_asgi(
            app,
            path="/mcp",
            headers=[(b"authorization", b"Bearer local-dev-secret")],
            body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
        )
    finally:
        server.shutdown()
        server.server_close()

    output = console.getvalue()
    assert "decision=continue" in output
    assert "allowed=true" in output
    assert "status=200" in output
    assert "method=POST" in output
    assert "path=/mcp" in output
    assert "mcp.method=tools/list" in output
    assert "mcp.id=1" in output
    assert "local-dev-secret" not in output


def test_reverse_proxy_writes_live_decision_console_json(tmp_path):
    policy = write_policy(tmp_path, "reject")
    console = io.StringIO()
    app = create_proxy_application(
        "http://127.0.0.1:9",
        policy,
        decision_console=console,
        decision_console_format="json",
    )

    run_asgi(
        app,
        path="/mcp",
        headers=[(b"authorization", b"Bearer local-dev-secret")],
        body=b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}',
    )

    event = json.loads(console.getvalue())
    assert event["decision"]["action"] == "reject"
    assert event["decision"]["allowed"] is False
    assert event["response"]["status"] == 403
    assert event["request"]["headers"]["authorization"] == "[REDACTED]"
    assert event["mcp"]["method"] == "tools/call"
    assert event["mcp"]["operation"] == "tools"
    assert event["mcp"]["operation_detail"] == "call"
    assert event["mcp"]["request_id"] == 1
    assert event["mcp"]["target"] == "shell_exec"
    assert event["mcp"]["tool"] == "shell_exec"
    assert event["trace"]["instruction_count"] == 0


def start_upstream():
    seen = {"count": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen["count"] += 1
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            payload = {
                "method": self.command,
                "path": self.path,
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "body": body.decode("utf-8"),
            }
            response = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, format, *args):  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, seen


def run_asgi(app, *, path="/mcp", headers=None, body=b"", query_string=b"") -> list[dict[str, Any]]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query_string,
        "headers": headers or [],
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent


def write_policy(tmp_path, action: str):
    if action == "continue":
        decision = '{ action = "continue" }'
    else:
        decision = '{ action = "reject", status = 403, body = "blocked by policy" }'
    path = tmp_path / "policy.lua"
    path.write_text(
        f"""
        return function(request, context, state)
          return {decision}
        end
        """,
        encoding="utf-8",
    )
    return path

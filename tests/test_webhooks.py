from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from snulbug import (
    WebhookSink,
    deliver_webhook_event,
    matching_webhook_sinks,
    normalize_webhook_sinks,
    prepare_webhook_payload,
    webhook_event_names,
)


def test_normalize_webhook_sinks_defaults_to_audit_events():
    sinks = normalize_webhook_sinks([{"name": "alerts", "url_env": "SNULBUG_WEBHOOK_URL"}])

    assert sinks == [
        WebhookSink(
            name="alerts",
            url_env="SNULBUG_WEBHOOK_URL",
            events=("snulbug.audit",),
        )
    ]


def test_webhook_event_names_include_mcp_decision_and_response_findings():
    event = {
        "type": "snulbug.audit",
        "decision": {"action": "reject", "allowed": False, "reason_code": "mcp.tool_not_allowed"},
        "response": {"status": 403, "body_bytes": 0},
        "metadata": {
            "response_policy": {
                "redacted": True,
                "warnings": [{"reason_code": "ignore_previous_instructions"}],
                "tool_pinning": {"changed": [{"tool": "shell"}]},
            }
        },
    }

    assert webhook_event_names(event) >= {
        "snulbug.audit",
        "mcp.request",
        "mcp.decision.blocked",
        "mcp.decision.reject",
        "mcp.tool_not_allowed",
        "mcp.response",
        "mcp.response.redacted",
        "mcp.response.warning",
        "mcp.tool.changed",
    }


def test_matching_webhook_sinks_uses_derived_event_names():
    sinks = normalize_webhook_sinks(
        [
            {"name": "blocked", "url": "http://127.0.0.1:1/hook", "events": ["mcp.decision.blocked"]},
            {"name": "allowed", "url": "http://127.0.0.1:1/hook", "events": ["mcp.decision.allowed"]},
        ]
    )

    matches = matching_webhook_sinks(
        sinks,
        {"type": "snulbug.audit", "decision": {"action": "reject", "allowed": False}},
    )

    assert [sink.name for sink in matches] == ["blocked"]


def test_prepare_webhook_payload_redacts_and_minimizes_metadata_only_events():
    sink = WebhookSink(name="alerts", url="http://127.0.0.1:1/hook")
    payload = prepare_webhook_payload(
        sink,
        {
            "type": "snulbug.audit",
            "request": {
                "method": "POST",
                "path": "/mcp",
                "query_string": "token=secret",
                "headers": {"authorization": "Bearer local-dev-secret"},
            },
            "decision": {"action": "continue", "allowed": True},
        },
    )

    assert payload["type"] == "snulbug.webhook"
    assert payload["event"]["request"] == {"method": "POST", "path": "/mcp"}
    assert "mcp.decision.allowed" in payload["event_names"]
    assert "local-dev-secret" not in json.dumps(payload)


def test_deliver_webhook_event_posts_signed_json(monkeypatch):
    received = {}
    ready = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            received["path"] = self.path
            received["headers"] = dict(self.headers.items())
            length = int(self.headers["content-length"])
            received["body"] = self.rfile.read(length)
            ready.set()
            self.send_response(204)
            self.end_headers()

        def log_message(self, format, *args):  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SNULBUG_WEBHOOK_SECRET", "test-secret")
    sink = WebhookSink(
        name="alerts",
        url=f"http://127.0.0.1:{server.server_port}/hook",
        retry_attempts=0,
        signing_secret_env="SNULBUG_WEBHOOK_SECRET",
    )

    try:
        result = deliver_webhook_event(
            sink,
            {"type": "snulbug.audit", "decision": {"action": "reject", "allowed": False}},
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.delivered is True
    assert ready.is_set()
    assert received["path"] == "/hook"
    assert received["headers"]["X-Snulbug-Webhook-Sink"] == "alerts"
    assert received["headers"]["X-Snulbug-Signature"].startswith("sha256=")
    assert json.loads(received["body"])["sink"] == "alerts"

from __future__ import annotations

import asyncio
import io
import json
import socket
import ssl

import httpx
import pytest

import snulbug.proxy as proxy
from snulbug import (
    ConsoleEventSink,
    EventDispatcher,
    build_audit_event,
    create_lease,
    create_mcp_share,
    create_proxy_application,
    inspect_mcp_log,
    load_record_log,
    revoke_lease,
    share_report,
)
from snulbug.credentials import CredentialResolutionError
from snulbug.events import format_decision_console_line
from snulbug.request_explanations import explain_request, upstream_failure, upstream_response_observation
from snulbug.share_console import _decision_timeline_compaction_signature, _decision_timeline_item, _timeline_outcome


def event(*, metadata=None, status=502, decision=None):
    return {
        "type": "snulbug.audit",
        "request": {"method": "POST", "path": "/mcp"},
        "mcp": {"method": "tools/call", "tool": "safe_read_file", "request_id": "call-1"},
        "decision": decision or {"action": "continue", "allowed": True, "reason_code": "policy.allowed"},
        "response": {"status": status},
        "metadata": metadata or {},
    }


@pytest.mark.parametrize(
    ("exc", "transport", "code", "execution"),
    [
        (CredentialResolutionError("private-value"), "http", "upstream.credentials_unavailable", "not_forwarded"),
        (socket.gaierror("private-value"), "http", "upstream.dns_failed", "not_forwarded"),
        (ConnectionRefusedError("private-value"), "http", "upstream.connection_refused", "not_forwarded"),
        (ssl.SSLCertVerificationError("private-value"), "http", "upstream.tls_failed", "not_forwarded"),
        (ssl.SSLError("private-value"), "http", "upstream.tls_failed", "unknown"),
        (TimeoutError("private-value"), "http", "upstream.timeout", "unknown"),
        (httpx.ReadTimeout("private-value"), "http", "upstream.timeout", "unknown"),
        (ConnectionResetError("private-value"), "http", "upstream.transport_failed", "unknown"),
        (FileNotFoundError("private-value"), "stdio", "upstream.process_unavailable", "not_forwarded"),
        (RuntimeError("private-value"), "custom-plugin", "upstream.transport_failed", "unknown"),
    ],
)
def test_exception_classification_does_not_retain_exception_text(exc, transport, code, execution):
    failure = upstream_failure(exc, transport=transport)
    assert failure == {"failure_code": code, "execution": execution}
    explanation = explain_request(event(metadata={"upstream_exchanges": [failure]}))
    assert explanation["reason_code"] == code
    assert explanation["execution"] == execution
    assert "private-value" not in json.dumps(explanation)


def test_wrapped_exception_causes_are_bounded_and_classified():
    error = httpx.ConnectError("do not log this")
    error.__cause__ = socket.gaierror("do not log this either")
    assert upstream_failure(error)["failure_code"] == "upstream.dns_failed"
    error.__cause__ = error
    assert upstream_failure(error)["failure_code"] == "upstream.transport_failed"


def test_unrecognized_plugin_marker_cannot_invent_an_http_error_or_execution_proof():
    explanation = explain_request(
        event(
            status=200,
            metadata={"upstream_exchanges": [{"failure_code": "plugin.private_value", "execution": "private-value"}]},
        )
    )
    assert explanation["stage"] == "unknown"
    assert explanation["reason_code"] == "request.failure_unattributed"
    assert explanation["execution"] == "unknown"
    assert "private" not in json.dumps(explanation)


@pytest.mark.parametrize(
    ("metadata", "stage", "code"),
    [
        (
            {"auth": {"allowed": False, "reason_code": "oauth.scope_map_denied"}},
            "authentication",
            "oauth.scope_map_denied",
        ),
        (
            {"lease": {"enabled": True, "checked": True, "allowed": False, "reason_code": "lease.revoked"}},
            "lease",
            "lease.revoked",
        ),
        (
            {"mcp_transport": {"allowed": False, "reason_code": "mcp.transport.accept_required"}},
            "request_validation",
            "mcp.transport.accept_required",
        ),
        (
            {"response_policy": {"blocked": True, "reason_code": "response.too_large"}},
            "response_policy",
            "response.too_large",
        ),
        (
            {"schema_validation": {"tool_result": {"blocked": True, "reason_code": "schema.output_invalid"}}},
            "response_policy",
            "schema.output_invalid",
        ),
        (
            {"upstream_exchanges": [{"status": 401, "execution": "response_received"}]},
            "upstream_response",
            "upstream.auth_rejected",
        ),
        ({"stream": {"status": "failed"}}, "stream", "stream.failed"),
        ({"operational_controls": {"paused": True}}, "routing", "routing.unavailable"),
    ],
)
def test_failure_stages_follow_recorded_gate_evidence(metadata, stage, code):
    explanation = explain_request(event(metadata=metadata, status=503))
    assert explanation["stage"] == stage
    assert explanation["reason_code"] == code
    assert explanation["next_steps"]


def test_lua_allow_is_preserved_but_not_mistaken_for_success():
    record = event(metadata={"upstream_exchanges": [{"failure_code": "upstream.connection_refused"}]})
    explanation = explain_request(record)
    assert record["decision"]["reason_code"] == "policy.allowed"
    assert explanation["outcome"] == "failed"
    assert explanation["stage"] == "upstream_transport"
    line = format_decision_console_line(record)
    assert "reason_code=policy.allowed" in line
    assert "failure.code=upstream.connection_refused" in line


def test_old_status_only_logs_remain_unattributed_instead_of_blaming_upstream(tmp_path):
    record = event()
    explanation = explain_request(record)
    assert explanation["stage"] == "unknown"
    assert explanation["evidence"]["basis"] == "http_status_only"
    item = _decision_timeline_item(record, source=tmp_path / "audit.jsonl", line=1)
    assert item["outcome"] == "failed"
    assert item["explanation"] == explanation


def test_response_block_takes_precedence_over_upstream_failure():
    record = event(
        status=200,
        metadata={
            "response_policy": {"blocked": True, "reason_code": "response.changed"},
            "upstream_exchanges": [{"status": 500}],
        },
    )
    assert explain_request(record)["stage"] == "response_policy"
    assert _timeline_outcome(record, decision=record["decision"]) == "blocked"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (
            {"error": {"code": -32000, "message": "private-value", "data": {"value": "private-value"}}},
            "upstream.rpc_error",
        ),
        ({"result": {"isError": True, "content": [{"text": "private-value"}]}}, "upstream.tool_error"),
    ],
)
def test_http_200_mcp_errors_are_failed_without_retaining_payload_values(payload, code):
    response = {"status": 200, "body": json.dumps({"jsonrpc": "2.0", "id": 1, **payload}).encode()}
    observation = upstream_response_observation(response)
    assert "private-value" not in json.dumps(observation)
    explanation = explain_request(event(status=200, metadata={"upstream_exchanges": [observation]}))
    assert explanation["reason_code"] == code
    assert explanation["outcome"] == "failed"


def test_oversized_or_non_json_payloads_are_not_interpreted_as_diagnostic_text():
    for body in (b"private-value", b"{" * 132_000, b"[" * 1000):
        assert upstream_response_observation({"status": 200, "body": body}) == {
            "status": 200,
            "execution": "response_received",
        }


def test_facade_partial_catalog_retains_failed_upstream_identity():
    explanation = explain_request(
        event(
            status=200,
            metadata={
                "operation": "tools/list",
                "upstream_exchanges": [
                    {"upstream": "remote", "failure_code": "upstream.timeout"},
                    {"upstream": "local", "status": 200},
                ],
            },
        )
    )
    assert explanation["outcome"] == "partial"
    assert explanation["evidence"]["upstream"] == "remote"


def test_successful_and_local_synthetic_responses_are_not_failed():
    assert explain_request(event(status=200)) == {}
    assert explain_request(event(status=200, decision={"action": "respond", "allowed": False})) == {}
    assert explain_request(event(status=200, metadata={"auth": {"enabled": False, "allowed": False}})) == {}


@pytest.mark.parametrize("name", ["protocol_policy", "resource_policy"])
def test_protocol_request_controls_are_not_mistaken_for_response_failures(name):
    explanation = explain_request(
        event(status=200, metadata={name: {"request": {"blocked": True, "reason_code": "mcp.request_not_allowed"}}})
    )
    assert explanation["stage"] == "request_policy"
    assert explanation["execution"] == "not_forwarded"


def test_confirmation_uses_existing_approval_evidence():
    record = event(status=403, decision={"action": "reject", "allowed": False, "confirmation": {"approved": False}})
    assert explain_request(record)["stage"] == "confirmation"


def test_confirmation_does_not_hide_a_subsequent_upstream_failure():
    record = event(metadata={"upstream_exchanges": [{"status": 500}]})
    record["decision"]["confirmation"] = {"approved": True}
    assert _timeline_outcome(record, decision=record["decision"]) == "upstream_failed"


def test_compaction_does_not_merge_different_failure_causes(tmp_path):
    records = [
        event(metadata={"upstream_exchanges": [{"failure_code": code}]})
        for code in ("upstream.timeout", "upstream.connection_refused")
    ]
    items = [
        _decision_timeline_item(record, source=tmp_path / "audit.jsonl", line=index)
        for index, record in enumerate(records)
    ]
    assert _decision_timeline_compaction_signature(items[0]) != _decision_timeline_compaction_signature(items[1])


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "policy.lua"
    path.write_text(
        'return function(request, context, state) return {action="continue", reason_code="policy.allowed"} end'
    )
    return path


def call(app, request, *, headers=()):
    messages = [{"type": "http.request", "body": json.dumps(request).encode(), "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        await asyncio.sleep(3600)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
            *headers,
        ],
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    asyncio.run(app(scope, receive, send))
    return sent


@pytest.mark.parametrize("facade", [False, True])
def test_live_transport_errors_reach_existing_records_console_and_reports(policy, tmp_path, monkeypatch, facade):
    console = io.StringIO()
    dispatcher = EventDispatcher([ConsoleEventSink(output=console)])
    record_path = tmp_path / "records.jsonl"
    calls = []

    def fail(*args):
        calls.append(True)
        raise ConnectionRefusedError("private-value from plugin or credential backend")

    async def async_fail(*args):
        fail(*args)

    monkeypatch.setattr(proxy.ReverseProxyApp, "_forward", fail)
    monkeypatch.setattr(proxy.McpFacadeProxyApp, "_forward_upstream", async_fail)
    options = (
        {"upstreams": [{"name": "remote", "url": "http://127.0.0.1:9/mcp", "tool_prefix": "remote."}]} if facade else {}
    )
    app = create_proxy_application(
        None if facade else "http://127.0.0.1:9", policy, record_out=record_path, event_dispatcher=dispatcher, **options
    )
    sent = call(
        app,
        {
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "remote.read" if facade else "read", "arguments": {}},
        },
    )
    assert sent[0]["status"] == 502
    assert len(calls) == 1
    record = load_record_log(record_path)[0]
    audit = build_audit_event(record)
    assert audit["explanation"]["reason_code"] == "upstream.connection_refused"
    assert audit["decision"]["reason_code"] == "policy.allowed"
    assert "failure.code=upstream.connection_refused" in console.getvalue()
    assert "private-value" not in record_path.read_text() + str(sent) + console.getvalue()
    assert inspect_mcp_log(record_path)["failures"]["reason_codes"] == [
        {"value": "upstream.connection_refused", "count": 1}
    ]
    if facade:
        assert json.loads(sent[-1]["body"])["id"] == "call-1"


def test_fanout_keeps_failure_evidence_when_successful_siblings_exceed_limit():
    scope = {"state": {}}
    proxy._record_upstream_exchange(scope, upstream="failed", transport="http", error=TimeoutError("private-value"))
    for index in range(30):
        proxy._record_upstream_exchange(scope, upstream=f"healthy-{index}", transport="http", response={"status": 200})
    metadata = scope["state"]["snulbug_proxy"]
    assert len(metadata["upstream_exchanges"]) == 20
    assert metadata["upstream_exchanges_truncated"] is True
    metadata["operation"] = "tools/list"
    assert explain_request(event(metadata=metadata, status=200))["outcome"] == "partial"


def test_missing_upstream_credential_does_not_forward_or_leak_backend_errors(policy, tmp_path, monkeypatch):
    monkeypatch.delenv("SNULBUG_MISSING_UPSTREAM_AUTH", raising=False)
    monkeypatch.setattr(proxy.http.client.HTTPConnection, "request", lambda *args, **kwargs: pytest.fail("forwarded"))
    record_path = tmp_path / "records.jsonl"
    app = create_proxy_application(
        "http://127.0.0.1:9",
        policy,
        record_out=record_path,
        upstream_credential={"id": "service-auth", "type": "env", "env": "SNULBUG_MISSING_UPSTREAM_AUTH"},
    )
    sent = call(app, {"jsonrpc": "2.0", "id": "auth", "method": "tools/list"})
    audit = build_audit_event(load_record_log(record_path)[0])
    assert sent[0]["status"] == 502
    assert audit["explanation"]["stage"] == "upstream_credentials"
    assert audit["explanation"]["execution"] == "not_forwarded"
    assert "SNULBUG_MISSING_UPSTREAM_AUTH" not in str(sent)


def test_share_report_and_offline_inspection_reuse_failure_explanation(tmp_path):
    create_mcp_share(tmp_path, provider="generic", token="share-value", allowed_tools=["read"], validate=False)
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    record = event(metadata={"upstream_exchanges": [{"failure_code": "upstream.timeout", "execution": "unknown"}]})
    (traces / "audit.jsonl").write_text(json.dumps(record) + "\n")
    report = share_report(tmp_path, live_checks=False)
    assert "Request Failures" in report["report"]
    assert "upstream.timeout" in report["report"]
    assert "before repeating" in report["report"]


def test_revoked_lease_is_explained_as_a_lease_failure_without_forwarding(policy, tmp_path, monkeypatch):
    lease_file = tmp_path / "leases.json"
    created = create_lease(lease_file, task="Read files", allow_tools=["read"], ttl="30m", token="sbl_test_value")
    revoke_lease(lease_file, created["lease"]["id"])
    monkeypatch.setattr(proxy.ReverseProxyApp, "_forward", lambda *_: pytest.fail("revoked lease was forwarded"))
    record_path = tmp_path / "records.jsonl"
    app = create_proxy_application(
        "http://127.0.0.1:9", policy, record_out=record_path, lease_file=lease_file, lease_required=True
    )
    call(
        app,
        {"jsonrpc": "2.0", "id": "lease", "method": "tools/call", "params": {"name": "read"}},
        headers=[(b"x-snulbug-lease", b"sbl_test_value")],
    )
    audit = build_audit_event(load_record_log(record_path)[0])
    assert audit["explanation"]["stage"] == "lease"
    assert audit["explanation"]["reason_code"] == "lease.revoked"
    assert audit["explanation"]["execution"] == "not_forwarded"


def test_live_facade_partial_fanout_uses_existing_health_controls_and_safe_evidence(policy, tmp_path, monkeypatch):
    calls = []

    async def forward(_self, _routes, upstream, _scope, _body, request):
        calls.append(upstream.name)
        if upstream.name == "remote":
            raise TimeoutError("private-value")
        return {
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
            "body": json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {"tools": []}}).encode(),
        }

    monkeypatch.setattr(proxy.McpFacadeProxyApp, "_forward_upstream", forward)
    record_path = tmp_path / "records.jsonl"
    app = create_proxy_application(
        None,
        policy,
        record_out=record_path,
        facade_health_routing=True,
        upstreams=[
            {"name": "remote", "url": "http://127.0.0.1:9/mcp", "tool_prefix": "remote."},
            {"name": "local", "url": "http://127.0.0.1:8/mcp", "tool_prefix": "local."},
        ],
    )
    sent = call(app, {"jsonrpc": "2.0", "id": "fanout", "method": "tools/list"})
    audit = build_audit_event(load_record_log(record_path)[0])
    assert sent[0]["status"] == 200
    assert calls == ["remote", "local"]
    assert audit["explanation"]["outcome"] == "partial"
    assert audit["explanation"]["evidence"]["upstream"] == "remote"
    assert "private-value" not in record_path.read_text() + str(sent)

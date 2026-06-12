from __future__ import annotations

import asyncio
import json
from typing import Any

from examples.customer_policy.app import application
from snulbug import simulate_policy


def run_demo_request(
    *,
    tenant: str,
    method: str = "POST",
    path: str = "/webhooks/raw",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> list[dict[str, Any]]:
    raw_headers = [(b"x-tenant", tenant.encode("latin-1"))]
    if headers:
        raw_headers.extend(headers)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": raw_headers,
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

    asyncio.run(application(scope, receive, send))
    return sent


def test_acme_policy_rewrites_valid_signed_request():
    sent = run_demo_request(
        tenant="acme",
        headers=[(b"x-acme-signature", b"signed-demo")],
        body=b'{"event":"invoice.created"}',
    )

    payload = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 200
    assert payload["path"] == "/tenants/acme/events"
    assert payload["query_string"] == "source=acme-policy"
    assert payload["tenant_context"]["tenant"] == "acme"
    assert payload["policy_trace"]["action"] == "rewrite"


def test_acme_policy_rejects_unsigned_request():
    sent = run_demo_request(tenant="acme", body=b'{"event":"invoice.created"}')

    assert sent[0]["status"] == 401
    assert json.loads(sent[1]["body"]) == {"error": "missing or invalid Acme signature"}


def test_globex_policy_can_short_circuit_sandbox_request():
    sent = run_demo_request(
        tenant="globex",
        path="/callbacks",
        headers=[(b"x-globex-env", b"sandbox")],
        body=b'{"test":true}',
    )

    assert sent[0]["status"] == 202
    assert json.loads(sent[1]["body"]) == {"accepted": True, "mode": "sandbox"}


def test_unknown_tenant_uses_default_reject_policy():
    sent = run_demo_request(tenant="initech", path="/callbacks")

    assert sent[0]["status"] == 404
    assert json.loads(sent[1]["body"]) == {"error": "unknown tenant policy"}


def test_customer_policy_fixture_can_be_simulated():
    result = simulate_policy(
        "examples/customer_policy/policies/acme.lua",
        json.loads(open("examples/customer_policy/requests/acme-valid.json", encoding="utf-8").read()),
    )

    assert result["action"] == "rewrite"
    assert result["decision"]["path"] == "/tenants/acme/events"

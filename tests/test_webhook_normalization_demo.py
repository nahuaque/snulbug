from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from examples.webhook_normalization.app import application
from snulbug import simulate_policy

REQUEST_DIR = Path("examples/webhook_normalization/requests")


def run_webhook_request(fixture_name: str) -> list[dict[str, Any]]:
    fixture = json.loads((REQUEST_DIR / fixture_name).read_text(encoding="utf-8"))
    headers = [(name.encode("latin-1"), str(value).encode("latin-1")) for name, value in fixture["headers"].items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": fixture["method"],
        "scheme": "http",
        "path": fixture["path"],
        "raw_path": fixture["path"].encode(),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "state": {},
    }
    messages = [{"type": "http.request", "body": fixture["body"].encode("utf-8"), "more_body": False}]
    sent = []

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(application(scope, receive, send))
    return sent


def test_stripe_webhook_is_normalized_before_app_receives_it():
    sent = run_webhook_request("stripe-invoice.json")

    payload = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 200
    assert payload["received_path"] == "/webhooks/normalized"
    assert payload["normalized_webhook"] == {
        "vendor": "stripe",
        "event_id": "evt_123",
        "event_type": "invoice.payment_succeeded",
        "subject": "cus_456",
        "source_path": "/webhooks/stripe",
    }
    assert payload["received_headers"]["x-webhook-vendor"] == "stripe"
    assert payload["normalization_context"]["event_id"] == "evt_123"
    assert payload["policy_trace"]["body_rewritten"] is True


def test_github_webhook_is_normalized_before_app_receives_it():
    sent = run_webhook_request("github-push.json")

    payload = json.loads(sent[1]["body"])
    assert sent[0]["status"] == 200
    assert payload["received_path"] == "/webhooks/normalized"
    assert payload["normalized_webhook"] == {
        "vendor": "github",
        "event_id": "2f1c2a3b-demo",
        "event_type": "push",
        "subject": "octo-org/widgets",
        "source_path": "/webhooks/github",
    }
    assert payload["received_headers"]["x-webhook-vendor"] == "github"


def test_malformed_stripe_webhook_is_rejected_by_policy():
    sent = run_webhook_request("stripe-malformed.json")

    assert sent[0]["status"] == 422
    assert json.loads(sent[1]["body"]) == {"error": "Stripe payload missing id or type"}


def test_unknown_webhook_vendor_is_rejected_by_default_policy():
    sent = run_webhook_request("unknown-vendor.json")

    assert sent[0]["status"] == 404
    assert json.loads(sent[1]["body"]) == {"error": "no webhook normalizer installed for this path"}


def test_webhook_normalization_fixture_can_be_replayed():
    result = simulate_policy(
        "examples/webhook_normalization/policies/github.lua",
        json.loads((REQUEST_DIR / "github-push.json").read_text(encoding="utf-8")),
    )

    assert result["action"] == "rewrite"
    assert json.loads(result["decision"]["body"]) == {
        "vendor": "github",
        "event_id": "2f1c2a3b-demo",
        "event_type": "push",
        "subject": "octo-org/widgets",
        "source_path": "/webhooks/github",
    }

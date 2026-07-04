from __future__ import annotations

import json

from snulbug.mcp_resources import (
    ResourcePolicyConfig,
    enforce_mcp_resource_request_policy,
    enforce_mcp_resource_response_policy,
    mcp_resource_request_metadata,
    mcp_resource_response_metadata,
)
from snulbug.state import MemoryStateStore


def test_mcp_resource_metadata_identifies_subscription_and_change_events():
    subscribe = mcp_resource_request_metadata(
        {
            "jsonrpc": "2.0",
            "id": "sub-1",
            "method": "resources/subscribe",
            "params": {"uri": "file:///project/README.md"},
        }
    )
    changed = mcp_resource_response_metadata(
        {
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": {"uri": "file:///project/README.md"},
        }
    )

    assert subscribe["operation"] == "subscribe"
    assert subscribe["resource"]["uri"] == "file:///project/README.md"
    assert changed["updated_count"] == 1
    assert changed["events"][0]["operation"] == "updated"


def test_mcp_resource_request_policy_blocks_subscribe_without_uri():
    allowed, metadata = enforce_mcp_resource_request_policy(
        {
            "jsonrpc": "2.0",
            "id": "sub-1",
            "method": "resources/subscribe",
            "params": {},
        },
        config=ResourcePolicyConfig(action="block"),
        state_store=MemoryStateStore(),
    )

    assert allowed is False
    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "request.resource_uri_missing"


def test_mcp_resource_response_policy_tracks_subscribe_and_unsubscribe():
    store = MemoryStateStore()
    config = ResourcePolicyConfig(action="block")
    request = {
        "jsonrpc": "2.0",
        "id": "sub-1",
        "method": "resources/subscribe",
        "params": {"uri": "file:///project/README.md"},
    }
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps({"jsonrpc": "2.0", "id": "sub-1", "result": {}}).encode(),
    }

    _, metadata = enforce_mcp_resource_response_policy(response, request=request, config=config, state_store=store)
    assert metadata["subscription"]["operation"] == "subscribe"

    update = {
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {"uri": "file:///project/README.md"},
    }
    allowed, metadata = enforce_mcp_resource_request_policy(update, config=config, state_store=store)
    assert allowed is True
    assert metadata["tracked"] is True

    unsubscribe = {
        "jsonrpc": "2.0",
        "id": "unsub-1",
        "method": "resources/unsubscribe",
        "params": {"uri": "file:///project/README.md"},
    }
    response["body"] = json.dumps({"jsonrpc": "2.0", "id": "unsub-1", "result": {}}).encode()
    _, metadata = enforce_mcp_resource_response_policy(response, request=unsubscribe, config=config, state_store=store)
    assert metadata["subscription"]["operation"] == "unsubscribe"

    allowed, metadata = enforce_mcp_resource_request_policy(update, config=config, state_store=store)
    assert allowed is False
    assert metadata["reason_code"] == "request.resource_update_unknown_subscription"


def test_mcp_resource_response_policy_blocks_unknown_sse_resource_update():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"text/event-stream")],
        "body": (
            b'data: {"jsonrpc":"2.0","method":"notifications/resources/updated",'
            b'"params":{"uri":"file:///project/README.md"}}\n\n'
        ),
    }

    updated, metadata = enforce_mcp_resource_response_policy(
        response,
        request=None,
        config=ResourcePolicyConfig(action="block"),
        state_store=MemoryStateStore(),
    )

    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "request.resource_update_unknown_subscription"
    assert "error" in updated["body"].decode("utf-8")
    assert "notifications/resources/updated" in updated["body"].decode("utf-8")

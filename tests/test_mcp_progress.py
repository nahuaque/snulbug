from __future__ import annotations

import json

from snulbug.mcp_progress import (
    ProgressPolicyConfig,
    enforce_mcp_progress_request_policy,
    enforce_mcp_progress_response_policy,
    mcp_progress_request_metadata,
    mcp_progress_response_metadata,
)
from snulbug.state import MemoryStateStore


def test_mcp_progress_request_policy_blocks_non_monotonic_progress():
    store = MemoryStateStore()
    config = ProgressPolicyConfig(action="block")
    request = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "task": {},
            "_meta": {"progressToken": "progress-1"},
        },
    }

    allowed, metadata = enforce_mcp_progress_request_policy(request, config=config, state_store=store)
    assert allowed is True
    assert metadata["registered_progress_token"]["type"] == "str"

    allowed, metadata = enforce_mcp_progress_request_policy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "progress-1", "progress": 10},
        },
        config=config,
        state_store=store,
    )
    assert allowed is True
    assert metadata["tracked"] is True

    allowed, metadata = enforce_mcp_progress_request_policy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "progress-1", "progress": 5},
        },
        config=config,
        state_store=store,
    )
    assert allowed is False
    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "request.progress_non_monotonic"


def test_mcp_progress_request_policy_rate_limits_progress_notifications():
    store = MemoryStateStore()
    config = ProgressPolicyConfig(action="block", progress_rate_limit=1)
    request = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "task": {},
            "_meta": {"progressToken": "progress-1"},
        },
    }
    enforce_mcp_progress_request_policy(request, config=config, state_store=store)

    first = {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": "progress-1", "progress": 1},
    }
    second = {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progressToken": "progress-1", "progress": 2},
    }
    assert enforce_mcp_progress_request_policy(first, config=config, state_store=store)[0] is True

    allowed, metadata = enforce_mcp_progress_request_policy(second, config=config, state_store=store)
    assert allowed is False
    assert metadata["reason_code"] == "request.progress_rate_limited"
    assert metadata["rate_count"] == 2


def test_mcp_cancelled_notification_requires_tasks_cancel_for_task_augmented_requests():
    store = MemoryStateStore()
    config = ProgressPolicyConfig(action="block")
    request = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "task": {},
            "_meta": {"progressToken": "progress-1"},
        },
    }
    enforce_mcp_progress_request_policy(request, config=config, state_store=store)

    allowed, metadata = enforce_mcp_progress_request_policy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "call-1", "reason": "stop"},
        },
        config=config,
        state_store=store,
    )

    assert allowed is False
    assert metadata["reason_code"] == "request.cancel_task_requires_tasks_cancel"


def test_mcp_progress_response_policy_blocks_non_monotonic_sse_progress():
    store = MemoryStateStore()
    config = ProgressPolicyConfig(action="block")
    request = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "task": {},
            "_meta": {"progressToken": "progress-1"},
        },
    }
    enforce_mcp_progress_request_policy(request, config=config, state_store=store)

    first = {
        "status": 200,
        "headers": [(b"content-type", b"text/event-stream")],
        "body": (
            b'data: {"jsonrpc":"2.0","method":"notifications/progress",'
            b'"params":{"progressToken":"progress-1","progress":7}}\n\n'
        ),
    }
    _, metadata = enforce_mcp_progress_response_policy(first, request=None, config=config, state_store=store)
    assert metadata["checked"] is True
    assert metadata["notifications"][0]["tracked"] is True

    second = {
        "status": 200,
        "headers": [(b"content-type", b"text/event-stream")],
        "body": (
            b'data: {"jsonrpc":"2.0","method":"notifications/progress",'
            b'"params":{"progressToken":"progress-1","progress":6}}\n\n'
        ),
    }
    updated, metadata = enforce_mcp_progress_response_policy(second, request=None, config=config, state_store=store)
    payload = updated["body"].decode("utf-8")
    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "request.progress_non_monotonic"
    assert "error" in payload
    assert "notifications/progress" in payload


def test_mcp_task_terminal_status_expires_progress_token():
    store = MemoryStateStore()
    config = ProgressPolicyConfig(action="block")
    request = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "slow_tool",
            "task": {},
            "_meta": {"progressToken": "progress-1"},
        },
    }
    enforce_mcp_progress_request_policy(request, config=config, state_store=store)
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "call-1",
                "result": {"task": {"taskId": "task-1", "status": "working"}},
            }
        ).encode(),
    }
    enforce_mcp_progress_response_policy(response, request=request, config=config, state_store=store)

    enforce_mcp_progress_request_policy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/tasks/status",
            "params": {"taskId": "task-1", "status": "completed"},
        },
        config=config,
        state_store=store,
    )
    allowed, metadata = enforce_mcp_progress_request_policy(
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "progress-1", "progress": 99},
        },
        config=config,
        state_store=store,
    )

    assert allowed is False
    assert metadata["reason_code"] == "request.progress_unknown_token"


def test_mcp_progress_metadata_hashes_tokens_and_request_ids():
    request_metadata = mcp_progress_request_metadata(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "raw-request-id", "reason": "user stopped"},
        }
    )
    response_metadata = mcp_progress_response_metadata(
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "raw-progress-token", "progress": 1},
        }
    )

    assert request_metadata["request_id"]["hash"]
    assert "raw-request-id" not in json.dumps(request_metadata)
    assert response_metadata["progress"][0]["token"]["hash"]
    assert "raw-progress-token" not in json.dumps(response_metadata)

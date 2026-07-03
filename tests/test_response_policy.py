from __future__ import annotations

import json

from snulbug.response_policy import ResponsePolicyConfig, enforce_mcp_response_policy


def test_mcp_response_policy_redacts_tasks_result_payloads():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "task-result",
                "result": {
                    "content": [{"type": "text", "text": "token is Bearer local-dev-secret"}],
                    "_meta": {"io.modelcontextprotocol/related-task": {"taskId": "task_123"}},
                },
            }
        ).encode(),
    }

    updated, metadata = enforce_mcp_response_policy(
        response,
        request={"jsonrpc": "2.0", "id": "task-result", "method": "tasks/result", "params": {"taskId": "task_123"}},
        config=ResponsePolicyConfig(),
    )
    payload = json.loads(updated["body"].decode())

    assert metadata["checked"] is True
    assert metadata["redacted"] is True
    assert payload["result"]["content"][0]["text"] == "token is [REDACTED]"

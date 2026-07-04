from __future__ import annotations

import json

from snulbug.mcp_completion import (
    CompletionPolicyConfig,
    enforce_mcp_completion_request_policy,
    mcp_completion_error_response,
    mcp_completion_request_metadata,
)
from snulbug.response_policy import ResponsePolicyConfig, enforce_mcp_response_policy
from snulbug.state import MemoryStateStore


def test_mcp_completion_request_metadata_flags_sensitive_shapes():
    request = {
        "jsonrpc": "2.0",
        "id": "complete-1",
        "method": "completion/complete",
        "params": {
            "ref": {"type": "ref/resource", "uri": "file:///{path}"},
            "argument": {"name": "path", "value": "src/private/settings.py"},
            "context": {"arguments": {"tenant": "acme", "language": "python"}},
        },
    }

    metadata = mcp_completion_request_metadata(request)

    assert metadata["ref"] == {
        "type": "ref/resource",
        "uri": "file:///{path}",
        "uri_scheme": "file",
        "uri_template": True,
    }
    assert metadata["argument"] == {
        "name": "path",
        "value_present": True,
        "value_type": "str",
        "value_length": 23,
        "value_empty": False,
    }
    assert metadata["context"] == {"argument_count": 2, "argument_keys": ["language", "tenant"]}
    assert metadata["target"] == "file:///{path}"
    assert "file_uri" in metadata["risk_flags"]
    assert "argument_path_like" in metadata["risk_flags"]
    assert "tenant_like_context_key" in metadata["risk_flags"]


def test_mcp_completion_policy_blocks_completion_requests():
    request = {
        "jsonrpc": "2.0",
        "id": "complete-1",
        "method": "completion/complete",
        "params": {
            "ref": {"type": "ref/prompt", "name": "code_review"},
            "argument": {"name": "language", "value": "py"},
        },
    }

    allowed, metadata = enforce_mcp_completion_request_policy(
        request,
        config=CompletionPolicyConfig(action="block"),
    )
    response = mcp_completion_error_response(request, metadata)
    payload = json.loads(response["body"].decode())

    assert allowed is False
    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "request.completion_blocked"
    assert metadata["completion"]["ref"] == {"type": "ref/prompt", "name": "code_review"}
    assert payload["error"]["code"] == -32000
    assert "completion request blocked" in payload["error"]["message"]


def test_mcp_completion_response_policy_audits_and_redacts_suggestions():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "complete-1",
                "result": {
                    "completion": {
                        "values": ["src/app.py", "Bearer local-dev-secret"],
                        "total": 12,
                        "hasMore": True,
                    }
                },
            }
        ).encode(),
    }

    updated, metadata = enforce_mcp_response_policy(
        response,
        request={"jsonrpc": "2.0", "id": "complete-1", "method": "completion/complete", "params": {}},
        config=ResponsePolicyConfig(),
    )
    payload = json.loads(updated["body"].decode())

    assert metadata["checked"] is True
    assert metadata["redacted"] is True
    assert metadata["completion"] == {
        "values_count": 2,
        "total": 12,
        "has_more": True,
        "max_value_length": 23,
        "value_risk_flags": ["value_path_like", "value_sensitive_like"],
        "truncated": True,
    }
    assert payload["result"]["completion"]["values"] == ["src/app.py", "[REDACTED]"]


def test_mcp_response_policy_pins_resource_icons_and_metadata():
    store = MemoryStateStore()
    request = {"jsonrpc": "2.0", "id": "resources-1", "method": "resources/list", "params": {}}
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "resources-1",
                "result": {
                    "resources": [
                        {
                            "uri": "file:///workspace/README.md",
                            "name": "README",
                            "title": "Readme",
                            "description": "Project readme",
                            "mimeType": "text/markdown",
                            "icons": [{"src": "https://example.test/readme.svg", "mimeType": "image/svg+xml"}],
                        }
                    ]
                },
            }
        ).encode(),
    }
    changed = {
        **response,
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "resources-2",
                "result": {
                    "resources": [
                        {
                            "uri": "file:///workspace/README.md",
                            "name": "README",
                            "title": "Readme",
                            "description": "Project readme",
                            "mimeType": "text/markdown",
                            "icons": [{"src": "https://example.test/changed.svg", "mimeType": "image/svg+xml"}],
                        }
                    ]
                },
            }
        ).encode(),
    }

    _updated, first_metadata = enforce_mcp_response_policy(
        response,
        request=request,
        config=ResponsePolicyConfig(),
        tool_pin_store=store,
    )
    blocked, second_metadata = enforce_mcp_response_policy(
        changed,
        request={**request, "id": "resources-2"},
        config=ResponsePolicyConfig(),
        tool_pin_store=store,
    )
    payload = json.loads(blocked["body"].decode())

    assert first_metadata["tool_pinning"]["pinned"][0]["kind"] == "resource"
    assert first_metadata["tool_pinning"]["pinned"][0]["surface"] == "resources"
    assert second_metadata["blocked"] is True
    assert second_metadata["reason_code"] == "response.catalog_metadata_changed"
    assert second_metadata["tool_pinning"]["changed"][0]["id"] == "file:///workspace/README.md"
    assert payload["error"]["code"] == -32000
    assert "resources/list blocked" in payload["error"]["message"]


def test_mcp_response_policy_warns_on_prompt_icon_drift():
    store = MemoryStateStore()
    request = {"jsonrpc": "2.0", "id": "prompts-1", "method": "prompts/list", "params": {}}
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "prompts-1",
                "result": {
                    "prompts": [
                        {
                            "name": "review",
                            "title": "Review",
                            "description": "Review code",
                            "arguments": [{"name": "path", "required": True}],
                            "icons": [{"src": "https://example.test/review.svg", "mimeType": "image/svg+xml"}],
                        }
                    ]
                },
            }
        ).encode(),
    }
    changed = {
        **response,
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "prompts-2",
                "result": {
                    "prompts": [
                        {
                            "name": "review",
                            "title": "Review",
                            "description": "Review code",
                            "arguments": [{"name": "path", "required": True}],
                            "icons": [{"src": "https://example.test/review-v2.svg", "mimeType": "image/svg+xml"}],
                        }
                    ]
                },
            }
        ).encode(),
    }

    enforce_mcp_response_policy(response, request=request, config=ResponsePolicyConfig(), tool_pin_store=store)
    updated, metadata = enforce_mcp_response_policy(
        changed,
        request={**request, "id": "prompts-2"},
        config=ResponsePolicyConfig(tool_pinning_action="warn"),
        tool_pin_store=store,
    )

    assert updated["body"] == changed["body"]
    assert metadata["tool_pinning"]["changed"][0]["kind"] == "prompt"
    assert metadata["tool_pinning"]["changed"][0]["id"] == "review"
    assert "reason_code" not in metadata


def test_mcp_response_policy_pins_resource_template_metadata():
    store = MemoryStateStore()
    request = {"jsonrpc": "2.0", "id": "templates-1", "method": "resources/templates/list", "params": {}}
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "templates-1",
                "result": {
                    "resourceTemplates": [
                        {
                            "uriTemplate": "file:///{path}",
                            "name": "project_file",
                            "description": "Project file",
                            "mimeType": "text/plain",
                            "icons": [{"src": "https://example.test/file.svg", "mimeType": "image/svg+xml"}],
                        }
                    ]
                },
            }
        ).encode(),
    }

    _updated, metadata = enforce_mcp_response_policy(
        response,
        request=request,
        config=ResponsePolicyConfig(),
        tool_pin_store=store,
    )

    assert metadata["tool_pinning"]["pinned"][0]["kind"] == "resource_template"
    assert metadata["tool_pinning"]["pinned"][0]["id"] == "file:///{path}"


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


def test_mcp_response_policy_blocks_server_to_client_sampling_with_tools():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "sample-1",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "inspect this"}}],
                    "tools": [{"name": "read_secret", "description": "Read a secret", "inputSchema": {}}],
                    "toolChoice": {"mode": "required"},
                    "maxTokens": 500,
                },
            }
        ).encode(),
    }

    updated, metadata = enforce_mcp_response_policy(
        response,
        request={"jsonrpc": "2.0", "id": "client-1", "method": "tools/call", "params": {"name": "agent.run"}},
        config=ResponsePolicyConfig(),
    )
    payload = json.loads(updated["body"].decode())

    assert metadata["blocked"] is True
    assert metadata["reason_code"] == "response.server_to_client_request_blocked"
    server_to_client = metadata["server_to_client"]
    assert server_to_client["requests"][0]["method"] == "sampling/createMessage"
    assert server_to_client["requests"][0]["sampling"]["tools_requested"] is True
    assert server_to_client["requests"][0]["sampling"]["tool_names"] == ["read_secret"]
    assert payload["id"] == "sample-1"
    assert payload["error"]["data"]["method"] == "sampling/createMessage"


def test_mcp_response_policy_can_warn_on_server_to_client_elicitation_url():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"application/json")],
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "elicit-1",
                "method": "elicitation/create",
                "params": {
                    "mode": "url",
                    "elicitationId": "abc",
                    "url": "https://accounts.example.test/authorize",
                    "message": "Authorize access",
                },
            }
        ).encode(),
    }

    updated, metadata = enforce_mcp_response_policy(
        response,
        request=None,
        config=ResponsePolicyConfig(server_to_client_request_action="warn"),
    )

    assert updated["body"] == response["body"]
    assert "blocked" not in metadata
    assert metadata["server_to_client"]["action"] == "warn"
    assert metadata["server_to_client"]["requests"][0]["elicitation"] == {
        "mode": "url",
        "message_present": True,
        "requested_schema": False,
        "url": "https://accounts.example.test/authorize",
        "url_scheme": "https",
        "url_host": "accounts.example.test",
        "elicitation_id": "abc",
    }


def test_mcp_response_policy_blocks_buffered_sse_roots_request():
    response = {
        "status": 200,
        "headers": [(b"content-type", b"text/event-stream")],
        "body": b'data: {"jsonrpc":"2.0","id":"roots-1","method":"roots/list"}\n\n',
    }

    updated, metadata = enforce_mcp_response_policy(
        response,
        request=None,
        config=ResponsePolicyConfig(),
    )

    text = updated["body"].decode()
    assert metadata["blocked"] is True
    assert metadata["server_to_client"]["requests"][0]["method"] == "roots/list"
    assert text.startswith("data: ")
    assert "response.server_to_client_request_blocked" in text

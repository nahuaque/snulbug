from __future__ import annotations

import json

from snulbug import CatalogProjectionConfig, project_mcp_tool_catalog_response


def test_project_mcp_tool_catalog_filters_by_scope_claim_and_lease():
    response = _tools_response(
        [
            {"name": "files.read_file", "description": "Read file"},
            {"name": "git.status", "description": "Show status"},
            {"name": "shell.exec", "description": "Run shell"},
        ]
    )

    projected, metadata = project_mcp_tool_catalog_response(
        response,
        request={"method": "tools/list"},
        config=CatalogProjectionConfig(projection="policy-aware"),
        auth_context={
            "enabled": True,
            "scopes": ["mcp:files"],
            "tenant": "tenant-a",
            "scope_map": {
                "mcp:files": ["tools/call:files.*", "tools/call:git.status"],
            },
        },
        auth_config={
            "claim_policy": {
                "enabled": True,
                "default_action": "deny",
                "rules": [
                    {
                        "id": "tenant-a-files",
                        "claim": "tenant",
                        "values": ["tenant-a"],
                        "allow_tool_prefixes": ["files."],
                        "allow_tools": [],
                        "allow_selectors": ["tools/call:git.status"],
                    }
                ],
            }
        },
        lease={
            "enabled": True,
            "catalog_checked": True,
            "allowed": True,
            "allow_tools": ["files.read_file"],
        },
    )

    payload = json.loads(projected["body"].decode("utf-8"))
    assert [tool["name"] for tool in payload["result"]["tools"]] == ["files.read_file"]
    assert metadata["original_tool_count"] == 3
    assert metadata["visible_tool_count"] == 1
    assert metadata["hidden_reason_counts"] == {
        "lease.tool_not_allowed": 1,
        "oauth.scope_map_denied": 1,
    }


def test_project_mcp_tool_catalog_is_noop_when_disabled():
    response = _tools_response([{"name": "git.status"}])

    projected, metadata = project_mcp_tool_catalog_response(
        response,
        request={"method": "tools/list"},
        config=CatalogProjectionConfig(),
    )

    assert projected == response
    assert metadata == {"enabled": False, "projection": "off", "method": "tools/list"}


def _tools_response(tools):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}).encode("utf-8")
    return {
        "status": 200,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))],
        "body": body,
    }

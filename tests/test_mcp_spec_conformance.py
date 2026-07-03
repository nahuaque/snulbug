from __future__ import annotations

from snulbug.mcp_auth import OAuthResourceConfig, mcp_scope_target, oauth_bearer_challenge
from snulbug.mcp_spec_conformance import LATEST_MCP_SPEC_VERSION, run_mcp_2025_11_25_conformance


def test_mcp_2025_conformance_recognizes_latest_client_headers():
    result = run_mcp_2025_11_25_conformance(
        url="http://127.0.0.1:8080/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
        },
        status={"schemas": {"catalog_count": 1, "tool_count": 2}},
        live_checks=False,
    )
    checks = {check["id"]: check for check in result["checks"]}

    assert result["result"]["ok"] is True
    assert checks["mcp2025.transport.accept_header"]["status"] == "pass"
    assert checks["mcp2025.transport.protocol_version_header"]["status"] == "pass"
    assert checks["mcp2025.transport.edge_hardening"]["status"] == "warn"
    assert checks["mcp2025.transport.origin_guard"]["status"] == "skip"
    assert checks["mcp2025.transport.streamable_get"]["status"] == "skip"
    assert checks["mcp2025.schemas.catalog_loaded"]["status"] == "pass"


def test_mcp_2025_conformance_surfaces_public_oauth_share_gaps():
    result = run_mcp_2025_11_25_conformance(
        url="https://share.example.test/mcp",
        headers={},
        proxy_config={
            "auth": {
                "mode": "oauth-resource",
                "resource": "https://share.example.test/mcp",
                "issuer": "https://issuer.example.test",
                "required_scopes": ["mcp:connect"],
                "scope_map": {"mcp:tools.read": ["tools/list"]},
            }
        },
        status={"schemas": {"catalog_count": 0, "tool_count": 0}},
        live_checks=False,
    )
    checks = {check["id"]: check for check in result["checks"]}

    assert result["result"]["ok"] is True
    assert checks["mcp2025.transport.accept_header"]["status"] == "warn"
    assert checks["mcp2025.transport.edge_hardening"]["status"] == "warn"
    assert checks["mcp2025.transport.origin_guard"]["status"] == "warn"
    assert checks["mcp2025.auth.protected_resource_metadata"]["status"] == "pass"
    assert checks["mcp2025.auth.incremental_scope_challenge"]["status"] == "pass"
    assert checks["mcp2025.auth.client_id_metadata_documents"]["status"] == "warn"
    assert checks["mcp2025.schemas.catalog_loaded"]["status"] == "warn"


def test_mcp_2025_conformance_recognizes_streamable_edge_hardening():
    result = run_mcp_2025_11_25_conformance(
        url="https://share.example.test/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
        },
        proxy_config={
            "streamable_http_hardening": True,
            "streamable_http_require_accept": True,
            "streamable_http_require_content_type": True,
            "streamable_http_allow_get": False,
            "streamable_http_allow_delete": False,
            "streamable_http_allowed_origins": ["https://client.example.test"],
            "streamable_http_protocol_version": LATEST_MCP_SPEC_VERSION,
        },
        status={"schemas": {"catalog_count": 1, "tool_count": 2}},
        live_checks=False,
    )
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["mcp2025.transport.edge_hardening"]["status"] == "pass"
    assert checks["mcp2025.transport.origin_guard"]["status"] == "pass"


def test_mcp_2025_conformance_warns_when_task_tools_lack_server_capability():
    result = run_mcp_2025_11_25_conformance(
        url="http://127.0.0.1:8080/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
        },
        status={
            "schemas": {
                "catalog_count": 1,
                "tool_count": 1,
                "server_tasks_capability": False,
                "task_support": {
                    "counts": {"forbidden": 0, "optional": 0, "required": 1},
                    "task_capable_tools": 1,
                    "task_required_tools": 1,
                },
            }
        },
        live_checks=False,
    )
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["mcp2025.tasks.support"]["status"] == "warn"
    assert checks["mcp2025.tasks.support"]["details"]["task_required_tools"] == 1


def test_oauth_bearer_challenge_can_advertise_incremental_scopes():
    challenge = oauth_bearer_challenge(
        OAuthResourceConfig(
            mode="oauth-resource",
            resource="https://share.example.test/mcp",
            required_scopes=("mcp:connect",),
        ),
        error="insufficient_scope",
        scope=["mcp:connect", "mcp:tools.read", "mcp:connect"],
    )

    assert 'error="insufficient_scope"' in challenge
    assert 'scope="mcp:connect mcp:tools.read"' in challenge


def test_oauth_scope_target_supports_mcp_tasks_methods():
    target = mcp_scope_target(
        b'{"jsonrpc":"2.0","id":"task-result","method":"tasks/result","params":{"taskId":"task_123"}}'
    )

    assert target["task_method"] == "tasks/result"
    assert target["task_id"] == "task_123"
    assert target["selectors"] == ["tasks/result:task_123", "tasks/result"]


def test_oauth_scope_target_supports_server_to_client_methods():
    target = mcp_scope_target(
        b'{"jsonrpc":"2.0","id":"sample-1","method":"sampling/createMessage","params":{"messages":[]}}'
    )

    assert target["server_to_client_method"] == "sampling/createMessage"
    assert target["selectors"] == ["server-to-client:sampling/createMessage", "sampling/createMessage"]

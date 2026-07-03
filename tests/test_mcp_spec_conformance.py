from __future__ import annotations

from snulbug.mcp_auth import OAuthResourceConfig, oauth_bearer_challenge
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
    assert checks["mcp2025.transport.origin_guard"]["status"] == "warn"
    assert checks["mcp2025.auth.protected_resource_metadata"]["status"] == "pass"
    assert checks["mcp2025.auth.incremental_scope_challenge"]["status"] == "pass"
    assert checks["mcp2025.auth.client_id_metadata_documents"]["status"] == "warn"
    assert checks["mcp2025.schemas.catalog_loaded"]["status"] == "warn"


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

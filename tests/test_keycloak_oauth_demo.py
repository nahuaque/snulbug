from __future__ import annotations

import json
from pathlib import Path

from snulbug import load_mcp_proxy_config

EXAMPLE = Path("examples/keycloak_oauth_demo")


def test_keycloak_oauth_demo_config_loads_and_uses_generated_auth_shape():
    config = load_mcp_proxy_config(EXAMPLE / "snulbug.toml")
    auth = config["auth"]

    assert config["upstream"] == "http://mcp-upstream:9000"
    assert config["host"] == "0.0.0.0"
    assert config["port"] == 8081
    assert config["policy"] == EXAMPLE / "policy.snulbug/policy.lua"
    assert config["record_out"] == EXAMPLE / "traces/session.jsonl"
    assert config["event_sinks"][0]["type"] == "audit_jsonl"
    assert config["event_sinks"][0]["path"] == EXAMPLE / "traces/audit.jsonl"
    assert config["lease_required"] is False
    assert auth["mode"] == "oauth-resource"
    assert auth["resource"] == "http://127.0.0.1:18081/mcp"
    assert auth["issuer"] == "http://localhost:8080/realms/snulbug-demo"
    assert auth["audience"] == "http://127.0.0.1:18081/mcp"
    assert auth["required_scopes"] == ["mcp:connect"]
    assert auth["issuer_discovery"] is True
    assert auth["strip_authorization_upstream"] is True
    assert auth["scope_map"]["mcp:tools.read"] == ["tools/list", "resources/list"]
    assert auth["scope_map"]["mcp:tool.files.read"] == [
        "tools/call:keycloak_demo.safe_read_file",
        "tools/call:keycloak_demo.list_project_files",
    ]


def test_keycloak_oauth_demo_compose_builds_gateway_from_local_source():
    compose = (EXAMPLE / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (EXAMPLE / "Dockerfile.gateway").read_text(encoding="utf-8")

    assert "quay.io/keycloak/keycloak:26.1" in compose
    assert "platform: ${SNULBUG_KEYCLOAK_DEMO_PLATFORM:-linux/amd64}" in compose
    assert "network_mode: service:keycloak" in compose
    assert "18081:8081" in compose
    assert "mcp-upstream" in compose
    for token in ("- snulbug", "- mcp", "- share", "- run", "- --config", "- /demo/snulbug.toml"):
        assert token in compose
    assert "COPY snulbug ./snulbug" in dockerfile
    assert 'uv pip install --system --no-cache "."' in dockerfile
    assert "snulbug[proxy]" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "npm install" not in dockerfile


def test_keycloak_oauth_demo_realm_matches_generated_auth_init():
    metadata = json.loads((EXAMPLE / "auth/keycloak/auth-init.json").read_text(encoding="utf-8"))
    client_request = json.loads((EXAMPLE / "auth/keycloak/client-token-request.json").read_text(encoding="utf-8"))
    realm = json.loads((EXAMPLE / "keycloak/snulbug-demo-realm.json").read_text(encoding="utf-8"))

    assert metadata["kind"] == "snulbug.auth.init"
    assert metadata["provider"] == "keycloak"
    assert metadata["public_url"] == "http://127.0.0.1:18081/mcp"
    assert client_request == {
        "audience": "http://127.0.0.1:18081/mcp",
        "client_id": "snulbug-agent",
        "issuer": "http://localhost:8080/realms/snulbug-demo",
        "scopes": [
            "mcp:connect",
            "mcp:tools.read",
            "mcp:tool.files.read",
            "mcp:tool.git.status",
        ],
    }
    assert realm["realm"] == "snulbug-demo"
    client = realm["clients"][0]
    assert client["clientId"] == "snulbug-agent"
    assert client["secret"] == "snulbug-agent-secret"
    assert "mcp:tool.files.read" in client["defaultClientScopes"]
    mapper = client["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.custom.audience"] == "http://127.0.0.1:18081/mcp"

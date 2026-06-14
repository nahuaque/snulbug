from __future__ import annotations

import json

from snulbug import generate_mcp_auth_recipe
from snulbug.simulator import main as simulator_main


def test_generate_keycloak_auth_recipe_includes_snulbug_oauth_config():
    result = generate_mcp_auth_recipe(
        "keycloak",
        public_url="https://mcp.example.test/mcp",
        issuer="https://idp.example.test/realms/dev",
        client_id="mcp-agent",
    )

    assert result["ok"] is True
    assert result["provider"] == "keycloak"
    assert result["issuer"] == "https://idp.example.test/realms/dev"
    assert 'mode = "oauth-resource"' in result["snulbug_config"]
    assert 'resource = "https://mcp.example.test/mcp"' in result["snulbug_config"]
    assert 'audience = "https://mcp.example.test/mcp"' in result["snulbug_config"]
    assert "issuer_discovery = true" in result["snulbug_config"]
    assert "mcp:tool.git.status" in result["snulbug_config"]
    assert "audience mapper" in " ".join(result["provider_steps"])
    assert "share auth doctor" in result["report"]


def test_generate_cloudflare_access_recipe_uses_access_adapter_not_oauth_mode():
    result = generate_mcp_auth_recipe(
        "cloudflare-access",
        public_url="https://mcp.example.test/mcp",
    )

    assert result["ok"] is True
    assert result["provider"] == "cloudflare-access"
    assert 'cloudflare_access = "enforce"' in result["snulbug_config"]
    assert 'mode = "off"' in result["snulbug_config"]
    assert "Cloudflare Access headers" in result["summary"]


def test_generate_github_oidc_recipe_uses_issuer_and_no_mcp_scopes():
    result = generate_mcp_auth_recipe(
        "github-oidc",
        public_url="https://mcp.example.test/mcp",
    )

    assert result["issuer"] == "https://token.actions.githubusercontent.com"
    assert result["scopes"] == []
    assert "required_scopes = []" in result["snulbug_config"]
    assert "lease_required = true" in result["snulbug_config"]


def test_share_auth_recipe_cli_emits_compact_json(tmp_path, capsys):
    output_path = tmp_path / "auth0-recipe.md"
    status = simulator_main(
        [
            "mcp",
            "share",
            "auth",
            "recipe",
            "--provider",
            "auth0",
            "--url",
            "https://mcp.example.test/mcp",
            "--domain",
            "tenant.example.test",
            "--client-id",
            "mcp-agent",
            "--output",
            str(output_path),
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["provider"] == "auth0"
    assert output["issuer"] == "https://tenant.example.test/"
    assert output["output"] == str(output_path)
    assert output_path.is_file()
    assert "Auth0" in output_path.read_text(encoding="utf-8")

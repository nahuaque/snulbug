from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from snulbug import (
    AuthProvider,
    AuthProviderRecipeContext,
    auth_provider_claim_context,
    generate_mcp_auth_init,
    generate_mcp_auth_recipe,
    get_auth_provider,
    list_auth_providers,
    register_auth_provider,
)
from snulbug.simulator import main as simulator_main


class FixtureAuthProvider(AuthProvider):
    name = "fixture-auth"
    title = "Fixture Auth"
    docs = ("https://example.test/fixture-auth",)
    context_key = "fixture"

    def recipe(self, context: AuthProviderRecipeContext) -> dict[str, Any]:
        return {
            "ok": True,
            "kind": "snulbug.auth.recipe",
            "provider": self.name,
            "title": self.title,
            "public_url": context.public_url,
            "issuer": context.issuer or "https://fixture-idp.example.test",
            "audience": context.audience or context.public_url,
            "scopes": list(context.scopes),
            "summary": "Fixture auth provider recipe.",
            "provider_steps": ["Create a fixture auth application."],
            "client_request": {"audience": context.audience or context.public_url},
            "snulbug_config": '[mcp.auth]\nmode = "oauth-resource"\n',
            "commands": {"doctor": f"snulbug mcp share auth doctor --url {context.public_url}"},
            "docs": list(self.docs),
        }

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        tenant = claims.get("fixture_tenant")
        return {"tenant": tenant} if tenant else {}


def register_fixture_auth_provider() -> None:
    register_auth_provider(FixtureAuthProvider(), replace=True)


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
    assert "cloudflare_access_validate_jwt = true" in result["snulbug_config"]
    assert 'mode = "off"' in result["snulbug_config"]
    assert "Cloudflare Access assertion" in result["summary"]


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


def test_generate_auth_init_writes_provider_setup_files(tmp_path):
    result = generate_mcp_auth_init(
        "keycloak",
        public_url="https://mcp.example.test/mcp",
        issuer="https://idp.example.test/realms/dev",
        client_id="mcp-agent",
        output_dir=tmp_path / "auth/keycloak",
    )

    files = result["files"]
    metadata = json.loads((tmp_path / "auth/keycloak/auth-init.json").read_text(encoding="utf-8"))

    assert result["ok"] is True
    assert result["provider"] == "keycloak"
    assert files["readme"] == str(tmp_path / "auth/keycloak/README.md")
    assert files["config"] == str(tmp_path / "auth/keycloak/snulbug.auth.toml")
    assert files["client_request"] == str(tmp_path / "auth/keycloak/client-token-request.json")
    assert files["commands"] == str(tmp_path / "auth/keycloak/commands.json")
    assert 'mode = "oauth-resource"' in (tmp_path / "auth/keycloak/snulbug.auth.toml").read_text(encoding="utf-8")
    assert "snulbug auth recipe: Keycloak" in (tmp_path / "auth/keycloak/README.md").read_text(encoding="utf-8")
    assert metadata["written_files"] == result["written_files"]
    assert "share auth doctor" in result["commands"]["doctor"]


def test_share_auth_init_cli_emits_compact_json_and_writes_files(tmp_path, capsys):
    output_dir = tmp_path / "auth0"
    status = simulator_main(
        [
            "mcp",
            "share",
            "auth",
            "init",
            "--provider",
            "auth0",
            "--url",
            "https://mcp.example.test/mcp",
            "--domain",
            "tenant.example.test",
            "--client-id",
            "mcp-agent",
            "--output-dir",
            str(output_dir),
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["kind"] == "snulbug.auth.init"
    assert output["provider"] == "auth0"
    assert output["directory"] == str(output_dir)
    assert output["files"]["readme"] == str(output_dir / "README.md")
    assert (output_dir / "README.md").is_file()
    assert (output_dir / "snulbug.auth.toml").is_file()
    assert "Auth0" in (output_dir / "README.md").read_text(encoding="utf-8")


def test_auth_provider_registry_accepts_custom_recipe_and_claim_mapper():
    register_fixture_auth_provider()

    result = generate_mcp_auth_recipe(
        "fixture-auth",
        public_url="https://mcp.example.test/mcp",
        scopes=["mcp:connect"],
    )
    context = auth_provider_claim_context({"fixture_tenant": "tenant-a"})

    assert "fixture-auth" in list_auth_providers()
    assert get_auth_provider("fixture-auth").title == "Fixture Auth"
    assert result["ok"] is True
    assert result["provider"] == "fixture-auth"
    assert result["issuer"] == "https://fixture-idp.example.test"
    assert "Fixture auth provider recipe." in result["report"]
    assert context["fixture"] == {"tenant": "tenant-a"}


def test_share_auth_recipe_cli_accepts_registered_custom_provider(capsys):
    register_fixture_auth_provider()
    status = simulator_main(
        [
            "mcp",
            "share",
            "auth",
            "recipe",
            "--provider",
            "fixture-auth",
            "--url",
            "https://mcp.example.test/mcp",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["provider"] == "fixture-auth"
    assert output["issuer"] == "https://fixture-idp.example.test"

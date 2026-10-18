from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from snulbug import (
    build_mcp_schema_catalog,
    doctor_mcp_share_auth,
    generate_auth_conformance_pack,
    generate_mcp_auth_init,
    generate_mcp_auth_recipe,
    list_auth_providers,
    run_auth_conformance_pack,
)
from snulbug.config import load_mcp_proxy_config
from snulbug.mcp_auth import (
    RemoteIssuerMetadataCache,
    RemoteJwksCache,
    evaluate_oauth_request,
    evaluate_scope_map,
    protected_resource_metadata,
)
from snulbug.proxy import _oauth_resource_config
from snulbug.simulator import main

FIXTURE = json.loads((Path(__file__).parent / "fixtures/pocket_id/oauth.json").read_text(encoding="utf-8"))
ISSUER = FIXTURE["issuer_metadata"]["issuer"]
RESOURCE = "https://mcp.example.test/mcp"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def pocket_auth(tmp_path, signing_key):
    result = generate_mcp_auth_init("pocket-id", public_url=RESOURCE, issuer=ISSUER, output_dir=tmp_path / "auth")
    config_path = Path(result["files"]["config"])
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "[mcp.proxy]\n", '[mcp.proxy]\nupstream = "http://127.0.0.1:9000/mcp"\n'
        ),
        encoding="utf-8",
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwks = {"keys": [{**jwk, "kid": "pocket-id-test", "alg": "RS256", "use": "sig"}]}
    config = replace(
        _oauth_resource_config(load_mcp_proxy_config(config_path)["auth"]),
        issuer_metadata_cache=RemoteIssuerMetadataCache(),
        jwks_cache=RemoteJwksCache(),
    )
    return config_path, config, jwks


def sign_case(signing_key, case):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "user-123",
        "client_id": "agent-client",
        "iat": now - 7200,
        "exp": now + case.get("expires_in", 3600),
        "jti": "synthetic-token-id",
        **case["claims"],
    }
    return jwt.encode(
        claims, signing_key, algorithm="RS256", headers={"kid": "pocket-id-test", "typ": case.get("typ", "at+jwt")}
    )


def check_token(token, config, *, method="tools/list", params=None):
    return evaluate_oauth_request(
        {"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode("ascii"))]},
        config=config,
        body=json.dumps({"jsonrpc": "2.0", "id": "test", "method": method, "params": params or {}}).encode(),
    )


def mock_runtime_discovery(monkeypatch, jwks):
    calls = []

    def fetch(url, **_kwargs):
        calls.append(url)
        if url in {f"{ISSUER}/.well-known/oauth-authorization-server", f"{ISSUER}/.well-known/openid-configuration"}:
            return dict(FIXTURE["issuer_metadata"])
        assert url == FIXTURE["issuer_metadata"]["jwks_uri"]
        return jwks

    monkeypatch.setattr("snulbug.mcp_auth._fetch_remote_json", fetch)
    return calls


def test_pocket_id_recipe_uses_resource_permissions_and_existing_registry():
    recipe = generate_mcp_auth_recipe("pocket-id", public_url=RESOURCE, domain="id.example.test", client_id="agent")

    assert "pocket-id" in list_auth_providers()
    assert recipe["issuer"] == ISSUER
    assert recipe["audience"] == RESOURCE
    assert recipe["client_request"]["resource"] == RESOURCE
    assert recipe["client_request"]["code_challenge_method"] == "S256"
    assert recipe["client_request"]["scopes"] == ["openid", *recipe["scopes"]]
    assert "CIMD is disabled by default" in recipe["report"]
    assert "Client access (M2M)" in recipe["report"]
    assert "Empty selector lists grant no MCP actions" in recipe["report"]
    assert "not access tokens" in recipe["report"]
    assert "--token $ACCESS_TOKEN" in recipe["commands"]["doctor"]
    assert '--header "x-snulbug-lease: ${SNULBUG_LEASE}"' in recipe["commands"]["doctor"]


@pytest.mark.parametrize("scopes", [["mcp:connect"], ["mcp:custom"], ["mcp:tools.read"]])
def test_pocket_id_subset_and_custom_scopes_keep_a_deny_by_default_map(tmp_path, scopes):
    generated = generate_mcp_auth_init(
        "pocket-id", public_url=RESOURCE, issuer=ISSUER, scopes=scopes, output_dir=tmp_path
    )
    path = Path(generated["files"]["config"])
    path.write_text(path.read_text().replace("[mcp.proxy]\n", '[mcp.proxy]\nupstream = "http://127.0.0.1:9000/mcp"\n'))
    config = _oauth_resource_config(load_mcp_proxy_config(path)["auth"])
    permissions = {"mcp:connect", *scopes}

    assert set(config.scopes_supported) == permissions
    assert set(config.mapped_scopes) == permissions
    assert config.required_scopes == ("mcp:connect",)
    decision = evaluate_scope_map(
        body=b'{"method":"tools/call","params":{"name":"delete_everything"}}', scopes=list(permissions), config=config
    )
    assert decision["allowed"] is False


def test_pocket_id_rejects_client_id_as_resource_audience():
    with pytest.raises(ValueError, match="audience must equal the public MCP URL"):
        generate_mcp_auth_recipe("pocket-id", public_url=RESOURCE, issuer=ISSUER, audience="agent-client")


@pytest.mark.parametrize(
    "issuer", ["http://id.example.test", "https://user:secret@id.example.test", "https://id.example.test?token=secret"]
)
def test_pocket_id_recipe_rejects_unsafe_issuer_urls(issuer):
    with pytest.raises(ValueError, match="Pocket ID issuer must be"):
        generate_mcp_auth_recipe("pocket-id", public_url=RESOURCE, issuer=issuer)


def test_pocket_id_identity_scopes_are_not_api_permissions():
    with pytest.raises(ValueError, match="API permission keys"):
        generate_mcp_auth_recipe("pocket-id", public_url=RESOURCE, issuer=ISSUER, scopes=["openid", "mcp:connect"])


def test_pocket_id_init_cli_writes_normal_auth_setup_files(tmp_path, capsys):
    assert (
        main(
            [
                "mcp",
                "share",
                "auth",
                "init",
                "--provider",
                "pocket-id",
                "--url",
                RESOURCE,
                "--issuer",
                ISSUER,
                "--output-dir",
                str(tmp_path),
                "--compact",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["provider"] == "pocket-id"
    assert len(result["written_files"]) == 5
    assert "SNULBUG_LEASE" in result["commands"]["doctor"]
    assert json.loads(Path(result["files"]["client_request"]).read_text())["resource"] == RESOURCE
    assert "lease_required = true" in Path(result["files"]["config"]).read_text()
    assert "strip_authorization_upstream = true" in Path(result["files"]["config"]).read_text()


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_pocket_id_signed_token_fixtures_use_existing_validation(pocket_auth, signing_key, monkeypatch, case):
    _path, config, jwks = pocket_auth
    mock_runtime_discovery(monkeypatch, jwks)
    token = sign_case(signing_key, case)

    decision = check_token(token, config)

    assert decision.allowed is case["allowed"]
    assert decision.metadata["reason_code"] == case["reason_code"]
    assert token not in json.dumps(decision.metadata)
    if decision.allowed:
        assert decision.context["subject"] == case["claims"]["sub"]
        assert decision.context["client_id"] == "agent-client"
        assert not decision.context.get("groups")
        assert not decision.context.get("tenant")


def test_pocket_id_discovery_caches_jwks_and_gates_tool_scopes(pocket_auth, signing_key, monkeypatch):
    _path, config, jwks = pocket_auth
    calls = mock_runtime_discovery(monkeypatch, jwks)
    token = sign_case(signing_key, FIXTURE["cases"][0])
    assert check_token(token, config).allowed
    denied = check_token(token, config, method="tools/call", params={"name": "filesystem.read_file"})
    assert not denied.allowed
    assert denied.metadata["reason_code"] == "oauth.scope_map_denied"
    assert len(calls) == 2
    assert config.jwks_cache.snapshot()["totals"]["hits"] == 1


def test_pocket_id_rejects_a_token_signed_by_an_untrusted_key(pocket_auth, monkeypatch):
    _path, config, jwks = pocket_auth
    mock_runtime_discovery(monkeypatch, jwks)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    decision = check_token(sign_case(other_key, FIXTURE["cases"][0]), config)

    assert decision.allowed is False
    assert decision.metadata["reason_code"] == "oauth.invalid_token"


def test_pocket_id_reuses_runtime_jwks_rotation(pocket_auth, signing_key, monkeypatch):
    _path, config, jwks = pocket_auth
    mock_runtime_discovery(monkeypatch, jwks)
    assert check_token(sign_case(signing_key, FIXTURE["cases"][0]), config).allowed
    rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated_jwk = json.loads(RSAAlgorithm.to_jwk(rotated_key.public_key()))
    jwks["keys"] = [{**rotated_jwk, "kid": "pocket-id-test", "alg": "RS256", "use": "sig"}]

    assert check_token(sign_case(rotated_key, FIXTURE["cases"][0]), config).allowed
    assert config.jwks_cache.snapshot()["totals"]["fetches"] == 2


@pytest.mark.parametrize(
    ("changes", "check_id", "status", "ok"),
    [
        ({}, "auth.issuer_metadata.pkce_s256", "pass", True),
        ({"issuer": "https://wrong.example.test"}, "auth.issuer_metadata.issuer", "fail", False),
        ({"issuer": ISSUER + "/"}, "auth.issuer_metadata.issuer", "fail", False),
        ({"issuer": None}, "auth.issuer_metadata.issuer", "fail", False),
        ({"code_challenge_methods_supported": ["plain"]}, "auth.issuer_metadata.pkce_s256", "fail", False),
        ({"client_id_metadata_document_supported": False}, "auth.issuer_metadata.cimd", "skip", True),
    ],
)
def test_pocket_id_doctor_checks_metadata_without_claiming_private_grant_access(
    pocket_auth, monkeypatch, changes, check_id, status, ok
):
    path, config, jwks = pocket_auth
    metadata = {**FIXTURE["issuer_metadata"], **changes}

    def fetch(url, **_kwargs):
        if "oauth-protected-resource" in url:
            payload = protected_resource_metadata(config)
        elif url == metadata["jwks_uri"]:
            payload = jwks
        else:
            payload = metadata
        return {"ok": True, "url": url, "status": 200, "json": payload}

    monkeypatch.setattr("snulbug.share._fetch_auth_json_document", fetch)
    result = doctor_mcp_share_auth(config=path)
    checks = {check["id"]: check for check in result["checks"]}
    assert checks[check_id]["status"] == status
    assert result["ok"] is ok
    assert checks["auth.scope_map.tools_discovered"]["status"] == "skip"
    assert (
        result["live"]["issuer_metadata"]["json"]["scopes_supported"] == FIXTURE["issuer_metadata"]["scopes_supported"]
    )


def test_pocket_id_fixtures_work_with_existing_auth_conformance_pack(pocket_auth, signing_key, monkeypatch, tmp_path):
    path, config, jwks = pocket_auth
    mock_runtime_discovery(monkeypatch, jwks)
    # Use local test keys so the offline conformance run never needs a provider.
    key_path = tmp_path / "jwks.json"
    key_path.write_text(json.dumps(jwks))
    path.write_text(
        path.read_text().replace(
            "issuer_discovery = true", f"issuer_discovery = false\njwks_path = {json.dumps(str(key_path))}"
        )
    )
    catalog = build_mcp_schema_catalog(
        {
            "tools/list": {
                "result": {
                    "tools": [
                        {"name": name, "inputSchema": {"type": "object"}}
                        for name in ("filesystem.read_file", "git.status")
                    ]
                }
            },
            "resources/list": {"result": {"resources": []}},
        }
    )
    catalog_path = tmp_path / "schemas.json"
    catalog_path.write_text(json.dumps(catalog))
    allowed = sign_case(signing_key, FIXTURE["cases"][0])
    denied = sign_case(signing_key, FIXTURE["cases"][2])
    monkeypatch.setenv("POCKET_ID_TEST_ACCESS", allowed)
    monkeypatch.setenv("POCKET_ID_TEST_WRONG_AUDIENCE", denied)
    decision = check_token(allowed, config)
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(
        json.dumps(
            {
                "type": "snulbug.audit",
                "version": 1,
                "auth": decision.metadata,
                "request": {"method": "POST", "path": "/mcp"},
                "mcp": {"method": "tools/list"},
                "decision": {"action": "continue", "allowed": True},
                "response": {"status": 200},
            }
        )
        + "\n"
    )
    pack = tmp_path / "conformance"
    generate_auth_conformance_pack(
        config=path,
        public_url=RESOURCE,
        schema_catalogs=[catalog_path],
        logs=[audit_path],
        kind="audit",
        token_envs=["valid=POCKET_ID_TEST_ACCESS"],
        denied_token_envs=["wrong-audience=POCKET_ID_TEST_WRONG_AUDIENCE"],
        output=pack,
    )
    result = run_auth_conformance_pack(pack, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert checks["tokens.valid"]["status"] == "pass"
    assert checks["tokens.wrong_audience"]["status"] == "pass"
    assert checks["schemas.scope_map_targets"]["status"] == "pass"
    assert checks["logs.scope_map_evidence"]["status"] == "pass"
    assert allowed not in json.dumps(result)
    assert denied not in json.dumps(result)
    for artifact in pack.rglob("*"):
        if artifact.is_file():
            assert allowed not in artifact.read_text()
            assert denied not in artifact.read_text()

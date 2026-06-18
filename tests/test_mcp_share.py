from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import jwt
import pytest

from snulbug import (
    ShareDoctorCheck,
    ShareDoctorCheckResult,
    ShareDoctorContext,
    activate_mcp_share_policy,
    append_record,
    approve_share_capability_request,
    attach_mcp_share_member,
    close_mcp_share,
    create_mcp_share,
    create_mcp_share_invite,
    deny_share_capability_request,
    doctor_mcp_share,
    doctor_mcp_share_auth,
    generate_auth_conformance_pack,
    learn_mcp_policy,
    list_mcp_share_invites,
    list_share_doctor_checks,
    load_fabric_member_registry,
    load_mcp_proxy_config,
    load_share_contract,
    load_share_session_model,
    promote_mcp_share_policy,
    record_policy_request,
    register_share_doctor_check,
    revoke_mcp_share_invite,
    run_auth_conformance_pack,
    run_mcp_share,
    share_capability_requests,
    share_client_config,
    share_contract,
    share_report,
    share_session_model_path,
    share_status,
    write_share_session_model,
)
from snulbug.mcp_schemas import build_mcp_schema_catalog
from snulbug.simulator import main as simulator_main


def test_create_mcp_share_writes_ephemeral_holepunch_session(tmp_path):
    result = create_mcp_share(
        tmp_path,
        provider="holepunch",
        upstream="http://127.0.0.1:9100",
        token="share-secret",
        ttl="15m",
        task="Read docs for collaborator",
        allowed_tools=["safe_read_file"],
        allowed_paths=["README.md"],
        max_calls=3,
    )

    client_config = json.loads((tmp_path / "mcp-client.json").read_text(encoding="utf-8"))
    facade_client_config = json.loads((tmp_path / "containers" / "mcp-client.facade.json").read_text(encoding="utf-8"))
    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    local_config = load_mcp_proxy_config(tmp_path / "containers" / "snulbug.local.toml")
    facade_config = load_mcp_proxy_config(tmp_path / "containers" / "snulbug.facade.toml")
    report = (tmp_path / "SHARE.md").read_text(encoding="utf-8")
    session_model = load_share_session_model(tmp_path)

    assert result["ok"] is True
    assert result["session"]["provider"] == "holepunch"
    assert result["session"]["model"] == str(share_session_model_path(tmp_path))
    assert result["session"]["ttl"] == "15m"
    assert result["client"]["url"] == "http://127.0.0.1:18080/mcp"
    assert result["client"]["headers"]["Authorization"] == "Bearer share-secret"
    assert result["client"]["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert result["generated_session"]["file_map"]["config"] == result["files"]["config"]
    assert result["generated_session"]["file_map"]["session_model"] == result["files"]["session_model"]
    assert result["generated_session"]["primary_client"]["url"] == result["client"]["url"]
    assert result["generated_session"]["command_map"]["run"] == result["commands"]["run"]
    assert result["generated_session"]["log_map"]["audit_log"] == str(tmp_path / "traces" / "audit.jsonl")
    assert result["next_steps"] == result["generated_session"]["next_steps"]
    assert client_config["mcpServers"]["snulbug-share"] == {
        "url": "http://127.0.0.1:18080/mcp",
        "headers": result["client"]["headers"],
    }
    assert proxy_config["upstream"] == "http://127.0.0.1:9100"
    assert proxy_config["lease_required"] is True
    assert proxy_config["tunnel_provider"] == "holepunch"
    assert proxy_config["tunnel_public_url"] == "http://127.0.0.1:18080/mcp"
    assert result["lease"]["lease"]["allow_tools"] == ["safe_read_file"]
    assert result["lease"]["lease"]["allow_paths"] == ["README.md"]
    assert result["lease"]["lease"]["max_calls"] == 3
    assert result["recipes"]["remote_container_upstream"]["kind"] == "remote-container-upstream"
    assert result["recipes"]["remote_container_upstream"]["allowed_tools"] == [
        "local.safe_read_file",
        "remote.safe_read_file",
    ]
    assert result["recipes"]["remote_container_upstream"]["client"]["headers"]["Authorization"] == (
        "Bearer share-secret"
    )
    assert result["recipes"]["remote_container_upstream"]["client"]["url"] == "http://127.0.0.1:18080/mcp"
    assert result["recipes"]["remote_container_upstream"]["client"]["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert (
        str(tmp_path / "containers" / "snulbug.facade.toml")
        in (result["recipes"]["remote_container_upstream"]["written_files"])
    )
    assert result["recipes"]["remote_container_upstream"]["scaffold"]["name"] == "share container recipe"
    assert facade_client_config["mcpServers"]["snulbug-share-facade"]["url"] == "http://127.0.0.1:18080/mcp"
    assert (
        facade_client_config["mcpServers"]["snulbug-share-facade"]["headers"]
        == (result["recipes"]["remote_container_upstream"]["client"]["headers"])
    )
    assert local_config["host"] == "0.0.0.0"
    assert local_config["port"] == 8080
    assert [upstream["name"] for upstream in local_config["upstreams"]] == ["local"]
    assert local_config["upstreams"][0]["url"] == "http://local-mcp:9000/mcp"
    assert facade_config["host"] == "0.0.0.0"
    assert facade_config["port"] == 8080
    assert facade_config["lease_required"] is True
    assert [upstream["name"] for upstream in facade_config["upstreams"]] == ["local", "remote"]
    assert facade_config["upstreams"][0]["url"] == "http://local-mcp:9000/mcp"
    assert facade_config["upstreams"][1]["transport"] == "holepunch"
    assert facade_config["upstreams"][1]["local_port"] == 19100
    assert facade_config["upstreams"][1]["bridge_cwd"] == "/share/containers"
    assert (tmp_path / "containers" / "docker-compose.yml").is_file()
    assert (tmp_path / "containers" / "Dockerfile.gateway").is_file()
    assert (tmp_path / "containers" / "Dockerfile.remote-peer").is_file()
    assert (tmp_path / "containers" / "mock_mcp_server.py").is_file()
    assert (tmp_path / "containers" / "mock_mcp_server.js").is_file()
    assert (tmp_path / "containers" / "snulbug-src" / "pyproject.toml").is_file()
    assert (tmp_path / "containers" / "snulbug-src" / "snulbug" / "share.py").is_file()
    assert (tmp_path / "containers" / "policy.snulbug" / "policy.lua").is_file()
    assert (tmp_path / "containers" / "leases.json").is_file()
    compose = (tmp_path / "containers" / "docker-compose.yml").read_text(encoding="utf-8")
    gateway_dockerfile = (tmp_path / "containers" / "Dockerfile.gateway").read_text(encoding="utf-8")
    remote_dockerfile = (tmp_path / "containers" / "Dockerfile.remote-peer").read_text(encoding="utf-8")
    assert "remote-by-peer-mcp" in compose
    assert "snulbug.local.toml" in compose
    assert "snulbug-src/" in gateway_dockerfile
    assert "snulbug[proxy]" not in gateway_dockerfile
    assert "apt-get" not in gateway_dockerfile
    assert "npm install" not in gateway_dockerfile
    assert "apt-get" not in remote_dockerfile
    assert "python3" not in remote_dockerfile
    assert "mock_mcp_server.js" in remote_dockerfile
    assert (tmp_path / "tunnel" / "hypertele-server.json").is_file()
    assert (tmp_path / "tunnel" / "hypertele-client.json").is_file()
    assert (tmp_path / "share.json").is_file()
    assert share_session_model_path(tmp_path).is_file()
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    assert manifest["type"] == "snulbug.share"
    assert manifest["state"] == "created"
    assert manifest["files"]["session_model"] == str(share_session_model_path(tmp_path))
    assert manifest["commands"]["run"] == f"uv run snulbug mcp share run {tmp_path}"
    assert manifest["commands"]["share_doctor"] == f"uv run snulbug mcp share doctor {tmp_path}"
    assert manifest["client"]["headers"]["Authorization"] == "Bearer share-secret"
    assert manifest["lease"]["id"] == result["lease"]["lease"]["id"]
    assert "snulbug MCP share session" in report
    assert "## Client" in report
    assert "## Files" in report
    assert "Bearer share-secret" not in report
    assert "SNULBUG_SHARE_TOKEN=<redacted>" in report
    assert "uv run snulbug mcp share doctor" in report
    assert "uv run snulbug mcp share close" in report
    assert "Remote container as upstream" in report
    assert session_model["type"] == "snulbug.share.session"
    assert session_model["id"] == tmp_path.name
    assert session_model["status"]["state"] == "created"
    assert session_model["share"]["preset"] == "tunnel-safe"
    assert session_model["gateway"]["config"] == str(tmp_path / "snulbug.toml")
    assert session_model["tunnel"]["provider"] == "holepunch"
    assert session_model["tunnel"]["public_url"] == "http://127.0.0.1:18080/mcp"
    assert session_model["upstreams"] == [{"name": "default", "transport": "http", "url": "http://127.0.0.1:9100"}]
    assert session_model["policy"]["bundle"] == str(tmp_path / "policy.snulbug")
    assert session_model["policy"]["active_policy"] == str(tmp_path / "policy.snulbug" / "policy.lua")
    assert session_model["lease"]["file"] == str(tmp_path / "leases.json")
    assert session_model["evidence"]["record_log"] == str(tmp_path / "traces" / "session.jsonl")
    assert session_model["client"]["header_names"] == ["Authorization", "x-snulbug-lease"]
    assert "Bearer share-secret" not in json.dumps(session_model)


def test_mcp_share_cli_emits_compact_session_plan(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
            "share",
            "create",
            "--directory",
            str(tmp_path),
            "--provider",
            "generic",
            "--url",
            "https://mcp.example.test/mcp",
            "--token",
            "share-secret",
            "--allow-tool",
            "read_repo",
            "--allow-path",
            "docs/",
            "--ttl",
            "10m",
            "--no-validate",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["ok"] is True
    assert output["name"] == "mcp share"
    assert output["metadata"]["provider"] == "generic"
    assert output["client"]["url"] == "https://mcp.example.test/mcp"
    assert output["client"]["headers"]["Authorization"] == "Bearer share-secret"
    assert output["legacy"]["quickstart"]["tests"] is None
    assert output["legacy"]["tunnel"]["written_files"] == [str(tmp_path / "tunnel" / "README.md")]
    assert "fixture_count" not in json.dumps(output["legacy"]["tunnel"])
    assert (tmp_path / "mcp-client.json").is_file()
    assert (tmp_path / "share.json").is_file()
    assert share_session_model_path(tmp_path).is_file()
    assert (tmp_path / "SHARE.md").is_file()


def test_mcp_share_invite_create_list_and_revoke_redacts_stored_snippets(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        allowed_paths=["README.md"],
        validate=False,
    )

    created = create_mcp_share_invite(
        tmp_path,
        recipient="frontend agent",
        task="Read project docs",
        allow_tools=["safe_read_file"],
        allow_paths=["README.md"],
        ttl="10m",
        max_calls=2,
    )
    listing = list_mcp_share_invites(tmp_path)
    session_model = load_share_session_model(tmp_path)
    revoked = revoke_mcp_share_invite(tmp_path, invite_id=created["invite"]["id"])
    active_only = list_mcp_share_invites(tmp_path, include_revoked=False)

    assert created["ok"] is True
    assert created["invite"]["id"].startswith("invite_")
    assert created["invite"]["lease_id"] == created["lease"]["id"]
    assert created["headers"]["Authorization"] == "Bearer share-secret"
    assert created["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert created["bearer_token"] == "share-secret"
    assert created["lease_token"].startswith("sbl_")
    assert created["setup_snippets"]["client_url"] == "https://mcp.example.test/mcp"
    assert created["setup_snippets"]["headers"]["Authorization"] == "Bearer share-secret"
    assert created["setup_snippets"]["env"]["SNULBUG_BEARER_TOKEN"] == "share-secret"
    assert "[mcp_servers.snulbug-share]" in created["setup_snippets"]["codex"]["config_toml"]
    assert 'bearer_token_env_var = "SNULBUG_MCP_BEARER_TOKEN"' in created["setup_snippets"]["codex"]["config_toml"]
    assert '"x-snulbug-lease" = "SNULBUG_MCP_LEASE_TOKEN"' in created["setup_snippets"]["codex"]["config_toml"]
    assert created["setup_snippets"]["codex"]["env"]["SNULBUG_MCP_BEARER_TOKEN"] == "share-secret"
    assert created["setup_snippets"]["codex"]["env"]["SNULBUG_MCP_LEASE_TOKEN"].startswith("sbl_")
    assert "tools/list" in created["setup_snippets"]["curl"]["command"]
    assert "claude mcp add" in created["setup_snippets"]["claude_code"]["command"]
    assert listing["summary"] == {"total": 1, "active": 1, "revoked": 0}
    assert listing["invitations"][0]["recipient"] == "frontend agent"
    assert listing["invitations"][0]["setup_snippets"]["headers"]["Authorization"] == "Bearer [REDACTED]"
    assert "share-secret" not in json.dumps(listing)
    assert "sbl_" not in json.dumps(listing)
    assert "share-secret" not in json.dumps(session_model["invitations"])
    assert "sbl_" not in json.dumps(session_model["invitations"])
    assert revoked["ok"] is True
    assert revoked["lease_revoked"] is True
    assert revoked["invite"]["revoked_at"]
    assert active_only["summary"] == {"total": 0, "active": 0, "revoked": 0}


def test_mcp_share_invite_cli_emits_setup_snippets(tmp_path, capsys):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status = simulator_main(
        [
            "mcp",
            "share",
            "invite",
            "create",
            str(tmp_path),
            "--recipient",
            "local agent",
            "--task",
            "Read docs",
            "--allow-tool",
            "safe_read_file",
            "--allow-path",
            "README.md",
            "--ttl",
            "5m",
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["ok"] is True
    assert output["invite"]["recipient"] == "local agent"
    assert output["headers"]["Authorization"] == "Bearer share-secret"
    assert output["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert output["setup_snippets"]["mcp_client_json"]["mcpServers"]["snulbug-share"]["url"] == (
        "https://mcp.example.test/mcp"
    )
    assert "[mcp_servers.snulbug-share]" in output["setup_snippets"]["codex"]["config_toml"]
    assert "curl -sS https://mcp.example.test/mcp" in output["setup_snippets"]["curl"]["command"]


def test_mcp_share_requires_lifecycle_subcommand(tmp_path):
    with pytest.raises(SystemExit) as exc:
        simulator_main(["mcp", "share", "--directory", str(tmp_path)])

    assert exc.value.code == 2


def test_mcp_share_create_subcommand_emits_compact_session_plan(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
            "share",
            "create",
            "--directory",
            str(tmp_path),
            "--provider",
            "generic",
            "--url",
            "https://mcp.example.test/mcp",
            "--token",
            "share-secret",
            "--allow-tool",
            "read_repo",
            "--no-validate",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["ok"] is True
    assert output["files"]["manifest"] == str(tmp_path / "share.json")
    assert output["legacy"]["files"]["manifest"] == str(tmp_path / "share.json")
    assert (tmp_path / "share.json").is_file()


def test_create_mcp_share_ngrok_writes_cloud_endpoint_artifacts(tmp_path):
    result = create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        ngrok_internal_url="https://team-snulbug.internal",
        ngrok_endpoint_name="team-snulbug-agent",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    policy = tmp_path / "tunnel" / "ngrok-traffic-policy.yml"
    agent = tmp_path / "tunnel" / "ngrok-agent.yml"
    assert result["ok"] is True
    assert policy.is_file()
    assert agent.is_file()
    assert "type: forward-internal" in policy.read_text(encoding="utf-8")
    assert 'url: "https://team-snulbug.internal"' in policy.read_text(encoding="utf-8")
    assert 'name: "team-snulbug-agent"' in agent.read_text(encoding="utf-8")
    assert 'url: "https://team-snulbug.internal"' in agent.read_text(encoding="utf-8")
    assert result["tunnel"]["bridge"]["mode"] == "cloud-endpoint"
    assert result["commands"]["provider"][0] == f"ngrok start --config {agent} --all"
    assert "Attach" in result["commands"]["provider"][1]


def test_create_mcp_share_cloudflare_access_gate_profile_defaults_to_safe_jwt_validation(tmp_path, monkeypatch):
    result = create_mcp_share(
        tmp_path,
        provider="cloudflare",
        public_url="https://mcp.example.com/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)
    doctor = doctor_mcp_share(tmp_path, live_checks=False)
    checks = {check["id"]: check for check in doctor["checks"]}

    assert result["session"]["cloudflare_access_profile"] == "access-gate"
    assert manifest["session"]["cloudflare_access_profile"] == "access-gate"
    assert proxy_config["cloudflare_access_profile"] == "access-gate"
    assert proxy_config["cloudflare_access"] == "enforce"
    assert proxy_config["cloudflare_access_require_jwt"] is True
    assert proxy_config["cloudflare_access_require_cf_ray"] is True
    assert proxy_config["cloudflare_access_validate_jwt"] is True
    assert proxy_config["cloudflare_access_team_domain"] is None
    assert proxy_config["cloudflare_access_audience"] is None
    assert doctor["ok"] is False
    assert checks["cloudflare.access_gate.jwt_config"]["status"] == "fail"


def test_mcp_share_doctor_builtin_checks_are_registered():
    assert list_share_doctor_checks()[:8] == (
        "status",
        "config",
        "policy",
        "cloudflare",
        "tailscale",
        "fabric",
        "conformance",
        "tunnel",
    )


def test_mcp_share_doctor_runs_custom_check_plugin(tmp_path, monkeypatch):
    share_dir = tmp_path / "plugin-share"
    create_mcp_share(
        share_dir,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    class FixtureShareDoctorCheck(ShareDoctorCheck):
        name = "fixture-share-check"
        component = "fixture"

        def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
            if context.share_dir.name != "plugin-share":
                return ShareDoctorCheckResult()
            return ShareDoctorCheckResult(
                checks=[
                    {
                        "id": "fixture.context_loaded",
                        "status": "pass",
                        "message": "fixture check saw loaded share doctor context",
                        "component": "fixture",
                        "details": {
                            "provider": context.provider,
                            "config_loaded": context.proxy_config is not None,
                        },
                    }
                ],
                recommendations=["Review fixture share doctor output."],
                artifacts={"fixture": {"provider": context.provider, "url": context.url}},
            )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    register_share_doctor_check(FixtureShareDoctorCheck(), replace=True)
    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    result = doctor_mcp_share(share_dir, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert checks["fixture.context_loaded"]["status"] == "pass"
    assert checks["fixture.context_loaded"]["details"]["config_loaded"] is True
    assert "fixture-share-check" in [plugin["name"] for plugin in result["doctor_plugins"]]
    assert result["doctor_artifacts"]["fixture"] == {
        "provider": "generic",
        "url": "https://mcp.example.test/mcp",
    }
    assert "Review fixture share doctor output." in result["recommendations"]


def test_mcp_share_cloudflare_service_token_profile_writes_client_headers_and_doctor_checks(
    tmp_path,
    monkeypatch,
):
    create_mcp_share(
        tmp_path,
        provider="cloudflare",
        public_url="https://mcp.example.com/mcp",
        token="share-secret",
        cloudflare_profile="service-token",
        cloudflare_access_team_domain="team.cloudflareaccess.com",
        cloudflare_access_audience="access-aud-tag",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    client = json.loads((tmp_path / "mcp-client.json").read_text(encoding="utf-8"))
    result = doctor_mcp_share(tmp_path, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert client["mcpServers"]["snulbug-share"]["headers"]["CF-Access-Client-Id"] == ("${CLOUDFLARE_ACCESS_CLIENT_ID}")
    assert client["mcpServers"]["snulbug-share"]["headers"]["CF-Access-Client-Secret"] == (
        "${CLOUDFLARE_ACCESS_CLIENT_SECRET}"
    )
    assert result["ok"] is True
    assert result["cloudflare"]["profile"] == "service-token"
    assert checks["cloudflare.access_gate.jwt_config"]["status"] == "pass"
    assert checks["cloudflare.service_token.client_headers"]["status"] == "pass"


def test_mcp_share_cloudflare_oauth_resource_profile_keeps_access_out_of_oauth_path(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="cloudflare",
        public_url="https://mcp.example.com/mcp",
        token="share-secret",
        cloudflare_profile="oauth-resource",
        auth_issuer="https://auth.example.com",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    result = doctor_mcp_share(tmp_path, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert proxy_config["cloudflare_access_profile"] == "oauth-resource"
    assert proxy_config["cloudflare_access"] == "audit"
    assert proxy_config["auth"]["mode"] == "oauth-resource"
    assert proxy_config["auth"]["resource"] == "https://mcp.example.com/mcp"
    assert proxy_config["auth"]["issuer"] == "https://auth.example.com"
    assert result["ok"] is True
    assert result["cloudflare"]["profile"] == "oauth-resource"
    assert checks["cloudflare.oauth_resource.auth_enabled"]["status"] == "pass"
    assert checks["cloudflare.oauth_resource.access_not_enforced"]["status"] == "pass"
    assert checks["cloudflare.oauth_resource.no_access_client_headers"]["status"] == "pass"
    assert checks["cloudflare.oauth_resource.anti_passthrough"]["status"] == "pass"


def test_mcp_share_tailscale_funnel_public_profile_requires_bearer_and_lease(tmp_path, monkeypatch):
    result = create_mcp_share(
        tmp_path,
        provider="tailscale",
        public_url="https://dev.tailnet.ts.net/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    doctor = doctor_mcp_share(tmp_path, live_checks=False)
    checks = {check["id"]: check for check in doctor["checks"]}

    assert result["session"]["tailscale_profile"] == "funnel-public"
    assert manifest["session"]["tailscale_profile"] == "funnel-public"
    assert session_model["tunnel"]["tailscale_profile"] == "funnel-public"
    assert proxy_config["tunnel_provider"] == "tailscale"
    assert proxy_config["tailscale_profile"] == "funnel-public"
    assert proxy_config["lease_required"] is True
    assert doctor["ok"] is True
    assert doctor["tailscale"]["profile"] == "funnel-public"
    assert checks["tailscale.profile.configured"]["status"] == "pass"
    assert checks["tailscale.url.tsnet"]["status"] == "pass"
    assert checks["tailscale.client.bearer"]["status"] == "pass"
    assert checks["tailscale.funnel_public.lease_required"]["status"] == "pass"
    assert checks["tailscale.funnel_public.active_lease"]["status"] == "pass"
    assert checks["tailscale.funnel_public.not_oauth_resource"]["status"] == "pass"


def test_mcp_share_tailscale_oauth_resource_profile_doctor_checks_auth_boundary(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="tailscale",
        public_url="https://dev.tailnet.ts.net/mcp",
        token="share-secret",
        tailscale_profile="oauth-resource",
        auth_issuer="https://auth.example.com",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    contract = share_contract(tmp_path, live_checks=False)["contract"]
    doctor = doctor_mcp_share(tmp_path, live_checks=False)
    checks = {check["id"]: check for check in doctor["checks"]}

    assert proxy_config["tunnel_provider"] == "tailscale"
    assert proxy_config["tailscale_profile"] == "oauth-resource"
    assert proxy_config["auth"]["mode"] == "oauth-resource"
    assert proxy_config["auth"]["resource"] == "https://dev.tailnet.ts.net/mcp"
    assert proxy_config["auth"]["issuer"] == "https://auth.example.com"
    assert proxy_config["auth"]["strip_authorization_upstream"] is True
    assert contract["tailscale"]["profile"] == "oauth-resource"
    assert contract["tailscale"]["auth_mode"] == "oauth-resource"
    assert doctor["ok"] is True
    assert doctor["tailscale"]["profile"] == "oauth-resource"
    assert checks["tailscale.oauth_resource.auth_enabled"]["status"] == "pass"
    assert checks["tailscale.oauth_resource.resource_matches_url"]["status"] == "pass"
    assert checks["tailscale.oauth_resource.anti_passthrough"]["status"] == "pass"


def test_mcp_share_lifecycle_helpers_read_manifest(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status = share_status(tmp_path, live_checks=False)
    client = share_client_config(tmp_path)
    run_plan = run_mcp_share(tmp_path, dry_run=True)

    assert status["ok"] is True
    assert status["state"] == "created"
    assert status["session_model"]["status"]["state"] == "created"
    assert status["session_model_path"] == str(share_session_model_path(tmp_path))
    assert status["lease"]["active"] is True
    assert status["leases"]["active_count"] == 1
    assert status["gateway"]["checked"] is False
    assert status["recordings"]["audit_log"]["exists"] is False
    assert client["config"]["mcpServers"]["snulbug-share"]["headers"]["Authorization"] == "Bearer share-secret"
    assert run_plan is not None
    assert run_plan["source"] == "session_model"
    assert run_plan["resolved_paths"]["config"] == str(tmp_path / "snulbug.toml")
    assert run_plan["resolved_paths"]["policy"] == str(tmp_path / "policy.snulbug" / "policy.lua")
    assert run_plan["resolved_paths"]["lease_file"] == str(tmp_path / "leases.json")
    assert run_plan["resolved_paths"]["record_log"] == str(tmp_path / "traces" / "session.jsonl")
    assert run_plan["resolved_paths"]["audit_log"] == str(tmp_path / "traces" / "audit.jsonl")
    assert run_plan["commands"]["run"] == f"uv run snulbug mcp share run {tmp_path}"


def test_mcp_share_run_reconciles_from_session_model_without_manifest(tmp_path, capsys, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    (tmp_path / "share.json").unlink()

    run_plan = run_mcp_share(tmp_path, dry_run=True)

    assert run_plan is not None
    assert run_plan["source"] == "session_model"
    assert run_plan["commands"] == {}
    assert run_plan["resolved_paths"]["config"] == str(tmp_path / "snulbug.toml")
    assert run_plan["resolved_paths"]["policy"] == str(tmp_path / "policy.snulbug" / "policy.lua")
    assert run_plan["resolved_paths"]["lease_file"] == str(tmp_path / "leases.json")
    assert run_plan["resolved_paths"]["record_log"] == str(tmp_path / "traces" / "session.jsonl")
    assert run_plan["resolved_paths"]["audit_log"] == str(tmp_path / "traces" / "audit.jsonl")

    monkeypatch.chdir(tmp_path)
    status_code = simulator_main(["mcp", "share", "run", "--dry-run", "--compact"])
    output = json.loads(capsys.readouterr().out)

    assert status_code == 0
    assert output["source"] == "session_model"
    assert output["share"] == str(tmp_path)
    assert output["resolved_paths"]["config"] == str(tmp_path / "snulbug.toml")


def test_mcp_share_run_accepts_relative_share_directory_paths(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    share_dir = Path(".snulbug/shares/ngrok-demo")
    create_mcp_share(
        share_dir,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status_code = simulator_main(["mcp", "share", "run", str(share_dir), "--dry-run", "--compact"])
    output = json.loads(capsys.readouterr().out)

    assert status_code == 0
    assert output["ok"] is True
    assert output["resolved_paths"]["config"] == str(share_dir / "snulbug.toml")
    assert output["resolved_paths"]["policy"] == str(share_dir / "policy.snulbug" / "policy.lua")


def test_mcp_share_status_cli_uses_rich_human_output(tmp_path, capsys):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status_code = simulator_main(["mcp", "share", "status", str(tmp_path), "--no-live-checks"])
    output = capsys.readouterr().out

    assert status_code == 0
    assert "snulbug share status" in output
    assert "Health" in output
    assert "Policy And Artifacts" in output
    assert "Traffic" in output
    assert "Next Commands" in output
    assert not output.lstrip().startswith("{")


def test_mcp_share_run_applies_session_model_paths_before_starting_gateway(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    active_policy = tmp_path / "policy.snulbug" / "active.lua"
    active_policy.write_text(
        'return { handle_request = function() return { action = "continue" } end }\n',
        encoding="utf-8",
    )
    replay_log = tmp_path / "traces" / "active-session.jsonl"
    audit_log = tmp_path / "traces" / "active-audit.jsonl"
    lease_file = tmp_path / "active-leases.json"

    session_model = load_share_session_model(tmp_path)
    session_model["policy"]["active_policy"] = str(active_policy)
    session_model["lease"]["file"] = str(lease_file)
    session_model["evidence"]["record_log"] = str(replay_log)
    session_model["evidence"]["audit_log"] = str(audit_log)
    write_share_session_model(tmp_path, session_model, force=True)
    calls = []

    def fake_run_mcp_proxy_config(proxy_config, fabric_config, **kwargs):
        calls.append((proxy_config, fabric_config, kwargs))

    monkeypatch.setattr("snulbug.proxy.run_mcp_proxy_config", fake_run_mcp_proxy_config)

    result = run_mcp_share(tmp_path)
    updated_model = load_share_session_model(tmp_path)

    assert result is None
    assert len(calls) == 1
    proxy_config, fabric_config, kwargs = calls[0]
    assert proxy_config["policy"] == active_policy
    assert proxy_config["lease_file"] == lease_file
    assert kwargs["share_contract"] is None
    assert proxy_config["record_out"] == replay_log
    assert any(
        sink.get("type") == "audit_jsonl" and sink.get("path") == audit_log for sink in proxy_config["event_sinks"]
    )
    assert fabric_config["proxy"] == proxy_config
    assert updated_model["status"]["state"] == "running"
    assert updated_model["policy"]["active_policy"] == str(active_policy)
    assert updated_model["runtime"]["resolved_paths"]["policy"] == str(active_policy)


def test_mcp_share_lifecycle_shortcuts_update_session_model_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SNULBUG_BUNDLE_SECRET", "dev-secret")
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    proposed = promote_mcp_share_policy(tmp_path, to_state="proposed", secret="dev-secret", key_id="dev")
    approved = promote_mcp_share_policy(tmp_path, to_state="approved", secret="dev-secret", key_id="dev")
    activated = activate_mcp_share_policy(tmp_path, secret="dev-secret", key_id="dev")
    session_model = load_share_session_model(tmp_path)
    status = share_status(tmp_path, live_checks=False)
    report = share_report(tmp_path, live_checks=False)

    assert proposed["ok"] is True
    assert proposed["from_state"] == "observed"
    assert proposed["state"] == "proposed"
    assert approved["ok"] is True
    assert approved["from_state"] == "proposed"
    assert approved["state"] == "approved"
    assert activated["ok"] is True
    assert activated["action"] == "activate"
    assert activated["from_state"] == "approved"
    assert activated["state"] == "active"
    assert session_model["policy"]["lifecycle_state"] == "active"
    assert session_model["policy"]["lifecycle_signed"] is True
    assert session_model["policy"]["last_lifecycle"]["action"] == "activate"
    assert status["policy"]["lifecycle_state"] == "active"
    assert status["policy"]["last_lifecycle"]["action"] == "activate"
    assert "activate approved->active" in report["report"]


def test_mcp_share_lifecycle_cli_promote_and_activate_from_cwd(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SNULBUG_BUNDLE_SECRET", "dev-secret")
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    monkeypatch.chdir(tmp_path)

    proposed_code = simulator_main(
        ["mcp", "share", "policy", "promote", "--to", "proposed", "--key-id", "dev", "--compact"]
    )
    proposed = json.loads(capsys.readouterr().out)
    approved_code = simulator_main(
        ["mcp", "share", "policy", "promote", "--to", "approved", "--key-id", "dev", "--compact"]
    )
    approved = json.loads(capsys.readouterr().out)
    active_code = simulator_main(["mcp", "share", "policy", "activate", "--key-id", "dev", "--compact"])
    active = json.loads(capsys.readouterr().out)

    assert proposed_code == 0
    assert proposed["state"] == "proposed"
    assert approved_code == 0
    assert approved["state"] == "approved"
    assert active_code == 0
    assert active["state"] == "active"
    assert load_share_session_model(tmp_path)["policy"]["last_lifecycle"]["action"] == "activate"


def test_mcp_share_policy_cli_amend_records_candidate_from_share_evidence(tmp_path, capsys):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["files.read_file"],
        validate=False,
    )
    allow_policy = tmp_path / "allow.lua"
    allow_policy.write_text(
        """
        return function(request, context, state)
          return {
            action = "continue",
            reason = "observed",
            reason_code = "test.observed"
          }
        end
        """,
        encoding="utf-8",
    )
    observed_log = tmp_path / "observed.jsonl"
    append_record(
        observed_log,
        record_policy_request(
            allow_policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": (
                    '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                    '"params":{"name":"files.read_file","arguments":{"path":"README.md"}}}'
                ),
            },
            response={"status": 200},
        ),
    )
    learn_mcp_policy(observed_log, tmp_path / "policy.snulbug", force=True)
    audit_log = tmp_path / "traces" / "audit.jsonl"
    append_record(
        audit_log,
        record_policy_request(
            tmp_path / "policy.snulbug" / "policy.lua",
            {
                "method": "POST",
                "path": "/mcp",
                "body": (
                    '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                    '"params":{"name":"git.status","arguments":{"staged":true}}}'
                ),
            },
            response={"status": 403},
        ),
    )

    status_code = simulator_main(["mcp", "share", "policy", "amend", str(tmp_path), "--compact"])
    payload = json.loads(capsys.readouterr().out)
    session_model = load_share_session_model(tmp_path)

    assert status_code == 0
    assert payload["ok"] is True
    assert payload["log"] == str(audit_log)
    assert payload["output"] == str(tmp_path / "policy.snulbug")
    assert payload["candidate"]["in_place"] is True
    assert payload["candidate"]["output"] == payload["output"]
    assert (Path(payload["output"]) / "policy.lua").is_file()
    assert {"kind": "tool", "value": "git.status", "reason_code": "mcp.learn.tool_not_observed"} in (
        payload["amendment"]["additions"]
    )
    assert session_model["amendments"]["last"] == payload["output"]
    assert session_model["amendments"]["candidates"][0]["output"] == payload["output"]
    assert session_model["policy"]["last_amendment"]["output"] == payload["output"]


def test_mcp_share_attach_consumes_member_metadata_and_updates_config_session(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    metadata_file = tmp_path / "codespace-member.json"
    metadata_file.write_text(
        json.dumps(
            {
                "member_id": "codespace-a",
                "kind": "codespaces",
                "labels": {"codespace": "demo"},
                "metadata": {"repo": "demo/repo"},
                "upstreams": [{"name": "files", "url": "https://codespace.example.dev/mcp"}],
            }
        ),
        encoding="utf-8",
    )

    result = attach_mcp_share_member(tmp_path, metadata_file=metadata_file, ttl_seconds=120)
    registry_path = tmp_path / ".snulbug" / "fabric-members.json"
    registry = load_fabric_member_registry(registry_path)
    config_text = (tmp_path / "snulbug.toml").read_text(encoding="utf-8")
    proxy_config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    status = share_status(tmp_path, live_checks=False)
    report = share_report(tmp_path, live_checks=False)

    assert result["ok"] is True
    assert result["member_id"] == "codespace-a"
    assert registry["members"]["codespace-a"]["metadata"]["kind"] == "codespaces"
    assert registry["members"]["codespace-a"]["labels"]["codespace"] == "demo"
    assert 'type = "members"' in config_text
    assert 'path = ".snulbug/fabric-members.json"' in config_text
    assert proxy_config["upstreams"][0]["name"] == "codespace-a-files"
    assert proxy_config["upstreams"][0]["fabric_member_id"] == "codespace-a"
    assert proxy_config["upstreams"][0]["url"] == "https://codespace.example.dev/mcp"
    assert manifest["files"]["member_registry"] == str(registry_path)
    assert manifest["members"]["attachments"][0]["member_id"] == "codespace-a"
    assert session_model["members"]["attachments"][0]["kind"] == "codespaces"
    assert session_model["paths"]["member_registry"] == str(registry_path)
    assert status["members"]["attachments"][0]["member_id"] == "codespace-a"
    assert "codespace-a" in report["report"]


def test_mcp_share_attach_cli_registers_container_member(tmp_path, capsys):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status_code = simulator_main(
        [
            "mcp",
            "share",
            "member",
            "attach",
            str(tmp_path),
            "--member-id",
            "remote-container",
            "--kind",
            "container",
            "--upstream",
            "git=http://127.0.0.1:9010/mcp",
            "--label",
            "runtime=docker",
            "--metadata",
            "image=demo-mcp",
            "--metadata-output",
            "remote-container-member.json",
            "--ttl-seconds",
            "120",
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    registry = load_fabric_member_registry(tmp_path / ".snulbug" / "fabric-members.json")
    session_model = load_share_session_model(tmp_path)
    metadata_output = json.loads((tmp_path / "remote-container-member.json").read_text(encoding="utf-8"))

    assert status_code == 0
    assert output["ok"] is True
    assert output["member_id"] == "remote-container"
    assert output["metadata_output"] == str(tmp_path / "remote-container-member.json")
    assert metadata_output["member_id"] == "remote-container"
    assert metadata_output["upstreams"][0]["url"] == "http://127.0.0.1:9010/mcp"
    assert registry["members"]["remote-container"]["upstreams"][0]["name"] == "git"
    assert registry["members"]["remote-container"]["labels"]["runtime"] == "docker"
    assert registry["members"]["remote-container"]["metadata"]["image"] == "demo-mcp"
    assert session_model["members"]["attachments"][0]["member_id"] == "remote-container"


def test_mcp_share_status_and_report_summarize_session_evidence(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_share_audit_log(tmp_path)

    status = share_status(tmp_path, live_checks=False)
    report = share_report(tmp_path, output=tmp_path / "share-report.md", live_checks=False)

    assert status["traffic"]["event_count"] == 3
    assert status["traffic"]["allowed"] == 2
    assert status["traffic"]["blocked"] == 1
    assert status["traffic"]["confirmed"] == 1
    assert status["traffic"]["confirmation_approved"] == 1
    assert status["traffic"]["redacted_events"] == 1
    assert status["traffic"]["response_redacted"] == 1
    assert status["traffic"]["tools"][0]["value"] == "shell_exec"
    assert status["tool_risks"]["summary"]["high"] == 1
    assert status["tool_risks"]["tools"][0]["name"] == "shell_exec"
    assert status["tool_risks"]["tools"][0]["level"] == "high"
    assert status["tool_risks"]["tools"][0]["count"] == 2
    assert "command" in status["tool_risks"]["tools"][0]["categories"]
    assert status["recordings"]["audit_log"]["exists"] is True
    assert any(finding["type"] == "risky_tools_observed" for finding in status["findings"])
    assert any(finding["type"] == "high_risk_mcp_tools" for finding in status["findings"])
    assert report["ok"] is True
    assert report["path"] == str(tmp_path / "share-report.md")
    assert "## Executive Summary" in report["report"]
    assert "## Exposure Boundary" in report["report"]
    assert "## Access And Activity Review" in report["report"]
    assert "## Tool Risk Review" in report["report"]
    assert "## Data Protection Review" in report["report"]
    assert "## Policy Review" in report["report"]
    assert "## Findings To Review" in report["report"]
    assert "## Action Checklist" in report["report"]
    assert "This report is secret-light" in report["report"]
    assert "review recommended" in report["report"]
    assert "## Traffic" in report["report"]
    assert "Confirmed approved" in report["report"]
    assert "Secrets redacted events" in report["report"]
    assert "shell_exec" in report["report"]
    assert "tool.shell_or_process" in report["report"]
    assert "Tool risk summary: `1` high, `0` medium, `0` low" in report["report"]
    assert "Policy Amendments" in report["report"]
    assert "share-secret" not in report["report"]
    assert "sbl_" not in report["report"]
    assert (tmp_path / "share-report.md").is_file()


def test_mcp_share_capability_requests_promote_to_auth_bound_lease(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_share_capability_audit_log(tmp_path)

    listing = share_capability_requests(tmp_path)
    request = listing["requests"][0]
    approved = approve_share_capability_request(
        tmp_path,
        request_id=request["id"],
        reviewer="dev",
        ttl="15m",
    )
    lease_store = json.loads((tmp_path / "leases.json").read_text(encoding="utf-8"))
    lease = lease_store["leases"][-1]
    listed_after = share_capability_requests(tmp_path, status="all")
    status = share_status(tmp_path, live_checks=False)
    session_model = load_share_session_model(tmp_path)

    assert listing["summary"]["pending"] == 1
    assert request["status"] == "pending"
    assert request["tool"] == "safe_read_file"
    assert request["auth"]["subject"] == "user-1"
    assert approved["ok"] is True
    assert approved["review"]["status"] == "approved"
    assert approved["review"]["lease_id"] == lease["id"]
    assert approved["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert approved["retry_header"].startswith('-H "x-snulbug-lease: sbl_')
    assert lease["task"] == "Read project docs"
    assert lease["allow_tools"] == ["safe_read_file"]
    assert lease["allow_paths"] == ["README.md", "docs"]
    assert lease["allow_subjects"] == ["user-1"]
    assert lease["allow_issuers"] == ["https://issuer.example"]
    assert lease["allow_tenants"] == ["tenant-a"]
    assert lease["allow_client_ids"] == ["client-1"]
    assert lease["allow_groups"] == ["dev"]
    assert lease["allow_auth_profiles"] == ["tenant-a"]
    assert lease["max_calls"] == 2
    assert listed_after["summary"]["approved"] == 1
    assert listed_after["requests"][0]["status"] == "approved"
    assert status["capability_requests"]["approved"] == 1
    assert session_model["capability_requests"]["last_review"]["lease_id"] == lease["id"]
    assert "sbl_" not in json.dumps(session_model)


def test_mcp_share_capability_requests_can_be_denied_without_creating_lease(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_share_capability_audit_log(tmp_path)
    request_id = share_capability_requests(tmp_path)["requests"][0]["id"]
    before = json.loads((tmp_path / "leases.json").read_text(encoding="utf-8"))

    denied = deny_share_capability_request(
        tmp_path,
        request_id=request_id,
        reason="outside demo task",
        reviewer="dev",
    )
    after = json.loads((tmp_path / "leases.json").read_text(encoding="utf-8"))
    listing = share_capability_requests(tmp_path, status="all")

    assert denied["ok"] is True
    assert denied["review"]["status"] == "denied"
    assert denied["review"]["reason"] == "outside demo task"
    assert after["leases"] == before["leases"]
    assert listing["summary"]["denied"] == 1
    assert listing["requests"][0]["status"] == "denied"


def test_mcp_share_requests_cli_lists_and_approves_from_share_session(tmp_path, capsys, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_share_capability_audit_log(tmp_path)
    monkeypatch.chdir(tmp_path)

    list_code = simulator_main(["mcp", "share", "requests", "list", "--compact"])
    listing = json.loads(capsys.readouterr().out)
    request_id = listing["requests"][0]["id"]
    approve_code = simulator_main(
        [
            "mcp",
            "share",
            "requests",
            "approve",
            request_id,
            "--ttl",
            "20m",
            "--reviewer",
            "cli",
            "--compact",
        ]
    )
    approved = json.loads(capsys.readouterr().out)

    assert list_code == 0
    assert listing["summary"]["pending"] == 1
    assert approve_code == 0
    assert approved["ok"] is True
    assert approved["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert approved["review"]["reviewer"] == "cli"


def test_mcp_share_tool_risks_use_schema_catalog_metadata(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    catalog = build_mcp_schema_catalog(
        {
            "tools/list": {
                "result": {
                    "tools": [
                        {
                            "name": "run_command",
                            "description": "Run a shell command in the workspace",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"command": {"type": "string", "description": "Shell command"}},
                            },
                            "annotations": {"destructiveHint": True},
                        }
                    ]
                }
            }
        },
        methods=("tools/list",),
        label="risk-review",
    )
    schema_path = tmp_path / "traces" / "schemas.json"
    schema_path.parent.mkdir(exist_ok=True)
    schema_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    status = share_status(tmp_path, live_checks=False)
    report = share_report(tmp_path, live_checks=False)
    tool = status["tool_risks"]["tools"][0]
    signal_codes = {signal["code"] for signal in tool["signals"]}

    assert status["schemas"]["catalog_count"] == 1
    assert status["schemas"]["tool_count"] == 1
    assert status["tool_risks"]["schema_catalogs"]["sources"][0]["path"] == str(schema_path)
    assert tool["name"] == "run_command"
    assert tool["level"] == "high"
    assert tool["count"] == 0
    assert tool["evidence_sources"] == ["schema"]
    assert tool["confidence"] == "medium"
    assert tool["schema"]["tool_hash"] == catalog["surfaces"]["tools"][0]["hash"]
    assert tool["schema"]["input_properties"] == ["command"]
    assert "argument.command" in signal_codes
    assert "annotation.destructive" in signal_codes
    assert "schema.open_arguments" in signal_codes
    assert "Schema catalogs: `1` loaded, `1` declared tools, `0` errors" in report["report"]
    assert "`schema`" in report["report"]


def test_mcp_share_contract_redacts_tokens_and_can_sign(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_share_audit_log(tmp_path)

    output_path = tmp_path / "share-contract.json"
    result = share_contract(tmp_path, output=output_path, sign=True, secret="contract-secret", key_id="dev-key")
    contract = result["contract"]
    loaded = load_share_contract(output_path)
    status = share_status(tmp_path, live_checks=False)
    encoded = json.dumps(contract, sort_keys=True)

    assert result["ok"] is True
    assert result["signed"] is True
    assert contract["schema"] == "snulbug.share-contract.v1"
    assert contract["binding_digest"].startswith("sha256:")
    assert contract["digest"].startswith("sha256:")
    assert loaded["binding_digest"] == contract["binding_digest"]
    assert contract["snulbug_signature"]["algorithm"] == "hmac-sha256"
    assert contract["snulbug_signature"]["key_id"] == "dev-key"
    assert contract["snulbug_signature"]["digest"] == contract["digest"]
    assert contract["client"]["headers"]["Authorization"] == "[REDACTED]"
    assert contract["client"]["headers"]["x-snulbug-lease"] == "[REDACTED]"
    assert contract["commands"]["export_token"] == "export SNULBUG_SHARE_TOKEN=[REDACTED]"
    assert contract["evidence"]["traffic"]["event_count"] == 3
    assert contract["evidence"]["traffic"]["blocked"] == 1
    assert contract["evidence"]["tool_risks"]["summary"]["high"] == 1
    assert contract["evidence"]["tool_risks"]["tools"][0]["name"] == "shell_exec"
    assert contract["upstream_auth"]["strip_client_authorization"] is True
    assert status["contract"]["required"] is False
    assert status["contract"]["binding_digest"] == contract["binding_digest"]
    assert status["contract"]["drifted"] is False
    assert "share-secret" not in encoded
    assert "sbl_" not in encoded


def test_mcp_share_contract_cli_writes_contract_file(tmp_path, capsys, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    monkeypatch.setenv("SNULBUG_SHARE_CONTRACT_SECRET", "contract-secret")
    output_path = tmp_path / "share-contract.json"

    status_code = simulator_main(
        [
            "mcp",
            "share",
            "contract",
            str(tmp_path),
            "--output",
            str(output_path),
            "--sign",
            "--key-id",
            "dev-key",
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    written = json.loads(output_path.read_text(encoding="utf-8"))

    assert status_code == 0
    assert output["ok"] is True
    assert output["path"] == str(output_path)
    assert output["digest"] == written["digest"]
    assert written["snulbug_signature"]["key_id"] == "dev-key"
    assert written["client"]["headers"]["Authorization"] == "[REDACTED]"


def test_mcp_share_run_dry_run_validates_required_contract(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    contract_path = tmp_path / "share-contract.json"
    contract_result = share_contract(
        tmp_path,
        output=contract_path,
        sign=True,
        secret="contract-secret",
        key_id="dev-key",
    )

    result = run_mcp_share(tmp_path, dry_run=True, require_contract=contract_path)

    assert result is not None
    assert result["ok"] is True
    assert result["contract"]["contract_required"] is True
    assert result["contract"]["contract_signed"] is True
    assert result["contract"]["contract_key_id"] == "dev-key"
    assert result["contract"]["contract_digest"] == contract_result["contract"]["binding_digest"]
    assert result["contract"]["contract_matched_at_startup"] is True
    assert result["contract"]["contract_drifted"] is False


def test_mcp_share_run_rejects_drifted_required_contract(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    contract_path = tmp_path / "share-contract.json"
    share_contract(
        tmp_path,
        output=contract_path,
        sign=True,
        secret="contract-secret",
        key_id="dev-key",
    )
    manifest_path = tmp_path / "share.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["client"]["url"] = "https://changed.example.test/mcp"
    manifest["tunnel"]["public_url"] = "https://changed.example.test/mcp"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="required share contract has drifted"):
        run_mcp_share(tmp_path, dry_run=True, require_contract=contract_path)


def test_mcp_share_doctor_url_override_updates_manifest_and_client(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://placeholder.example/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    calls = []

    def fake_doctor_tunnel(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "checks": []}

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    result = doctor_mcp_share(tmp_path, public_url="https://actual.example/mcp", live_checks=False)
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    client_config = json.loads((tmp_path / "mcp-client.json").read_text(encoding="utf-8"))

    assert result["ok"] is True
    assert result["tunnel"]["ok"] is True
    assert result["summary"]["failed"] == 0
    assert calls[0]["url"] == "https://actual.example/mcp"
    assert manifest["client"]["url"] == "https://actual.example/mcp"
    assert session_model["status"]["state"] == "verified"
    assert session_model["tunnel"]["public_url"] == "https://actual.example/mcp"
    assert session_model["health"]["tunnel_doctor"]["ok"] is True
    assert session_model["health"]["share_doctor"]["ok"] is True
    assert manifest["tunnel"]["public_url"] == "https://actual.example/mcp"
    assert client_config["mcpServers"]["snulbug-share"]["url"] == "https://actual.example/mcp"


def test_mcp_share_doctor_fails_invalid_policy_and_missing_required_conformance(tmp_path, capsys, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    (tmp_path / "policy.snulbug" / "policy.lua").write_text("function broken(", encoding="utf-8")

    def fake_doctor_tunnel(**_kwargs):
        return {"ok": True, "checks": [], "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0}}

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)

    result = doctor_mcp_share(tmp_path, live_checks=False, require_conformance=True)
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is False
    assert checks["policy.bundle_valid"]["status"] == "fail"
    assert checks["conformance.pack_configured"]["status"] == "fail"
    assert manifest["state"] == "doctor_failed"
    assert session_model["health"]["share_doctor"]["ok"] is False

    sarif = tmp_path / "share-doctor.sarif"
    status_code = simulator_main(
        [
            "mcp",
            "share",
            "doctor",
            str(tmp_path),
            "--no-live-checks",
            "--require-conformance",
            "--sarif-out",
            str(sarif),
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    sarif_payload = json.loads(sarif.read_text(encoding="utf-8"))

    assert status_code == 1
    assert output["sarif_out"] == str(sarif)
    assert sarif_payload["runs"][0]["results"][0]["ruleId"] == "snulbug.share.doctor_failed_check"
    failed_results = [
        result
        for result in sarif_payload["runs"][0]["results"]
        if result["ruleId"] == "snulbug.share.doctor_failed_check"
    ]
    assert failed_results
    assert {result["level"] for result in failed_results} == {"error"}


def test_mcp_share_auth_doctor_validates_static_oauth_config(tmp_path):
    resource = "https://mcp.example.test/mcp"
    config = write_oauth_share_config(tmp_path, resource=resource, issuer="https://issuer.example.test")

    result = doctor_mcp_share_auth(config=config, public_url=resource, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert checks["auth.mode"]["status"] == "pass"
    assert checks["auth.resource.matches_public_url"]["status"] == "pass"
    assert checks["auth.audience.matches_public_url"]["status"] == "pass"
    assert checks["auth.public_url.sources_consistent"]["status"] == "pass"
    assert checks["auth.resource.indicators_valid"]["status"] == "pass"
    assert checks["auth.resource.audience_overlap"]["status"] == "pass"
    assert checks["auth.jwks.local"]["status"] == "pass"
    assert checks["auth.protected_resource_metadata.reachable"]["status"] == "skip"
    assert checks["auth.scope_map.tools_discovered"]["status"] == "skip"


def test_mcp_share_auth_conformance_pack_proves_config_schema_token_and_logs(tmp_path, monkeypatch):
    resource = "https://mcp.example.test/mcp"
    issuer = "https://issuer.example.test"
    secret = "auth-conformance-secret-32-bytes"
    config = write_hs256_oauth_share_config(tmp_path, resource=resource, issuer=issuer, secret=secret)
    catalog = write_auth_schema_catalog(tmp_path)
    audit_log = write_auth_audit_log(tmp_path, issuer=issuer)
    token = make_hs256_oauth_token(secret, issuer=issuer, audience=resource, scopes=["mcp:connect", "mcp:tools.read"])
    monkeypatch.setenv("SNULBUG_AUTH_CONFORMANCE_TOKEN", token)
    pack = tmp_path / "auth-conformance"

    generated = generate_auth_conformance_pack(
        config=config,
        public_url=resource,
        schema_catalogs=[catalog],
        logs=[audit_log],
        kind="audit",
        token_envs=["valid=SNULBUG_AUTH_CONFORMANCE_TOKEN"],
        output=pack,
    )
    result = run_auth_conformance_pack(pack, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert generated["ok"] is True
    assert (pack / "manifest.json").is_file()
    assert result["ok"] is True
    assert checks["config.fingerprint"]["status"] == "pass"
    assert checks["tokens.valid"]["status"] == "pass"
    assert checks["schemas.scope_map_targets"]["status"] == "pass"
    assert checks["logs.auth_evidence"]["status"] == "pass"
    assert checks["logs.scope_map_evidence"]["status"] == "pass"
    assert checks["logs.runtime_observability"]["status"] == "pass"
    assert token not in json.dumps(result)


def test_mcp_share_auth_conformance_pack_fails_when_schema_catalog_drifts(tmp_path, monkeypatch):
    resource = "https://mcp.example.test/mcp"
    issuer = "https://issuer.example.test"
    secret = "auth-conformance-secret-32-bytes"
    config = write_hs256_oauth_share_config(tmp_path, resource=resource, issuer=issuer, secret=secret)
    catalog = write_auth_schema_catalog(tmp_path)
    audit_log = write_auth_audit_log(tmp_path, issuer=issuer)
    token = make_hs256_oauth_token(secret, issuer=issuer, audience=resource, scopes=["mcp:connect", "mcp:tools.read"])
    monkeypatch.setenv("SNULBUG_AUTH_CONFORMANCE_TOKEN", token)
    pack = tmp_path / "auth-conformance"
    generate_auth_conformance_pack(
        config=config,
        public_url=resource,
        schema_catalogs=[catalog],
        logs=[audit_log],
        kind="audit",
        token_envs=["valid=SNULBUG_AUTH_CONFORMANCE_TOKEN"],
        output=pack,
    )
    catalog.write_text(
        json.dumps(build_mcp_schema_catalog({"tools/list": {"result": {"tools": []}}})), encoding="utf-8"
    )

    result = run_auth_conformance_pack(pack, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is False
    assert checks["schemas.01.fingerprint"]["status"] == "fail"
    assert checks["schemas.scope_map_targets"]["status"] == "fail"


def test_mcp_share_auth_doctor_flags_public_url_drift_and_resource_audience_mismatch(tmp_path):
    configured = "https://old-tunnel.example.test/mcp"
    actual = "https://actual-tunnel.example.test/mcp"
    config = write_oauth_share_config(tmp_path, resource=configured, issuer="https://issuer.example.test")

    result = doctor_mcp_share_auth(config=config, public_url=actual, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is False
    assert checks["auth.public_url.sources_consistent"]["status"] == "fail"
    assert checks["auth.resource.matches_public_url"]["status"] == "fail"
    assert checks["auth.audience.matches_public_url"]["status"] == "fail"


def test_mcp_share_auth_doctor_accepts_explicit_multi_url_resource_alias_and_audience(tmp_path):
    primary = "https://mcp.example.test/mcp"
    alias = "https://preview.example.test/mcp"
    (tmp_path / "jwks.json").write_text(
        json.dumps({"keys": [{"kty": "RSA", "kid": "demo", "n": "AQAB", "e": "AQAB"}]}),
        encoding="utf-8",
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(alias)}

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(primary)}
resource_aliases = [{json.dumps(alias)}]
issuer = "https://issuer.example.test"
authorization_servers = ["https://issuer.example.test"]
audience = {json.dumps(primary)}
audiences = [{json.dumps(alias)}]
required_scopes = ["mcp:connect"]
jwks_path = "jwks.json"

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
""".lstrip(),
        encoding="utf-8",
    )

    result = doctor_mcp_share_auth(config=config, public_url=alias, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert checks["auth.public_url.sources_consistent"]["status"] == "pass"
    assert checks["auth.resource.matches_public_url"]["status"] == "pass"
    assert checks["auth.audience.matches_public_url"]["status"] == "pass"
    assert checks["auth.resource.public_url_uses_alias"]["status"] == "warn"
    assert checks["auth.multi_url.explicit"]["status"] == "warn"
    assert result["summary"]["warnings"] >= 2


def test_mcp_share_auth_doctor_flags_unsafe_oauth_config(tmp_path):
    resource = "https://mcp.example.test/mcp"
    config = write_oauth_share_config(
        tmp_path,
        resource=resource,
        issuer="https://issuer.example.test",
        audience="https://wrong.example.test/mcp",
        redact_records=False,
        strip_authorization_upstream=False,
        cloudflare_access="enforce",
    )

    result = doctor_mcp_share_auth(config=config, public_url=resource, live_checks=False)
    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is False
    assert checks["auth.audience.matches_public_url"]["status"] == "fail"
    assert checks["auth.raw_token_logging"]["status"] == "fail"
    assert checks["auth.anti_passthrough"]["status"] == "fail"
    assert checks["auth.cloudflare_access.conflict"]["status"] == "fail"


def test_mcp_share_auth_doctor_checks_live_metadata_jwks_and_scope_tools(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthMcpHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.resource = f"{origin}/mcp"  # type: ignore[attr-defined]
    server.issuer = origin  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = write_oauth_share_config(tmp_path, resource=server.resource, issuer=server.issuer)  # type: ignore[attr-defined]

        result = doctor_mcp_share_auth(config=config, public_url=server.resource, token="demo-token")  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert checks["auth.https_or_localhost"]["status"] == "pass"
    assert checks["auth.protected_resource_metadata.reachable"]["status"] == "pass"
    assert checks["auth.issuer_metadata.reachable"]["status"] == "pass"
    assert checks["auth.jwks_or_introspection"]["status"] == "pass"
    assert checks["auth.scope_map.tools_discovered"]["status"] == "pass"
    assert result["live"]["tools_list"]["tools"] == ["safe_read_file"]


def test_mcp_share_auth_doctor_checks_claim_policy_tools(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthMcpHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.resource = f"{origin}/mcp"  # type: ignore[attr-defined]
    server.issuer = origin  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = write_oauth_share_config(
            tmp_path,
            resource=server.resource,  # type: ignore[attr-defined]
            issuer=server.issuer,  # type: ignore[attr-defined]
            claim_policy="""
[mcp.auth.claim_policy]
enabled = true
default_action = "deny"

[[mcp.auth.claim_policy.rules]]
id = "tenant-a-files"
claim = "tenant"
values = ["tenant-a"]
allow_tools = ["safe_read_file"]
""",
        )

        result = doctor_mcp_share_auth(config=config, public_url=server.resource, token="demo-token")  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["id"]: check for check in result["checks"]}

    assert result["ok"] is True
    assert checks["auth.claim_policy.configured"]["status"] == "pass"
    assert checks["auth.claim_policy.tools_discovered"]["status"] == "pass"
    assert result["auth"]["claim_policy"]["rules"][0]["id"] == "tenant-a-files"


def test_mcp_share_auth_doctor_accepts_configured_remote_jwks_without_local_file(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthMcpHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.resource = f"{origin}/mcp"  # type: ignore[attr-defined]
    server.issuer = origin  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "snulbug.toml"
    try:
        config.write_text(
            f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(server.resource)}

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(server.resource)}
issuer = {json.dumps(server.issuer)}
authorization_servers = [{json.dumps(server.issuer)}]
audience = {json.dumps(server.resource)}
required_scopes = ["mcp:connect"]
jwks_url = {json.dumps(f"{server.issuer}/jwks")}
jwks_cache_seconds = 30
jwks_fetch_timeout = 1

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
"mcp:tool.files.read" = ["tools/call:safe_read_file"]
""".lstrip(),
            encoding="utf-8",
        )
        result = doctor_mcp_share_auth(config=config, public_url=server.resource, token="demo-token")  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert checks["auth.jwks.local"]["status"] == "skip"
    assert checks["auth.jwks_or_introspection"]["status"] == "pass"
    assert result["auth"]["jwks_url"].endswith("/jwks")
    assert result["auth"]["jwks_cache_seconds"] == 30.0


def test_mcp_share_auth_doctor_discovers_issuer_jwks_without_jwks_config(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthMcpHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.resource = f"{origin}/mcp"  # type: ignore[attr-defined]
    server.issuer = origin  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "snulbug.toml"
    try:
        config.write_text(
            f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(server.resource)}

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(server.resource)}
issuer = {json.dumps(server.issuer)}
authorization_servers = [{json.dumps(server.issuer)}]
audience = {json.dumps(server.resource)}
required_scopes = ["mcp:connect"]

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
""".lstrip(),
            encoding="utf-8",
        )
        result = doctor_mcp_share_auth(config=config, public_url=server.resource, token="demo-token")  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert checks["auth.jwks.local"]["status"] == "skip"
    assert checks["auth.jwks_or_introspection"]["status"] == "pass"
    assert result["auth"]["issuer_discovery"] is True
    assert result["auth"]["jwks_url"] is None


def test_mcp_share_auth_doctor_checks_discovered_introspection_endpoint(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OAuthMcpHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.resource = f"{origin}/mcp"  # type: ignore[attr-defined]
    server.issuer = origin  # type: ignore[attr-defined]
    server.introspection_tokens = {"demo-token": {"active": True}}  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "snulbug.toml"
    try:
        config.write_text(
            f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(server.resource)}

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(server.resource)}
issuer = {json.dumps(server.issuer)}
authorization_servers = [{json.dumps(server.issuer)}]
audience = {json.dumps(server.resource)}
required_scopes = ["mcp:connect"]
token_validation = "introspection"

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
""".lstrip(),
            encoding="utf-8",
        )
        result = doctor_mcp_share_auth(config=config, public_url=server.resource, token="demo-token")  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["id"]: check for check in result["checks"]}
    assert result["ok"] is True
    assert checks["auth.jwks.local"]["status"] == "skip"
    assert checks["auth.jwks_or_introspection"]["status"] == "pass"
    assert result["auth"]["token_validation"] == "introspection"
    assert result["live"]["introspection"]["json"]["active"] is True


def test_mcp_share_auth_doctor_cli_accepts_config_without_share_directory(tmp_path, capsys):
    resource = "https://mcp.example.test/mcp"
    config = write_oauth_share_config(tmp_path, resource=resource, issuer="https://issuer.example.test")

    status_code = simulator_main(
        [
            "mcp",
            "share",
            "auth",
            "doctor",
            "--config",
            str(config),
            "--url",
            resource,
            "--no-live-checks",
            "--compact",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert status_code == 0
    assert output["ok"] is True
    assert output["config"] == str(config)

    rich_status_code = simulator_main(
        [
            "mcp",
            "share",
            "auth",
            "doctor",
            "--config",
            str(config),
            "--url",
            resource,
            "--no-live-checks",
        ]
    )
    rich_output = capsys.readouterr().out

    assert rich_status_code == 0
    assert "snulbug share auth doctor" in rich_output
    assert "Checks" in rich_output


def test_mcp_share_lifecycle_cli_status_doctor_client_run_and_close(tmp_path, capsys, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status_code = simulator_main(["mcp", "share", "status", str(tmp_path), "--no-live-checks", "--compact"])
    status_output = json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert status_output["state"] == "created"
    assert status_output["gateway"]["checked"] is False
    assert status_output["gateway"]["reachable"] is None

    report_code = simulator_main(["mcp", "share", "report", str(tmp_path), "--no-live-checks", "--compact"])
    report_output = json.loads(capsys.readouterr().out)
    assert report_code == 0
    assert "snulbug MCP share report" in report_output["report"]

    rich_report_code = simulator_main(["mcp", "share", "report", str(tmp_path), "--no-live-checks"])
    rich_report_output = capsys.readouterr().out
    assert rich_report_code == 0
    assert "snulbug share report" in rich_report_output
    assert "Tool Risk Review" in rich_report_output

    def fake_doctor_tunnel(**_kwargs):
        return {"ok": True, "checks": [], "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0}}

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)
    doctor_code = simulator_main(["mcp", "share", "doctor", str(tmp_path), "--no-live-checks", "--compact"])
    doctor_output = json.loads(capsys.readouterr().out)
    assert doctor_code == 0
    assert doctor_output["ok"] is True
    assert doctor_output["policy"]["ok"] is True

    rich_doctor_code = simulator_main(["mcp", "share", "doctor", str(tmp_path), "--no-live-checks"])
    rich_doctor_output = capsys.readouterr().out
    assert rich_doctor_code == 0
    assert "snulbug share doctor" in rich_doctor_output
    assert "Checks" in rich_doctor_output

    client_code = simulator_main(["mcp", "share", "client", str(tmp_path), "--compact"])
    client_output = json.loads(capsys.readouterr().out)
    assert client_code == 0
    assert client_output["config"]["mcpServers"]["snulbug-share"]["url"] == "https://mcp.example.test/mcp"

    run_code = simulator_main(["mcp", "share", "run", str(tmp_path), "--dry-run", "--compact"])
    run_output = json.loads(capsys.readouterr().out)
    assert run_code == 0
    assert run_output["commands"]["client"] == f"uv run snulbug mcp share client {tmp_path}"

    close_code = simulator_main(["mcp", "share", "close", str(tmp_path), "--compact"])
    close_output = json.loads(capsys.readouterr().out)
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    assert close_code == 0
    assert close_output["state"] == "closed"
    assert close_output["revoked"]["ok"] is True
    assert (tmp_path / "session-report.md").is_file()
    assert manifest["state"] == "closed"
    assert session_model["status"]["state"] == "closed"
    assert session_model["evidence"]["closeout_report"] == str(tmp_path / "session-report.md")


def test_close_mcp_share_revokes_lease_and_writes_report(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    result = close_mcp_share(tmp_path)
    status = share_status(tmp_path)

    assert result["ok"] is True
    assert result["revoked"]["lease"]["active"] is False
    assert status["state"] == "closed"
    assert status["lease"]["active"] is False


def test_mcp_share_refuses_to_overwrite_without_force(tmp_path):
    create_mcp_share(tmp_path, token="share-secret", allowed_tools=["safe_read_file"], validate=False)

    try:
        create_mcp_share(tmp_path, token="share-secret", allowed_tools=["safe_read_file"], validate=False)
    except FileExistsError as exc:
        assert "share output already exists" in str(exc)
    else:  # pragma: no cover - defensive assertion.
        raise AssertionError("expected FileExistsError")


def test_checked_in_container_facade_example_matches_proxy_schema():
    root = Path(__file__).resolve().parents[1]
    example = root / "examples" / "mcp_container_facade"
    local_config = load_mcp_proxy_config(example / "snulbug.local.toml")
    config = load_mcp_proxy_config(example / "snulbug.facade.toml")
    compose = (example / "docker-compose.yml").read_text(encoding="utf-8")
    gateway_dockerfile = (example / "Dockerfile.gateway").read_text(encoding="utf-8")
    remote_dockerfile = (example / "Dockerfile.remote-peer").read_text(encoding="utf-8")
    client = json.loads((example / "mcp-client.json").read_text(encoding="utf-8"))

    assert local_config["host"] == "0.0.0.0"
    assert [upstream["name"] for upstream in local_config["upstreams"]] == ["local"]
    assert config["host"] == "0.0.0.0"
    assert config["upstreams"][0]["name"] == "local"
    assert config["upstreams"][0]["url"] == "http://local-mcp:9000/mcp"
    assert config["upstreams"][1]["name"] == "remote"
    assert config["upstreams"][1]["transport"] == "holepunch"
    assert config["upstreams"][1]["bridge_config"] == "hypertele-client.json"
    assert "snulbug-gateway" in compose
    assert "snulbug.local.toml" in compose
    assert "local-mcp" in compose
    assert "remote-by-peer-mcp" in compose
    assert "apt-get" not in gateway_dockerfile
    assert "npm install" not in gateway_dockerfile
    assert "apt-get" not in remote_dockerfile
    assert "python3" not in remote_dockerfile
    assert "mock_mcp_server.js" in remote_dockerfile
    assert client["mcpServers"]["snulbug-container-facade"]["headers"]["Authorization"] == ("Bearer local-dev-secret")


def write_oauth_share_config(
    tmp_path: Path,
    *,
    resource: str,
    issuer: str,
    audience: str | None = None,
    redact_records: bool = True,
    strip_authorization_upstream: bool = True,
    cloudflare_access: str = "off",
    claim_policy: str = "",
) -> Path:
    (tmp_path / "jwks.json").write_text(
        json.dumps({"keys": [{"kty": "RSA", "kid": "demo", "n": "AQAB", "e": "AQAB"}]}),
        encoding="utf-8",
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(resource)}
redact_records = {str(redact_records).lower()}
cloudflare_access = {json.dumps(cloudflare_access)}

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(resource)}
issuer = {json.dumps(issuer)}
authorization_servers = [{json.dumps(issuer)}]
audience = {json.dumps(audience or resource)}
required_scopes = ["mcp:connect"]
jwks_path = "jwks.json"
strip_authorization_upstream = {str(strip_authorization_upstream).lower()}

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
"mcp:tool.files.read" = ["tools/call:safe_read_file"]
{claim_policy}
""".lstrip(),
        encoding="utf-8",
    )
    return config


def write_hs256_oauth_share_config(
    tmp_path: Path,
    *,
    resource: str,
    issuer: str,
    secret: str,
) -> Path:
    (tmp_path / "jwks.json").write_text(
        json.dumps({"keys": [hs256_jwk(secret)]}),
        encoding="utf-8",
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
[mcp.proxy]
upstream = "http://127.0.0.1:9000/mcp"
tunnel_public_url = {json.dumps(resource)}
redact_records = true

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(resource)}
issuer = {json.dumps(issuer)}
authorization_servers = [{json.dumps(issuer)}]
audience = {json.dumps(resource)}
required_scopes = ["mcp:connect"]
jwks_path = "jwks.json"
strip_authorization_upstream = true

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
"mcp:tool.files.read" = ["tools/call:safe_read_file"]
""".lstrip(),
        encoding="utf-8",
    )
    return config


def hs256_jwk(secret: str) -> dict[str, str]:
    encoded = base64.urlsafe_b64encode(secret.encode("utf-8")).decode("ascii").rstrip("=")
    return {"kty": "oct", "kid": "demo", "alg": "HS256", "k": encoded}


def make_hs256_oauth_token(
    secret: str,
    *,
    issuer: str,
    audience: str,
    scopes: list[str],
) -> str:
    return jwt.encode(
        {
            "iss": issuer,
            "sub": "user-1",
            "aud": audience,
            "scope": " ".join(scopes),
            "client_id": "agent-client",
        },
        secret,
        algorithm="HS256",
        headers={"kid": "demo"},
    )


def write_auth_schema_catalog(tmp_path: Path) -> Path:
    catalog = build_mcp_schema_catalog(
        {
            "tools/list": {
                "result": {
                    "tools": [
                        {
                            "name": "safe_read_file",
                            "description": "Read a demo file",
                            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                        }
                    ]
                }
            }
        },
        methods=("tools/list",),
        label="auth-conformance",
    )
    path = tmp_path / "schemas.json"
    path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_auth_audit_log(tmp_path: Path, *, issuer: str) -> Path:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    event = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:00:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {"authorization": "[REDACTED]"}},
        "mcp": {"method": "tools/list"},
        "decision": {"action": "continue", "allowed": True, "reason_code": "test.allowed"},
        "response": {"status": 200},
        "auth": {
            "allowed": True,
            "reason_code": "oauth.allowed",
            "subject": "user-1",
            "issuer": issuer,
            "scopes": ["mcp:connect", "mcp:tools.read"],
            "scope_map": {
                "enabled": True,
                "allowed": True,
                "reason_code": "oauth.scope_map_allowed",
                "matched_scope": "mcp:tools.read",
                "matched_selector": "tools/list",
                "target": {"method": "tools/list", "selectors": ["tools/list"]},
            },
            "runtime": {
                "caches": {"jwks": {"entries": 1, "hits": 0, "misses": 1, "fetches": 1}},
                "decisions": {"total": 1, "allowed": 1, "reason_codes": {"oauth.allowed": 1}},
            },
        },
    }
    path = traces / "auth-audit.jsonl"
    path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    return path


class OAuthMcpHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):  # noqa: A002
        return

    def do_GET(self):
        if self.path == "/.well-known/oauth-protected-resource":
            self._write_json(
                {
                    "resource": self.server.resource,  # type: ignore[attr-defined]
                    "authorization_servers": [self.server.issuer],  # type: ignore[attr-defined]
                    "scopes_supported": ["mcp:connect", "mcp:tools.read", "mcp:tool.files.read"],
                }
            )
            return
        if self.path == "/.well-known/oauth-authorization-server":
            issuer = self.server.issuer  # type: ignore[attr-defined]
            self._write_json(
                {
                    "issuer": issuer,
                    "jwks_uri": f"{issuer}/jwks",
                    "introspection_endpoint": f"{issuer}/introspect",
                }
            )
            return
        if self.path == "/jwks":
            self._write_json({"keys": [{"kty": "RSA", "kid": "demo", "n": "AQAB", "e": "AQAB"}]})
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("content-length") or "0")
        body = self.rfile.read(length)
        if self.path == "/introspect":
            token = parse_qs(body.decode("utf-8")).get("token", [""])[0]
            payload = getattr(self.server, "introspection_tokens", {}).get(token, {"active": False})
            self._write_json(payload)
            return
        request = json.loads(body.decode("utf-8")) if body else {}
        if self.path == "/mcp" and request.get("method") == "tools/list":
            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "safe_read_file",
                                "description": "Read a demo file",
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ]
                    },
                }
            )
            return
        self.send_response(404)
        self.end_headers()

    def _write_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def write_share_audit_log(tmp_path):
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    events = [
        {
            "type": "snulbug.audit",
            "version": 1,
            "time": "2026-06-14T00:00:00+00:00",
            "request": {"method": "POST", "path": "/mcp", "headers": {}},
            "mcp": {"method": "tools/list"},
            "decision": {"action": "continue", "allowed": True, "reason_code": "mcp.allowed"},
            "response": {"status": 200},
            "tunnel": {"source_ip": "203.0.113.10"},
        },
        {
            "type": "snulbug.audit",
            "version": 1,
            "time": "2026-06-14T00:01:00+00:00",
            "request": {"method": "POST", "path": "/mcp", "headers": {"authorization": "[REDACTED]"}},
            "mcp": {"method": "tools/call", "tool": "shell_exec"},
            "decision": {
                "action": "continue",
                "allowed": True,
                "reason_code": "mcp.policy.tool_rejected",
                "confirmation": {"approved": True, "mode": "once", "reason_code": "confirm.approved_once"},
            },
            "response": {"status": 200},
            "tunnel": {"source_ip": "203.0.113.10"},
            "metadata": {"response_policy": {"checked": True, "redacted": True}},
        },
        {
            "type": "snulbug.audit",
            "version": 1,
            "time": "2026-06-14T00:02:00+00:00",
            "request": {"method": "POST", "path": "/mcp", "headers": {}},
            "mcp": {"method": "tools/call", "tool": "shell_exec"},
            "decision": {"action": "reject", "allowed": False, "reason_code": "mcp.tool_not_allowed"},
            "response": {"status": 403},
            "tunnel": {"source_ip": "198.51.100.20"},
        },
    ]
    (traces / "audit.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def write_share_capability_audit_log(tmp_path):
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    event = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:03:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/call", "tool": "safe_read_file"},
        "decision": {
            "action": "reject",
            "allowed": False,
            "reason_code": "mcp.docs_capability_requested",
            "confirmation": {
                "approved": False,
                "mode": "denied",
                "reason_code": "confirm.unavailable",
            },
        },
        "metadata": {
            "auth": {
                "subject": "user-1",
                "issuer": "https://issuer.example",
                "tenant": "tenant-a",
                "client_id": "client-1",
                "groups": ["dev"],
                "profile_id": "tenant-a",
            },
            "capability_request": {
                "requested": True,
                "reason_code": "mcp.docs_capability_requested",
                "capability_request": {
                    "schema": "snulbug.capability_request.v1",
                    "kind": "task_lease",
                    "task": "Read project docs",
                    "reason_code": "mcp.docs_capability_requested",
                    "method": "tools/call",
                    "tool": "safe_read_file",
                    "argument_keys": ["path"],
                    "suggested_lease": {
                        "task": "Read project docs",
                        "ttl": "10m",
                        "max_calls": 2,
                        "allow_tools": ["safe_read_file"],
                        "allow_paths": ["README.md", "docs"],
                    },
                },
                "confirmation": {
                    "approved": False,
                    "mode": "denied",
                    "reason_code": "confirm.unavailable",
                },
            },
        },
        "response": {"status": 403},
    }
    (traces / "audit.jsonl").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

from __future__ import annotations

import json
from pathlib import Path

import pytest

from snulbug import (
    close_mcp_share,
    create_mcp_share,
    doctor_mcp_share,
    load_mcp_proxy_config,
    load_share_session_model,
    run_mcp_share,
    share_client_config,
    share_session_model_path,
    share_status,
)
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


def test_mcp_share_lifecycle_helpers_read_manifest(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status = share_status(tmp_path)
    client = share_client_config(tmp_path)
    run_plan = run_mcp_share(tmp_path, dry_run=True)

    assert status["ok"] is True
    assert status["state"] == "created"
    assert status["session_model"]["status"]["state"] == "created"
    assert status["session_model_path"] == str(share_session_model_path(tmp_path))
    assert status["lease"]["active"] is True
    assert client["config"]["mcpServers"]["snulbug-share"]["headers"]["Authorization"] == "Bearer share-secret"
    assert run_plan is not None
    assert run_plan["commands"]["run"] == f"uv run snulbug mcp share run {tmp_path}"


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

    result = doctor_mcp_share(tmp_path, public_url="https://actual.example/mcp")
    manifest = json.loads((tmp_path / "share.json").read_text(encoding="utf-8"))
    session_model = load_share_session_model(tmp_path)
    client_config = json.loads((tmp_path / "mcp-client.json").read_text(encoding="utf-8"))

    assert result["ok"] is True
    assert calls[0]["url"] == "https://actual.example/mcp"
    assert manifest["client"]["url"] == "https://actual.example/mcp"
    assert session_model["status"]["state"] == "verified"
    assert session_model["tunnel"]["public_url"] == "https://actual.example/mcp"
    assert manifest["tunnel"]["public_url"] == "https://actual.example/mcp"
    assert client_config["mcpServers"]["snulbug-share"]["url"] == "https://actual.example/mcp"


def test_mcp_share_lifecycle_cli_status_client_run_and_close(tmp_path, capsys):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    status_code = simulator_main(["mcp", "share", "status", str(tmp_path), "--compact"])
    status_output = json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert status_output["state"] == "created"

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

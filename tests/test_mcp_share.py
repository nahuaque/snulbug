from __future__ import annotations

import json
from pathlib import Path

from snulbug import create_mcp_share, load_mcp_proxy_config
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
    facade_config = load_mcp_proxy_config(tmp_path / "containers" / "snulbug.facade.toml")
    report = (tmp_path / "SHARE.md").read_text(encoding="utf-8")

    assert result["ok"] is True
    assert result["session"]["provider"] == "holepunch"
    assert result["session"]["ttl"] == "15m"
    assert result["client"]["url"] == "http://127.0.0.1:18080/mcp"
    assert result["client"]["headers"]["Authorization"] == "Bearer share-secret"
    assert result["client"]["headers"]["x-snulbug-lease"].startswith("sbl_")
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
    assert facade_client_config["mcpServers"]["snulbug-share-facade"]["url"] == "http://127.0.0.1:18080/mcp"
    assert (
        facade_client_config["mcpServers"]["snulbug-share-facade"]["headers"]
        == (result["recipes"]["remote_container_upstream"]["client"]["headers"])
    )
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
    assert (tmp_path / "containers" / "snulbug-src" / "pyproject.toml").is_file()
    assert (tmp_path / "containers" / "snulbug-src" / "snulbug" / "share.py").is_file()
    assert (tmp_path / "containers" / "policy.snulbug" / "policy.lua").is_file()
    assert (tmp_path / "containers" / "leases.json").is_file()
    compose = (tmp_path / "containers" / "docker-compose.yml").read_text(encoding="utf-8")
    gateway_dockerfile = (tmp_path / "containers" / "Dockerfile.gateway").read_text(encoding="utf-8")
    assert "remote-by-peer-mcp" in compose
    assert "snulbug-src/" in gateway_dockerfile
    assert "snulbug[proxy]" not in gateway_dockerfile
    assert (tmp_path / "tunnel" / "hypertele-server.json").is_file()
    assert (tmp_path / "tunnel" / "hypertele-client.json").is_file()
    assert "snulbug MCP share session" in report
    assert "uv run snulbug tunnel doctor" in report
    assert "uv run snulbug mcp lease revoke" in report
    assert "Remote container as upstream" in report


def test_mcp_share_cli_emits_compact_session_plan(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
            "share",
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
    assert output["session"]["provider"] == "generic"
    assert output["client"]["url"] == "https://mcp.example.test/mcp"
    assert output["client"]["headers"]["Authorization"] == "Bearer share-secret"
    assert output["quickstart"]["tests"] is None
    assert output["tunnel"]["written_files"] == [str(tmp_path / "tunnel" / "README.md")]
    assert "fixture_count" not in json.dumps(output["tunnel"])
    assert (tmp_path / "mcp-client.json").is_file()
    assert (tmp_path / "SHARE.md").is_file()


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
    config = load_mcp_proxy_config(example / "snulbug.facade.toml")
    compose = (example / "docker-compose.yml").read_text(encoding="utf-8")
    client = json.loads((example / "mcp-client.json").read_text(encoding="utf-8"))

    assert config["host"] == "0.0.0.0"
    assert config["upstreams"][0]["name"] == "local"
    assert config["upstreams"][0]["url"] == "http://local-mcp:9000/mcp"
    assert config["upstreams"][1]["name"] == "remote"
    assert config["upstreams"][1]["transport"] == "holepunch"
    assert config["upstreams"][1]["bridge_config"] == "hypertele-client.json"
    assert "snulbug-gateway" in compose
    assert "local-mcp" in compose
    assert "remote-by-peer-mcp" in compose
    assert client["mcpServers"]["snulbug-container-facade"]["headers"]["Authorization"] == ("Bearer local-dev-secret")

from __future__ import annotations

import json

from snulbug import create_mcp_quickstart, load_mcp_proxy_config, validate_bundle
from snulbug import test_bundle as run_bundle_tests
from snulbug.simulator import main as simulator_main


def test_create_mcp_quickstart_writes_policy_config_and_trace_dir(tmp_path):
    result = create_mcp_quickstart(
        tmp_path,
        upstream="http://127.0.0.1:9100",
        token="dev-secret",
        allowed_tools=["read_repo"],
        port=8181,
        state="sqlite:policy-state.sqlite3",
    )

    policy = tmp_path / "policy.snulbug"
    config = tmp_path / "snulbug.toml"
    traces = tmp_path / "traces"
    proxy_config = load_mcp_proxy_config(config)

    assert result["ok"] is True
    assert result["client"] == {
        "url": "http://127.0.0.1:8181/mcp",
        "headers": {"Authorization": "Bearer dev-secret"},
    }
    assert result["generated_session"]["file_map"]["config"] == str(config)
    assert result["generated_session"]["primary_client"]["url"] == result["client"]["url"]
    assert result["generated_session"]["log_map"]["audit_events"] == str(tmp_path / "traces/audit.jsonl")
    assert result["generated_session"]["command_map"]["proxy"] == f"uv run snulbug mcp share run --config {config}"
    assert result["next_steps"] == result["generated_session"]["next_steps"]
    assert policy.is_dir()
    assert config.is_file()
    assert traces.is_dir()
    assert proxy_config["upstream"] == "http://127.0.0.1:9100"
    assert proxy_config["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert proxy_config["port"] == 8181
    assert proxy_config["state"] == "sqlite:policy-state.sqlite3"
    assert proxy_config["event_sinks"][0]["type"] == "audit_jsonl"
    assert proxy_config["event_sinks"][0]["path"] == tmp_path / "traces/audit.jsonl"
    assert proxy_config["event_sinks"][1]["type"] == "console"
    assert proxy_config["redact_records"] is True
    assert proxy_config["confirm"] is False
    assert proxy_config["response_redact_secrets"] is True
    assert proxy_config["response_block_instructions"] is False
    assert proxy_config["tool_pinning"] is True
    assert proxy_config["tool_pinning_action"] == "block"
    assert proxy_config["schema_validation"] is True
    assert proxy_config["schema_validation_action"] == "block"
    assert proxy_config["lease_file"] == tmp_path / "leases.json"
    assert proxy_config["lease_required"] is False
    assert proxy_config["lease_header"] == "x-snulbug-lease"
    assert proxy_config["tunnel_provider"] == "auto"
    assert proxy_config["tunnel_public_url"] is None
    assert proxy_config["cloudflare_access"] == "off"
    assert proxy_config["cloudflare_access_require_jwt"] is True
    assert proxy_config["cloudflare_access_require_email"] is False
    assert proxy_config["cloudflare_access_require_cf_ray"] is True
    assert proxy_config["cloudflare_access_allowed_emails"] == []
    assert proxy_config["cloudflare_access_allowed_domains"] == []
    assert validate_bundle(policy)["ok"] is True
    assert run_bundle_tests(policy)["ok"] is True
    assert 'local token = "dev-secret"' in (policy / "policy.lua").read_text(encoding="utf-8")
    assert '"read_repo",' in (policy / "policy.lua").read_text(encoding="utf-8")


def test_mcp_share_quickstart_cli_writes_compact_result(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
            "share",
            "quickstart",
            "--directory",
            str(tmp_path),
            "--upstream",
            "http://127.0.0.1:9100",
            "--token",
            "dev-secret",
            "--allow-tool",
            "read_repo",
            "--port",
            "8181",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["name"] == "mcp share quickstart"
    assert output["files"]["policy"] == str(tmp_path / "policy.snulbug")
    assert output["files"]["config"] == str(tmp_path / "snulbug.toml")
    assert output["client"]["url"] == "http://127.0.0.1:8181/mcp"
    assert output["client"]["headers"]["Authorization"] == "Bearer dev-secret"
    assert output["commands"]["proxy"] == f"uv run snulbug mcp share run --config {tmp_path / 'snulbug.toml'}"
    assert output["metadata"]["preset"] == "local-dev-safe"
    assert output["legacy"]["proxy"]["cloudflare_access"] == "off"
    assert output["legacy"]["validation"]["ok"] is True
    assert output["legacy"]["tests"]["ok"] is True


def test_mcp_share_quickstart_cli_can_generate_path_profile(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
            "share",
            "quickstart",
            "--directory",
            str(tmp_path),
            "--preset",
            "project-path-allowlist",
            "--allow-tool",
            "read_repo",
            "--allow-path",
            "src/",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    policy = (tmp_path / "policy.snulbug" / "policy.lua").read_text(encoding="utf-8")
    assert status == 0
    assert output["ok"] is True
    assert output["metadata"]["preset"] == "project-path-allowlist"
    assert output["legacy"]["policy_options"]["allowed_tools"] == ["read_repo"]
    assert output["legacy"]["policy_options"]["allowed_paths"] == ["src/"]
    assert '"read_repo",' in policy
    assert '"src/",' in policy


def test_mcp_share_quickstart_cli_refuses_to_overwrite_without_force(tmp_path, capsys):
    status = simulator_main(["mcp", "share", "quickstart", "--directory", str(tmp_path), "--compact"])
    assert status == 0
    capsys.readouterr()

    status = simulator_main(["mcp", "share", "quickstart", "--directory", str(tmp_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert "already exists" in output["error"]


def test_mcp_share_quickstart_cli_can_skip_validation(tmp_path, capsys):
    status = simulator_main(["mcp", "share", "quickstart", "--directory", str(tmp_path), "--no-validate", "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["legacy"]["validation"] is None
    assert output["legacy"]["tests"] is None
    assert output["next_steps"][0].startswith("uv run snulbug bundle validate")

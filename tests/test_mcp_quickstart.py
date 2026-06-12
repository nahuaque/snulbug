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
    assert policy.is_dir()
    assert config.is_file()
    assert traces.is_dir()
    assert proxy_config["upstream"] == "http://127.0.0.1:9100"
    assert proxy_config["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert proxy_config["port"] == 8181
    assert proxy_config["state"] == "sqlite:policy-state.sqlite3"
    assert proxy_config["decision_console"] is True
    assert proxy_config["redact_records"] is True
    assert validate_bundle(policy)["ok"] is True
    assert run_bundle_tests(policy)["ok"] is True
    assert 'local token = "dev-secret"' in (policy / "policy.lua").read_text(encoding="utf-8")
    assert '"read_repo",' in (policy / "policy.lua").read_text(encoding="utf-8")


def test_mcp_quickstart_cli_writes_compact_result(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
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
    assert output["policy"] == str(tmp_path / "policy.snulbug")
    assert output["config"] == str(tmp_path / "snulbug.toml")
    assert output["client"]["url"] == "http://127.0.0.1:8181/mcp"
    assert output["client"]["headers"]["Authorization"] == "Bearer dev-secret"
    assert output["validation"]["ok"] is True
    assert output["tests"]["ok"] is True


def test_mcp_quickstart_cli_can_generate_path_profile(tmp_path, capsys):
    status = simulator_main(
        [
            "mcp",
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
    assert output["preset"] == "project-path-allowlist"
    assert output["policy_options"]["allowed_tools"] == ["read_repo"]
    assert output["policy_options"]["allowed_paths"] == ["src/"]
    assert '"read_repo",' in policy
    assert '"src/",' in policy


def test_mcp_quickstart_cli_refuses_to_overwrite_without_force(tmp_path, capsys):
    status = simulator_main(["mcp", "quickstart", "--directory", str(tmp_path), "--compact"])
    assert status == 0
    capsys.readouterr()

    status = simulator_main(["mcp", "quickstart", "--directory", str(tmp_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert "already exists" in output["error"]


def test_mcp_quickstart_cli_can_skip_validation(tmp_path, capsys):
    status = simulator_main(["mcp", "quickstart", "--directory", str(tmp_path), "--no-validate", "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["validation"] is None
    assert output["tests"] is None
    assert output["next_steps"][0].startswith("uv run snulbug bundle validate")

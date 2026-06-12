from __future__ import annotations

import json

from asgi_lua import McpPolicyOptions, copy_builtin_preset, generate_mcp_preset, list_builtin_presets, validate_bundle
from asgi_lua import test_bundle as run_bundle_tests
from asgi_lua.simulator import main as simulator_main


def test_builtin_mcp_presets_are_listed():
    presets = {preset["preset"]: preset for preset in list_builtin_presets()}

    assert set(presets) == {"auth-required", "local-dev-safe", "tool-allowlist"}
    assert presets["local-dev-safe"]["required_capabilities"] == ["body", "mcp", "state", "rate_limit"]


def test_builtin_mcp_presets_copy_validate_and_test(tmp_path):
    for preset in list_builtin_presets():
        output = tmp_path / f"{preset['preset']}.asgi-lua"

        result = copy_builtin_preset(str(preset["preset"]), output)

        assert result["ok"] is True
        assert (output / "manifest.json").is_file()
        assert (output / "policy.lua").is_file()
        assert validate_bundle(output)["ok"] is True
        bundle_result = run_bundle_tests(output)
        assert bundle_result["ok"] is True
        assert bundle_result["passed"] == bundle_result["fixture_count"]


def test_mcp_presets_cli_lists_presets(capsys):
    status = simulator_main(["mcp", "presets", "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert [preset["preset"] for preset in output["presets"]] == [
        "auth-required",
        "local-dev-safe",
        "tool-allowlist",
    ]


def test_mcp_init_cli_copies_default_preset(tmp_path, capsys):
    output_path = tmp_path / "policy.asgi-lua"

    status = simulator_main(["mcp", "init", "--output", str(output_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["preset"] == "local-dev-safe"
    assert output["output"] == str(output_path)
    assert validate_bundle(output_path)["ok"] is True
    assert run_bundle_tests(output_path)["ok"] is True


def test_mcp_init_cli_refuses_to_overwrite(tmp_path, capsys):
    output_path = tmp_path / "policy.asgi-lua"
    output_path.mkdir()

    status = simulator_main(["mcp", "init", "auth-required", "--output", str(output_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert "already exists" in output["error"]


def test_generate_mcp_preset_renders_custom_policy_values(tmp_path):
    output_path = tmp_path / "policy.asgi-lua"

    result = generate_mcp_preset(
        "local-dev-safe",
        output_path,
        options=McpPolicyOptions(
            token="custom-secret",
            allowed_tools=["read_repo"],
            rate_limit=7,
            rate_window=11,
        ),
    )

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    safe_fixture = json.loads((output_path / "fixtures" / "safe-tool.json").read_text(encoding="utf-8"))
    assert result["generated"] is True
    assert 'local token = "custom-secret"' in policy
    assert '"read_repo",' in policy
    assert "limit = 7" in policy
    assert "window = 11" in policy
    assert safe_fixture["headers"]["authorization"] == "Bearer custom-secret"
    assert "read_repo" in safe_fixture["body"]
    assert validate_bundle(output_path)["ok"] is True
    bundle_result = run_bundle_tests(output_path)
    assert bundle_result["ok"] is True


def test_generate_mcp_preset_can_use_context_token_env(tmp_path):
    output_path = tmp_path / "policy.asgi-lua"

    generate_mcp_preset(
        "auth-required",
        output_path,
        options=McpPolicyOptions(token_env="MCP_GATEWAY_TOKEN", token="fallback-secret"),
    )

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    assert 'local token = context.mcp_gateway_token or "fallback-secret"' in policy
    assert validate_bundle(output_path)["ok"] is True


def test_mcp_init_cli_generates_custom_policy(tmp_path, capsys):
    output_path = tmp_path / "policy.asgi-lua"

    status = simulator_main(
        [
            "mcp",
            "init",
            "tool-allowlist",
            "--output",
            str(output_path),
            "--allow-tool",
            "read_repo",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    assert status == 0
    assert output["generated"] is True
    assert '"read_repo",' in policy
    assert validate_bundle(output_path)["ok"] is True
    assert run_bundle_tests(output_path)["ok"] is True

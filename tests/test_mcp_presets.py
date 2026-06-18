from __future__ import annotations

import json

from snulbug import (
    McpPolicyOptions,
    copy_builtin_preset,
    generate_mcp_preset,
    list_builtin_presets,
    simulate_policy,
    validate_bundle,
)
from snulbug import test_bundle as run_bundle_tests
from snulbug.simulator import main as simulator_main


def test_builtin_mcp_presets_are_listed():
    presets = {preset["preset"]: preset for preset in list_builtin_presets()}

    assert set(presets) == {
        "auth-required",
        "local-dev-safe",
        "no-shell-tools",
        "project-path-allowlist",
        "read-only-local-dev",
        "tool-allowlist",
        "tunnel-safe",
        "workspace-firewall",
    }
    assert presets["local-dev-safe"]["required_capabilities"] == ["body", "mcp", "state", "rate_limit"]
    assert presets["tunnel-safe"]["risk_profile"] == "tunnel-safe"
    assert presets["workspace-firewall"]["risk_profile"] == "workspace-firewall"


def test_builtin_mcp_presets_copy_validate_and_test(tmp_path):
    for preset in list_builtin_presets():
        output = tmp_path / f"{preset['preset']}.snulbug"

        result = copy_builtin_preset(str(preset["preset"]), output)

        assert result["ok"] is True
        assert (output / "manifest.json").is_file()
        assert (output / "policy.lua").is_file()
        assert validate_bundle(output)["ok"] is True
        bundle_result = run_bundle_tests(output)
        assert bundle_result["ok"] is True
        assert bundle_result["passed"] == bundle_result["fixture_count"]


def test_mcp_policy_preset_cli_lists_presets(capsys):
    status = simulator_main(["mcp", "policy", "preset", "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert [preset["preset"] for preset in output["presets"]] == [
        "auth-required",
        "local-dev-safe",
        "no-shell-tools",
        "project-path-allowlist",
        "read-only-local-dev",
        "tool-allowlist",
        "tunnel-safe",
        "workspace-firewall",
    ]


def test_mcp_policy_preset_cli_copies_default_preset(tmp_path, capsys):
    output_path = tmp_path / "policy.snulbug"

    status = simulator_main(["mcp", "policy", "preset", "--output", str(output_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["preset"] == "local-dev-safe"
    assert output["output"] == str(output_path)
    assert validate_bundle(output_path)["ok"] is True
    assert run_bundle_tests(output_path)["ok"] is True


def test_mcp_policy_preset_cli_refuses_to_overwrite(tmp_path, capsys):
    output_path = tmp_path / "policy.snulbug"
    output_path.mkdir()

    status = simulator_main(["mcp", "policy", "preset", "auth-required", "--output", str(output_path), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert "already exists" in output["error"]


def test_generate_mcp_preset_renders_custom_policy_values(tmp_path):
    output_path = tmp_path / "policy.snulbug"

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


def test_generate_tunnel_safe_preset_declares_invite_capabilities(tmp_path):
    output_path = tmp_path / "policy.snulbug"

    generate_mcp_preset("tunnel-safe", output_path)

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    assert "capabilities.declare" in policy
    assert 'id = "project_readonly"' in policy
    assert "default = true" in policy


def test_generate_mcp_preset_can_use_context_token_env(tmp_path):
    output_path = tmp_path / "policy.snulbug"

    generate_mcp_preset(
        "auth-required",
        output_path,
        options=McpPolicyOptions(token_env="MCP_GATEWAY_TOKEN", token="fallback-secret"),
    )

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    assert 'local token = context.mcp_gateway_token or "fallback-secret"' in policy
    assert validate_bundle(output_path)["ok"] is True


def test_generate_project_path_profile_renders_custom_paths(tmp_path):
    output_path = tmp_path / "policy.snulbug"

    result = generate_mcp_preset(
        "project-path-allowlist",
        output_path,
        options=McpPolicyOptions(
            token="custom-secret",
            allowed_tools=["read_repo"],
            allowed_paths=["src/", "README.md"],
        ),
    )

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    fixture = json.loads((output_path / "fixtures" / "allowed-path.json").read_text(encoding="utf-8"))
    assert result["generated"] is True
    assert '"read_repo",' in policy
    assert '"src/",' in policy
    assert fixture["headers"]["authorization"] == "Bearer custom-secret"
    assert "read_repo" in fixture["body"]
    assert "src/" in fixture["body"]
    assert validate_bundle(output_path)["ok"] is True
    assert run_bundle_tests(output_path)["ok"] is True


def test_generate_workspace_firewall_profile_blocks_generated_write_paths(tmp_path):
    output_path = tmp_path / "policy.snulbug"

    result = generate_mcp_preset(
        "workspace-firewall",
        output_path,
        options=McpPolicyOptions(
            token="custom-secret",
            allowed_tools=["safe_read_file", "write_file"],
            allowed_paths=["README.md", "docs/", "dist/"],
        ),
    )

    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    allowed = simulate_policy(
        output_path / "policy.lua",
        {
            "method": "POST",
            "path": "/mcp",
            "headers": {"authorization": "Bearer custom-secret", "content-type": "application/json"},
            "body": (
                '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                '"params":{"name":"safe_read_file","arguments":{"path":"docs/guide.md"}}}'
            ),
        },
    )
    generated_write = simulate_policy(
        output_path / "policy.lua",
        {
            "method": "POST",
            "path": "/mcp",
            "headers": {"authorization": "Bearer custom-secret", "content-type": "application/json"},
            "body": (
                '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                '"params":{"name":"write_file","arguments":{"path":"dist/app.js","content":"new"}}}'
            ),
        },
    )

    assert result["generated"] is True
    assert '"write_file",' in policy
    assert '"dist/",' in policy
    assert allowed["action"] == "continue"
    assert allowed["decision"]["context"]["workspace"]["path_class"] == "allowed"
    assert generated_write["action"] == "reject"
    assert generated_write["decision"]["reason_code"] == "mcp.workspace_generated_write_blocked"
    assert generated_write["decision"]["context"]["workspace"] == {
        "argument": "path",
        "path": "dist/app.js",
        "path_class": "generated",
        "write_intent": True,
    }
    assert validate_bundle(output_path)["ok"] is True


def test_mcp_policy_preset_cli_generates_custom_policy(tmp_path, capsys):
    output_path = tmp_path / "policy.snulbug"

    status = simulator_main(
        [
            "mcp",
            "policy",
            "preset",
            "project-path-allowlist",
            "--output",
            str(output_path),
            "--allow-tool",
            "read_repo",
            "--allow-path",
            "src/",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    policy = (output_path / "policy.lua").read_text(encoding="utf-8")
    assert status == 0
    assert output["generated"] is True
    assert '"read_repo",' in policy
    assert '"src/",' in policy
    assert output["options"]["allowed_paths"] == ["src/"]
    assert validate_bundle(output_path)["ok"] is True
    assert run_bundle_tests(output_path)["ok"] is True

from __future__ import annotations

import json

from asgi_lua import copy_builtin_preset, list_builtin_presets, validate_bundle
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

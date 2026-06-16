from __future__ import annotations

import json

from snulbug import run_mcp_auth_lab, run_mcp_lab, validate_bundle
from snulbug.simulator import main as simulator_main


def test_run_mcp_lab_exercises_policy_lifecycle(tmp_path):
    output = tmp_path / "lab"

    result = run_mcp_lab(output, emit=False)

    assert result["ok"] is True
    assert result["tools"] == ["files.read_file", "files.shell_exec", "git.status"]
    assert [step["ok"] for step in result["steps"]] == [True, True, True, True, True, True, True]
    assert result["steps"][4]["reason_code"] == "mcp.learn.tool_not_observed"
    assert validate_bundle(output / "learned-policy.snulbug")["ok"] is True
    assert validate_bundle(output / "candidate-policy.snulbug")["ok"] is True
    assert (output / "traces" / "session.jsonl").is_file()
    assert (output / "traces" / "audit.jsonl").is_file()
    assert (output / "traces" / "blocked.jsonl").is_file()
    assert (output / "traces" / "session-report.md").is_file()
    assert (output / "candidate-policy.snulbug" / "AMEND.md").is_file()
    assert any("decision=continue" in line for line in result["decision_console"])


def test_mcp_lab_cli_compact_outputs_json(tmp_path, capsys):
    output = tmp_path / "lab"

    status = simulator_main(["mcp", "share", "demo", "local", "--output-dir", str(output), "--compact"])

    payload = json.loads(capsys.readouterr().out)
    assert status == 0
    assert payload["ok"] is True
    assert payload["output_dir"] == str(output)
    assert payload["artifacts"]["learned_policy"] == str(output / "learned-policy.snulbug")


def test_run_mcp_auth_lab_exercises_oauth_scope_lease_lua_access(tmp_path):
    output = tmp_path / "auth-lab"

    result = run_mcp_auth_lab(output, emit=False)

    assert result["ok"] is True
    assert result["doctor"]["ok"] is True
    assert [step["ok"] for step in result["steps"]] == [True, True, True, True, True]
    assert result["steps"][1]["access"]["reason_code"] == "access.oauth_scope_lease_lua_allowed"
    assert result["steps"][2]["access"]["reason_code"] == "lease.missing"
    assert result["steps"][3]["access"]["reason_code"] == "oauth.scope_map_denied"
    assert result["token_redacted"] is True
    assert result["leases"]["leases"][0]["use_count"] == 1
    assert (output / "snulbug.toml").is_file()
    assert (output / "policy.lua").is_file()
    assert (output / "auth" / "jwks.json").is_file()
    assert (output / "auth" / "tokens.json").is_file()
    assert (output / "leases.json").is_file()
    assert (output / "traces" / "session.jsonl").is_file()
    assert (output / "traces" / "audit.jsonl").is_file()
    assert (output / "AUTH_LAB.md").is_file()


def test_mcp_share_auth_lab_cli_compact_outputs_json(tmp_path, capsys):
    output = tmp_path / "auth-lab"

    status = simulator_main(["mcp", "share", "demo", "auth", "--output-dir", str(output), "--compact"])

    payload = json.loads(capsys.readouterr().out)
    assert status == 0
    assert payload["ok"] is True
    assert payload["output_dir"] == str(output)
    assert payload["artifacts"]["report"] == str(output / "AUTH_LAB.md")

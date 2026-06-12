from __future__ import annotations

import json

from snulbug import append_record, learn_mcp_policy, record_policy_request, simulate_policy, validate_bundle
from snulbug.simulator import main as simulator_main


def test_learn_mcp_policy_generates_enforcing_bundle(tmp_path):
    log = write_observed_log(tmp_path)
    output = tmp_path / "learned.snulbug"

    result = learn_mcp_policy(log, output)

    assert result["ok"] is True
    assert result["methods"] == ["tools/call", "tools/list"]
    assert result["tools"] == ["files.read_file"]
    assert validate_bundle(output)["ok"] is True
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["generated_by"] == "snulbug mcp learn"
    assert manifest["learned"]["tools"] == ["files.read_file"]
    report = (output / "LEARNED.md").read_text(encoding="utf-8")
    assert "`files.read_file`" in report
    assert "`path`" in report

    allowed = simulate_policy(
        output / "policy.lua",
        {
            "method": "POST",
            "path": "/mcp",
            "body": (
                '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                '"params":{"name":"files.read_file","arguments":{"path":"README.md"}}}'
            ),
        },
    )
    assert allowed["action"] == "continue"
    assert allowed["decision"]["reason_code"] == "mcp.learn.allowed"

    unknown_tool = simulate_policy(
        output / "policy.lua",
        {
            "method": "POST",
            "path": "/mcp",
            "body": (
                '{"jsonrpc":"2.0","id":3,"method":"tools/call",'
                '"params":{"name":"shell_exec","arguments":{"command":"pwd"}}}'
            ),
        },
    )
    assert unknown_tool["action"] == "reject"
    assert unknown_tool["decision"]["reason_code"] == "mcp.learn.tool_not_observed"

    unknown_argument = simulate_policy(
        output / "policy.lua",
        {
            "method": "POST",
            "path": "/mcp",
            "body": (
                '{"jsonrpc":"2.0","id":4,"method":"tools/call",'
                '"params":{"name":"files.read_file","arguments":{"path":"README.md","secret":"x"}}}'
            ),
        },
    )
    assert unknown_argument["action"] == "reject"
    assert unknown_argument["decision"]["reason_code"] == "mcp.learn.argument_not_observed"


def test_mcp_learn_cli_writes_bundle(tmp_path, capsys):
    log = write_observed_log(tmp_path)
    output = tmp_path / "learned.snulbug"

    status = simulator_main(["mcp", "learn", str(log), "--out", str(output), "--compact"])

    payload = json.loads(capsys.readouterr().out)
    assert status == 0
    assert payload["ok"] is True
    assert payload["output"] == str(output)
    assert (output / "policy.lua").is_file()
    assert (output / "manifest.json").is_file()
    assert (output / "LEARNED.md").is_file()


def write_observed_log(tmp_path):
    policy = tmp_path / "allow.lua"
    policy.write_text(
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
    log = tmp_path / "session.jsonl"
    append_record(
        log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            },
            response={"status": 200},
        ),
    )
    append_record(
        log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": (
                    '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                    '"params":{"name":"files.read_file","arguments":{"path":"README.md"}}}'
                ),
            },
            response={"status": 200},
        ),
    )
    return log

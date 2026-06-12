from __future__ import annotations

import json

from snulbug import append_record, load_record_log, record_policy_request, replay_record_log
from snulbug.simulator import main as simulator_main


def test_record_policy_request_creates_replayable_record(tmp_path):
    policy = write_policy(tmp_path, "policy.lua", "continue")
    request = {"method": "POST", "path": "/mcp", "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}
    log = tmp_path / "requests.jsonl"

    record = record_policy_request(policy, request, recorded_at="2026-06-12T00:00:00+00:00")
    append_record(log, record)

    records = load_record_log(log)
    replay = replay_record_log(log)

    assert records[0]["type"] == "snulbug.request_record"
    assert records[0]["version"] == 1
    assert records[0]["request"] == request
    assert records[0]["result"]["action"] == "continue"
    assert replay["ok"] is True
    assert replay["changed"] == 0
    assert replay["record_count"] == 1


def test_replay_record_log_detects_policy_drift(tmp_path):
    old_policy = write_policy(tmp_path, "old.lua", "continue")
    new_policy = write_policy(tmp_path, "new.lua", "reject")
    request = {"method": "POST", "path": "/mcp", "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}
    log = tmp_path / "requests.jsonl"

    append_record(log, record_policy_request(old_policy, request))

    replay = replay_record_log(log, script_path=new_policy)

    assert replay["ok"] is False
    assert replay["changed"] == 1
    assert replay["results"][0]["recorded"]["decision"]["action"] == "continue"
    assert replay["results"][0]["actual"]["decision"]["action"] == "reject"


def test_mcp_record_and_replay_cli(tmp_path, capsys):
    policy = write_policy(tmp_path, "policy.lua", "continue")
    request = tmp_path / "request.json"
    log = tmp_path / "requests.jsonl"
    request.write_text(
        json.dumps({"method": "POST", "path": "/mcp", "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}),
        encoding="utf-8",
    )

    record_status = simulator_main(["mcp", "record", str(policy), str(request), "--out", str(log), "--compact"])
    record_output = json.loads(capsys.readouterr().out)
    replay_status = simulator_main(["mcp", "replay", str(log), "--compact"])
    replay_output = json.loads(capsys.readouterr().out)

    assert record_status == 0
    assert record_output["ok"] is True
    assert record_output["action"] == "continue"
    assert log.read_text(encoding="utf-8").count("\n") == 1
    assert replay_status == 0
    assert replay_output["ok"] is True
    assert replay_output["record_count"] == 1


def test_mcp_replay_cli_returns_nonzero_for_drift(tmp_path, capsys):
    old_policy = write_policy(tmp_path, "old.lua", "continue")
    new_policy = write_policy(tmp_path, "new.lua", "reject")
    request = {"method": "POST", "path": "/mcp", "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}
    log = tmp_path / "requests.jsonl"
    append_record(log, record_policy_request(old_policy, request))

    status = simulator_main(["mcp", "replay", str(log), "--script", str(new_policy), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert output["changed"] == 1


def write_policy(tmp_path, name: str, action: str):
    if action == "continue":
        decision = '{ action = "continue", context = { policy = "old" } }'
    else:
        decision = '{ action = "reject", status = 403, body = "blocked" }'
    path = tmp_path / name
    path.write_text(
        f"""
        return function(request, context, state)
          return {decision}
        end
        """,
        encoding="utf-8",
    )
    return path

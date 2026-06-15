from __future__ import annotations

import json

from snulbug import (
    append_audit_event,
    append_record,
    build_audit_event,
    format_mcp_inspection_report,
    inspect_mcp_log,
    record_policy_request,
)
from snulbug.simulator import main as simulator_main


def test_inspect_mcp_audit_log_summarizes_decisions_and_findings(tmp_path):
    policy = write_policy(tmp_path)
    audit_log = tmp_path / "audit.jsonl"
    allowed = build_audit_event(
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            },
            response={"status": 200},
            recorded_at="2026-06-12T00:00:00+00:00",
        )
    )
    blocked = build_audit_event(
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell_exec"}}',
            },
            response={"status": 403},
            recorded_at="2026-06-12T00:01:00+00:00",
        )
    )
    invalid = dict(allowed)
    invalid["time"] = "2026-06-12T00:02:00+00:00"
    invalid["mcp"] = {"body_kind": "invalid", "valid_json": False}
    invalid["decision"] = {"action": "reject", "allowed": False, "reason_code": "mcp.invalid_json"}
    invalid["response"] = {"status": 400}
    append_audit_event(audit_log, allowed)
    append_audit_event(audit_log, blocked)
    append_audit_event(audit_log, invalid)

    report = inspect_mcp_log(audit_log)

    assert report["ok"] is True
    assert report["kind"] == "audit"
    assert report["event_count"] == 3
    assert report["time_range"] == {
        "first": "2026-06-12T00:00:00+00:00",
        "last": "2026-06-12T00:02:00+00:00",
    }
    assert report["decisions"]["blocked"] == 2
    assert {"value": "continue", "count": 1} in report["decisions"]["actions"]
    assert {"value": "mcp.tool_not_allowed", "count": 1} in report["decisions"]["reason_codes"]
    assert {"value": "tools/call", "count": 1} in report["mcp"]["methods"]
    assert {"value": "shell_exec", "count": 1} in report["mcp"]["tools"]
    assert report["mcp"]["invalid_json"] == 1
    assert {"type": "blocked_decisions", "severity": "warning", "count": 2} in report["findings"]
    assert {"type": "invalid_mcp_json", "severity": "warning", "count": 1} in report["findings"]
    assert report["examples"]["blocked"][0]["reason_code"] == "mcp.tool_not_allowed"


def test_inspect_mcp_record_log_normalizes_to_audit_shape(tmp_path):
    policy = write_policy(tmp_path)
    record_log = tmp_path / "records.jsonl"
    append_record(
        record_log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_read_file"}}',
            },
            response={"status": 200},
        ),
    )

    report = inspect_mcp_log(record_log, kind="record")

    assert report["kind"] == "record"
    assert report["event_count"] == 1
    assert report["decisions"]["allowed"] == 1
    assert report["mcp"]["tools"] == [{"value": "safe_read_file", "count": 1}]


def test_format_mcp_inspection_report_outputs_markdown_summary(tmp_path):
    policy = write_policy(tmp_path)
    audit_log = tmp_path / "audit.jsonl"
    append_audit_event(
        audit_log,
        build_audit_event(
            record_policy_request(
                policy,
                {
                    "method": "POST",
                    "path": "/mcp",
                    "body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}',
                },
                response={"status": 403},
            )
        ),
    )

    report = format_mcp_inspection_report(inspect_mcp_log(audit_log))

    assert report.startswith("# snulbug MCP Session Report")
    assert "| Events | 1 |" in report
    assert "mcp.tool_not_allowed" in report
    assert "shell_exec" in report
    assert "Blocked Decisions" in report


def test_mcp_inspect_cli_outputs_compact_report(tmp_path, capsys):
    policy = write_policy(tmp_path)
    record_log = tmp_path / "records.jsonl"
    append_record(
        record_log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            },
        ),
    )

    status = simulator_main(["mcp", "evidence", "inspect", str(record_log), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert output["kind"] == "record"
    assert output["event_count"] == 1

    rich_status = simulator_main(["mcp", "evidence", "inspect", str(record_log)])
    rich_output = capsys.readouterr().out

    assert rich_status == 0
    assert "snulbug evidence inspect" in rich_output
    assert "Decision Actions" in rich_output


def test_mcp_inspect_cli_writes_markdown_session_report(tmp_path, capsys):
    policy = write_policy(tmp_path)
    record_log = tmp_path / "records.jsonl"
    report_path = tmp_path / "reports" / "session.md"
    append_record(
        record_log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec"}}',
            },
            response={"status": 403},
        ),
    )

    status = simulator_main(
        ["mcp", "evidence", "inspect", str(record_log), "--report-out", str(report_path), "--compact"]
    )

    output = json.loads(capsys.readouterr().out)
    report = report_path.read_text(encoding="utf-8")
    assert status == 0
    assert output["ok"] is True
    assert output["report_out"] == str(report_path)
    assert output["report_format"] == "markdown"
    assert "# snulbug MCP Session Report" in report
    assert "mcp.tool_not_allowed" in report
    assert "shell_exec" in report


def test_mcp_inspect_cli_returns_nonzero_for_bad_log(tmp_path, capsys):
    log = tmp_path / "bad.jsonl"
    log.write_text("{}\n", encoding="utf-8")

    status = simulator_main(["mcp", "evidence", "inspect", str(log), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 1
    assert output["ok"] is False
    assert "unsupported event type" in output["error"]


def write_policy(tmp_path):
    path = tmp_path / "policy.lua"
    path.write_text(
        """
        return function(request, context, state)
          local blocked = mcp.allow_tools(request, { "safe_read_file" })
          if blocked ~= nil then
            return blocked
          end
          return {
            action = "continue",
            reason = "request allowed",
            reason_code = "test.allowed",
            context = {
              method = mcp.method(request) or "",
              tool = mcp.tool_name(request) or ""
            }
          }
        end
        """,
        encoding="utf-8",
    )
    return path

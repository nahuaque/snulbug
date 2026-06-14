from __future__ import annotations

import json

from snulbug import analyze_mcp_impact, create_lease, format_mcp_impact_report, record_policy_request
from snulbug.recorder import append_record
from snulbug.simulator import main as simulator_main


def test_mcp_impact_reports_policy_newly_blocked_decisions(tmp_path):
    active = write_policy(tmp_path, "active.lua", blocked_tools={"shell_exec"})
    candidate = write_policy(tmp_path, "candidate.lua", blocked_tools={"read_file", "shell_exec"})
    log = tmp_path / "session.jsonl"
    append_record(
        log,
        record_policy_request(
            active,
            mcp_request("call-1", "read_file", {"path": "README.md"}),
            redact=False,
        ),
    )

    result = analyze_mcp_impact(log, policy=candidate)

    assert result["ok"] is False
    assert result["policy"]["changed"] == 1
    assert result["policy"]["newly_blocked"] == 1
    assert result["policy"]["changes"][0]["tool"] == "read_file"
    assert result["findings"][0]["type"] == "policy.newly_blocked"


def test_mcp_impact_reports_lease_coverage_and_risks(tmp_path):
    policy = write_policy(tmp_path, "active.lua")
    log = tmp_path / "session.jsonl"
    append_record(
        log,
        record_policy_request(policy, mcp_request("call-1", "read_file", {"path": "README.md"}), redact=False),
    )
    append_record(
        log,
        record_policy_request(policy, mcp_request("call-2", "read_file", {"path": "../secret.env"}), redact=False),
    )
    lease_file = tmp_path / "leases.json"
    create_lease(
        lease_file,
        task="Read README",
        allow_tools=["read_file"],
        allow_paths=["README.md"],
        ttl="30m",
        token="sbl_test-token",
    )

    result = analyze_mcp_impact(log, lease_file=lease_file)

    assert result["ok"] is False
    assert result["lease"]["tool_call_count"] == 2
    assert result["lease"]["covered"] == 1
    assert result["lease"]["uncovered"] == 1
    assert result["lease"]["uncovered_examples"][0]["lease_reason_code"] == "lease.path_not_allowed"


def test_mcp_impact_cli_writes_markdown_report_and_can_no_fail(tmp_path, capsys):
    active = write_policy(tmp_path, "active.lua")
    candidate = write_policy(tmp_path, "candidate.lua", blocked_tools={"read_file"})
    log = tmp_path / "session.jsonl"
    report = tmp_path / "impact.md"
    append_record(
        log,
        record_policy_request(active, mcp_request("call-1", "read_file", {"path": "README.md"}), redact=False),
    )

    status = simulator_main(
        [
            "mcp",
            "evidence",
            "impact",
            str(log),
            "--policy",
            str(candidate),
            "--report-out",
            str(report),
            "--no-fail",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is False
    assert output["report_out"] == str(report)
    assert "# snulbug MCP Impact Report" in report.read_text(encoding="utf-8")


def test_mcp_impact_report_formats_markdown(tmp_path):
    active = write_policy(tmp_path, "active.lua")
    log = tmp_path / "session.jsonl"
    append_record(
        log,
        record_policy_request(active, mcp_request("call-1", "read_file", {"path": "README.md"}), redact=False),
    )

    report = format_mcp_impact_report(analyze_mcp_impact(log, policy=active))

    assert "## Policy Impact" in report
    assert "| Changed | 0 |" in report


def mcp_request(request_id: str, tool: str, arguments: dict[str, object]):
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": {"authorization": "Bearer local-dev-secret"},
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
            separators=(",", ":"),
        ),
    }


def write_policy(tmp_path, name: str, *, blocked_tools: set[str] | None = None):
    blocked_tools = blocked_tools or set()
    blocked_lua = "\n".join(f'  ["{tool}"] = true,' for tool in sorted(blocked_tools))
    path = tmp_path / name
    path.write_text(
        f"""
        local blocked_tools = {{
        {blocked_lua}
        }}

        return function(request, context, state)
          local method = mcp.method(request)
          local tool = mcp.tool_name(request)
          if blocked_tools[tool] then
            return {{
              action = "reject",
              status = 403,
              body = "blocked",
              reason = "blocked by test policy",
              reason_code = "test.blocked",
              context = {{ method = method, tool = tool }}
            }}
          end
          return {{
            action = "continue",
            reason = "allowed by test policy",
            reason_code = "test.allowed",
            context = {{ method = method, tool = tool }}
          }}
        end
        """,
        encoding="utf-8",
    )
    return path

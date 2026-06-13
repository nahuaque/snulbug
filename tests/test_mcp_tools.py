from __future__ import annotations

import json

from snulbug import (
    MCP_TOOL_SNAPSHOT_SCHEMA,
    build_mcp_tool_snapshot,
    diff_mcp_tool_snapshots,
    parse_mcp_tool_headers,
    snapshot_mcp_tools,
)
from snulbug.simulator import main as simulator_main


def test_snapshot_mcp_tools_normalizes_tools_list_response(tmp_path):
    response = tmp_path / "tools-list.json"
    out = tmp_path / "tools.snapshot.json"
    response.write_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "tools",
                "result": {
                    "tools": [
                        {
                            "name": "write_file",
                            "description": "Write a file",
                            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                        },
                        {
                            "name": "read_file",
                            "description": "Read a file",
                            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    snapshot = snapshot_mcp_tools(source=response, out=out, label="dev")
    saved = json.loads(out.read_text(encoding="utf-8"))

    assert snapshot["ok"] is True
    assert snapshot["schema"] == MCP_TOOL_SNAPSHOT_SCHEMA
    assert snapshot["label"] == "dev"
    assert snapshot["tool_count"] == 2
    assert [tool["name"] for tool in snapshot["tools"]] == ["read_file", "write_file"]
    assert len(snapshot["tools"][0]["hash"]) == 64
    assert saved["tools"] == snapshot["tools"]


def test_diff_mcp_tool_snapshots_reports_added_changed_and_removed():
    baseline = build_mcp_tool_snapshot(
        [
            {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
        ],
        label="baseline",
    )
    current = build_mcp_tool_snapshot(
        [
            {
                "name": "read_file",
                "description": "Read a project file",
                "inputSchema": {"type": "object", "required": ["path"]},
            },
            {"name": "list_files", "description": "List files", "inputSchema": {"type": "object"}},
        ],
        label="current",
    )

    informational = diff_mcp_tool_snapshots(baseline, current)
    blocking = diff_mcp_tool_snapshots(baseline, current, fail_on=["changed", "removed"])

    assert informational["ok"] is True
    assert informational["summary"] == {
        "added": 1,
        "changed": 1,
        "removed": 1,
        "unchanged": 0,
        "baseline_tools": 2,
        "current_tools": 2,
    }
    assert informational["added"][0]["name"] == "list_files"
    assert informational["removed"][0]["name"] == "write_file"
    assert informational["changed"][0]["name"] == "read_file"
    assert informational["changed"][0]["changed_fields"] == ["description", "inputSchema"]
    assert blocking["ok"] is False
    assert blocking["failing_changes"] == {"added": 0, "changed": 1, "removed": 1}


def test_mcp_tools_cli_snapshot_and_diff(tmp_path, capsys):
    baseline_response = tmp_path / "baseline.json"
    current_response = tmp_path / "current.json"
    baseline_snapshot = tmp_path / "baseline.snapshot.json"
    current_snapshot = tmp_path / "current.snapshot.json"
    baseline_response.write_text(
        json.dumps({"result": {"tools": [{"name": "read_file", "description": "Read", "inputSchema": {}}]}}),
        encoding="utf-8",
    )
    current_response.write_text(
        json.dumps(
            {
                "result": {
                    "tools": [
                        {"name": "read_file", "description": "Read", "inputSchema": {}},
                        {"name": "write_file", "description": "Write", "inputSchema": {}},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    status = simulator_main(
        [
            "mcp",
            "tools",
            "snapshot",
            "--from",
            str(baseline_response),
            "--out",
            str(baseline_snapshot),
            "--compact",
        ]
    )
    baseline_output = json.loads(capsys.readouterr().out)
    status_current = simulator_main(
        [
            "mcp",
            "tools",
            "snapshot",
            "--from",
            str(current_response),
            "--out",
            str(current_snapshot),
            "--compact",
        ]
    )
    current_output = json.loads(capsys.readouterr().out)
    diff_status = simulator_main(
        [
            "mcp",
            "tools",
            "diff",
            str(baseline_snapshot),
            str(current_snapshot),
            "--fail-on",
            "added",
            "--compact",
        ]
    )
    diff_output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert status_current == 0
    assert baseline_output["output"] == str(baseline_snapshot)
    assert current_output["tool_count"] == 2
    assert diff_status == 1
    assert diff_output["ok"] is False
    assert diff_output["summary"]["added"] == 1
    assert diff_output["added"][0]["name"] == "write_file"


def test_parse_mcp_tool_headers_adds_bearer_when_missing():
    headers = parse_mcp_tool_headers(["X-Test: yes"], token="secret")

    assert headers == {"x-test": "yes", "authorization": "Bearer secret"}

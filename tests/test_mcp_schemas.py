from __future__ import annotations

import json

from snulbug import (
    MCP_SCHEMA_CATALOG_SCHEMA,
    build_mcp_schema_catalog,
    build_mcp_tool_snapshot,
    diff_mcp_schema_catalogs,
    discover_mcp_schemas,
    parse_mcp_schema_headers,
)
from snulbug.simulator import main as simulator_main


def _schema_responses(*, tool_description: str = "Read a demo file", include_resource: bool = True) -> dict:
    resources = (
        [
            {
                "uri": "file:///workspace/README.md",
                "name": "README",
                "title": "Readme",
                "description": "Project readme",
                "mimeType": "text/markdown",
            }
        ]
        if include_resource
        else []
    )
    return {
        "initialize": {
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": True}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "demo-server", "version": "1.0.0"},
            }
        },
        "tools/list": {
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "title": "Read",
                        "description": tool_description,
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                        "outputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                        "annotations": {"readOnlyHint": True},
                    }
                ]
            }
        },
        "resources/list": {"result": {"resources": resources}},
        "resources/templates/list": {
            "result": {
                "resourceTemplates": [
                    {
                        "uriTemplate": "file:///{path}",
                        "name": "project_file",
                        "description": "Project file",
                        "mimeType": "text/plain",
                    }
                ]
            }
        },
        "prompts/list": {
            "result": {
                "prompts": [
                    {
                        "name": "review",
                        "title": "Review",
                        "description": "Review a project file",
                        "arguments": [{"name": "path", "description": "File path", "required": True}],
                    }
                ]
            }
        },
    }


def test_discover_mcp_schemas_from_response_collection_writes_catalog_and_report(tmp_path):
    source = tmp_path / "responses.json"
    out = tmp_path / "catalog.json"
    report = tmp_path / "catalog.md"
    source.write_text(json.dumps({"responses": _schema_responses()}), encoding="utf-8")

    catalog = discover_mcp_schemas(source=source, out=out, report_out=report, label="dev")
    saved = json.loads(out.read_text(encoding="utf-8"))
    report_text = report.read_text(encoding="utf-8")

    assert catalog["ok"] is True
    assert catalog["schema"] == MCP_SCHEMA_CATALOG_SCHEMA
    assert catalog["label"] == "dev"
    assert catalog["summary"] == {"tools": 1, "resources": 1, "resource_templates": 1, "prompts": 1, "errors": 0}
    assert len(catalog["hash"]) == 64
    assert catalog["server"]["serverInfo"]["name"] == "demo-server"
    assert catalog["surfaces"]["tools"][0]["outputSchema"]["properties"]["text"]["type"] == "string"
    assert saved["surfaces"] == catalog["surfaces"]
    assert "# snulbug mcp policy schemas discover" in report_text
    assert "- `read_file`" in report_text


def test_diff_mcp_schema_catalogs_reports_added_changed_and_removed():
    baseline = build_mcp_schema_catalog(_schema_responses(), label="baseline")
    current_responses = _schema_responses(tool_description="Read a project file", include_resource=False)
    current_responses["prompts/list"]["result"]["prompts"].append(
        {
            "name": "summarize",
            "description": "Summarize a project file",
            "arguments": [{"name": "path", "required": True}],
        }
    )
    current = build_mcp_schema_catalog(current_responses, label="current")

    informational = diff_mcp_schema_catalogs(baseline, current)
    blocking = diff_mcp_schema_catalogs(baseline, current, fail_on=["changed", "removed"])

    assert informational["ok"] is True
    assert informational["summary"] == {
        "added": 1,
        "changed": 1,
        "removed": 1,
        "unchanged": 2,
        "baseline_items": 4,
        "current_items": 4,
    }
    assert informational["added"][0]["surface"] == "prompts"
    assert informational["changed"][0]["surface"] == "tools"
    assert informational["changed"][0]["changed_fields"] == ["description"]
    assert informational["removed"][0]["surface"] == "resources"
    assert blocking["ok"] is False
    assert blocking["failing_changes"] == {"added": 0, "changed": 1, "removed": 1}


def test_discover_mcp_schemas_accepts_tools_only_inputs(tmp_path):
    tools = [
        {
            "name": "read_file",
            "title": "Read File",
            "description": "Read a file",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
        }
    ]
    raw_tools = tmp_path / "tools.json"
    tool_snapshot = tmp_path / "tools.snapshot.json"
    raw_tools.write_text(json.dumps(tools), encoding="utf-8")
    tool_snapshot.write_text(json.dumps(build_mcp_tool_snapshot(tools)), encoding="utf-8")

    raw_catalog = discover_mcp_schemas(source=raw_tools, methods=("tools",))
    snapshot_catalog = discover_mcp_schemas(source=tool_snapshot, methods=("tools",))

    assert raw_catalog["ok"] is True
    assert raw_catalog["summary"] == {"tools": 1, "resources": 0, "resource_templates": 0, "prompts": 0, "errors": 0}
    assert snapshot_catalog["surfaces"]["tools"] == raw_catalog["surfaces"]["tools"]


def test_mcp_schemas_cli_discover_and_diff(tmp_path, capsys):
    baseline_source = tmp_path / "baseline-responses.json"
    current_source = tmp_path / "current-responses.json"
    baseline_catalog = tmp_path / "baseline.catalog.json"
    current_catalog = tmp_path / "current.catalog.json"
    diff_report = tmp_path / "diff.md"
    diff_sarif = tmp_path / "diff.sarif"
    baseline_source.write_text(json.dumps({"responses": _schema_responses()}), encoding="utf-8")
    current_source.write_text(
        json.dumps({"responses": _schema_responses(tool_description="Read a project file")}),
        encoding="utf-8",
    )

    status = simulator_main(
        [
            "mcp",
            "policy",
            "schemas",
            "discover",
            "--from",
            str(baseline_source),
            "--out",
            str(baseline_catalog),
            "--compact",
        ]
    )
    baseline_output = json.loads(capsys.readouterr().out)
    status_current = simulator_main(
        [
            "mcp",
            "policy",
            "schemas",
            "discover",
            "--from",
            str(current_source),
            "--out",
            str(current_catalog),
            "--compact",
        ]
    )
    current_output = json.loads(capsys.readouterr().out)
    diff_status = simulator_main(
        [
            "mcp",
            "policy",
            "schemas",
            "diff",
            str(baseline_catalog),
            str(current_catalog),
            "--fail-on",
            "changed",
            "--report-out",
            str(diff_report),
            "--sarif-out",
            str(diff_sarif),
            "--compact",
        ]
    )
    diff_output = json.loads(capsys.readouterr().out)
    sarif_payload = json.loads(diff_sarif.read_text(encoding="utf-8"))

    assert status == 0
    assert status_current == 0
    assert baseline_output["output"] == str(baseline_catalog)
    assert current_output["summary"]["tools"] == 1
    assert diff_status == 1
    assert diff_output["ok"] is False
    assert diff_output["summary"]["changed"] == 1
    assert diff_output["changed"][0]["id"] == "read_file"
    assert diff_output["report_out"] == str(diff_report)
    assert diff_output["sarif_out"] == str(diff_sarif)
    assert "# snulbug mcp policy schemas diff" in diff_report.read_text(encoding="utf-8")
    assert sarif_payload["runs"][0]["results"][0]["ruleId"] == "snulbug.schema.changed"
    assert sarif_payload["runs"][0]["results"][0]["level"] == "error"


def test_parse_mcp_schema_headers_adds_bearer_when_missing():
    headers = parse_mcp_schema_headers(["X-Test: yes"], token="secret")

    assert headers == {"x-test": "yes", "authorization": "Bearer secret"}

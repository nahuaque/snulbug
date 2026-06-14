from __future__ import annotations

import json

from snulbug import (
    MCP_SCHEMA_POLICY_SCHEMA,
    SchemaPolicyOptions,
    build_mcp_schema_catalog,
    generate_mcp_schema_policy,
    score_mcp_schema_catalog,
    simulate_policy,
)
from snulbug.simulator import main as simulator_main


def test_generate_mcp_schema_policy_scores_and_enforces_catalog(tmp_path):
    catalog = build_mcp_schema_catalog(_schema_responses(), label="demo")
    output = tmp_path / "schema-policy.snulbug"

    result = generate_mcp_schema_policy(
        catalog,
        output,
        options=SchemaPolicyOptions(token="dev-secret"),
    )
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))

    assert result["ok"] is True
    assert result["schema"] == MCP_SCHEMA_POLICY_SCHEMA
    assert result["risk_summary"] == {"low": 0, "medium": 1, "high": 1}
    assert result["lease_suggestions"]["allow_tools"] == ["read_file"]
    assert result["lease_suggestions"]["confirm_tools"] == ["shell_exec"]
    assert result["validation"]["ok"] is True
    assert result["tests"]["ok"] is True
    assert manifest["schema_policy"]["catalog_hash"] == catalog["hash"]
    assert "shell_exec" in (output / "SCHEMA_POLICY.md").read_text(encoding="utf-8")

    allowed = simulate_policy(
        output / "policy.lua",
        _request("tools/call", {"name": "read_file", "arguments": {"path": "README.md"}}),
    )
    extra_arg = simulate_policy(
        output / "policy.lua",
        _request("tools/call", {"name": "read_file", "arguments": {"path": "README.md", "mode": "raw"}}),
    )
    blocked_path = simulate_policy(
        output / "policy.lua",
        _request("tools/call", {"name": "read_file", "arguments": {"path": "/etc/passwd"}}),
    )
    high_risk = simulate_policy(
        output / "policy.lua",
        _request("tools/call", {"name": "shell_exec", "arguments": {"command": "ls"}}),
    )
    unknown = simulate_policy(
        output / "policy.lua",
        _request("tools/call", {"name": "unknown_tool", "arguments": {}}),
    )

    assert allowed["action"] == "continue"
    assert extra_arg["action"] == "reject"
    assert extra_arg["decision"]["reason_code"] == "mcp.schema.argument_not_allowed"
    assert blocked_path["action"] == "reject"
    assert blocked_path["decision"]["reason_code"] == "mcp.schema.path_not_allowed"
    assert high_risk["action"] == "confirm"
    assert high_risk["decision"]["reason_code"] == "mcp.schema.high_risk_confirm"
    assert unknown["action"] == "reject"
    assert unknown["decision"]["reason_code"] == "mcp.schema.tool_not_allowed"


def test_score_mcp_schema_catalog_returns_tool_risk_summary():
    catalog = build_mcp_schema_catalog(_schema_responses(), label="demo")

    result = score_mcp_schema_catalog(catalog)

    assert result["risk_summary"] == {"low": 0, "medium": 1, "high": 1}
    assert [tool["id"] for tool in result["tools"]] == ["read_file", "shell_exec"]
    assert result["tools"][1]["level"] == "high"


def test_mcp_schemas_policy_cli_generates_bundle(tmp_path, capsys):
    catalog_path = tmp_path / "catalog.json"
    output = tmp_path / "generated.snulbug"
    catalog_path.write_text(
        json.dumps(build_mcp_schema_catalog(_schema_responses(), label="demo")),
        encoding="utf-8",
    )

    status = simulator_main(
        [
            "mcp",
            "policy",
            "schemas",
            "generate",
            str(catalog_path),
            "--out",
            str(output),
            "--token",
            "dev-secret",
            "--compact",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert status == 0
    assert payload["ok"] is True
    assert payload["output"] == str(output)
    assert payload["tests"]["ok"] is True
    assert (output / "policy.lua").is_file()
    assert (output / "SCHEMA_POLICY.md").is_file()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["generated_by"] == "snulbug mcp policy schemas generate"


def _schema_responses() -> dict:
    return {
        "initialize": {
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "demo-server", "version": "1.0.0"},
            }
        },
        "tools/list": {
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a project file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string", "description": "Project path"}},
                            "required": ["path"],
                            "additionalProperties": False,
                        },
                        "annotations": {"readOnlyHint": True},
                    },
                    {
                        "name": "shell_exec",
                        "description": "Execute a shell command",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"command": {"type": "string"}},
                            "required": ["command"],
                            "additionalProperties": False,
                        },
                        "annotations": {"destructiveHint": True, "openWorldHint": True},
                    },
                ]
            }
        },
        "resources/list": {"result": {"resources": []}},
        "resources/templates/list": {"result": {"resourceTemplates": []}},
        "prompts/list": {"result": {"prompts": []}},
    }


def _request(method: str, params: dict) -> dict:
    return {
        "method": "POST",
        "path": "/mcp",
        "headers": {"authorization": "Bearer dev-secret", "content-type": "application/json"},
        "body": json.dumps({"jsonrpc": "2.0", "id": "test", "method": method, "params": params}),
    }

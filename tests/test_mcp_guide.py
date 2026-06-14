from __future__ import annotations

import json

from snulbug import build_mcp_guide, format_mcp_guide
from snulbug.simulator import main as simulator_main


def test_build_mcp_guide_defaults_to_all_workflows():
    guide = build_mcp_guide()

    workflow_ids = [workflow["id"] for workflow in guide["workflows"]]
    assert guide["ok"] is True
    assert workflow_ids == ["share", "tunnel", "learn-amend-impact", "leases", "facade"]
    assert guide["default_public_tunnel_profile"] == "tunnel-safe"


def test_format_mcp_guide_prints_copy_paste_tunnel_flow():
    guide = build_mcp_guide(workflow="tunnel")

    output = format_mcp_guide(guide)

    assert "# snulbug MCP guide" in output
    assert "snulbug mcp quickstart \\" in output
    assert "--preset tunnel-safe" in output
    assert "snulbug mcp proxy --config snulbug.toml --decision-console" in output
    assert "ngrok http 8080" in output
    assert "Do not expose the upstream MCP server directly." in output


def test_mcp_guide_cli_emits_human_workflow(capsys):
    status = simulator_main(["mcp", "guide", "--workflow", "leases"])

    output = capsys.readouterr().out
    assert status == 0
    assert "## Task-Scoped Capability Lease" in output
    assert "snulbug mcp lease create \\" in output
    assert "snulbug mcp evidence impact traces/session.jsonl --lease leases.json" in output


def test_mcp_guide_cli_emits_share_workflow(capsys):
    status = simulator_main(["mcp", "guide", "--workflow", "share"])

    output = capsys.readouterr().out
    assert status == 0
    assert "## Ephemeral MCP Share Session" in output
    assert "snulbug mcp share create \\" in output
    assert "uv run snulbug mcp share run .snulbug/shares/share-*" in output
    assert "uv run snulbug mcp share close .snulbug/shares/share-* --report --revoke" in output
    assert "--provider holepunch" in output
    assert "Do not share mcp-client.json until tunnel doctor passes." in output


def test_mcp_guide_cli_emits_compact_json_for_harness(capsys):
    status = simulator_main(["mcp", "guide", "--workflow", "learn-amend-impact", "--compact"])

    output = json.loads(capsys.readouterr().out)
    workflow = output["workflows"][0]
    assert status == 0
    assert output["ok"] is True
    assert output["recommended_entrypoint"] == "snulbug mcp guide --compact"
    assert workflow["id"] == "learn-amend-impact"
    assert workflow["steps"][0]["command"] == (
        "snulbug mcp evidence inspect traces/session.jsonl --report-out traces/session-report.md"
    )
    assert workflow["steps"][0]["produces"] == ["traces/session-report.md"]
    assert workflow["steps"][1]["success_signals"] == ["learned bundle validates", "learned bundle tests pass"]
    assert "unexpected newly blocked calls" in workflow["stop_conditions"][1]

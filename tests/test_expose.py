from __future__ import annotations

import json

from snulbug import format_exposure_session_report, plan_exposure_session
from snulbug.simulator import main as simulator_main


def test_expose_dry_run_plans_without_writing_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = plan_exposure_session(provider="localxpose", dry_run=True)

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["would_generate_config"] is True
    assert result["config"] == ".snulbug/configs/snulbug.toml"
    assert result["public_url"] == "https://YOUR-LOCALXPOSE-FORWARDING-DOMAIN/mcp"
    assert result["public_url_display"] == "${LOCALXPOSE_URL}/mcp"
    assert result["client"]["display_url"] == "${LOCALXPOSE_URL}/mcp"
    assert result["commands"]["provider"] == ["loclx tunnel http"]
    assert result["commands"]["proxy"] == "snulbug mcp proxy --config .snulbug/configs/snulbug.toml --decision-console"
    assert '  --url "${LOCALXPOSE_URL}/mcp" \\' in result["commands"]["doctor"]
    assert "  --config .snulbug/configs/snulbug.toml \\" in result["commands"]["doctor"]
    assert result["files"]["written"] == []
    assert result["files"]["audit_log"] == ".snulbug/configs/traces/audit.jsonl"
    assert result["files"]["report"] == ".snulbug/configs/session-report.md"
    assert not (tmp_path / ".snulbug/configs/snulbug.toml").exists()


def test_expose_normal_mode_generates_tunnel_safe_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = plan_exposure_session(provider="ngrok")

    assert result["ok"] is True
    assert result["dry_run"] is False
    assert result["config_generated"] is True
    assert result["config"] == ".snulbug/configs/snulbug.toml"
    assert result["commands"]["provider"] == [
        "ngrok http 8080 --traffic-policy-file .snulbug/configs/ngrok-traffic-policy.yml"
    ]
    assert "snulbug mcp evidence inspect .snulbug/configs/traces/audit.jsonl" in result["commands"]["inspect_audit"]
    assert (tmp_path / ".snulbug/configs/snulbug.toml").is_file()
    assert (tmp_path / ".snulbug/configs/ngrok-traffic-policy.yml").is_file()


def test_format_exposure_session_report_includes_lifecycle_commands(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = plan_exposure_session(provider="localxpose", dry_run=True)
    report = format_exposure_session_report(result)

    assert "# snulbug expose" in report
    assert "Mode: dry run; no files written" in report
    assert "Public MCP URL: ${LOCALXPOSE_URL}/mcp" in report
    assert "URL: `${LOCALXPOSE_URL}/mcp`" in report
    assert "## Start proxy" in report
    assert "loclx tunnel http" in report
    assert "## Run doctor" in report
    assert "## Session report" in report


def test_expose_cli_emits_compact_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    status = simulator_main(["expose", "--provider", "localxpose", "--dry-run", "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["provider"] == "localxpose"
    assert output["dry_run"] is True
    assert output["commands"]["provider"] == ["loclx tunnel http"]
    assert output["config"] == ".snulbug/configs/snulbug.toml"
    assert not (tmp_path / ".snulbug/configs/snulbug.toml").exists()


def test_expose_pinggy_dry_run_uses_pinggy_url_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = plan_exposure_session(provider="pinggy", dry_run=True)

    assert result["provider"] == "pinggy"
    assert result["public_url_display"] == "${PINGGY_URL}/mcp"
    assert result["client"]["display_url"] == "${PINGGY_URL}/mcp"
    assert result["commands"]["provider"] == ["ssh -p 443 -R0:localhost:8080 free.pinggy.io"]
    assert '  --url "${PINGGY_URL}/mcp" \\' in result["commands"]["doctor"]

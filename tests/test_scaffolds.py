from __future__ import annotations

import json

import pytest

from snulbug import (
    GeneratedArtifact,
    GeneratedClient,
    GeneratedCommand,
    GeneratedEnv,
    GeneratedLog,
    GeneratedSession,
    ScaffoldFile,
    ScaffoldPlan,
    format_scaffold_report,
    format_session_report,
    json_scaffold_file,
    session_result,
    session_summary,
    write_scaffold,
)


def test_write_scaffold_preflights_and_writes_files_and_dirs(tmp_path):
    result = write_scaffold(
        ScaffoldPlan(
            name="demo scaffold",
            root=tmp_path,
            directories=["traces"],
            files=[
                ScaffoldFile(path="policy.lua", content="return function() end\n", kind="policy"),
                json_scaffold_file("client.json", {"mcpServers": {"demo": {"url": "http://127.0.0.1"}}}),
            ],
            commands={"run": "uv run snulbug mcp proxy --config snulbug.toml"},
        )
    )

    assert result["ok"] is True
    assert result["written_files"] == [str(tmp_path / "policy.lua"), str(tmp_path / "client.json")]
    assert result["directories"] == [str(tmp_path / "traces")]
    assert (tmp_path / "traces").is_dir()
    assert (tmp_path / "policy.lua").read_text(encoding="utf-8") == "return function() end\n"
    assert json.loads((tmp_path / "client.json").read_text(encoding="utf-8")) == {
        "mcpServers": {"demo": {"url": "http://127.0.0.1"}}
    }


def test_write_scaffold_refuses_partial_overwrite(tmp_path):
    existing = tmp_path / "policy.lua"
    existing.write_text("existing\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="demo scaffold output already exists"):
        write_scaffold(
            ScaffoldPlan(
                name="demo scaffold",
                root=tmp_path,
                files=[
                    ScaffoldFile(path="policy.lua", content="new\n"),
                    ScaffoldFile(path="snulbug.toml", content="[mcp.proxy]\n"),
                ],
            )
        )

    assert existing.read_text(encoding="utf-8") == "existing\n"
    assert not (tmp_path / "snulbug.toml").exists()


def test_format_scaffold_report_lists_files_and_commands(tmp_path):
    result = write_scaffold(
        ScaffoldPlan(
            name="demo scaffold",
            root=tmp_path,
            files=[ScaffoldFile(path="snulbug.toml", content="[mcp.proxy]\n", kind="config")],
            commands={"run": "uv run snulbug mcp proxy --config snulbug.toml"},
        )
    )

    report = format_scaffold_report(result)

    assert "# demo scaffold" in report
    assert str(tmp_path / "snulbug.toml") in report
    assert "uv run snulbug mcp proxy" in report


def test_session_result_normalizes_generated_session_metadata(tmp_path):
    result = session_result(
        GeneratedSession(
            name="demo session",
            root=tmp_path,
            generated_by="snulbug demo",
            artifacts=[GeneratedArtifact("config", tmp_path / "snulbug.toml", "config")],
            commands=[GeneratedCommand("run", "uv run snulbug mcp proxy --config snulbug.toml")],
            clients=[GeneratedClient("default", "http://127.0.0.1:8080/mcp", {"Authorization": "Bearer test"})],
            env=[GeneratedEnv("SNULBUG_TOKEN", "test")],
            logs=[GeneratedLog("audit", tmp_path / "traces/audit.jsonl", "audit_jsonl")],
            next_steps=["uv run snulbug mcp proxy --config snulbug.toml"],
        )
    )

    assert result["file_map"]["config"] == str(tmp_path / "snulbug.toml")
    assert result["command_map"]["run"] == "uv run snulbug mcp proxy --config snulbug.toml"
    assert result["primary_client"]["url"] == "http://127.0.0.1:8080/mcp"
    assert result["env_map"]["SNULBUG_TOKEN"] == "test"
    assert result["log_map"]["audit"] == str(tmp_path / "traces/audit.jsonl")

    report = format_session_report(result)
    assert "# demo session" in report
    assert "http://127.0.0.1:8080/mcp" in report
    assert "traces/audit.jsonl" in report
    assert "Bearer test" not in report
    assert "Bearer <redacted>" in report
    assert "`SNULBUG_TOKEN`: `<redacted>`" in report

    summary = session_summary(result)
    assert summary["client"]["headers"]["Authorization"] == "Bearer <redacted>"
    assert summary["env"]["SNULBUG_TOKEN"] == "<redacted>"
    unredacted = session_summary(result, redact=False)
    assert unredacted["client"]["headers"]["Authorization"] == "Bearer test"
    assert unredacted["env"]["SNULBUG_TOKEN"] == "test"


def test_format_session_report_supports_sections_and_extra_sections(tmp_path):
    result = session_result(
        GeneratedSession(
            name="demo session",
            root=tmp_path,
            artifacts=[GeneratedArtifact("config", tmp_path / "snulbug.toml", "config")],
            commands=[GeneratedCommand("run", ["export SNULBUG_TOKEN=secret", "uv run snulbug"])],
        )
    )

    report = format_session_report(
        result,
        title="custom report",
        sections=("overview", "commands"),
        extra_sections=[("Notes", "Use the generated config.")],
    )

    assert "# custom report" in report
    assert "## Commands" in report
    assert "SNULBUG_TOKEN=<redacted>" in report
    assert "## Notes" in report
    assert "Use the generated config." in report
    assert "## Files" not in report

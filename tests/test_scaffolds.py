from __future__ import annotations

import json

import pytest

from snulbug import (
    ScaffoldFile,
    ScaffoldPlan,
    format_scaffold_report,
    json_scaffold_file,
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

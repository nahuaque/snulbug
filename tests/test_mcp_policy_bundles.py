from __future__ import annotations

import json

from snulbug.mcp_policy_bundles import write_mcp_policy_bundle


def test_write_mcp_policy_bundle_writes_validated_bundle_with_fixtures(tmp_path):
    output = tmp_path / "generated.snulbug"
    request = {
        "method": "GET",
        "path": "/health",
        "headers": {},
    }
    manifest = {
        "name": "generated-policy",
        "version": "0.1.0",
        "entrypoint": "policy.lua",
        "required_capabilities": [],
        "fixtures": [
            {
                "name": "continues",
                "request": "fixtures/continue.json",
                "expect": {"action": "continue"},
            }
        ],
    }

    result = write_mcp_policy_bundle(
        output,
        policy='return function(request, context, state)\n  return { action = "continue" }\nend\n',
        manifest=manifest,
        report="# Generated\n",
        report_name="REPORT.md",
        extra_files={"fixtures/continue.json": json.dumps(request) + "\n"},
        validate=True,
        run_tests=True,
    )

    assert result.ok is True
    assert result.validation["ok"] is True
    assert result.tests["ok"] is True
    assert result.policy == output / "policy.lua"
    assert result.manifest == output / "manifest.json"
    assert result.report == output / "REPORT.md"
    assert result.extra_files == (output / "fixtures" / "continue.json",)
    assert result.next_steps[0] == f"uv run snulbug bundle validate {output}"


def test_write_mcp_policy_bundle_force_clean_removes_stale_files(tmp_path):
    output = tmp_path / "generated.snulbug"
    output.mkdir()
    stale = output / "stale.txt"
    stale.write_text("old", encoding="utf-8")

    result = write_mcp_policy_bundle(
        output,
        policy='return function(request, context, state)\n  return { action = "continue" }\nend\n',
        manifest={
            "name": "generated-policy",
            "version": "0.1.0",
            "entrypoint": "policy.lua",
            "fixtures": [],
        },
        report="# Generated\n",
        report_name="REPORT.md",
        force=True,
        clean=True,
        validate=True,
    )

    assert result.ok is True
    assert not stale.exists()
    assert (output / "policy.lua").is_file()

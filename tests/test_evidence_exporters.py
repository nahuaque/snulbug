from __future__ import annotations

import json

from snulbug import (
    EvidenceExportContext,
    EvidenceExporter,
    append_record,
    export_evidence,
    inspect_mcp_log,
    list_evidence_exporters,
    record_policy_request,
    register_evidence_exporter,
)
from snulbug.simulator import main as simulator_main


class FixtureEvidenceExporter(EvidenceExporter):
    name = "fixture"
    commands = ("inspect",)
    extension = ".txt"

    def render(self, context: EvidenceExportContext) -> str:
        return f"{context.command}:{context.result['event_count']}:{context.output.name}\n"


def test_evidence_exporter_registry_accepts_custom_exporter(tmp_path):
    register_evidence_exporter(FixtureEvidenceExporter(), replace=True)
    log = _record_log(tmp_path)
    report = inspect_mcp_log(log)
    output = tmp_path / "fixture.txt"

    metadata = export_evidence("inspect", report, output, exporter="fixture")

    assert "fixture" in list_evidence_exporters(command="inspect")
    assert metadata == {"exporter": "fixture", "format": "fixture", "path": str(output)}
    assert output.read_text(encoding="utf-8") == "inspect:1:fixture.txt\n"


def test_evidence_inspect_cli_writes_custom_export(tmp_path, capsys):
    register_evidence_exporter(FixtureEvidenceExporter(), replace=True)
    log = _record_log(tmp_path)
    output_path = tmp_path / "exports" / "session.fixture"

    status = simulator_main(
        [
            "mcp",
            "evidence",
            "inspect",
            str(log),
            "--export",
            f"fixture={output_path}",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert status == 0
    assert output["exports"] == [{"exporter": "fixture", "format": "fixture", "path": str(output_path)}]
    assert output_path.read_text(encoding="utf-8") == "inspect:1:session.fixture\n"


def test_builtin_json_evidence_exporter_writes_replay_result(tmp_path, capsys):
    log = _record_log(tmp_path)
    output_path = tmp_path / "replay.json"

    status = simulator_main(
        [
            "mcp",
            "evidence",
            "replay",
            str(log),
            "--export",
            f"json={output_path}",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    exported = json.loads(output_path.read_text(encoding="utf-8"))

    assert status == 0
    assert output["exports"] == [{"exporter": "json", "format": "json", "path": str(output_path)}]
    assert exported["ok"] is True
    assert exported["record_count"] == 1


def _record_log(tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text(
        """
        return function(request, context, state)
          return { action = "continue", reason_code = "test.allowed" }
        end
        """,
        encoding="utf-8",
    )
    log = tmp_path / "records.jsonl"
    append_record(
        log,
        record_policy_request(
            policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
            },
        ),
    )
    return log

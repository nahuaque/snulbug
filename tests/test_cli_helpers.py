from __future__ import annotations

import io
import json

from snulbug import GeneratedClient, GeneratedCommand, GeneratedSession, session_result
from snulbug.cli_helpers import write_generated_session_output


def test_write_generated_session_output_emits_compact_summary_with_legacy():
    stream = io.StringIO()
    payload = {
        "ok": True,
        "legacy_value": "kept",
        "generated_session": session_result(
            GeneratedSession(
                name="demo",
                root=".",
                commands=[GeneratedCommand("run", "uv run snulbug")],
                clients=[GeneratedClient("default", "http://127.0.0.1:8080/mcp", {"Authorization": "Bearer test"})],
            )
        ),
    }

    write_generated_session_output(payload, compact=True, stream=stream)
    output = json.loads(stream.getvalue())

    assert output["name"] == "demo"
    assert output["commands"]["run"] == "uv run snulbug"
    assert output["client"]["headers"]["Authorization"] == "Bearer test"
    assert output["legacy"]["legacy_value"] == "kept"
    assert "generated_session" not in output["legacy"]


def test_write_generated_session_output_emits_report_by_default():
    stream = io.StringIO()
    payload = {
        "ok": True,
        "generated_session": session_result(
            GeneratedSession(
                name="demo",
                root=".",
                clients=[GeneratedClient("default", "http://127.0.0.1:8080/mcp", {"Authorization": "Bearer test"})],
            )
        ),
    }

    write_generated_session_output(payload, compact=False, stream=stream)

    output = stream.getvalue()
    assert "# demo" in output
    assert "Bearer <redacted>" in output
    assert "Bearer test" not in output

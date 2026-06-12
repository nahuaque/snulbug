from __future__ import annotations

import json

from asgi_lua import build_audit_event, record_policy_request, redact_secrets
from asgi_lua.simulator import main as simulator_main


def test_redact_secrets_covers_headers_strings_and_json_body():
    value = {
        "headers": {
            "authorization": "Bearer local-dev-secret",
            "x-api-key": "sk-test_abcdefghijklmnopqrstuvwxyz",
        },
        "body": json.dumps(
            {
                "token": "ghp_abcdefghijklmnopqrstuvwxyz",
                "nested": {"client_secret": "secret-value"},
                "safe": "visible",
            }
        ),
        "note": "send Bearer abc.def.ghi to the gateway",
    }

    redacted = redact_secrets(value)

    assert redacted["headers"]["authorization"] == "[REDACTED]"
    assert redacted["headers"]["x-api-key"] == "[REDACTED]"
    assert json.loads(redacted["body"]) == {
        "nested": {"client_secret": "[REDACTED]"},
        "safe": "visible",
        "token": "[REDACTED]",
    }
    assert redacted["note"] == "send [REDACTED] to the gateway"


def test_build_audit_event_is_redacted_and_compact(tmp_path):
    policy = write_policy(tmp_path)
    request = {
        "method": "POST",
        "path": "/mcp",
        "headers": {"authorization": "Bearer local-dev-secret"},
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "safe_read_file", "token": "sk-test_abcdefghijklmnopqrstuvwxyz"},
            }
        ),
    }

    record = record_policy_request(policy, request, recorded_at="2026-06-12T00:00:00+00:00")
    audit = build_audit_event(record)

    assert audit["type"] == "asgi-lua.audit"
    assert audit["request"]["headers"]["authorization"] == "[REDACTED]"
    assert audit["mcp"] == {"method": "tools/call", "tool": "safe_read_file"}
    assert audit["decision"]["action"] == "continue"
    assert audit["decision"]["allowed"] is True


def test_mcp_record_cli_writes_redacted_audit_log_without_redacting_record(tmp_path, capsys):
    policy = write_policy(tmp_path)
    request = tmp_path / "request.json"
    record_log = tmp_path / "records.jsonl"
    audit_log = tmp_path / "audit.jsonl"
    request.write_text(
        json.dumps(
            {
                "method": "POST",
                "path": "/mcp",
                "headers": {"authorization": "Bearer local-dev-secret"},
                "body": json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {"token": "ghp_abcdefghijklmnopqrstuvwxyz"},
                    }
                ),
            }
        ),
        encoding="utf-8",
    )

    status = simulator_main(
        [
            "mcp",
            "record",
            str(policy),
            str(request),
            "--out",
            str(record_log),
            "--audit-out",
            str(audit_log),
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    record = json.loads(record_log.read_text(encoding="utf-8"))
    audit = json.loads(audit_log.read_text(encoding="utf-8"))
    assert status == 0
    assert output["audit_out"] == str(audit_log)
    assert record["request"]["headers"]["authorization"] == "Bearer local-dev-secret"
    assert audit["request"]["headers"]["authorization"] == "[REDACTED]"
    assert "ghp_" not in audit_log.read_text(encoding="utf-8")


def test_mcp_record_cli_can_redact_record_itself(tmp_path, capsys):
    policy = write_policy(tmp_path)
    request = tmp_path / "request.json"
    record_log = tmp_path / "records.jsonl"
    request.write_text(
        json.dumps(
            {
                "method": "POST",
                "path": "/mcp",
                "headers": {"authorization": "Bearer local-dev-secret"},
                "body": json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {"token": "ghp_abcdefghijklmnopqrstuvwxyz"},
                    }
                ),
            }
        ),
        encoding="utf-8",
    )

    status = simulator_main(
        ["mcp", "record", str(policy), str(request), "--out", str(record_log), "--redact", "--compact"]
    )

    output = json.loads(capsys.readouterr().out)
    record = json.loads(record_log.read_text(encoding="utf-8"))
    assert status == 0
    assert output["redacted"] is True
    assert record["redacted"] is True
    assert record["request"]["headers"]["authorization"] == "[REDACTED]"
    assert "ghp_" not in record_log.read_text(encoding="utf-8")


def write_policy(tmp_path):
    path = tmp_path / "policy.lua"
    path.write_text(
        """
        return function(request, context, state)
          return {
            action = "continue",
            context = {
              method = mcp.method(request) or "",
              tool = mcp.tool_name(request) or ""
            }
          }
        end
        """,
        encoding="utf-8",
    )
    return path

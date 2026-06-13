from __future__ import annotations

import json

from snulbug import build_audit_event, record_policy_request, redact_secrets
from snulbug.simulator import main as simulator_main


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
                "params": {
                    "name": "safe_read_file",
                    "arguments": {"path": "README.md", "token": "sk-test_abcdefghijklmnopqrstuvwxyz"},
                },
            }
        ),
    }

    record = record_policy_request(policy, request, recorded_at="2026-06-12T00:00:00+00:00")
    audit = build_audit_event(record)

    assert audit["type"] == "snulbug.audit"
    assert audit["request"]["headers"]["authorization"] == "[REDACTED]"
    assert audit["mcp"] == {
        "argument_keys": ["path", "token"],
        "body_kind": "object",
        "jsonrpc": "2.0",
        "method": "tools/call",
        "notification": False,
        "operation": "tools",
        "operation_detail": "call",
        "params_keys": ["arguments", "name"],
        "request_id": 1,
        "target": "safe_read_file",
        "tool": "safe_read_file",
        "valid_json": True,
    }
    assert audit["decision"]["action"] == "continue"
    assert audit["decision"]["allowed"] is True
    assert audit["decision"]["reason"] == "audit fixture allowed"
    assert audit["decision"]["reason_code"] == "test.audit_allowed"


def test_build_audit_event_extracts_initialize_client_metadata(tmp_path):
    policy = write_policy(tmp_path)
    request = {
        "method": "POST",
        "path": "/mcp",
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-06-12",
                    "clientInfo": {"name": "codex", "version": "1.2.3"},
                    "capabilities": {"roots": {}, "sampling": {}},
                },
            }
        ),
    }

    audit = build_audit_event(record_policy_request(policy, request))

    assert audit["mcp"]["method"] == "initialize"
    assert audit["mcp"]["operation"] == "initialize"
    assert audit["mcp"]["request_id"] == "init-1"
    assert audit["mcp"]["protocol_version"] == "2026-06-12"
    assert audit["mcp"]["client"] == {"name": "codex", "version": "1.2.3"}
    assert audit["mcp"]["capabilities"] == ["roots", "sampling"]


def test_build_audit_event_promotes_tunnel_metadata(tmp_path):
    policy = write_policy(tmp_path)
    request = {
        "method": "POST",
        "path": "/mcp",
        "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    }

    record = record_policy_request(
        policy,
        request,
        metadata={
            "source": "proxy",
            "tunnel": {
                "provider": "ngrok",
                "public_url": "https://mcp-dev.ngrok.app/mcp",
                "edge_request_id": "req_123",
            },
        },
    )
    audit = build_audit_event(record)

    assert audit["tunnel"] == {
        "provider": "ngrok",
        "public_url": "https://mcp-dev.ngrok.app/mcp",
        "edge_request_id": "req_123",
    }
    assert audit["metadata"]["tunnel"] == audit["tunnel"]


def test_build_audit_event_promotes_cloudflare_access_metadata(tmp_path):
    policy = write_policy(tmp_path)
    request = {
        "method": "POST",
        "path": "/mcp",
        "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    }

    record = record_policy_request(
        policy,
        request,
        metadata={
            "source": "proxy",
            "cloudflare_access": {
                "provider": "cloudflare",
                "mode": "enforce",
                "allowed": True,
                "reason_code": "cloudflare_access.allowed",
                "email": "dev@example.com",
            },
        },
    )
    audit = build_audit_event(record)

    assert audit["cloudflare_access"] == {
        "provider": "cloudflare",
        "mode": "enforce",
        "allowed": True,
        "reason_code": "cloudflare_access.allowed",
        "email": "dev@example.com",
    }
    assert audit["metadata"]["cloudflare_access"] == audit["cloudflare_access"]


def test_build_audit_event_promotes_facade_upstream_identity(tmp_path):
    policy = write_policy(tmp_path)
    request = {
        "method": "POST",
        "path": "/mcp",
        "body": json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {"name": "remote.status"},
            }
        ),
    }

    record = record_policy_request(
        policy,
        request,
        metadata={
            "source": "proxy",
            "facade": True,
            "operation": "tools/call",
            "upstream": "remote",
            "upstream_transport": "holepunch",
            "tool": "remote.status",
            "upstream_tool": "status",
            "upstream_metadata": {
                "name": "remote",
                "transport": "holepunch",
                "tool_prefix": "remote.",
                "bridge": {"transport": "hypertele", "peer": "peer_123", "local_port": 19100},
            },
        },
    )
    audit = build_audit_event(record)

    assert audit["facade"] == {
        "operation": "tools/call",
        "upstream": "remote",
        "upstream_transport": "holepunch",
        "tool": "remote.status",
        "upstream_tool": "status",
        "upstream_metadata": {
            "name": "remote",
            "transport": "holepunch",
            "tool_prefix": "remote.",
            "bridge": {"transport": "hypertele", "peer": "peer_123", "local_port": 19100},
        },
    }
    assert audit["metadata"]["upstream_metadata"] == audit["facade"]["upstream_metadata"]


def test_build_audit_event_marks_batch_and_invalid_mcp_bodies(tmp_path):
    policy = write_policy(tmp_path)
    batch_request = {
        "method": "POST",
        "path": "/mcp",
        "body": json.dumps(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 2, "method": "resources/read"},
            ]
        ),
    }
    invalid_request = {"method": "POST", "path": "/mcp", "body": "not json"}

    batch_audit = build_audit_event(record_policy_request(policy, batch_request))
    invalid_audit = build_audit_event(record_policy_request(policy, invalid_request))

    assert batch_audit["mcp"]["body_kind"] == "batch"
    assert batch_audit["mcp"]["batch"] is True
    assert batch_audit["mcp"]["batch_count"] == 2
    assert batch_audit["mcp"]["methods"] == ["tools/list", "resources/read"]
    assert invalid_audit["mcp"]["body_kind"] == "invalid"
    assert invalid_audit["mcp"]["valid_json"] is False


def test_mcp_record_cli_redacts_record_and_audit_log_by_default(tmp_path, capsys):
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
    assert output["redacted"] is True
    assert record["redacted"] is True
    assert record["request"]["headers"]["authorization"] == "[REDACTED]"
    assert audit["request"]["headers"]["authorization"] == "[REDACTED]"
    assert "local-dev-secret" not in record_log.read_text(encoding="utf-8")
    assert "ghp_" not in audit_log.read_text(encoding="utf-8")


def test_mcp_record_cli_can_write_exact_record_when_explicitly_requested(tmp_path, capsys):
    policy = write_policy(tmp_path)
    request = tmp_path / "request.json"
    record_log = tmp_path / "records.jsonl"
    request.write_text(
        json.dumps(
            {
                "method": "POST",
                "path": "/mcp",
                "headers": {"authorization": "Bearer local-dev-secret"},
                "body": json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
            }
        ),
        encoding="utf-8",
    )

    status = simulator_main(
        ["mcp", "record", str(policy), str(request), "--out", str(record_log), "--no-redact", "--compact"]
    )

    output = json.loads(capsys.readouterr().out)
    record = json.loads(record_log.read_text(encoding="utf-8"))
    assert status == 0
    assert output["redacted"] is False
    assert record.get("redacted") is None
    assert record["request"]["headers"]["authorization"] == "Bearer local-dev-secret"


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
            reason = "audit fixture allowed",
            reason_code = "test.audit_allowed",
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

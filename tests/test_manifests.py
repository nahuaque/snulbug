from __future__ import annotations

import json

import pytest

from snulbug import load_manifest, sign_upstream_manifest, verify_upstream_manifest
from snulbug.simulator import main as simulator_main


def test_sign_and_verify_upstream_manifest_returns_safe_summary():
    manifest = unsigned_manifest()

    signed = sign_upstream_manifest(manifest, secret="dev-secret", key_id="dev")
    verified = verify_upstream_manifest(signed, secrets={"dev": "dev-secret"})

    assert signed["snulbug_signature"]["algorithm"] == "hmac-sha256"
    assert signed["snulbug_signature"]["key_id"] == "dev"
    assert signed["snulbug_signature"]["digest"].startswith("sha256:")
    assert verified["identity"] == "files@local"
    assert verified["tool_prefix"] == "files."
    assert verified["tool_count"] == 1
    assert verified["labels"] == {"owner": "local-dev"}


def test_verify_upstream_manifest_rejects_tampering():
    signed = sign_upstream_manifest(unsigned_manifest(), secret="dev-secret", key_id="dev")
    signed["tool_prefix"] = "shell."

    with pytest.raises(ValueError, match="digest"):
        verify_upstream_manifest(signed, secrets={"dev": "dev-secret"})


def test_verify_upstream_manifest_can_require_identity():
    signed = sign_upstream_manifest(unsigned_manifest(), secret="dev-secret", key_id="dev")

    with pytest.raises(ValueError, match="does not match expected"):
        verify_upstream_manifest(signed, secrets={"dev": "dev-secret"}, expected_identity="git@local")


def test_mcp_manifest_cli_signs_and_verifies(tmp_path, capsys, monkeypatch):
    input_path = tmp_path / "files.manifest.json"
    output_path = tmp_path / "files.signed.json"
    input_path.write_text(json.dumps(unsigned_manifest()), encoding="utf-8")
    monkeypatch.setenv("SNULBUG_MANIFEST_SECRET", "dev-secret")

    sign_status = simulator_main(
        [
            "mcp",
            "fabric",
            "manifest",
            "sign",
            str(input_path),
            "--out",
            str(output_path),
            "--key-id",
            "dev",
            "--compact",
        ]
    )
    sign_output = json.loads(capsys.readouterr().out)

    assert sign_status == 0
    assert sign_output["ok"] is True
    assert sign_output["output"] == str(output_path)
    assert load_manifest(output_path)["snulbug_signature"]["key_id"] == "dev"

    verify_status = simulator_main(
        [
            "mcp",
            "fabric",
            "manifest",
            "verify",
            str(output_path),
            "--expect-identity",
            "files@local",
            "--compact",
        ]
    )
    verify_output = json.loads(capsys.readouterr().out)

    assert verify_status == 0
    assert verify_output["ok"] is True
    assert verify_output["verified"]["identity"] == "files@local"


def unsigned_manifest() -> dict[str, object]:
    return {
        "schema": "snulbug.upstream-manifest.v1",
        "identity": "files@local",
        "transport": "http",
        "tool_prefix": "files.",
        "labels": {"owner": "local-dev"},
        "tools": [
            {
                "name": "read_file",
                "description": "Read a project file",
                "inputSchema": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {"path": {"type": "string"}},
                },
            }
        ],
    }

from __future__ import annotations

import json

from snulbug import create_lease, list_leases, revoke_lease
from snulbug.simulator import main as simulator_main


def test_create_lease_stores_only_token_hash_and_lists_without_secret(tmp_path):
    lease_file = tmp_path / "leases.json"

    result = create_lease(
        lease_file,
        task="Update README only",
        allow_tools=["files.read_file", "files.write_file"],
        allow_paths=["README.md"],
        ttl="30m",
        token="sbl_test-token",
    )

    raw = json.loads(lease_file.read_text(encoding="utf-8"))
    listed = list_leases(lease_file)
    assert result["ok"] is True
    assert result["token"] == "sbl_test-token"
    assert raw["leases"][0]["token_hash"].startswith("sha256:")
    assert "sbl_test-token" not in lease_file.read_text(encoding="utf-8")
    assert listed["leases"][0]["task"] == "Update README only"
    assert "token" not in listed["leases"][0]


def test_revoke_lease_marks_it_inactive(tmp_path):
    lease_file = tmp_path / "leases.json"
    created = create_lease(
        lease_file,
        task="Inspect git status",
        allow_tools=["git.status"],
        ttl="30m",
        token="sbl_test-token",
    )

    revoked = revoke_lease(lease_file, created["lease"]["id"])

    assert revoked["ok"] is True
    assert revoked["lease"]["active"] is False
    assert revoked["lease"]["revoked_at"] is not None


def test_mcp_share_lease_cli_create_list_and_revoke(tmp_path, capsys):
    lease_file = tmp_path / "leases.json"

    status = simulator_main(
        [
            "mcp",
            "share",
            "lease",
            "create",
            "--file",
            str(lease_file),
            "--task",
            "Docs edit",
            "--allow-tool",
            "files.write_file",
            "--allow-path",
            "README.md",
            "--ttl",
            "10m",
            "--compact",
        ]
    )
    created = json.loads(capsys.readouterr().out)
    assert status == 0
    assert created["ok"] is True
    assert created["headers"]["x-snulbug-lease"].startswith("sbl_")

    status = simulator_main(["mcp", "share", "lease", "list", "--file", str(lease_file), "--compact"])
    listed = json.loads(capsys.readouterr().out)
    assert status == 0
    assert listed["leases"][0]["task"] == "Docs edit"

    status = simulator_main(
        ["mcp", "share", "lease", "revoke", listed["leases"][0]["id"], "--file", str(lease_file), "--compact"]
    )
    revoked = json.loads(capsys.readouterr().out)
    assert status == 0
    assert revoked["lease"]["active"] is False

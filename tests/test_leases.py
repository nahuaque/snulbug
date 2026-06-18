from __future__ import annotations

import json

from snulbug import create_lease, list_leases, reactivate_lease, revoke_lease
from snulbug.leases import LeasePolicyConfig, enforce_mcp_lease_policy, preview_mcp_lease_coverage
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


def test_create_lease_can_bind_to_oauth_identity(tmp_path):
    lease_file = tmp_path / "leases.json"

    create_lease(
        lease_file,
        task="Tenant-bound docs edit",
        allow_tools=["files.write_file"],
        allow_subjects=["user-1"],
        allow_issuers=["https://issuer.example.test"],
        allow_tenants=["tenant-a"],
        allow_client_ids=["agent-client"],
        allow_groups=["platform-dev"],
        allow_auth_profiles=["tenant-a"],
        ttl="30m",
        token="sbl_test-token",
    )

    listed = list_leases(lease_file)
    lease = listed["leases"][0]
    assert lease["auth_bound"] is True
    assert lease["allow_subjects"] == ["user-1"]
    assert lease["allow_issuers"] == ["https://issuer.example.test"]
    assert lease["allow_tenants"] == ["tenant-a"]
    assert lease["allow_client_ids"] == ["agent-client"]
    assert lease["allow_groups"] == ["platform-dev"]
    assert lease["allow_auth_profiles"] == ["tenant-a"]


def test_auth_bound_lease_requires_matching_sanitized_auth_context(tmp_path):
    lease_file = tmp_path / "leases.json"
    create_lease(
        lease_file,
        task="Inspect git status",
        allow_tools=["git.status"],
        allow_subjects=["user-1"],
        allow_tenants=["tenant-a"],
        allow_groups=["platform-dev"],
        ttl="30m",
        token="sbl_test-token",
    )
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "git.status"}}
    config = LeasePolicyConfig(lease_file=lease_file, required=True)

    allowed, metadata = enforce_mcp_lease_policy(
        request,
        {
            "headers": [(b"x-snulbug-lease", b"sbl_test-token")],
            "state": {
                "snulbug_proxy": {
                    "auth": {
                        "enabled": True,
                        "subject": "user-1",
                        "tenant": "tenant-a",
                        "groups": ["platform-dev"],
                    }
                }
            },
        },
        config=config,
    )

    assert allowed is True
    assert metadata["allowed"] is True
    assert metadata["auth_bound"] is True
    assert metadata["auth"]["subject"] == "user-1"


def test_auth_bound_lease_rejects_mismatched_subject(tmp_path):
    lease_file = tmp_path / "leases.json"
    create_lease(
        lease_file,
        task="Inspect git status",
        allow_tools=["git.status"],
        allow_subjects=["user-1"],
        ttl="30m",
        token="sbl_test-token",
    )
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "git.status"}}

    allowed, metadata = enforce_mcp_lease_policy(
        request,
        {
            "headers": [(b"x-snulbug-lease", b"sbl_test-token")],
            "state": {"snulbug_proxy": {"auth": {"enabled": True, "subject": "user-2"}}},
        },
        config=LeasePolicyConfig(lease_file=lease_file, required=True),
    )

    assert allowed is False
    assert metadata["reason_code"] == "lease.subject_not_allowed"
    assert metadata["auth_subject"] == "user-2"


def test_auth_bound_lease_coverage_can_use_replay_auth_context(tmp_path):
    lease_file = tmp_path / "leases.json"
    create_lease(
        lease_file,
        task="Inspect git status",
        allow_tools=["git.status"],
        allow_groups=["platform-dev"],
        ttl="30m",
        token="sbl_test-token",
    )
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "git.status"}}

    result = preview_mcp_lease_coverage(
        request,
        lease_file,
        auth_context={"enabled": True, "groups": ["platform-dev"]},
    )

    assert result["covered"] is True
    assert result["matches"][0]["auth_bound"] is True


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


def test_reactivate_lease_renews_token_and_resets_usage(tmp_path):
    lease_file = tmp_path / "leases.json"
    created = create_lease(
        lease_file,
        task="Inspect git status",
        allow_tools=["git.status"],
        ttl="30m",
        max_calls=2,
        token="sbl_old-token",
    )
    lease_id = created["lease"]["id"]
    revoke_lease(lease_file, lease_id)

    reactivated = reactivate_lease(lease_file, lease_id, ttl="15m", max_calls=3, token="sbl_new-token")
    listed = list_leases(lease_file)
    lease = next(item for item in listed["leases"] if item["id"] == lease_id)

    assert reactivated["ok"] is True
    assert reactivated["headers"]["x-snulbug-lease"] == "sbl_new-token"
    assert reactivated["lease"]["active"] is True
    assert reactivated["lease"]["revoked_at"] is None
    assert reactivated["lease"]["max_calls"] == 3
    assert lease["active"] is True
    assert lease["use_count"] == 0
    assert lease["last_used_at"] is None


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
            "--allow-subject",
            "user-1",
            "--allow-tenant",
            "tenant-a",
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
    assert listed["leases"][0]["allow_subjects"] == ["user-1"]
    assert listed["leases"][0]["allow_tenants"] == ["tenant-a"]

    status = simulator_main(
        ["mcp", "share", "lease", "revoke", listed["leases"][0]["id"], "--file", str(lease_file), "--compact"]
    )
    revoked = json.loads(capsys.readouterr().out)
    assert status == 0
    assert revoked["lease"]["active"] is False

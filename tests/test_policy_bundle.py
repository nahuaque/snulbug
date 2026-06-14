from __future__ import annotations

import json
import shutil
import tarfile

import pytest

from snulbug import (
    inspect_bundle_lifecycle,
    pack_bundle,
    promote_bundle_lifecycle,
    validate_bundle,
    verify_bundle_lifecycle,
)
from snulbug import test_bundle as run_bundle_tests
from snulbug.simulator import main as simulator_main

BUNDLE = "examples/bundles/idempotency.snulbug"


def test_validate_bundle_accepts_example_bundle():
    result = validate_bundle(BUNDLE)

    assert result["ok"] is True
    assert result["name"] == "webhook-idempotency"
    assert result["version"] == "0.1.0"
    assert result["fixture_count"] == 2


def test_test_bundle_runs_manifest_fixtures():
    result = run_bundle_tests(BUNDLE)

    assert result["ok"] is True
    assert result["passed"] == 2
    assert result["failed"] == 0
    assert result["results"][0]["result"]["state_snapshot"]["final_state"] == {"delivery:evt-1": "seen"}
    assert result["results"][1]["result"]["decision"]["status"] == 409


def test_pack_bundle_creates_archive(tmp_path):
    output = tmp_path / "idempotency.snulbug.tar.gz"

    result = pack_bundle(BUNDLE, output)

    assert result["ok"] is True
    with tarfile.open(output, "r:gz") as archive:
        names = archive.getnames()
    assert "idempotency.snulbug/manifest.json" in names
    assert "idempotency.snulbug/policy.lua" in names


def test_bundle_cli_validate_test_and_pack(tmp_path, capsys):
    packed = tmp_path / "bundle.tar.gz"

    validate_status = simulator_main(["bundle", "validate", BUNDLE, "--compact"])
    validate_output = json.loads(capsys.readouterr().out)
    test_status = simulator_main(["bundle", "test", BUNDLE, "--compact"])
    test_output = json.loads(capsys.readouterr().out)
    pack_status = simulator_main(["bundle", "pack", BUNDLE, str(packed), "--compact"])
    pack_output = json.loads(capsys.readouterr().out)

    assert validate_status == 0
    assert validate_output["ok"] is True
    assert test_status == 0
    assert test_output["ok"] is True
    assert pack_status == 0
    assert pack_output["ok"] is True
    assert packed.exists()


def test_validate_bundle_rejects_path_escape(tmp_path):
    bundle = tmp_path / "bad.snulbug"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "name": "bad",
                "version": "0.1.0",
                "entrypoint": "../policy.lua",
                "fixtures": [],
            }
        ),
        encoding="utf-8",
    )

    result = validate_bundle(bundle)

    assert result["ok"] is False
    assert "escapes bundle root" in result["errors"][0]


def test_bundle_lifecycle_promotes_validated_signed_bundle_through_states(tmp_path):
    bundle = copy_example_bundle(tmp_path)

    observed = inspect_bundle_lifecycle(bundle)
    assert observed["state"] == "observed"
    assert observed["signed"] is False

    proposed = promote_bundle_lifecycle(bundle, to_state="proposed", secret="dev-secret", key_id="dev")
    assert proposed["ok"] is True
    assert proposed["state"] == "proposed"
    assert proposed["validation"]["ok"] is True
    assert proposed["validation"]["passed"] == 2
    assert proposed["signature"]["key_id"] == "dev"

    verified_proposed = verify_bundle_lifecycle(bundle, secrets={"dev": "dev-secret"}, required_state="proposed")
    assert verified_proposed["ok"] is True
    assert verified_proposed["state"] == "proposed"

    approved = promote_bundle_lifecycle(bundle, to_state="approved", secret="dev-secret", key_id="dev")
    assert approved["ok"] is True
    assert approved["state"] == "approved"

    active = promote_bundle_lifecycle(bundle, secret="dev-secret", key_id="dev")
    assert active["ok"] is True
    assert active["state"] == "active"
    assert active["next_state"] is None

    lifecycle = inspect_bundle_lifecycle(bundle)
    assert lifecycle["state"] == "active"
    assert [event["state"] for event in lifecycle["history"]] == ["observed", "proposed", "approved", "active"]
    assert verify_bundle_lifecycle(bundle, secrets={"dev": "dev-secret"}, required_state="active")["ok"] is True


def test_bundle_lifecycle_rejects_skipped_states(tmp_path):
    bundle = copy_example_bundle(tmp_path)

    with pytest.raises(ValueError, match="cannot move"):
        promote_bundle_lifecycle(bundle, to_state="active", secret="dev-secret", key_id="dev")


def test_bundle_lifecycle_verify_rejects_tampered_policy(tmp_path):
    bundle = copy_example_bundle(tmp_path)
    promote_bundle_lifecycle(bundle, to_state="proposed", secret="dev-secret", key_id="dev")
    policy = bundle / "policy.lua"
    policy.write_text(policy.read_text(encoding="utf-8") + "\n-- tampered\n", encoding="utf-8")

    with pytest.raises(ValueError, match="digest"):
        verify_bundle_lifecycle(bundle, secrets={"dev": "dev-secret"}, required_state="proposed")


def test_bundle_lifecycle_cli_promotes_and_verifies(tmp_path, capsys, monkeypatch):
    bundle = copy_example_bundle(tmp_path)
    monkeypatch.setenv("SNULBUG_BUNDLE_SECRET", "dev-secret")

    promote_status = simulator_main(
        ["mcp", "policy", "lifecycle", "promote", str(bundle), "--to", "proposed", "--key-id", "dev", "--compact"]
    )
    promote_output = json.loads(capsys.readouterr().out)
    lifecycle_status = simulator_main(["mcp", "policy", "lifecycle", "status", str(bundle), "--compact"])
    lifecycle_output = json.loads(capsys.readouterr().out)
    verify_status = simulator_main(
        ["mcp", "policy", "lifecycle", "verify", str(bundle), "--state", "proposed", "--compact"]
    )
    verify_output = json.loads(capsys.readouterr().out)

    assert promote_status == 0
    assert promote_output["ok"] is True
    assert promote_output["state"] == "proposed"
    assert lifecycle_status == 0
    assert lifecycle_output["state"] == "proposed"
    assert lifecycle_output["signed"] is True
    assert verify_status == 0
    assert verify_output["verified"]["state"] == "proposed"


def copy_example_bundle(tmp_path):
    destination = tmp_path / "idempotency.snulbug"
    shutil.copytree(BUNDLE, destination)
    return destination

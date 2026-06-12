from __future__ import annotations

import json
import tarfile

from asgi_lua import pack_bundle, test_bundle as run_bundle_tests, validate_bundle
from asgi_lua.simulator import main as simulator_main

BUNDLE = "examples/bundles/idempotency.asgi-lua"


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
    output = tmp_path / "idempotency.asgi-lua.tar.gz"

    result = pack_bundle(BUNDLE, output)

    assert result["ok"] is True
    with tarfile.open(output, "r:gz") as archive:
        names = archive.getnames()
    assert "idempotency.asgi-lua/manifest.json" in names
    assert "idempotency.asgi-lua/policy.lua" in names


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
    bundle = tmp_path / "bad.asgi-lua"
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

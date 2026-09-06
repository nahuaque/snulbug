from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import zipfile
from io import StringIO
from pathlib import Path

import pytest

from snulbug.release_qa import (
    PROTOCOL_MODULES,
    PROTOCOL_SMOKE_SUCCESS,
    SCHEMA_FIXTURES,
    _installed_protocol_smoke,
    build_release_qa_steps,
    check_built_distributions,
    check_readme_image_urls,
    check_version_consistency,
    run_release_qa,
    smoke_built_wheel_protocol,
)
from snulbug.simulator import main as simulator_main


def test_release_qa_plan_includes_release_gates():
    step_ids = [step.id for step in build_release_qa_steps()]

    assert step_ids == [
        "version",
        "readme",
        "format",
        "lint",
        "bandit",
        "tests",
        "build",
        "dist",
        "source-cli",
        "source-module",
        "wheel-cli",
        "wheel-module",
        "wheel-protocol",
    ]


def test_release_qa_dry_run_does_not_execute_commands():
    stream = StringIO()

    result, status = run_release_qa(
        dry_run=True,
        include_bandit=False,
        include_tests=False,
        include_build=False,
        include_smoke=False,
        stream=stream,
    )

    assert status == 0
    assert result["ok"] is True
    assert [step["id"] for step in result["steps"]] == ["version", "readme", "format", "lint"]
    assert all(step["dry_run"] for step in result["steps"])
    assert "$ uv run ruff format --check ." in stream.getvalue()


def test_release_qa_checks_version_consistency(tmp_path):
    (tmp_path / "snulbug").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "snulbug"\nversion = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "snulbug" / "__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")

    ok, error, details = check_version_consistency(tmp_path)

    assert ok is True
    assert error is None
    assert details == {"pyproject_version": "1.2.3", "package_version": "1.2.3"}


def test_release_qa_rejects_version_mismatch(tmp_path):
    (tmp_path / "snulbug").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "snulbug"\nversion = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "snulbug" / "__init__.py").write_text('__version__ = "1.2.4"\n', encoding="utf-8")

    ok, error, details = check_version_consistency(tmp_path)

    assert ok is False
    assert "do not match" in str(error)
    assert details["pyproject_version"] == "1.2.3"
    assert details["package_version"] == "1.2.4"


def test_release_qa_rejects_relative_readme_images(tmp_path):
    (tmp_path / "README.md").write_text('![logo](assets/snulbug.png)\n<img src="/logo.png">\n', encoding="utf-8")

    ok, error, details = check_readme_image_urls(tmp_path)

    assert ok is False
    assert "absolute" in str(error)
    assert details["relative_image_urls"] == ["assets/snulbug.png", "/logo.png"]


@pytest.mark.parametrize("feature_version,ok", [("1.2.3", True), ("1.2.2", False)])
def test_release_qa_checks_feature_version(tmp_path, feature_version, ok):
    (tmp_path / "snulbug").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    (tmp_path / "snulbug/__init__.py").write_text('__version__ = "1.2.3"\n')
    feature = tmp_path / "features/snulbug/devcontainer-feature.json"
    feature.parent.mkdir(parents=True)
    feature.write_text(json.dumps({"version": feature_version}))

    result, error, details = check_version_consistency(tmp_path)

    assert result is ok
    assert details["feature_version"] == feature_version
    if not ok:
        assert "devcontainer" in error


@pytest.mark.parametrize("lock_version,ok", [("1.2.3", True), ("1.2.2", False)])
def test_release_qa_checks_lock_version(tmp_path, lock_version, ok):
    (tmp_path / "snulbug").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    (tmp_path / "snulbug/__init__.py").write_text('__version__ = "1.2.3"\n')
    (tmp_path / "uv.lock").write_text(f'[[package]]\nname = "snulbug"\nversion = "{lock_version}"\n')
    result, error, details = check_version_consistency(tmp_path)
    assert result is ok
    assert details["lock_version"] == lock_version
    if not ok:
        assert "uv.lock" in error


def make_distributions(root, *, missing=None, cache=False):
    (root / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    (root / "dist").mkdir()
    modules = {f"snulbug/{name}.py" for name in PROTOCOL_MODULES}
    wheel_files = {"snulbug/__init__.py", "snulbug/release_qa.py", "snulbug/py.typed", *modules}
    sdist_files = {
        "README.md",
        "LICENSE",
        "pyproject.toml",
        "snulbug/__init__.py",
        "snulbug/release_qa.py",
        "docs/release.md",
        "docs/mcp-protocol.md",
        "tests/test_share_console.py",
        "tests/fixtures/stdio_subscriptions.py",
        *modules,
        *(f"tests/test_{name}.py" for name in PROTOCOL_MODULES),
        *(f"tests/fixtures/json_schema_2020_12/{name}" for name in SCHEMA_FIXTURES),
    }
    if cache:
        wheel_files.add("snulbug/__pycache__/mcp_protocol.cpython-313.pyc")
    with zipfile.ZipFile(root / "dist/snulbug-1.2.3-py3-none-any.whl", "w") as archive:
        for name in sorted(wheel_files - {missing}):
            archive.writestr(name, b"")
    with tarfile.open(root / "dist/snulbug-1.2.3.tar.gz", "w:gz") as archive:
        for name in sorted(sdist_files - {missing}):
            archive.addfile(tarfile.TarInfo(f"snulbug-1.2.3/{name}"))


def test_release_qa_accepts_complete_distributions(tmp_path):
    make_distributions(tmp_path)
    ok, error, _ = check_built_distributions(tmp_path)
    assert ok, error


@pytest.mark.parametrize(
    "missing",
    [
        "snulbug/mcp_stdio.py",
        "snulbug/json_schema.py",
        "snulbug/mcp_protocol.py",
        "docs/mcp-protocol.md",
        "tests/test_mcp_subscriptions.py",
        "tests/fixtures/stdio_subscriptions.py",
        "tests/fixtures/json_schema_2020_12/dynamicRef.json",
        "tests/fixtures/json_schema_2020_12/LICENSE",
    ],
)
def test_release_qa_rejects_missing_protocol_artifacts(tmp_path, missing):
    make_distributions(tmp_path, missing=missing)
    ok, error, details = check_built_distributions(tmp_path)
    assert not ok
    assert "missing" in error
    assert missing in json.dumps(details)


def test_release_qa_rejects_cache_artifacts(tmp_path):
    make_distributions(tmp_path, cache=True)
    ok, error, _ = check_built_distributions(tmp_path)
    assert not ok
    assert "cache" in error


def test_protocol_schema_smoke_exercises_real_modules(capsys, monkeypatch):
    from snulbug import __version__

    # Source-checkout tests need not have matching installed distribution metadata.
    monkeypatch.setattr("importlib.metadata.version", lambda name: __version__)
    _installed_protocol_smoke()
    assert PROTOCOL_SMOKE_SUCCESS in capsys.readouterr().out


def test_protocol_smoke_rejects_lost_schema_enforcement(monkeypatch):
    from snulbug import __version__

    monkeypatch.setattr("importlib.metadata.version", lambda name: __version__)
    monkeypatch.setattr("snulbug.json_schema.validate_schema", lambda *args: [])
    with pytest.raises(RuntimeError, match="constraints not enforced"):
        _installed_protocol_smoke()


def test_protocol_smoke_rejects_mismatched_installed_metadata(monkeypatch):
    monkeypatch.setattr("importlib.metadata.version", lambda name: "0.0.0")
    with pytest.raises(RuntimeError, match="metadata and package versions differ"):
        _installed_protocol_smoke()


@pytest.mark.parametrize("output,expected_ok", [(PROTOCOL_SMOKE_SUCCESS, True), ("release-qa", False)])
def test_wheel_protocol_smoke_is_isolated_and_requires_success_marker(tmp_path, monkeypatch, output, expected_ok):
    make_distributions(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path))

    def run(command, **kwargs):
        assert "--no-project" in command
        assert "--isolated" in command
        assert command[command.index("--python") + 1] == sys.executable
        assert str((tmp_path / "dist/snulbug-1.2.3-py3-none-any.whl").resolve()) in command
        assert Path(kwargs["cwd"]).is_dir()
        assert not Path(kwargs["cwd"]).is_relative_to(tmp_path)
        assert "PYTHONPATH" not in kwargs["env"]
        assert "PYTHONHOME" not in kwargs["env"]
        assert kwargs["timeout"] == 180
        return subprocess.CompletedProcess(command, 0, stdout=output)

    monkeypatch.setattr("snulbug.release_qa.subprocess.run", run)
    ok, _, _ = smoke_built_wheel_protocol(tmp_path)
    assert ok is expected_ok


def test_release_qa_cli_exposes_dry_run(capsys):
    status = simulator_main(
        [
            "release-qa",
            "--dry-run",
            "--skip-bandit",
            "--skip-tests",
            "--skip-build",
            "--skip-smoke",
            "--compact",
        ]
    )
    output = capsys.readouterr().out

    assert status == 0
    assert '"dry_run":true' in output
    assert '"id":"format"' in output

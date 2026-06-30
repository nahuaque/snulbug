from __future__ import annotations

from io import StringIO

from snulbug.release_qa import (
    build_release_qa_steps,
    check_readme_image_urls,
    check_version_consistency,
    run_release_qa,
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

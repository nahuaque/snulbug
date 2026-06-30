from __future__ import annotations

import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[no-redef]

README_IMAGE_PATTERN = re.compile(r"(?:<img\s+[^>]*src=[\"']([^\"']+)[\"']|!\[[^\]]*]\(([^)]+)\))", re.IGNORECASE)


@dataclass(frozen=True)
class ReleaseQAStep:
    id: str
    label: str
    command: tuple[str, ...] | None = None
    check: Callable[[Path], tuple[bool, str | None, dict[str, Any]]] | None = None
    env: dict[str, str] | None = None


def build_release_qa_steps(
    *,
    include_bandit: bool = True,
    include_tests: bool = True,
    include_build: bool = True,
    include_smoke: bool = True,
) -> list[ReleaseQAStep]:
    steps = [
        ReleaseQAStep("version", "Check version consistency", check=check_version_consistency),
        ReleaseQAStep("readme", "Check README image URLs for PyPI", check=check_readme_image_urls),
        ReleaseQAStep("format", "Check formatting", command=("uv", "run", "ruff", "format", "--check", ".")),
        ReleaseQAStep("lint", "Lint", command=("uv", "run", "ruff", "check", ".")),
    ]
    if include_bandit:
        steps.append(ReleaseQAStep("bandit", "Security scan", command=("uv", "run", "bandit", "-r", "snulbug", "-lll")))
    if include_tests:
        steps.append(
            ReleaseQAStep(
                "tests",
                "Test",
                command=("uv", "run", "pytest", "-q"),
                env={"PYTHONDONTWRITEBYTECODE": "1"},
            )
        )
    if include_build:
        steps.extend(
            [
                ReleaseQAStep("build", "Build distributions", command=("uv", "build")),
                ReleaseQAStep("dist", "Inspect built distributions", check=check_built_distributions),
            ]
        )
    if include_smoke:
        steps.extend(
            [
                ReleaseQAStep("source-cli", "Smoke test source CLI", command=("uv", "run", "snulbug", "--help")),
                ReleaseQAStep(
                    "source-module",
                    "Smoke test source module",
                    command=("uv", "run", "python", "-m", "snulbug", "--help"),
                ),
                ReleaseQAStep("wheel-cli", "Smoke test built wheel CLI", check=smoke_built_wheel_cli),
                ReleaseQAStep("wheel-module", "Smoke test built wheel module", check=smoke_built_wheel_module),
            ]
        )
    return steps


def run_release_qa(
    *,
    root: str | Path = ".",
    include_bandit: bool = True,
    include_tests: bool = True,
    include_build: bool = True,
    include_smoke: bool = True,
    dry_run: bool = False,
    keep_going: bool = False,
    stream: TextIO | None = None,
) -> tuple[dict[str, Any], int]:
    repo_root = Path(root)
    output = stream or sys.stdout
    steps = build_release_qa_steps(
        include_bandit=include_bandit,
        include_tests=include_tests,
        include_build=include_build,
        include_smoke=include_smoke,
    )
    result: dict[str, Any] = {
        "ok": True,
        "root": str(repo_root),
        "dry_run": dry_run,
        "steps": [],
    }

    for step in steps:
        _write_step_header(output, step)
        if dry_run:
            step_result = _dry_run_step(step)
        elif step.check is not None:
            step_result = _run_check_step(step, repo_root)
        else:
            step_result = _run_command_step(step, repo_root)

        result["steps"].append(step_result)
        if step_result["ok"]:
            output.write(f"ok: {step.label}\n")
        else:
            result["ok"] = False
            output.write(f"failed: {step.label}: {step_result.get('error') or 'command failed'}\n")
            if not keep_going:
                break

    return result, 0 if result["ok"] else 1


def check_version_consistency(root: Path) -> tuple[bool, str | None, dict[str, Any]]:
    pyproject_version = _pyproject_version(root)
    package_version = _package_version(root)
    details = {
        "pyproject_version": pyproject_version,
        "package_version": package_version,
    }
    if pyproject_version != package_version:
        return False, "pyproject.toml version and snulbug.__version__ do not match", details
    return True, None, details


def check_readme_image_urls(root: Path) -> tuple[bool, str | None, dict[str, Any]]:
    readme = root / "README.md"
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        return False, str(exc), {"path": str(readme)}
    images = [match.group(1) or match.group(2) for match in README_IMAGE_PATTERN.finditer(text)]
    bad = [image for image in images if image and not image.startswith(("https://", "http://"))]
    details = {"image_urls": images, "relative_image_urls": bad}
    if bad:
        return False, "README image URLs must be absolute so they render on PyPI", details
    return True, None, details


def check_built_distributions(root: Path) -> tuple[bool, str | None, dict[str, Any]]:
    version = _pyproject_version(root)
    dist = root / "dist"
    wheel = _built_wheel(root, version=version)
    sdist = dist / f"snulbug-{version}.tar.gz"
    details: dict[str, Any] = {
        "version": version,
        "wheel": str(wheel) if wheel else None,
        "sdist": str(sdist),
    }
    if wheel is None:
        return False, f"built wheel for version {version} not found in dist/", details
    if not sdist.is_file():
        return False, f"built sdist for version {version} not found in dist/", details

    wheel_ok, wheel_error, wheel_details = _inspect_wheel(wheel)
    details["wheel_inspection"] = wheel_details
    if not wheel_ok:
        return False, wheel_error, details

    sdist_ok, sdist_error, sdist_details = _inspect_sdist(sdist, version=version)
    details["sdist_inspection"] = sdist_details
    if not sdist_ok:
        return False, sdist_error, details

    return True, None, details


def smoke_built_wheel_cli(root: Path) -> tuple[bool, str | None, dict[str, Any]]:
    return _smoke_built_wheel(root, ("snulbug", "--help"))


def smoke_built_wheel_module(root: Path) -> tuple[bool, str | None, dict[str, Any]]:
    return _smoke_built_wheel(root, ("python", "-m", "snulbug", "--help"))


def _run_command_step(step: ReleaseQAStep, root: Path) -> dict[str, Any]:
    if step.command is None:
        return {"id": step.id, "label": step.label, "ok": False, "error": "step has no command"}
    env = os.environ.copy()
    if step.env:
        env.update(step.env)
    completed = subprocess.run(step.command, cwd=root, env=env)  # noqa: S603 - release QA executes fixed tool commands.
    return {
        "id": step.id,
        "label": step.label,
        "ok": completed.returncode == 0,
        "command": list(step.command),
        "returncode": completed.returncode,
    }


def _run_check_step(step: ReleaseQAStep, root: Path) -> dict[str, Any]:
    if step.check is None:
        return {"id": step.id, "label": step.label, "ok": False, "error": "step has no check"}
    try:
        ok, error, details = step.check(root)
    except Exception as exc:  # pragma: no cover - defensive guard for release tooling.
        return {"id": step.id, "label": step.label, "ok": False, "error": str(exc), "details": {}}
    return {
        "id": step.id,
        "label": step.label,
        "ok": ok,
        "error": error,
        "details": details,
    }


def _dry_run_step(step: ReleaseQAStep) -> dict[str, Any]:
    return {
        "id": step.id,
        "label": step.label,
        "ok": True,
        "dry_run": True,
        "command": list(step.command) if step.command else None,
        "check": step.check.__name__ if step.check else None,
    }


def _write_step_header(stream: TextIO, step: ReleaseQAStep) -> None:
    stream.write(f"\n==> {step.label}\n")
    if step.command:
        stream.write("$ " + " ".join(step.command) + "\n")


def _pyproject_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    return str(pyproject["project"]["version"])


def _package_version(root: Path) -> str:
    init_path = root / "snulbug" / "__init__.py"
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_path.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError("snulbug/__init__.py does not define __version__")
    return match.group(1)


def _built_wheel(root: Path, *, version: str) -> Path | None:
    wheels = sorted((root / "dist").glob(f"snulbug-{version}-*.whl"))
    return wheels[-1] if wheels else None


def _inspect_wheel(path: Path) -> tuple[bool, str | None, dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    required = {
        "snulbug/__init__.py",
        "snulbug/release_qa.py",
        "snulbug/py.typed",
    }
    missing = sorted(required - names)
    pycache = sorted(name for name in names if "__pycache__" in name or name.endswith((".pyc", ".pyo")))
    details = {
        "file_count": len(names),
        "missing": missing,
        "pycache_entries": pycache[:20],
    }
    if missing:
        return False, "wheel is missing required package files", details
    if pycache:
        return False, "wheel contains Python cache artifacts", details
    return True, None, details


def _inspect_sdist(path: Path, *, version: str) -> tuple[bool, str | None, dict[str, Any]]:
    prefix = f"snulbug-{version}/"
    with tarfile.open(path, "r:gz") as archive:
        names = set(archive.getnames())
    required = {
        f"{prefix}README.md",
        f"{prefix}LICENSE",
        f"{prefix}pyproject.toml",
        f"{prefix}snulbug/__init__.py",
        f"{prefix}snulbug/release_qa.py",
        f"{prefix}docs/release.md",
        f"{prefix}tests/test_share_console.py",
    }
    missing = sorted(required - names)
    pycache = sorted(name for name in names if "__pycache__" in name or name.endswith((".pyc", ".pyo")))
    details = {
        "file_count": len(names),
        "missing": missing,
        "pycache_entries": pycache[:20],
    }
    if missing:
        return False, "sdist is missing expected release files", details
    if pycache:
        return False, "sdist contains Python cache artifacts", details
    return True, None, details


def _smoke_built_wheel(root: Path, args: Sequence[str]) -> tuple[bool, str | None, dict[str, Any]]:
    version = _pyproject_version(root)
    wheel = _built_wheel(root, version=version)
    if wheel is None:
        return False, f"built wheel for version {version} not found in dist/", {"version": version}
    wheel_path = wheel.resolve()
    command = ("uv", "run", "--isolated", "--with", str(wheel_path), *args)
    with tempfile.TemporaryDirectory(prefix="snulbug-release-qa-") as temp_dir:
        completed = subprocess.run(  # noqa: S603 - release QA executes fixed tool commands.
            command,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    output = completed.stdout or ""
    details = {
        "command": list(command),
        "returncode": completed.returncode,
        "wheel": str(wheel_path),
        "output": output[-4000:],
    }
    if completed.returncode != 0:
        return False, "built wheel smoke test failed", details
    if "release-qa" not in output:
        return False, "built wheel help output does not include the release-qa command", details
    return True, None, details

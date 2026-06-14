from __future__ import annotations

import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bundle import test_bundle, validate_bundle


@dataclass(frozen=True)
class WrittenMcpPolicyBundle:
    root: Path
    policy: Path
    manifest: Path
    report: Path
    extra_files: tuple[Path, ...]
    validation: dict[str, Any] | None
    tests: dict[str, Any] | None

    @property
    def ok(self) -> bool:
        validation_ok = bool(self.validation["ok"]) if self.validation is not None else True
        tests_ok = bool(self.tests["ok"]) if self.tests is not None else True
        return validation_ok and tests_ok

    @property
    def next_steps(self) -> list[str]:
        return [
            f"uv run snulbug bundle validate {self.root}",
            f"uv run snulbug bundle test {self.root}",
            f"uv run snulbug mcp share run --policy {self.policy} --upstream http://127.0.0.1:9000",
        ]


def write_mcp_policy_bundle(
    output: str | Path,
    *,
    policy: str,
    manifest: Mapping[str, Any],
    report: str,
    report_name: str,
    force: bool = False,
    exists_label: str = "policy bundle output",
    clean: bool = False,
    extra_files: Mapping[str, str | bytes] | None = None,
    validate: bool = True,
    run_tests: bool = False,
) -> WrittenMcpPolicyBundle:
    """Write a generated MCP policy bundle and optionally validate/test it."""

    root = Path(output)
    if root.exists() and not force:
        raise FileExistsError(f"{exists_label} already exists: {root}")
    if root.exists() and clean:
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    written_extra_files = _write_extra_files(root, extra_files or {})
    policy_path = _safe_bundle_path(root, "policy.lua")
    manifest_path = _safe_bundle_path(root, "manifest.json")
    report_path = _safe_bundle_path(root, report_name)
    policy_path.write_text(policy, encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(report, encoding="utf-8")

    validation = validate_bundle(root) if validate else None
    tests = test_bundle(root) if run_tests and validation is not None and validation["ok"] else None
    return WrittenMcpPolicyBundle(
        root=root,
        policy=policy_path,
        manifest=manifest_path,
        report=report_path,
        extra_files=tuple(written_extra_files),
        validation=validation,
        tests=tests,
    )


def _write_extra_files(root: Path, files: Mapping[str, str | bytes]) -> list[Path]:
    written = []
    for relative_path, content in files.items():
        path = _safe_bundle_path(root, relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(str(content), encoding="utf-8")
        written.append(path)
    return written


def _safe_bundle_path(root: Path, relative_path: str) -> Path:
    root_resolved = root.resolve()
    target = (root_resolved / relative_path).resolve()
    if root_resolved != target and root_resolved not in target.parents:
        raise ValueError(f"bundle path escapes bundle root: {relative_path}")
    return target

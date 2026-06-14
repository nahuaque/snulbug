from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScaffoldFile:
    path: str | Path
    content: str | bytes
    kind: str = "file"
    executable: bool = False
    encoding: str = "utf-8"


@dataclass(frozen=True)
class ScaffoldPlan:
    name: str
    root: str | Path
    files: Sequence[ScaffoldFile] = ()
    directories: Sequence[str | Path] = ()
    commands: Mapping[str, Any] = field(default_factory=dict)
    env: Mapping[str, Any] = field(default_factory=dict)
    client: Mapping[str, Any] = field(default_factory=dict)
    smoke_checks: Sequence[Mapping[str, Any]] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


def json_scaffold_file(
    path: str | Path,
    value: Any,
    *,
    kind: str = "json",
    executable: bool = False,
) -> ScaffoldFile:
    return ScaffoldFile(
        path=path,
        content=json.dumps(value, indent=2, sort_keys=True) + "\n",
        kind=kind,
        executable=executable,
    )


def write_scaffold(plan: ScaffoldPlan, *, force: bool = False) -> dict[str, Any]:
    root = Path(plan.root)
    directories = [_resolve_scaffold_path(root, directory) for directory in plan.directories]
    files = [_materialize_file(root, file) for file in plan.files]

    for directory in directories:
        if directory.exists() and not directory.is_dir():
            raise FileExistsError(f"{plan.name} output already exists and is not a directory: {directory}")
    for file, path in files:
        if path.exists() and not force:
            raise FileExistsError(f"{plan.name} output already exists: {path}")

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    for file, path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(file.content, bytes):
            path.write_bytes(file.content)
        else:
            path.write_text(file.content, encoding=file.encoding)
        if file.executable:
            path.chmod(path.stat().st_mode | 0o111)

    return scaffold_result(plan, files=files, directories=directories)


def scaffold_result(
    plan: ScaffoldPlan,
    *,
    files: Sequence[tuple[ScaffoldFile, Path]] | None = None,
    directories: Sequence[Path] | None = None,
) -> dict[str, Any]:
    root = Path(plan.root)
    materialized_files = list(files) if files is not None else [_materialize_file(root, file) for file in plan.files]
    materialized_dirs = (
        list(directories)
        if directories is not None
        else [_resolve_scaffold_path(root, directory) for directory in plan.directories]
    )
    return {
        "ok": True,
        "name": plan.name,
        "root": str(root),
        "files": [
            {
                "path": str(path),
                "kind": file.kind,
                "executable": file.executable,
            }
            for file, path in materialized_files
        ],
        "written_files": [str(path) for _file, path in materialized_files],
        "directories": [str(path) for path in materialized_dirs],
        "commands": dict(plan.commands),
        "env": dict(plan.env),
        "client": dict(plan.client),
        "smoke_checks": [dict(check) for check in plan.smoke_checks],
        "metadata": dict(plan.metadata),
    }


def format_scaffold_report(result: Mapping[str, Any]) -> str:
    lines = [f"# {result.get('name', 'snulbug scaffold')}", ""]
    root = result.get("root")
    if root:
        lines.extend([f"Root: `{root}`", ""])
    files = result.get("written_files")
    if isinstance(files, Sequence) and not isinstance(files, str | bytes | bytearray):
        lines.extend(["## Files", ""])
        lines.extend(f"- `{file}`" for file in files)
    commands = result.get("commands")
    if isinstance(commands, Mapping) and commands:
        lines.extend(["", "## Commands", ""])
        lines.extend(f"- `{key}`: `{value}`" for key, value in commands.items())
    return "\n".join(lines).rstrip() + "\n"


def _materialize_file(root: Path, file: ScaffoldFile) -> tuple[ScaffoldFile, Path]:
    return file, _resolve_scaffold_path(root, file.path)


def _resolve_scaffold_path(root: Path, path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else root / value

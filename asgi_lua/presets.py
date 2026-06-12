from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Any

PRESET_GROUP = "mcp"
PRESET_SUFFIX = ".asgi-lua"


def list_builtin_presets() -> list[dict[str, Any]]:
    """Return bundled policy presets that can be copied into a project."""

    presets = []
    for preset in _preset_root().iterdir():
        if not preset.is_dir() or not preset.name.endswith(PRESET_SUFFIX):
            continue
        manifest = _read_resource_json(preset.joinpath("manifest.json"))
        presets.append(
            {
                "preset": preset.name.removesuffix(PRESET_SUFFIX),
                "name": manifest.get("name"),
                "version": manifest.get("version"),
                "description": manifest.get("description", ""),
                "required_capabilities": manifest.get("required_capabilities", []),
            }
        )
    return sorted(presets, key=lambda item: str(item["preset"]))


def copy_builtin_preset(preset: str, output: str | Path, *, force: bool = False) -> dict[str, Any]:
    """Copy a bundled preset policy bundle to a local directory."""

    source = _preset_path(preset)
    destination = Path(output)
    if destination.exists() and not force:
        raise FileExistsError(f"output path already exists: {destination}")
    if destination.exists() and force:
        shutil.rmtree(destination)
    _copy_tree(source, destination)
    manifest = _read_json_file(destination / "manifest.json")
    return {
        "ok": True,
        "preset": preset,
        "output": str(destination),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "description": manifest.get("description", ""),
    }


def _preset_root() -> Any:
    return resources.files("asgi_lua").joinpath("builtin_presets", PRESET_GROUP)


def _preset_path(preset: str) -> Any:
    normalized = preset.removesuffix(PRESET_SUFFIX)
    source = _preset_root().joinpath(f"{normalized}{PRESET_SUFFIX}")
    if not source.is_dir():
        known = ", ".join(item["preset"] for item in list_builtin_presets())
        raise KeyError(f"unknown MCP preset {preset!r}; available presets: {known}")
    return source


def _copy_tree(source: Any, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir():
            _copy_tree(child, target)
        else:
            with child.open("rb") as source_file, target.open("wb") as target_file:
                shutil.copyfileobj(source_file, target_file)


def _read_resource_json(path: Any) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"resource JSON must be an object: {path}")
    return value


def _read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"JSON file must be an object: {path}")
    return value

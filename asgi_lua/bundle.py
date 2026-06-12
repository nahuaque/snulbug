from __future__ import annotations

import json
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runtime import LuaRuntimeError, compile_lua_file
from .simulator import simulate_policy

MANIFEST_NAME = "manifest.json"


@dataclass(frozen=True)
class PolicyBundle:
    root: Path
    manifest: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.manifest["name"])

    @property
    def version(self) -> str:
        return str(self.manifest["version"])

    @property
    def entrypoint(self) -> Path:
        return _safe_join(self.root, str(self.manifest["entrypoint"]))


def load_bundle(path: str | Path) -> PolicyBundle:
    root = Path(path)
    manifest_path = root / MANIFEST_NAME
    if not root.is_dir():
        raise FileNotFoundError(f"bundle path is not a directory: {root}")
    if not manifest_path.is_file():
        raise FileNotFoundError(f"bundle manifest not found: {manifest_path}")
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("bundle manifest must be a JSON object")
    return PolicyBundle(root=root, manifest=manifest)


def validate_bundle(path: str | Path, *, compile_policy: bool = True) -> dict[str, Any]:
    errors: list[str] = []
    try:
        bundle = load_bundle(path)
    except Exception as exc:
        return {"ok": False, "errors": [str(exc)], "bundle": str(path)}

    manifest = bundle.manifest
    for field in ("name", "version", "entrypoint"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            errors.append(f"manifest field {field!r} must be a non-empty string")

    entrypoint = manifest.get("entrypoint")
    if isinstance(entrypoint, str) and entrypoint:
        try:
            entrypoint_path = _safe_join(bundle.root, entrypoint)
            if not entrypoint_path.is_file():
                errors.append(f"entrypoint file does not exist: {entrypoint}")
            elif compile_policy:
                try:
                    compile_lua_file(entrypoint_path)
                except LuaRuntimeError as exc:
                    errors.append(f"entrypoint does not compile: {exc}")
        except ValueError as exc:
            errors.append(str(exc))

    fixtures = manifest.get("fixtures", [])
    if not isinstance(fixtures, list):
        errors.append("manifest field 'fixtures' must be a list")
        fixtures = []
    for index, fixture in enumerate(fixtures):
        errors.extend(_validate_fixture(bundle.root, fixture, index))

    capabilities = manifest.get("required_capabilities", [])
    if capabilities is not None and not _string_list(capabilities):
        errors.append("manifest field 'required_capabilities' must be a list of strings")

    limits = manifest.get("limits", {})
    if limits is not None and not isinstance(limits, Mapping):
        errors.append("manifest field 'limits' must be an object")
    elif isinstance(limits, Mapping):
        for field, value in limits.items():
            if not isinstance(field, str):
                errors.append("manifest limit names must be strings")
            if not isinstance(value, int) or value <= 0:
                errors.append(f"manifest limit {field!r} must be a positive integer")

    return {
        "ok": not errors,
        "errors": errors,
        "bundle": str(bundle.root),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "fixture_count": len(fixtures),
    }


def test_bundle(
    path: str | Path,
    *,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    validation = validate_bundle(path)
    if not validation["ok"]:
        return {
            "ok": False,
            "bundle": str(path),
            "validation": validation,
            "fixture_count": 0,
            "passed": 0,
            "failed": 0,
            "results": [],
        }

    bundle = load_bundle(path)
    results = [
        _run_fixture(
            bundle,
            fixture,
            instruction_limit=instruction_limit,
            memory_limit_bytes=memory_limit_bytes,
        )
        for fixture in bundle.manifest.get("fixtures", [])
    ]
    failed = [result for result in results if not result["ok"]]
    return {
        "ok": not failed,
        "bundle": str(bundle.root),
        "name": bundle.name,
        "version": bundle.version,
        "fixture_count": len(results),
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "results": results,
    }


def pack_bundle(path: str | Path, output_path: str | Path) -> dict[str, Any]:
    validation = validate_bundle(path)
    if not validation["ok"]:
        return {"ok": False, "errors": validation["errors"], "bundle": str(path), "output": str(output_path)}

    bundle = load_bundle(path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        archive.add(bundle.root, arcname=bundle.root.name, recursive=True)
    return {
        "ok": True,
        "bundle": str(bundle.root),
        "output": str(output),
        "name": bundle.name,
        "version": bundle.version,
    }


def _validate_fixture(root: Path, fixture: Any, index: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(fixture, Mapping):
        return [f"fixture #{index} must be an object"]
    if not isinstance(fixture.get("name"), str) or not fixture["name"]:
        errors.append(f"fixture #{index} field 'name' must be a non-empty string")
    request = fixture.get("request")
    if not isinstance(request, str) or not request:
        errors.append(f"fixture #{index} field 'request' must be a non-empty string")
    else:
        errors.extend(_validate_existing_relative_file(root, request, f"fixture #{index} request"))
    for field in ("state", "context"):
        value = fixture.get(field)
        if value is not None:
            if not isinstance(value, str) or not value:
                errors.append(f"fixture #{index} field {field!r} must be a non-empty string when present")
            else:
                errors.extend(_validate_existing_relative_file(root, value, f"fixture #{index} {field}"))
    expect = fixture.get("expect", {})
    if expect is not None and not isinstance(expect, Mapping):
        errors.append(f"fixture #{index} field 'expect' must be an object")
    return errors


def _run_fixture(
    bundle: PolicyBundle,
    fixture: Mapping[str, Any],
    *,
    instruction_limit: int,
    memory_limit_bytes: int | None,
) -> dict[str, Any]:
    request_path = _safe_join(bundle.root, str(fixture["request"]))
    context = _optional_json(bundle.root, fixture.get("context"))
    state = _optional_json(bundle.root, fixture.get("state"))
    result = simulate_policy(
        bundle.entrypoint,
        _read_json(request_path),
        context=context,
        state_snapshot=state,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    expectation = fixture.get("expect", {})
    failures = _match_expectation(result, expectation if isinstance(expectation, Mapping) else {})
    return {
        "ok": not failures,
        "name": fixture["name"],
        "request": str(fixture["request"]),
        "state": fixture.get("state"),
        "context": fixture.get("context"),
        "failures": failures,
        "result": result,
    }


def _match_expectation(result: Mapping[str, Any], expect: Mapping[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for key, expected in expect.items():
        actual = _lookup_expectation(result, str(key))
        if actual != expected:
            failures.append({"field": str(key), "expected": expected, "actual": actual})
    return failures


def _lookup_expectation(result: Mapping[str, Any], key: str) -> Any:
    if key == "action":
        return result.get("action")
    if key.startswith("decision."):
        return _nested_get(result.get("decision"), key.removeprefix("decision."))
    if key.startswith("state_snapshot."):
        return _nested_get(result.get("state_snapshot"), key.removeprefix("state_snapshot."))
    if key in {"status", "path", "body", "headers", "context"}:
        decision = result.get("decision")
        return decision.get(key) if isinstance(decision, Mapping) else None
    return _nested_get(result, key)


def _nested_get(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _validate_existing_relative_file(root: Path, value: str, label: str) -> list[str]:
    try:
        path = _safe_join(root, value)
    except ValueError as exc:
        return [str(exc)]
    if not path.is_file():
        return [f"{label} file does not exist: {value}"]
    return []


def _safe_join(root: Path, relative_path: str) -> Path:
    root_resolved = root.resolve()
    target = (root_resolved / relative_path).resolve()
    if root_resolved != target and root_resolved not in target.parents:
        raise ValueError(f"bundle path escapes bundle root: {relative_path}")
    return target


def _optional_json(root: Path, relative_path: Any) -> Any:
    if relative_path is None:
        return None
    return _read_json(_safe_join(root, str(relative_path)))


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)

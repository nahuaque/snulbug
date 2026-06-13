from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .runtime import LuaRuntimeError, compile_lua_file
from .simulator import simulate_policy

MANIFEST_NAME = "manifest.json"
LIFECYCLE_FIELD = "snulbug_lifecycle"
LIFECYCLE_SIGNATURE_FIELD = "signature"
LIFECYCLE_SCHEMA = "snulbug.policy-lifecycle.v1"
LIFECYCLE_DIGEST_SCHEMA = "snulbug.policy-bundle-digest.v1"
LIFECYCLE_SIGNATURE_ALGORITHM = "hmac-sha256"
LIFECYCLE_STATES = ("observed", "proposed", "approved", "active")
_NEXT_STATE = {"observed": "proposed", "proposed": "approved", "approved": "active"}


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

    errors.extend(_validate_lifecycle(manifest.get(LIFECYCLE_FIELD)))

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


def inspect_bundle_lifecycle(path: str | Path) -> dict[str, Any]:
    bundle = load_bundle(path)
    lifecycle = _normalized_lifecycle(bundle.manifest.get(LIFECYCLE_FIELD))
    signature = lifecycle.get(LIFECYCLE_SIGNATURE_FIELD)
    return {
        "ok": True,
        "bundle": str(bundle.root),
        "name": bundle.name,
        "version": bundle.version,
        "state": lifecycle["state"],
        "next_state": _NEXT_STATE.get(str(lifecycle["state"])),
        "signed": isinstance(signature, Mapping),
        "signature": _signature_summary(signature),
        "validation": lifecycle.get("validation"),
        "history": lifecycle.get("history", []),
    }


def promote_bundle_lifecycle(
    path: str | Path,
    *,
    to_state: str = "next",
    secret: str,
    key_id: str,
    actor: str | None = None,
    note: str | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Advance a policy bundle through observed -> proposed -> approved -> active."""

    if not secret:
        raise ValueError("bundle signing secret must be non-empty")
    if not key_id:
        raise ValueError("bundle key_id must be non-empty")

    bundle = load_bundle(path)
    lifecycle = _normalized_lifecycle(bundle.manifest.get(LIFECYCLE_FIELD))
    current_state = str(lifecycle["state"])
    target_state = _target_state(current_state, to_state)

    if target_state in {"approved", "active"}:
        required_state = "proposed" if target_state == "approved" else "approved"
        verify_bundle_lifecycle(bundle.root, secrets={key_id: secret}, required_state=required_state)

    validation = _run_promotion_validation(
        bundle.root,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    if not validation["ok"]:
        return {
            "ok": False,
            "bundle": str(bundle.root),
            "from_state": current_state,
            "to_state": target_state,
            "validation": validation,
            "error": "bundle validation or fixture tests failed",
        }

    unsigned_manifest = dict(bundle.manifest)
    history = _lifecycle_history(lifecycle)
    now = _utc_now()
    if not history:
        history.append(_history_event("observed", now=now, actor=actor, note="initial observed state"))
    history.append(_history_event(target_state, now=now, actor=actor, note=note))
    unsigned_manifest[LIFECYCLE_FIELD] = {
        "schema": LIFECYCLE_SCHEMA,
        "state": target_state,
        "updated_at": now,
        "history": history,
        "validation": validation,
    }
    _write_manifest(bundle.root, unsigned_manifest)

    signed_manifest = _sign_bundle_manifest(bundle.root, secret=secret, key_id=key_id, signed_at=now)
    _write_manifest(bundle.root, signed_manifest)
    signed_lifecycle = _normalized_lifecycle(signed_manifest.get(LIFECYCLE_FIELD))
    signature = signed_lifecycle[LIFECYCLE_SIGNATURE_FIELD]
    return {
        "ok": True,
        "bundle": str(bundle.root),
        "name": signed_manifest.get("name"),
        "version": signed_manifest.get("version"),
        "from_state": current_state,
        "to_state": target_state,
        "state": target_state,
        "validation": validation,
        "signature": _signature_summary(signature),
        "next_state": _NEXT_STATE.get(target_state),
    }


def sign_bundle_lifecycle(
    path: str | Path,
    *,
    secret: str,
    key_id: str,
    state: str | None = None,
    actor: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Sign the current lifecycle metadata without changing lifecycle state."""

    if not secret:
        raise ValueError("bundle signing secret must be non-empty")
    if not key_id:
        raise ValueError("bundle key_id must be non-empty")
    if state is not None and state not in LIFECYCLE_STATES:
        raise ValueError(f"unknown policy bundle lifecycle state: {state}")

    bundle = load_bundle(path)
    lifecycle = _normalized_lifecycle(bundle.manifest.get(LIFECYCLE_FIELD))
    current_state = str(lifecycle["state"])
    target_state = state or current_state
    if target_state != current_state:
        raise ValueError("bundle sign does not change lifecycle state; use bundle promote")
    now = _utc_now()
    manifest = dict(bundle.manifest)
    history = _lifecycle_history(lifecycle)
    if not history:
        history.append(_history_event(target_state, now=now, actor=actor, note=note))
    manifest[LIFECYCLE_FIELD] = {
        "schema": LIFECYCLE_SCHEMA,
        "state": target_state,
        "updated_at": now,
        "history": history,
        **({"validation": lifecycle["validation"]} if "validation" in lifecycle else {}),
    }
    _write_manifest(bundle.root, manifest)

    signed_manifest = _sign_bundle_manifest(bundle.root, secret=secret, key_id=key_id, signed_at=now)
    _write_manifest(bundle.root, signed_manifest)
    signature = _normalized_lifecycle(signed_manifest[LIFECYCLE_FIELD])[LIFECYCLE_SIGNATURE_FIELD]
    return {
        "ok": True,
        "bundle": str(bundle.root),
        "state": target_state,
        "signature": _signature_summary(signature),
    }


def verify_bundle_lifecycle(
    path: str | Path,
    *,
    secrets: Mapping[str, str],
    required_state: str | None = None,
) -> dict[str, Any]:
    bundle = load_bundle(path)
    lifecycle = _normalized_lifecycle(bundle.manifest.get(LIFECYCLE_FIELD))
    state = str(lifecycle["state"])
    if required_state is not None and state != required_state:
        raise ValueError(f"policy bundle lifecycle state {state!r} does not match required {required_state!r}")

    signature = lifecycle.get(LIFECYCLE_SIGNATURE_FIELD)
    if not isinstance(signature, Mapping):
        raise ValueError("policy bundle lifecycle is missing signature")
    algorithm = signature.get("algorithm")
    if algorithm != LIFECYCLE_SIGNATURE_ALGORITHM:
        raise ValueError(f"unsupported policy bundle signature algorithm: {algorithm!r}")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("policy bundle signature key_id must be a non-empty string")
    secret = secrets.get(key_id)
    if not secret:
        raise ValueError(f"no secret configured for policy bundle key_id {key_id!r}")

    payload = _bundle_signature_payload(bundle.root, bundle.manifest)
    expected_digest = _payload_digest(payload)
    if signature.get("digest") != expected_digest:
        raise ValueError("policy bundle digest does not match payload")
    expected_signature = _sign_bytes(_canonical_json(payload), secret)
    actual_signature = signature.get("value")
    if not isinstance(actual_signature, str) or not hmac.compare_digest(actual_signature, expected_signature):
        raise ValueError("policy bundle signature verification failed")

    return {
        "ok": True,
        "bundle": str(bundle.root),
        "name": bundle.name,
        "version": bundle.version,
        "state": state,
        "digest": expected_digest,
        "algorithm": algorithm,
        "key_id": key_id,
        "signed_at": signature.get("signed_at"),
    }


def bundle_lifecycle_digest(path: str | Path) -> str:
    bundle = load_bundle(path)
    return _payload_digest(_bundle_signature_payload(bundle.root, bundle.manifest))


def _normalized_lifecycle(value: Any) -> dict[str, Any]:
    if value is None:
        return {"schema": LIFECYCLE_SCHEMA, "state": "observed", "history": []}
    if not isinstance(value, Mapping):
        raise ValueError(f"manifest field {LIFECYCLE_FIELD!r} must be an object")
    state = value.get("state")
    if state not in LIFECYCLE_STATES:
        raise ValueError(f"manifest field {LIFECYCLE_FIELD!r}.state must be one of {', '.join(LIFECYCLE_STATES)}")
    lifecycle = {str(key): item for key, item in value.items()}
    lifecycle.setdefault("schema", LIFECYCLE_SCHEMA)
    history = lifecycle.get("history", [])
    lifecycle["history"] = history if isinstance(history, list) else []
    return lifecycle


def _target_state(current_state: str, requested_state: str) -> str:
    if requested_state != "next" and requested_state not in LIFECYCLE_STATES:
        raise ValueError(f"unknown policy bundle lifecycle state: {requested_state}")
    next_state = _NEXT_STATE.get(current_state)
    if next_state is None:
        raise ValueError("policy bundle lifecycle is already active")
    target_state = next_state if requested_state == "next" else requested_state
    if target_state != next_state:
        raise ValueError(f"cannot move policy bundle lifecycle from {current_state!r} to {target_state!r}")
    return target_state


def _run_promotion_validation(
    path: Path,
    *,
    instruction_limit: int,
    memory_limit_bytes: int | None,
) -> dict[str, Any]:
    validation = validate_bundle(path)
    if not validation["ok"]:
        return {
            "ok": False,
            "validated_at": _utc_now(),
            "fixture_count": validation.get("fixture_count", 0),
            "errors": validation["errors"],
        }
    tests = test_bundle(path, instruction_limit=instruction_limit, memory_limit_bytes=memory_limit_bytes)
    return {
        "ok": bool(tests["ok"]),
        "validated_at": _utc_now(),
        "fixture_count": tests["fixture_count"],
        "passed": tests["passed"],
        "failed": tests["failed"],
        "errors": [],
        "test_failures": [
            {
                "name": result.get("name"),
                "request": result.get("request"),
                "failures": result.get("failures", []),
            }
            for result in tests.get("results", [])
            if not result.get("ok")
        ],
    }


def _sign_bundle_manifest(root: Path, *, secret: str, key_id: str, signed_at: str) -> dict[str, Any]:
    bundle = load_bundle(root)
    manifest = _manifest_without_lifecycle_signature(bundle.manifest)
    lifecycle = _normalized_lifecycle(manifest.get(LIFECYCLE_FIELD))
    manifest[LIFECYCLE_FIELD] = lifecycle
    payload = _bundle_signature_payload(root, manifest)
    digest = _payload_digest(payload)
    lifecycle[LIFECYCLE_SIGNATURE_FIELD] = {
        "algorithm": LIFECYCLE_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "digest": digest,
        "signed_at": signed_at,
        "value": _sign_bytes(_canonical_json(payload), secret),
    }
    return manifest


def _bundle_signature_payload(root: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": LIFECYCLE_DIGEST_SCHEMA,
        "manifest": _manifest_without_lifecycle_signature(manifest),
        "files": _bundle_file_digests(root),
    }


def _bundle_file_digests(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"policy bundle contains a symlink: {path.relative_to(root).as_posix()}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == MANIFEST_NAME:
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": relative,
                "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    return files


def _manifest_without_lifecycle_signature(manifest: Mapping[str, Any]) -> dict[str, Any]:
    unsigned = _json_copy(manifest)
    lifecycle = unsigned.get(LIFECYCLE_FIELD)
    if isinstance(lifecycle, dict):
        lifecycle.pop(LIFECYCLE_SIGNATURE_FIELD, None)
    return unsigned


def _payload_digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_bytes(value: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), value, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _write_manifest(root: Path, manifest: Mapping[str, Any]) -> None:
    (root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _lifecycle_history(lifecycle: Mapping[str, Any]) -> list[dict[str, Any]]:
    history = lifecycle.get("history", [])
    if not isinstance(history, list):
        return []
    return [_json_copy(event) for event in history if isinstance(event, Mapping)]


def _history_event(state: str, *, now: str, actor: str | None, note: str | None) -> dict[str, str]:
    event = {"state": state, "updated_at": now}
    if actor:
        event["actor"] = actor
    if note:
        event["note"] = note
    return event


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _signature_summary(signature: Any) -> dict[str, Any] | None:
    if not isinstance(signature, Mapping):
        return None
    return {str(key): signature[key] for key in ("algorithm", "key_id", "digest", "signed_at") if key in signature}


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


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


def _validate_lifecycle(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, Mapping):
        return [f"manifest field {LIFECYCLE_FIELD!r} must be an object"]

    errors: list[str] = []
    schema = value.get("schema")
    if schema is not None and schema != LIFECYCLE_SCHEMA:
        errors.append(f"manifest field {LIFECYCLE_FIELD!r}.schema must be {LIFECYCLE_SCHEMA!r}")
    state = value.get("state")
    if state not in LIFECYCLE_STATES:
        errors.append(f"manifest field {LIFECYCLE_FIELD!r}.state must be one of {', '.join(LIFECYCLE_STATES)}")
    history = value.get("history", [])
    if history is not None and not isinstance(history, list):
        errors.append(f"manifest field {LIFECYCLE_FIELD!r}.history must be a list")
    signature = value.get(LIFECYCLE_SIGNATURE_FIELD)
    if signature is not None:
        if not isinstance(signature, Mapping):
            errors.append(f"manifest field {LIFECYCLE_FIELD!r}.signature must be an object")
        else:
            if signature.get("algorithm") != LIFECYCLE_SIGNATURE_ALGORITHM:
                errors.append(
                    f"manifest field {LIFECYCLE_FIELD!r}.signature.algorithm must be {LIFECYCLE_SIGNATURE_ALGORITHM!r}"
                )
            if not isinstance(signature.get("key_id"), str) or not signature["key_id"]:
                errors.append(f"manifest field {LIFECYCLE_FIELD!r}.signature.key_id must be a non-empty string")
            if not isinstance(signature.get("digest"), str) or not str(signature["digest"]).startswith("sha256:"):
                errors.append(f"manifest field {LIFECYCLE_FIELD!r}.signature.digest must be a sha256 digest")
            if not isinstance(signature.get("value"), str) or not signature["value"]:
                errors.append(f"manifest field {LIFECYCLE_FIELD!r}.signature.value must be a non-empty string")
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

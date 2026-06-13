from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MANIFEST_SIGNATURE_FIELD = "snulbug_signature"
MANIFEST_ALGORITHM = "hmac-sha256"


def sign_upstream_manifest(
    manifest: Mapping[str, Any],
    *,
    secret: str,
    key_id: str,
) -> dict[str, Any]:
    """Return a signed upstream manifest using canonical JSON and HMAC-SHA256."""

    if not secret:
        raise ValueError("manifest signing secret must be non-empty")
    if not key_id:
        raise ValueError("manifest key_id must be non-empty")
    unsigned = _unsigned_manifest(manifest)
    digest = manifest_digest(unsigned)
    signature = _sign_bytes(_canonical_json(unsigned), secret)
    signed = dict(unsigned)
    signed[MANIFEST_SIGNATURE_FIELD] = {
        "algorithm": MANIFEST_ALGORITHM,
        "key_id": key_id,
        "digest": digest,
        "value": signature,
    }
    return signed


def verify_upstream_manifest(
    manifest: Mapping[str, Any],
    *,
    secrets: Mapping[str, str],
    expected_identity: str | None = None,
) -> dict[str, Any]:
    """Verify a signed upstream manifest and return a safe metadata summary."""

    unsigned = _unsigned_manifest(manifest)
    signature = manifest.get(MANIFEST_SIGNATURE_FIELD)
    if not isinstance(signature, Mapping):
        raise ValueError("upstream manifest is missing snulbug_signature")
    algorithm = signature.get("algorithm")
    if algorithm != MANIFEST_ALGORITHM:
        raise ValueError(f"unsupported upstream manifest signature algorithm: {algorithm!r}")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("upstream manifest signature key_id must be a non-empty string")
    secret = secrets.get(key_id)
    if not secret:
        raise ValueError(f"no secret configured for upstream manifest key_id {key_id!r}")
    expected_digest = manifest_digest(unsigned)
    if signature.get("digest") != expected_digest:
        raise ValueError("upstream manifest digest does not match payload")
    expected_signature = _sign_bytes(_canonical_json(unsigned), secret)
    actual_signature = signature.get("value")
    if not isinstance(actual_signature, str) or not hmac.compare_digest(actual_signature, expected_signature):
        raise ValueError("upstream manifest signature verification failed")

    identity = unsigned.get("identity")
    if expected_identity is not None and identity != expected_identity:
        raise ValueError(f"upstream manifest identity {identity!r} does not match expected {expected_identity!r}")
    tools = unsigned.get("tools", [])
    tool_count = len(tools) if isinstance(tools, list) else None
    labels = unsigned.get("labels")
    return _drop_empty(
        {
            "identity": identity,
            "digest": expected_digest,
            "algorithm": algorithm,
            "key_id": key_id,
            "schema": unsigned.get("schema"),
            "transport": unsigned.get("transport"),
            "tool_prefix": unsigned.get("tool_prefix"),
            "tool_count": tool_count,
            "labels": labels if isinstance(labels, Mapping) else None,
        }
    )


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(_unsigned_manifest(manifest))).hexdigest()


def load_manifest(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError("upstream manifest JSON must be an object")
    return value


def write_manifest(path: str | Path, manifest: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _unsigned_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in manifest.items() if key != MANIFEST_SIGNATURE_FIELD}


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_bytes(value: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), value, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}

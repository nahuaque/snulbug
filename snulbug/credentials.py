from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

CREDENTIAL_SOURCES = {"env", "file"}
CREDENTIAL_SCHEMES = {"bearer", "basic", "raw"}


class CredentialResolutionError(RuntimeError):
    """Raised when a configured credential reference cannot be resolved."""


def normalize_fabric_credentials(
    value: Any,
    *,
    base_dir: str | Path = ".",
) -> dict[str, dict[str, Any]]:
    """Normalize [mcp.fabric.credentials] without reading secret values."""

    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("mcp.fabric.credentials must be a table")

    base = Path(base_dir)
    credentials: dict[str, dict[str, Any]] = {}
    for credential_id, entry in value.items():
        if not isinstance(credential_id, str) or not credential_id.strip():
            raise ValueError("mcp.fabric.credentials keys must be non-empty strings")
        field = f"mcp.fabric.credentials.{credential_id}"
        if not isinstance(entry, Mapping):
            raise ValueError(f"{field} must be a table")
        credentials[credential_id] = _normalize_credential_entry(
            credential_id,
            entry,
            base_dir=base,
            field=field,
        )
    return credentials


def attach_upstream_credentials(
    proxy: Mapping[str, Any],
    credentials: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Attach resolved credential reference metadata to proxy upstream tables."""

    upstreams = proxy.get("upstreams")
    if not isinstance(upstreams, list) or not upstreams:
        return dict(proxy)

    attached = dict(proxy)
    normalized_upstreams = []
    for index, upstream in enumerate(upstreams):
        if not isinstance(upstream, Mapping):
            normalized_upstreams.append(upstream)
            continue
        item = dict(upstream)
        auth_ref = item.get("auth")
        credential_ref = item.get("credential")
        if auth_ref is None and isinstance(credential_ref, str):
            auth_ref = credential_ref
        if auth_ref is not None:
            if not isinstance(auth_ref, str) or not auth_ref:
                raise ValueError(f"mcp.proxy.upstreams[{index}].auth must be a non-empty credential id")
            credential = credentials.get(auth_ref)
            if credential is None:
                raise ValueError(
                    f"mcp.proxy.upstreams[{index}].auth references unknown mcp.fabric.credentials entry: {auth_ref!r}"
                )
            item["auth"] = auth_ref
            item["credential"] = dict(credential)
        normalized_upstreams.append(item)
    attached["upstreams"] = normalized_upstreams
    return attached


def normalize_upstream_credential(
    value: Any,
    *,
    field: str = "credential",
    base_dir: str | Path = ".",
    resolve_relative_paths: bool = False,
) -> dict[str, Any]:
    """Validate an already-attached upstream credential mapping."""

    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a credential table")
    credential_id = value.get("id")
    if not isinstance(credential_id, str) or not credential_id:
        raise ValueError(f"{field}.id must be a non-empty string")
    return _normalize_credential_entry(
        credential_id,
        value,
        base_dir=Path(base_dir),
        field=field,
        resolve_relative_paths=resolve_relative_paths,
    )


def credential_header(credential: Mapping[str, Any]) -> tuple[str, str]:
    """Resolve a credential reference into an HTTP header pair."""

    normalized = normalize_upstream_credential(credential)
    source_type = normalized["type"]
    if source_type == "env":
        env_name = normalized["env"]
        value = os.environ.get(env_name)
        if not value:
            raise CredentialResolutionError(f"environment variable {env_name!r} is not set")
    elif source_type == "file":
        path = Path(str(normalized["path"]))
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError as exc:
            raise CredentialResolutionError(f"credential file does not exist: {path}") from exc
        except OSError as exc:
            raise CredentialResolutionError(f"credential file cannot be read: {path}: {exc}") from exc
        if not value:
            raise CredentialResolutionError(f"credential file is empty: {path}")
    else:  # pragma: no cover - guarded by normalization.
        raise CredentialResolutionError(f"unsupported credential source: {source_type!r}")
    if "\r" in value or "\n" in value:
        raise CredentialResolutionError("credential value must be a single line")
    return normalized["header"], _format_secret(value, scheme=normalized["scheme"])


def apply_credential_header(
    headers: Mapping[str, str],
    credential: Mapping[str, Any] | None,
) -> dict[str, str]:
    """Return headers with the upstream credential header injected."""

    outgoing = dict(headers)
    if not credential:
        return outgoing
    header_name, header_value = credential_header(credential)
    lower_name = header_name.lower()
    outgoing = {name: value for name, value in outgoing.items() if name.lower() != lower_name}
    outgoing[header_name] = header_value
    return outgoing


def credential_metadata(credential: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return audit/status-safe metadata without secret values."""

    if not credential:
        return {}
    normalized = normalize_upstream_credential(credential)
    return _drop_empty(
        {
            "id": normalized.get("id"),
            "type": normalized.get("type"),
            "source": normalized.get("type"),
            "scheme": normalized.get("scheme"),
            "header": normalized.get("header"),
            "env": normalized.get("env") if normalized.get("type") == "env" else None,
            "path": normalized.get("path") if normalized.get("type") == "file" else None,
        }
    )


def credential_status(credential: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return safe availability status for a configured credential."""

    metadata = credential_metadata(credential)
    if not metadata:
        return {}
    try:
        credential_header(credential or {})
    except CredentialResolutionError as exc:
        return {**metadata, "configured": True, "available": False, "error": str(exc)}
    return {**metadata, "configured": True, "available": True}


def _normalize_credential_entry(
    credential_id: str,
    entry: Mapping[str, Any],
    *,
    base_dir: Path,
    field: str,
    resolve_relative_paths: bool = True,
) -> dict[str, Any]:
    source_type = entry.get("type", entry.get("source"))
    if source_type is None:
        if entry.get("env") is not None:
            source_type = "env"
        elif entry.get("path") is not None:
            source_type = "file"
    if source_type not in CREDENTIAL_SOURCES:
        raise ValueError(f"{field}.type must be 'env' or 'file'")

    scheme = entry.get("scheme", "bearer")
    if scheme not in CREDENTIAL_SCHEMES:
        raise ValueError(f"{field}.scheme must be 'bearer', 'basic', or 'raw'")
    header = entry.get("header", "Authorization")
    if not isinstance(header, str) or not _valid_header_name(header):
        raise ValueError(f"{field}.header must be a valid HTTP header name")

    normalized: dict[str, Any] = {
        "id": credential_id,
        "type": source_type,
        "scheme": scheme,
        "header": header,
    }
    if source_type == "env":
        env_name = entry.get("env")
        if not isinstance(env_name, str) or not env_name:
            raise ValueError(f"{field}.env must be a non-empty environment variable name")
        normalized["env"] = env_name
    else:
        path = entry.get("path")
        if not isinstance(path, str | Path) or not str(path):
            raise ValueError(f"{field}.path must be a non-empty file path")
        credential_path = Path(path)
        if resolve_relative_paths and not credential_path.is_absolute():
            credential_path = base_dir / credential_path
        normalized["path"] = str(credential_path)
    return normalized


def _format_secret(value: str, *, scheme: str) -> str:
    stripped = value.strip()
    if scheme == "raw":
        return stripped
    prefix = "Bearer" if scheme == "bearer" else "Basic"
    if stripped.lower().startswith(f"{prefix.lower()} "):
        return stripped
    return f"{prefix} {stripped}"


def _valid_header_name(value: str) -> bool:
    if not value:
        return False
    return all(33 <= ord(char) <= 126 and char != ":" for char in value)


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, "", [], {})}

"""Secret-free upstream credential checks for the existing share workflow."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .credentials import credential_metadata, credential_status
from .share_doctor import ShareDoctorCheck, ShareDoctorCheckResult, ShareDoctorContext


class ShareCredentialsDoctorCheck(ShareDoctorCheck):
    name = "credentials"
    component = "credentials"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        if context.proxy_config is None:
            return ShareDoctorCheckResult()
        result = inspect_upstream_credentials(context.proxy_config, live_checks=context.live_checks)
        return ShareDoctorCheckResult(
            checks=result["checks"],
            recommendations=result["recommendations"],
            artifacts={"upstream_credentials": result},
        )


def inspect_upstream_credentials(proxy: Mapping[str, Any], *, live_checks: bool = False) -> dict[str, Any]:
    """Inspect references; resolve sources only during an explicit live check."""

    references = _references(proxy)
    input_digest = _input_digest(proxy, references)
    items = []
    checks = []
    recommendations = []
    for index, (credential, upstreams) in enumerate(references):
        item = {**credential_metadata(credential), "upstreams": upstreams, "checked": live_checks}
        item["rotation"] = {
            "file": "Replace the file atomically; new requests read the replacement without a restart.",
            "env": (
                "Update the service environment and restart the gateway; shell exports cannot update a running service."
            ),
        }.get(str(item.get("type")), "Rotation and refresh are managed by the credential broker plugin.")
        if live_checks:
            item.update(credential_status(credential))
        else:
            item["available"] = None
        item["state"] = (
            "available"
            if item.get("available") is True
            else "unavailable"
            if item.get("available") is False
            else "unchecked"
        )
        checks.append(
            _check(
                f"credentials.{index}.available",
                "pass" if item.get("available") is True else "fail" if item.get("available") is False else "skip",
                "Credential source is locally available; upstream acceptance is not verified"
                if item.get("available") is True
                else str(item.get("error") or "Credential source was not resolved (live checks disabled)"),
                credential_id=item.get("id"),
                upstreams=upstreams,
                reason_code=item.get("reason_code"),
            )
        )
        if item.get("available") is False:
            recommendations.append(
                "Restore the referenced credential source, then run share doctor in the service environment."
            )
        warnings = []
        if item.get("type") == "file" and live_checks:
            revision = _file_revision(str(item["path"]))
            if revision and os.name == "posix":
                mode = stat.S_IMODE(revision["mode"])
                item["file_mode"] = f"{mode:04o}"
                if mode & 0o077:
                    warnings.append(
                        "Credential file grants group/other permissions; "
                        "prefer mode 0600 with a dedicated service account."
                    )
        insecure = [upstream["name"] for upstream in upstreams if _cleartext_remote(upstream)]
        if insecure:
            warnings.append(
                "Credential would be sent over non-loopback HTTP; use HTTPS or a deliberate private transport."
            )
        if any(upstream["transport"] == "stdio" for upstream in upstreams):
            warnings.append(
                "HTTP credential injection is not supported by the stdio transport; "
                "use its process environment instead."
            )
        item["warnings"] = warnings
        for warning_index, warning in enumerate(warnings):
            checks.append(
                _check(f"credentials.{index}.hygiene.{warning_index}", "warn", warning, credential_id=item.get("id"))
            )
            recommendations.append(warning)
        items.append(item)

    if references and _mapping(proxy.get("auth")).get("strip_authorization_upstream") is False:
        message = (
            "Client Authorization passthrough is enabled; "
            "terminate client auth and inject upstream-specific credentials."
        )
        checks.append(_check("credentials.client_passthrough", "warn", message))
        recommendations.append(message)
    summary = {
        "count": len(items),
        "available": sum(item.get("available") is True for item in items),
        "unavailable": sum(item.get("available") is False for item in items),
        "unchecked": sum(item.get("available") is None for item in items),
        "warnings": sum(check["status"] == "warn" for check in checks),
    }
    state = (
        "not_configured"
        if not items
        else "unchecked"
        if not live_checks
        else "unavailable"
        if summary["unavailable"]
        else "review"
        if summary["warnings"]
        else "available"
    )
    result = {
        "checked": live_checks,
        "checked_at": datetime.now(timezone.utc).isoformat() if live_checks else None,
        "checking_process_id": os.getpid() if live_checks else None,
        "availability_scope": "checking_process",
        "input_digest": input_digest,
        "state": state,
        "ok": not summary["unavailable"] if live_checks or not items else None,
        "summary": summary,
        "items": items,
        "checks": checks,
        "recommendations": list(dict.fromkeys(recommendations)),
    }
    if live_checks and input_digest != _input_digest(proxy, references):
        # A rotation during the check must not certify the uninspected replacement.
        result = inspect_upstream_credentials(proxy)
        result.update(state="stale", stale=True)
        result["checks"].append(
            _check(
                "credentials.changed_during_check",
                "warn",
                "Credential source changed during inspection; run doctor again",
            )
        )
    return result


def cached_upstream_credentials(saved: Mapping[str, Any], proxy: Mapping[str, Any]) -> dict[str, Any]:
    """Never resolve a secret during console refresh; invalidate changed sources."""

    current = inspect_upstream_credentials(proxy)
    if saved.get("checked") is True and saved.get("input_digest") == current["input_digest"]:
        return dict(saved)
    if saved.get("checked") is True and current["items"]:
        current.update(state="stale", stale=True, previous_checked_at=saved.get("checked_at"))
    return current


def _references(proxy: Mapping[str, Any]) -> list[tuple[Mapping[str, Any], list[dict[str, str]]]]:
    upstreams = proxy.get("upstreams") or [
        {"name": "default", "url": proxy.get("upstream"), "credential": proxy.get("upstream_credential")}
    ]
    grouped: dict[str, tuple[Mapping[str, Any], list[dict[str, str]]]] = {}
    for upstream in upstreams:
        credential = _mapping(upstream.get("credential"))
        if not credential:
            continue
        key = json.dumps(credential, sort_keys=True, default=str)
        if key not in grouped:
            grouped[key] = (credential, [])
        grouped[key][1].append(
            {
                "name": str(upstream.get("name") or "default"),
                "transport": str(upstream.get("transport") or "http"),
                # URLs can themselves contain credentials; retain only the origin.
                "origin": _origin(str(upstream.get("url") or "")),
            }
        )
    return list(grouped.values())


def _origin(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")


def _cleartext_remote(upstream: Mapping[str, str]) -> bool:
    parts = urlsplit(upstream["origin"])
    if parts.scheme != "http" or upstream["transport"] == "holepunch":
        return False
    if parts.hostname == "localhost":
        return False
    try:
        return not ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        return True


def _file_revision(path: str) -> dict[str, int] | None:
    try:
        info = Path(path).stat()
    except OSError:
        return None
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mtime": info.st_mtime_ns,
        "ctime": info.st_ctime_ns,
        "mode": info.st_mode,
    }


def _input_digest(proxy: Mapping[str, Any], references: list[tuple[Mapping[str, Any], list[dict[str, str]]]]) -> str:
    payload = {
        "strip_client_authorization": _mapping(proxy.get("auth")).get("strip_authorization_upstream"),
        "sources": [
            {
                "reference": credential_metadata(credential),
                "upstreams": upstreams,
                "file_revision": _file_revision(str(credential["path"])) if credential.get("type") == "file" else None,
            }
            for credential, upstreams in references
        ],
    }
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _check(check_id: str, status: str, message: str, **details: Any) -> dict[str, Any]:
    return {"id": check_id, "component": "credentials", "status": status, "message": message, "details": details}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}

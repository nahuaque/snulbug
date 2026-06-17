from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ShareDoctorContext:
    share_dir: Path
    manifest: Mapping[str, Any]
    session: Mapping[str, Any]
    client: Mapping[str, Any]
    config_path: Path
    provider: str
    url: str
    headers: Mapping[str, str]
    timeout: float
    live_checks: bool
    status: Mapping[str, Any]
    conformance_pack: str | Path | None = None
    require_conformance: bool = False
    proxy_config: Mapping[str, Any] | None = None
    fabric_config: Mapping[str, Any] | None = None
    state: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ShareDoctorCheckResult:
    checks: Sequence[Mapping[str, Any]] = ()
    recommendations: Sequence[str] = ()
    artifacts: Mapping[str, Any] = field(default_factory=dict)


class ShareDoctorCheck:
    """Extension point for share doctor and conformance readiness checks."""

    name = ""
    component = ""

    @property
    def normalized_name(self) -> str:
        return str(self.name).strip().lower()

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        del context
        return ShareDoctorCheckResult()


_SHARE_DOCTOR_CHECK_REGISTRY: dict[str, ShareDoctorCheck] = {}


def register_share_doctor_check(check: ShareDoctorCheck, *, replace: bool = False) -> ShareDoctorCheck:
    """Register a share doctor/conformance check plugin."""

    name = check.normalized_name
    if not name:
        raise ValueError("share doctor check name is required")
    if name in _SHARE_DOCTOR_CHECK_REGISTRY and not replace:
        raise ValueError(f"share doctor check already registered: {name}")
    _SHARE_DOCTOR_CHECK_REGISTRY[name] = check
    return check


def get_share_doctor_check(name: str) -> ShareDoctorCheck:
    normalized = str(name).strip().lower()
    try:
        return _SHARE_DOCTOR_CHECK_REGISTRY[normalized]
    except KeyError as exc:
        known = ", ".join(list_share_doctor_checks()) or "<none>"
        raise ValueError(f"unknown share doctor check {name!r}; known checks: {known}") from exc


def list_share_doctor_checks() -> tuple[str, ...]:
    return tuple(_SHARE_DOCTOR_CHECK_REGISTRY)


def run_share_doctor_checks(
    context: ShareDoctorContext,
    *,
    checks: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run registered share doctor checks and merge their standard outputs."""

    plugins = (
        [get_share_doctor_check(name) for name in checks]
        if checks is not None
        else list(_SHARE_DOCTOR_CHECK_REGISTRY.values())
    )
    all_checks: list[dict[str, Any]] = []
    recommendations: list[str] = []
    artifacts: dict[str, Any] = {}
    plugin_results: list[dict[str, Any]] = []
    for plugin in plugins:
        result = plugin.run(context)
        normalized_checks = [dict(item) for item in result.checks if isinstance(item, Mapping)]
        normalized_recommendations = [str(item) for item in result.recommendations if str(item)]
        normalized_artifacts = dict(result.artifacts)
        all_checks.extend(normalized_checks)
        recommendations.extend(normalized_recommendations)
        artifacts.update(normalized_artifacts)
        plugin_results.append(
            {
                "name": plugin.normalized_name,
                "component": plugin.component,
                "check_count": len(normalized_checks),
                "recommendation_count": len(normalized_recommendations),
                "artifacts": sorted(normalized_artifacts),
            }
        )
    return {
        "checks": all_checks,
        "recommendations": _unique_strings(recommendations),
        "artifacts": artifacts,
        "plugins": plugin_results,
    }


def _unique_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result

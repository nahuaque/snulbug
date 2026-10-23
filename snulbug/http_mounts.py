"""HTTP mount contract inspection through the existing share doctor workflow."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import httpx

from .http_routes import http_route_contract
from .public_origin import public_origin
from .share_doctor import ShareDoctorCheck, ShareDoctorCheckResult, ShareDoctorContext


class ShareHttpMountsDoctorCheck(ShareDoctorCheck):
    name = "http-mounts"
    component = "http-mounts"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        if context.proxy_config is None:
            return ShareDoctorCheckResult()
        result = inspect_http_mounts(context.proxy_config, live_checks=context.live_checks, timeout=context.timeout)
        return ShareDoctorCheckResult(
            checks=result["checks"], recommendations=result["recommendations"], artifacts={"http_mounts": result}
        )


def http_mount_contracts(proxy: Mapping[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [
            http_route_contract(
                route, timeout=float(proxy.get("timeout", 30.0)), public_url=proxy.get("tunnel_public_url")
            )
            for route in proxy.get("http_routes", [])
        ],
        key=lambda route: route["prefix"],
    )


def inspect_http_mounts(proxy: Mapping[str, Any], *, live_checks: bool = False, timeout: float = 5.0) -> dict[str, Any]:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("HTTP mount doctor timeout must be positive and finite")
    contracts = http_mount_contracts(proxy)
    items = []
    checks = []
    recommendations = []
    for index, contract in enumerate(contracts):
        prefix = contract["prefix"]

        def check(suffix: str, status: str, message: str) -> None:
            checks.append(
                {
                    "id": f"http_mounts.{index}.{suffix}",
                    "component": "http-mounts",
                    "status": status,
                    "message": message,
                    "details": {"prefix": prefix},
                }
            )

        declared = contract["auth"] != "undeclared"
        origin_message = (
            f"{prefix}: public origin is {contract['public_origin']}; Host uses "
            + ("the public authority" if contract["preserve_host"] else "the upstream authority")
            if contract["public_origin"]
            else f"{prefix}: public origin is not configured; forwarded URLs use the local request origin"
        )
        check("origin", "pass" if contract["public_origin"] else "warn", origin_message)
        check(
            "auth",
            "pass" if declared else "fail",
            f"{prefix}: declared auth owner is {contract['auth']}; application enforcement is not verified"
            if declared
            else f"{prefix}: declare auth = 'upstream' or 'public'; MCP authentication does not protect this mount",
        )
        if not declared:
            recommendations.append(f"Declare auth ownership for {prefix} in [[mcp.proxy.http_routes]] before sharing.")
        if contract["auth"] == "public":
            check(
                "public",
                "warn",
                f"{prefix}: explicitly public HTTP mount; no snulbug authentication or lease is required",
            )
            recommendations.append(
                f"Review public exposure of {prefix}; its access is independent of MCP invites and leases."
            )
        if contract["auth"] == "public" and (contract["forward_authorization"] or contract["forward_cookies"]):
            check("public_credentials", "warn", f"{prefix}: public mount explicitly forwards application credentials")
        health: dict[str, Any] = {"checked": False, "ok": None}
        if not contract["health_path"]:
            check("health", "warn", f"{prefix}: no dedicated backend health_path is configured")
        elif not live_checks:
            check("health", "skip", f"{prefix}: backend health check was not run (live checks disabled)")
        else:
            health = _probe_health(contract, timeout=timeout)
            check("health", "pass" if health["ok"] else "fail", f"{prefix}: {health['message']}")
        items.append({**contract, "health": health})
    result = {
        "input_digest": _digest(contracts),
        "items": items,
        "checks": checks,
        "recommendations": recommendations,
        "checked_at": datetime.now(timezone.utc).isoformat() if live_checks and contracts else None,
    }
    return _summarize(result)


def cached_http_mounts(saved: Mapping[str, Any], proxy: Mapping[str, Any]) -> dict[str, Any]:
    """Recheck static declarations, but never probe on status/console refresh."""

    current = inspect_http_mounts(proxy)
    if saved.get("input_digest") != current["input_digest"]:
        if saved.get("checked_at") and current["items"]:
            current["stale"] = True
        return current
    previous = {item["prefix"]: item for item in saved.get("items", [])}
    for item in current["items"]:
        health = previous.get(item["prefix"], {}).get("health", {})
        if health.get("checked") is True:
            item["health"] = dict(health)
    health_checks = {check["id"]: check for check in saved.get("checks", []) if check["id"].endswith(".health")}
    current["checks"] = [health_checks.get(check["id"], check) for check in current["checks"]]
    current["checked_at"] = saved.get("checked_at")
    return _summarize(current)


def _probe_health(contract: Mapping[str, Any], *, timeout: float) -> dict[str, Any]:
    # Only the declared origin/path, never a client URL or a redirect. Stream
    # headers and close immediately so arbitrary response bodies are not retained.
    target = httpx.URL(contract["upstream"]).copy_with(raw_path=contract["health_path"].encode("ascii"))
    result: dict[str, Any] = {
        "checked": True,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "ok": False,
        "status": None,
    }
    try:
        with httpx.Client(timeout=min(timeout, contract["timeout"]), trust_env=False, follow_redirects=False) as client:
            origin = public_origin(contract["public_origin"])
            headers = {"accept": "*/*"}
            if origin:
                headers.update({name.decode(): value.decode() for name, value in origin.headers()})
                headers["x-forwarded-prefix"] = contract["prefix"]
                if contract["preserve_host"]:
                    headers["host"] = origin.authority
            with client.stream("GET", target, headers=headers) as response:
                result["status"] = response.status_code
                result["ok"] = response.status_code == contract["health_status"]
                result["message"] = (
                    "backend health status matches the contract"
                    if result["ok"]
                    else "backend health status does not match the contract"
                )
    except (httpx.HTTPError, OSError):
        result["message"] = "backend health endpoint could not be reached"
    return result


def _summarize(result: dict[str, Any]) -> dict[str, Any]:
    result["summary"] = {
        "count": len(result["items"]),
        "passed": sum(check["status"] == "pass" for check in result["checks"]),
        "failed": sum(check["status"] == "fail" for check in result["checks"]),
        "warnings": sum(check["status"] == "warn" for check in result["checks"]),
        "skipped": sum(check["status"] == "skip" for check in result["checks"]),
    }
    result["ok"] = result["summary"]["failed"] == 0
    result["state"] = (
        "not_configured"
        if not result["items"]
        else "blocked"
        if not result["ok"]
        else "review"
        if result["summary"]["warnings"] or result["summary"]["skipped"]
        else "ready"
    )
    return result


def _digest(contracts: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(contracts, sort_keys=True).encode()).hexdigest()

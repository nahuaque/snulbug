"""Read-only comparison of desired, generated, and deployed ngrok policies."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .config import tomllib
from .credentials import CredentialResolutionError, credential_header, normalize_upstream_credential
from .share_doctor import ShareDoctorCheck, ShareDoctorCheckResult, ShareDoctorContext
from .share_runtime import tunnel_start_plan
from .tunnel import _ngrok_traffic_policy

_API = "https://api.ngrok.com"
_MAX_BYTES = 1_048_576
_PHASES = {"on_http_request", "on_http_response", "on_tcp_connect"}
_SAFE_KEYS = _PHASES | {
    "actions",
    "expressions",
    "type",
    "config",
    "headers",
    "url",
    "status_code",
    "body",
    "x-snulbug-tunnel-provider",
    "x-snulbug-traffic-policy",
    "x-snulbug-public-url",
    "x-snulbug-edge-client-ip",
    "x-snulbug-original-host",
    "x-snulbug-original-proto",
    "vars",
    "snulbug_original_host",
    "snulbug_original_proto",
}


class _InspectionError(ValueError):
    """Only fixed, secret-free diagnostic messages may cross this boundary."""


class _InspectionUnavailable(_InspectionError):
    pass


class ShareNgrokDoctorCheck(ShareDoctorCheck):
    name = "ngrok"
    component = "ngrok"

    def run(self, context: ShareDoctorContext) -> ShareDoctorCheckResult:
        if context.provider != "ngrok":
            return ShareDoctorCheckResult()
        checks: list[dict[str, Any]] = []
        recommendations: list[str] = []
        result: dict[str, Any] = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "cloud_checked": False,
            "state": "unchecked",
            "ok": None,
        }

        def check(name: str, status: str, message: str, **details: Any) -> None:
            checks.append(
                {"id": f"ngrok.{name}", "component": "ngrok", "status": status, "message": message, "details": details}
            )

        try:
            if context.proxy_config is None:
                raise _InspectionError("Load a valid snulbug proxy config before inspecting ngrok drift")
            plan = tunnel_start_plan(context.share_dir, config_path=context.config_path)
            result["input_digest"] = _input_digest(context.config_path, context.url, plan)
            internal = str(plan.get("internal_url") or "")
            if not internal or not urlsplit(internal).hostname or not urlsplit(internal).hostname.endswith(".internal"):
                raise _InspectionError("The share has no valid ngrok internal endpoint target")
            origin = _public_origin(context.url)
            mcp_path = str(context.proxy_config.get("streamable_http_endpoint_path") or "/mcp")
            configured_url = context.proxy_config.get("tunnel_public_url")
            desired_origin = _public_origin(configured_url) if configured_url else origin
            if configured_url:
                consistent = desired_origin == origin and (urlsplit(configured_url).path or mcp_path) == mcp_path
                check(
                    "public_url",
                    "pass" if consistent else "fail",
                    "Configured public URL matches the share"
                    if consistent
                    else "Configured public URL differs from the share; reconcile TOML and client URLs",
                )
            check(
                "mcp_path",
                "pass" if urlsplit(context.url).path == mcp_path else "fail",
                "Share URL path matches the configured MCP endpoint"
                if urlsplit(context.url).path == mcp_path
                else "Share URL path differs from the configured MCP endpoint",
            )
            auth = context.proxy_config.get("auth") or {}
            metadata_url = auth.get("resource_metadata_url") or "/.well-known/oauth-protected-resource"
            metadata_path = urlsplit(metadata_url).path
            desired_source = _ngrok_traffic_policy(
                desired_origin + mcp_path,
                internal_url=internal,
                http_routes=context.proxy_config.get("http_routes", []),
                auth_mode=str(auth.get("mode") or "bearer"),
                resource_metadata_path=metadata_path,
            )
            desired = parse_traffic_policy(desired_source)
            result["desired_digest"] = _digest(desired)
            result["desired_policy"] = desired_source
            result["route_prefixes"] = [route["prefix"] for route in context.proxy_config.get("http_routes", [])]
            local_path = plan.get("traffic_policy")
            if local_path and Path(local_path).is_file():
                try:
                    local = parse_traffic_policy(_bounded_file(Path(local_path)))
                    result["local"] = compare_traffic_policies(desired, local)
                    matched = result["local"]["matches"]
                    check(
                        "local_policy",
                        "pass" if matched else "fail",
                        "Generated policy matches current snulbug configuration"
                        if matched
                        else "Generated policy differs from current snulbug configuration; review the desired baseline",
                        **result["local"],
                    )
                except (OSError, _InspectionError):
                    check("local_policy", "fail", "Generated policy could not be parsed safely")
            else:
                check("local_policy", "fail", "Generated ngrok Traffic Policy file is missing")

            if not context.live_checks:
                check("cloud_policy", "skip", "Cloud inspection was not run (live checks disabled)")
            else:
                settings = _settings(context.config_path)
                credential = settings.get("api_credential", {"type": "env", "env": "NGROK_API_KEY"})
                if not isinstance(credential, Mapping):
                    raise _InspectionError("mcp.ngrok.api_credential must be a credential reference table")
                try:
                    reference = normalize_upstream_credential(
                        {**credential, "id": "ngrok-api", "scheme": "bearer", "header": "Authorization"},
                        base_dir=context.config_path.parent,
                        resolve_relative_paths=True,
                    )
                    header, token = credential_header(reference)
                except CredentialResolutionError:
                    check("cloud_policy", "warn", "ngrok API credential unavailable; deployed policy is unchecked")
                    recommendations.append(
                        "Provide NGROK_API_KEY (an API key, not the agent authtoken), or configure "
                        "[mcp.ngrok.api_credential], then run share doctor with live checks."
                    )
                except (ValueError, OSError):
                    raise _InspectionError("Invalid ngrok API credential reference") from None
                else:
                    endpoint = _get_endpoint(origin, settings.get("endpoint_id"), {header: token}, context.timeout)
                    result["cloud_checked"] = True
                    endpoint_matches = (
                        _public_origin(str(endpoint.get("url") or endpoint.get("public_url") or "")) == origin
                    )
                    check(
                        "endpoint_url",
                        "pass" if endpoint_matches else "fail",
                        "Endpoint public origin matches the share"
                        if endpoint_matches
                        else "Configured endpoint public origin does not match the share",
                    )
                    cloud = endpoint.get("type") == "cloud"
                    check(
                        "endpoint_type",
                        "pass" if cloud else "fail",
                        "Endpoint is a Cloud Endpoint" if cloud else "Expected a Cloud Endpoint, not an Agent Endpoint",
                    )
                    public = endpoint.get("bindings") == ["public"]
                    check(
                        "endpoint_binding",
                        "pass" if public else "fail",
                        "Endpoint has public binding"
                        if public
                        else "Endpoint bindings differ from the expected public binding",
                    )
                    deployed = parse_traffic_policy(endpoint.get("traffic_policy"))
                    result["deployed"] = compare_traffic_policies(desired, deployed)
                    matched = result["deployed"]["matches"]
                    check(
                        "cloud_policy",
                        "pass" if matched else "fail",
                        "Deployed policy matches the desired baseline"
                        if matched
                        else "Deployed policy differs structurally from the desired baseline; review it in ngrok",
                        **result["deployed"],
                    )
        except _InspectionUnavailable as exc:
            check("inspection", "warn", str(exc))
        except _InspectionError as exc:
            check("inspection", "fail", str(exc))
        except Exception:
            check("inspection", "warn", "ngrok inspection unavailable; no cloud policy match has been established")

        failed = any(item["status"] == "fail" for item in checks)
        cloud_match = any(item["id"] == "ngrok.cloud_policy" and item["status"] == "pass" for item in checks)
        result.update(
            {
                "state": (
                    "drifted"
                    if any(item["status"] == "fail" and item["id"] != "ngrok.inspection" for item in checks)
                    else "unavailable"
                )
                if failed
                else ("matched" if cloud_match else "unchecked"),
                "ok": False if failed else (True if cloud_match else None),
                "checks": checks,
            }
        )
        if failed:
            recommendations.append(
                "Review the desired baseline against your custom rules. Update the generated file "
                "and Cloud Endpoint policy manually, then rerun share doctor; snulbug never applies cloud changes."
            )
        result["recommendations"] = recommendations
        return ShareDoctorCheckResult(checks=checks, recommendations=recommendations, artifacts={"ngrok": result})


def cached_ngrok_inspection(
    saved: Mapping[str, Any],
    *,
    directory: Path,
    config_path: Path,
    public_url: str,
) -> dict[str, Any]:
    """Invalidate saved success on local edits, without resolving secrets or using the network."""
    if not saved:
        return {}
    try:
        plan = tunnel_start_plan(directory, config_path=config_path)
        if saved.get("input_digest") == _input_digest(config_path, public_url, plan):
            return dict(saved)
    except (OSError, ValueError):
        pass
    return {
        "state": "stale",
        "ok": None,
        "cloud_checked": False,
        "checked_at": saved.get("checked_at"),
        "checks": [],
        "recommendations": ["Local ngrok inputs changed; rerun share doctor to inspect current state."],
    }


def _input_digest(config_path: Path, public_url: str, plan: Mapping[str, Any]) -> str:
    policy_path = plan.get("traffic_policy")
    policy = _bounded_file(Path(policy_path)) if policy_path and Path(policy_path).is_file() else None
    return _digest(
        {
            "config": _bounded_file(config_path),
            "url": public_url,
            "internal_url": plan.get("internal_url"),
            "policy": policy,
        }
    )


def _settings(path: Path) -> Mapping[str, Any]:
    settings = tomllib.loads(_bounded_file(path)).get("mcp", {}).get("ngrok", {})
    if not isinstance(settings, Mapping):
        raise _InspectionError("mcp.ngrok must be a table")
    return settings


def _bounded_file(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise _InspectionError("Inspection input exceeds the 1 MiB limit")
    return data.decode("utf-8")


def _public_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise _InspectionError("ngrok inspection requires an HTTPS public URL without credentials, query, or fragment")
    port = parsed.port
    return f"https://{parsed.hostname.lower()}" + (f":{port}" if port and port != 443 else "")


def _get_endpoint(origin: str, endpoint_id: Any, headers: Mapping[str, str], timeout: float) -> Mapping[str, Any]:
    if endpoint_id is not None and (
        not isinstance(endpoint_id, str) or not re.fullmatch(r"ep_[A-Za-z0-9]+", endpoint_id)
    ):
        raise _InspectionError("mcp.ngrok.endpoint_id must be an ngrok endpoint ID")
    deadline = time.monotonic() + max(0.1, timeout)
    path = f"/endpoints/{endpoint_id}" if endpoint_id else "/endpoints?limit=100"
    seen: set[str] = set()
    matches: list[Mapping[str, Any]] = []
    with httpx.Client(headers={**headers, "Ngrok-Version": "2"}, follow_redirects=False, trust_env=False) as client:
        for _ in range(20):
            if path in seen or time.monotonic() >= deadline:
                raise _InspectionError("ngrok endpoint lookup exceeded its time or pagination limit")
            seen.add(path)
            with client.stream("GET", _API + path, timeout=max(0.1, deadline - time.monotonic())) as response:
                if response.status_code != 200:
                    # Never expose an API error body or exception containing credentials.
                    raise _InspectionError(
                        f"ngrok API returned HTTP {response.status_code}; deployed policy is unchecked"
                    )
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > _MAX_BYTES or time.monotonic() >= deadline:
                        raise _InspectionError("ngrok response exceeded the size or time limit")
                payload = json.loads(data)
            if not isinstance(payload, Mapping):
                raise _InspectionError("ngrok API returned an invalid endpoint response")
            if endpoint_id:
                return payload
            endpoints = payload.get("endpoints")
            if not isinstance(endpoints, list) or len(endpoints) > 100:
                raise _InspectionError("ngrok API returned an invalid endpoint list")
            for endpoint in endpoints:
                if not isinstance(endpoint, Mapping):
                    raise _InspectionError("ngrok API returned an invalid endpoint list entry")
                try:
                    if _public_origin(str(endpoint.get("url") or endpoint.get("public_url") or "")) == origin:
                        matches.append(endpoint)
                except _InspectionError:
                    continue
            next_page = payload.get("next_page_uri")
            if not next_page:
                if len(matches) != 1:
                    raise _InspectionError(
                        "Expected exactly one matching active endpoint; configure mcp.ngrok.endpoint_id to disambiguate"
                    )
                return matches[0]
            if not isinstance(next_page, str):
                raise _InspectionError("ngrok pagination link is invalid")
            page = urlsplit(next_page)
            if (page.scheme or page.netloc) and (page.scheme != "https" or page.netloc != "api.ngrok.com"):
                raise _InspectionError("ngrok pagination link points outside the API origin")
            if page.path != "/endpoints" or page.fragment or page.username or page.password:
                raise _InspectionError("ngrok pagination link is invalid")
            path = page.path + ("?" + page.query if page.query else "")
    raise _InspectionError("ngrok endpoint lookup exceeded its pagination limit")


def parse_traffic_policy(source: Any) -> dict[str, Any]:
    """Parse bounded JSON/YAML; rule names are cosmetic, execution order is not."""
    if not isinstance(source, str) or len(source.encode("utf-8")) > _MAX_BYTES:
        raise _InspectionError("Traffic Policy must be a JSON/YAML string of at most 1 MiB")
    try:
        import yaml
    except ImportError:
        raise _InspectionUnavailable("Install snulbug[discovery] for safe YAML Traffic Policy inspection") from None

    class PolicyLoader(yaml.SafeLoader):
        depth = 0
        nodes = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            self.nodes += 1
            self.depth += 1
            try:
                if self.depth > 32 or self.nodes > 20_000 or self.check_event(yaml.AliasEvent):
                    raise _InspectionError("Traffic Policy nesting, alias, or node limit exceeded")
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
            mapping: dict[str, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str) or key in mapping:
                    raise _InspectionError("Traffic Policy contains invalid or duplicate keys")
                mapping[key] = self.construct_object(value_node, deep=deep)
            return mapping

    try:
        value = yaml.load(source, Loader=PolicyLoader)  # noqa: S506 - bounded SafeLoader subclass
        if not isinstance(value, dict):
            raise _InspectionError("Traffic Policy must be an object")
        for phase in _PHASES & value.keys():
            if not isinstance(value[phase], list) or any(not isinstance(rule, dict) for rule in value[phase]):
                raise _InspectionError("Traffic Policy phases must contain rule lists")
            for rule in value[phase]:
                rule.pop("name", None)
        # Enforce JSON-compatible values (reject YAML timestamps, binary, NaN, etc.).
        json.dumps(value, allow_nan=False)
        return value
    except (yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, _InspectionError):
            raise
        raise _InspectionError("Traffic Policy could not be parsed safely") from None


def _digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def compare_traffic_policies(desired: Mapping[str, Any], actual: Mapping[str, Any]) -> dict[str, Any]:
    differences: list[dict[str, str]] = []

    def walk(left: Any, right: Any, path: str) -> None:
        if len(differences) >= 100:
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(left.keys() | right.keys()):
                child = path + "/" + (key if key in _SAFE_KEYS else "<field>")
                if key not in left or key not in right:
                    differences.append({"path": child, "change": "added" if key not in left else "removed"})
                else:
                    walk(left[key], right[key], child)
        elif isinstance(left, list) and isinstance(right, list):
            for index in range(max(len(left), len(right))):
                if index >= len(left) or index >= len(right):
                    differences.append(
                        {"path": f"{path}/{index}", "change": "added" if index >= len(left) else "removed"}
                    )
                else:
                    walk(left[index], right[index], f"{path}/{index}")
                if len(differences) >= 100:
                    break
        elif type(left) is not type(right) or left != right:
            differences.append({"path": path or "/", "change": "changed"})

    walk(dict(desired), dict(actual), "")
    return {"matches": not differences, "digest": _digest(actual), "differences": differences[:100]}

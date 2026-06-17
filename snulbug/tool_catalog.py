from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

CATALOG_PROJECTION_MODES = ("off", "policy-aware")


@dataclass(frozen=True)
class CatalogProjectionConfig:
    """Controls for projecting MCP tools/list responses."""

    projection: str = "off"

    @property
    def enabled(self) -> bool:
        return self.projection == "policy-aware"

    def __post_init__(self) -> None:
        if self.projection not in CATALOG_PROJECTION_MODES:
            raise ValueError("catalog projection must be 'off' or 'policy-aware'")


def project_mcp_tool_catalog_response(
    response: Mapping[str, Any],
    *,
    request: Mapping[str, Any] | None,
    config: CatalogProjectionConfig,
    auth_context: Mapping[str, Any] | None = None,
    auth_config: Mapping[str, Any] | None = None,
    lease: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Filter a tools/list response to tools the caller can plausibly invoke."""

    method = request.get("method") if isinstance(request, Mapping) else None
    metadata: dict[str, Any] = {
        "enabled": config.enabled,
        "projection": config.projection,
        "method": method,
    }
    if not config.enabled or method != "tools/list" or not _is_success_response(response):
        return dict(response), metadata

    payload, parse_error = _decode_json(_response_body(response))
    if parse_error is not None:
        metadata["json_error"] = parse_error
        return dict(response), metadata

    tools = _tools_from_response(payload)
    if tools is None:
        metadata["checked"] = False
        return dict(response), metadata

    auth = auth_context if isinstance(auth_context, Mapping) else {}
    auth_policy = auth_config if isinstance(auth_config, Mapping) else {}
    lease_metadata = lease if isinstance(lease, Mapping) else {}
    visible_tools = []
    hidden = []
    for tool in tools:
        if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
            visible_tools.append(tool)
            continue
        decision = _tool_visibility_decision(
            str(tool["name"]),
            auth_context=auth,
            auth_config=auth_policy,
            lease=lease_metadata,
        )
        if decision["visible"]:
            visible_tools.append(tool)
        else:
            hidden.append({"name": tool["name"], **_drop_empty({"reason_code": decision.get("reason_code")})})

    hidden_reason_counts = Counter(str(item.get("reason_code") or "catalog.hidden") for item in hidden)
    metadata.update(
        {
            "checked": True,
            "original_tool_count": len(tools),
            "visible_tool_count": len(visible_tools),
            "hidden_tool_count": len(hidden),
            "hidden_reason_counts": dict(sorted(hidden_reason_counts.items())),
            "hidden_tools": hidden[:20],
            "gates": _projection_gates(auth_context=auth, auth_config=auth_policy, lease=lease_metadata),
        }
    )
    if len(hidden) > 20:
        metadata["hidden_tools_truncated"] = len(hidden) - 20

    if len(visible_tools) == len(tools):
        return dict(response), metadata
    return _replace_tools_response(response, payload, visible_tools), metadata


def _tool_visibility_decision(
    tool_name: str,
    *,
    auth_context: Mapping[str, Any],
    auth_config: Mapping[str, Any],
    lease: Mapping[str, Any],
) -> dict[str, Any]:
    scope_decision = _scope_map_tool_decision(tool_name, auth_context)
    if scope_decision.get("visible") is False:
        return scope_decision
    claim_decision = _claim_policy_tool_decision(tool_name, auth_context=auth_context, auth_config=auth_config)
    if claim_decision.get("visible") is False:
        return claim_decision
    lease_decision = _lease_tool_decision(tool_name, lease)
    if lease_decision.get("visible") is False:
        return lease_decision
    return {"visible": True}


def _scope_map_tool_decision(tool_name: str, auth_context: Mapping[str, Any]) -> dict[str, Any]:
    scope_map = auth_context.get("scope_map")
    if not isinstance(scope_map, Mapping) or not scope_map:
        return {"visible": True}
    scopes = _sequence_strings(auth_context.get("scopes"))
    selectors = (f"tools/call:{tool_name}", "tools/call")
    for scope in scopes:
        configured_selectors = scope_map.get(scope)
        if not isinstance(configured_selectors, Sequence) or isinstance(configured_selectors, str | bytes | bytearray):
            continue
        for configured in configured_selectors:
            for selector in selectors:
                if _selector_matches(str(configured), selector):
                    return {
                        "visible": True,
                        "matched_scope": scope,
                        "matched_selector": str(configured),
                        "matched_request_selector": selector,
                    }
    return {"visible": False, "reason_code": "oauth.scope_map_denied"}


def _claim_policy_tool_decision(
    tool_name: str,
    *,
    auth_context: Mapping[str, Any],
    auth_config: Mapping[str, Any],
) -> dict[str, Any]:
    policy = _active_claim_policy(auth_context=auth_context, auth_config=auth_config)
    if not isinstance(policy, Mapping) or policy.get("enabled") is not True:
        return {"visible": True}
    selectors = (f"tools/call:{tool_name}", "tools/call")
    for rule in _claim_policy_rules(policy):
        claim_values = _claim_values(auth_context, str(rule.get("claim")))
        if not _matching_claim_values(claim_values, _sequence_strings(rule.get("values"))):
            continue
        if _claim_rule_allows_tool(rule, tool_name=tool_name, selectors=selectors):
            return {"visible": True}
    if policy.get("default_action") == "allow":
        return {"visible": True}
    return {"visible": False, "reason_code": "oauth.claim_policy_denied"}


def _active_claim_policy(
    *,
    auth_context: Mapping[str, Any],
    auth_config: Mapping[str, Any],
) -> Mapping[str, Any]:
    profile_id = auth_context.get("profile_id")
    profiles = auth_config.get("profiles")
    if isinstance(profile_id, str) and isinstance(profiles, Mapping):
        profile = profiles.get(profile_id)
        if isinstance(profile, Mapping) and isinstance(profile.get("claim_policy"), Mapping):
            return profile["claim_policy"]
    policy = auth_config.get("claim_policy")
    return policy if isinstance(policy, Mapping) else {}


def _lease_tool_decision(tool_name: str, lease: Mapping[str, Any]) -> dict[str, Any]:
    if lease.get("enabled") is not True:
        return {"visible": True}
    if lease.get("catalog_checked") is not True:
        if lease.get("required") is True:
            return {"visible": False, "reason_code": str(lease.get("reason_code") or "lease.missing")}
        return {"visible": True}
    if lease.get("allowed") is not True:
        return {"visible": False, "reason_code": str(lease.get("reason_code") or "lease.rejected")}
    allow_tools = _sequence_strings(lease.get("allow_tools"))
    if "*" in allow_tools or tool_name in allow_tools:
        return {"visible": True}
    return {"visible": False, "reason_code": "lease.tool_not_allowed"}


def _projection_gates(
    *,
    auth_context: Mapping[str, Any],
    auth_config: Mapping[str, Any],
    lease: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "scope_map": bool(isinstance(auth_context.get("scope_map"), Mapping) and auth_context.get("scope_map")),
        "claim_policy": bool(
            _active_claim_policy(auth_context=auth_context, auth_config=auth_config).get("enabled") is True
        ),
        "lease": bool(lease.get("enabled") is True),
    }


def _claim_policy_rules(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rules = policy.get("rules")
    if isinstance(rules, Sequence) and not isinstance(rules, str | bytes | bytearray):
        return [rule for rule in rules if isinstance(rule, Mapping)]
    return []


def _claim_values(claims: Mapping[str, Any], claim: str) -> list[str]:
    if claim == "tenant":
        return _sequence_strings(claims.get("tenant", claims.get("tid")))
    if claim == "subject":
        return _sequence_strings(claims.get("subject", claims.get("sub")))
    if claim == "client_id":
        return _sequence_strings(claims.get("client_id", claims.get("azp")))
    if claim == "scope":
        return _sequence_strings(claims.get("scopes"))
    if claim in claims:
        return _sequence_strings(claims.get(claim))
    value: Any = claims
    for part in claim.split("."):
        if not isinstance(value, Mapping):
            return []
        value = value.get(part)
    return _sequence_strings(value)


def _matching_claim_values(actual: Sequence[str], expected: Sequence[str]) -> list[str]:
    if "*" in expected:
        return sorted(set(actual))
    expected_set = set(expected)
    return sorted({value for value in actual if value in expected_set})


def _claim_rule_allows_tool(rule: Mapping[str, Any], *, tool_name: str, selectors: Sequence[str]) -> bool:
    for allowed_tool in _sequence_strings(rule.get("allow_tools")):
        if allowed_tool == "*" or allowed_tool == tool_name:
            return True
    for prefix in _sequence_strings(rule.get("allow_tool_prefixes")):
        if tool_name.startswith(prefix):
            return True
    for allowed_selector in _sequence_strings(rule.get("allow_selectors")):
        if any(_selector_matches(allowed_selector, selector) for selector in selectors):
            return True
    return False


def _tools_from_response(payload: Any) -> list[Any] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return None
    tools = result.get("tools")
    return tools if isinstance(tools, list) else None


def _replace_tools_response(response: Mapping[str, Any], payload: Any, tools: Sequence[Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return dict(response)
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return dict(response)
    updated_payload = dict(payload)
    updated_result = dict(result)
    updated_result["tools"] = list(tools)
    updated_payload["result"] = updated_result
    body = json.dumps(updated_payload, separators=(",", ":")).encode("utf-8")
    return {
        **dict(response),
        "headers": _replace_content_length(response.get("headers", []), len(body)),
        "body": body,
    }


def _decode_json(body: bytes) -> tuple[Any, str | None]:
    try:
        return json.loads(body.decode("utf-8")), None
    except UnicodeDecodeError as exc:
        return None, f"invalid UTF-8: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc}"


def _response_body(response: Mapping[str, Any]) -> bytes:
    body = response.get("body", b"")
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _is_success_response(response: Mapping[str, Any]) -> bool:
    status = int(response.get("status", 0))
    return 200 <= status < 300


def _replace_content_length(headers: Any, length: int) -> list[tuple[bytes, bytes]]:
    result: list[tuple[bytes, bytes]] = []
    if isinstance(headers, Sequence) and not isinstance(headers, str | bytes | bytearray):
        for pair in headers:
            if not isinstance(pair, Sequence) or isinstance(pair, str | bytes | bytearray) or len(pair) != 2:
                continue
            name = _header_bytes(pair[0])
            if name.lower() == b"content-length":
                continue
            result.append((name, _header_bytes(pair[1])))
    result.append((b"content-length", str(length).encode("ascii")))
    return result


def _header_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("latin-1")


def _selector_matches(configured: str, requested: str) -> bool:
    if configured == requested or configured == "*":
        return True
    if configured.endswith("*"):
        return requested.startswith(configured[:-1])
    return False


def _sequence_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}

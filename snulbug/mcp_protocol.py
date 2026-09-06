"""Version-specific MCP wire conventions and implementation coverage.

Recognizing a revision is deliberately separate from implementing all of it.
The modern profile exposes bounded request-scoped JSON/SSE dispatch; the legacy default stays
in place while modern interoperability and conformance remain incomplete.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .mcp_mrtr import continuation_issue, input_required_issue
from .mcp_subscriptions import LISTEN, matching_id
from .mcp_subscriptions import request_issue as subscription_request_issue

DEFAULT_MCP_PROTOCOL_VERSION = "2025-11-25"
LATEST_MCP_SPEC_VERSION = "2026-07-28"
PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_META = "io.modelcontextprotocol/clientInfo"
SERVER_INFO_META = "io.modelcontextprotocol/serverInfo"
IMPLEMENTATION_META = "io.snulbug/implementation"
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_REQUEST_METHODS = frozenset(
    {
        "server/discover",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        LISTEN,
    }
)
NAMED_METHOD_FIELDS = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}


@dataclass(frozen=True)
class McpProtocolProfile:
    version: str
    era: str
    discovery_method: str
    implementation: str

    @property
    def modern(self) -> bool:
        return self.era == "modern"


PROTOCOL_PROFILES = (
    McpProtocolProfile("2025-03-26", "legacy", "initialize", "untested"),
    McpProtocolProfile("2025-06-18", "legacy", "initialize", "untested"),
    McpProtocolProfile(DEFAULT_MCP_PROTOCOL_VERSION, "legacy", "initialize", "legacy"),
    McpProtocolProfile(LATEST_MCP_SPEC_VERSION, "modern", "server/discover", "request-stream-preview"),
)


def protocol_profile(version: str) -> McpProtocolProfile:
    for profile in PROTOCOL_PROFILES:
        if profile.version == version:
            return profile
    raise ValueError(f"Unknown MCP protocol version: {version}")


def protocol_coverage(version: str) -> dict[str, Any]:
    profile = protocol_profile(version)
    if profile.modern:
        requirements = (
            ("discovery.envelope", "supported"),
            ("server.discover", "supported"),
            ("requests.dispatch", "supported"),
            ("headers.schema_parameters", "supported"),
            ("transport.streaming", "supported"),
            ("requests.multi_round_trip", "supported"),
            ("subscriptions.listen", "supported"),
            ("subscriptions.stdio", "supported"),
            ("schemas.json_schema_2020_12", "supported"),
            ("results.cache_hints", "supported"),
            ("auth.interoperability", "untested"),
        )
    else:
        requirements = (
            ("transport.edge_checks", "supported" if profile.implementation == "legacy" else "untested"),
            ("transport.streaming", "unsupported"),
            ("lifecycle.end_to_end", "untested"),
        )
    return {
        "version": version,
        "era": profile.era,
        "implementation": profile.implementation,
        "complete": False,
        "requirements": [{"id": name, "support": support} for name, support in requirements],
    }


def mcp_request(
    method: str,
    *,
    version: str = DEFAULT_MCP_PROTOCOL_VERSION,
    request_id: str | int,
    params: Mapping[str, Any] | None = None,
    client_name: str = "snulbug",
) -> dict[str, Any]:
    profile = protocol_profile(version)
    parameters = dict(params or {})
    if profile.modern:
        if method == "initialize":
            raise ValueError("MCP 2026-07-28 uses server/discover instead of initialize")
        parameters["_meta"] = {
            **parameters.get("_meta", {}),
            PROTOCOL_VERSION_META: version,
            CLIENT_CAPABILITIES_META: {},
            CLIENT_INFO_META: {"name": client_name, "version": _package_version()},
        }
    elif method == "initialize":
        parameters.update(
            protocolVersion=version,
            capabilities={},
            clientInfo={"name": client_name, "version": _package_version()},
        )
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": parameters}


def discovery_request(version: str) -> dict[str, Any]:
    return mcp_request(
        protocol_profile(version).discovery_method,
        version=version,
        request_id="snulbug-protocol-discovery",
    )


def discovery_result(version: str) -> dict[str, Any]:
    """Describe this gateway, without copying an upstream's unsupported claims."""
    return {
        "resultType": "complete",
        "supportedVersions": [version],
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}, "completions": {}},
        "_meta": {
            SERVER_INFO_META: {"name": "snulbug", "version": _package_version()},
            IMPLEMENTATION_META: protocol_coverage(version),
        },
        "ttlMs": 0,
        "cacheScope": "private",
    }


def discovery_issues(payload: Any, *, version: str, request_id: str | int) -> list[str]:
    """Validate a discovery reply without accepting a generic HTTP 200 as proof."""
    if (
        not isinstance(payload, Mapping)
        or payload.get("jsonrpc") != "2.0"
        or type(payload.get("id")) is not type(request_id)
        or payload.get("id") != request_id
    ):
        return ["discovery response must be JSON-RPC 2.0 with the matching request id"]
    if "error" in payload:
        return ["server returned a JSON-RPC error for discovery"]
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return ["discovery response is missing result"]
    issues = []
    if not isinstance(result.get("capabilities"), Mapping):
        issues.append("discovery result is missing capabilities")
    if protocol_profile(version).modern:
        versions = result.get("supportedVersions")
        if not isinstance(versions, list) or not versions or not all(isinstance(v, str) and v for v in versions):
            issues.append("discovery result requires supportedVersions")
        elif version not in versions:
            issues.append("discovery result does not advertise the requested version")
        if result.get("resultType") != "complete":
            issues.append("discovery resultType must be complete")
        ttl = result.get("ttlMs")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
            issues.append("discovery ttlMs must be a non-negative integer")
        if result.get("cacheScope") not in ("private", "public"):
            issues.append("discovery cacheScope must be private or public")
    elif result.get("protocolVersion") != version:
        issues.append("initialize result does not select the requested version")
    return issues


def protocol_error(request_id: Any, code: int, message: str, **data: Any) -> dict[str, Any]:
    identifier = request_id if type(request_id) in (str, int) else None
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": identifier, "error": error}


def validate_modern_request(request: Any, headers: Mapping[str, Any], *, version: str) -> dict[str, Any] | None:
    identifier = request.get("id") if isinstance(request, Mapping) else None
    if (
        not isinstance(request, Mapping)
        or request.get("jsonrpc") != "2.0"
        or type(identifier) not in (str, int)
        or not isinstance(request.get("method"), str)
        or "result" in request
        or "error" in request
    ):
        return protocol_error(identifier, -32600, "Expected one JSON-RPC request with a string or integer id")
    params = request.get("params")
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    if not isinstance(meta, Mapping) or not isinstance(meta.get(CLIENT_CAPABILITIES_META), Mapping):
        return protocol_error(identifier, -32602, "Per-request clientCapabilities metadata is required")
    if CLIENT_INFO_META in meta:
        client = meta[CLIENT_INFO_META]
        if not isinstance(client, Mapping) or any(not isinstance(client.get(key), str) for key in ("name", "version")):
            return protocol_error(identifier, -32602, "clientInfo requires string name and version fields")
    requested = meta.get(PROTOCOL_VERSION_META)
    if (
        not isinstance(requested, str)
        or headers.get("mcp-protocol-version") != requested
        or headers.get("mcp-method") != request["method"]
    ):
        return protocol_error(identifier, HEADER_MISMATCH, "Required MCP headers must match the request body")
    if requested != version:
        return protocol_error(
            identifier,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            requested=requested,
            supported=[version],
        )
    method = request["method"]
    if method not in MODERN_REQUEST_METHODS:
        return protocol_error(identifier, -32601, "This MCP method is not implemented by the modern request preview")
    if method == LISTEN:
        issue = subscription_request_issue(params)
        if issue:
            return protocol_error(identifier, -32602, issue)
    name_field = NAMED_METHOD_FIELDS.get(method)
    if name_field:
        name = params.get(name_field)
        if not isinstance(name, str) or not name:
            return protocol_error(identifier, -32602, f"{method} requires a non-empty {name_field}")
        try:
            header_name = decode_mcp_header(headers.get("mcp-name"))
        except ValueError:
            header_name = None
        if header_name != name:
            return protocol_error(identifier, HEADER_MISMATCH, "Mcp-Name must match the request body")
    if "task" in params:
        return protocol_error(identifier, -32602, "Tasks are not implemented by this preview")
    issue = continuation_issue(method, params)
    if issue:
        return protocol_error(identifier, -32602, issue)
    if method == "server/discover" and set(params) - {"_meta"}:
        return protocol_error(identifier, -32602, "server/discover accepts only standard metadata")
    return None


def is_modern_request(request: Any) -> bool:
    params = request.get("params") if isinstance(request, Mapping) else None
    meta = params.get("_meta") if isinstance(params, Mapping) else None
    return isinstance(meta, Mapping) and meta.get(PROTOCOL_VERSION_META) == LATEST_MCP_SPEC_VERSION


def encode_mcp_header(value: str) -> str:
    if (
        value != value.strip()
        or any((ord(c) < 32 and c != "\t") or ord(c) > 126 for c in value)
        or (value.startswith("=?base64?") and value.endswith("?="))
    ):
        return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="
    return value


def decode_mcp_header(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or any((ord(c) < 32 and c != "\t") or ord(c) > 126 for c in value)
    ):
        raise ValueError("Invalid MCP header")
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeError) as exc:
            raise ValueError("Invalid encoded MCP header") from exc
    return value


def modern_request_headers(headers: Mapping[str, str], request: Mapping[str, Any]) -> dict[str, str]:
    """Rebuild mirrors after facade routing, without changing per-request capabilities."""
    result = {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"mcp-session-id", "last-event-id", "mcp-method", "mcp-name", "mcp-protocol-version"}
    }
    result["mcp-protocol-version"] = LATEST_MCP_SPEC_VERSION
    result["mcp-method"] = request["method"]
    name_field = NAMED_METHOD_FIELDS.get(request["method"])
    if name_field:
        result["mcp-name"] = encode_mcp_header(request["params"][name_field])
    return result


def modern_response_issue(body: bytes, request: Mapping[str, Any]) -> str | None:
    """Validate complete/interim results and JSON-RPC errors at the preview boundary."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError):
        return "Upstream did not return a JSON-RPC response"
    if (
        not isinstance(payload, Mapping)
        or payload.get("jsonrpc") != "2.0"
        or type(payload.get("id")) is not type(request.get("id"))
        or payload.get("id") != request.get("id")
        or "method" in payload
        or ("error" in payload) == ("result" in payload)
    ):
        return "Upstream returned an invalid or mismatched JSON-RPC response"
    if "error" in payload:
        error = payload["error"]
        if (
            not isinstance(error, Mapping)
            or type(error.get("code")) is not int
            or not isinstance(error.get("message"), str)
        ):
            return "Upstream returned an invalid JSON-RPC error"
        return None
    result = payload["result"]
    if request.get("method") == LISTEN and isinstance(result, Mapping) and not matching_id(result, request["id"]):
        return "Subscription completion has a missing or mismatched subscription ID"
    if isinstance(result, Mapping) and result.get("resultType") == "input_required":
        return input_required_issue(result, request)
    if (
        not isinstance(result, Mapping)
        or result.get("resultType") != "complete"
        or any(key in result for key in ("inputRequests", "requestState", "task"))
    ):
        return "Upstream result requires unsupported Tasks handling or an unknown result type"
    return None


def _package_version() -> str:
    from . import __version__

    return __version__

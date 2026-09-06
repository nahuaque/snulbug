"""Bounded MRTR envelopes; opaque upstream state is never interpreted here."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

MRTR_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
INPUT_METHODS = frozenset({"roots/list", "sampling/createMessage", "elicitation/create"})
MAX_INPUTS = 32
MAX_STATE_BYTES = 64 * 1024
MAX_INPUT_BYTES = 256 * 1024


def input_required(payload: Any) -> Mapping[str, Any] | None:
    result = payload.get("result") if isinstance(payload, Mapping) else None
    return result if isinstance(result, Mapping) and result.get("resultType") == "input_required" else None


def _state_issue(container: Mapping[str, Any]) -> str | None:
    if "requestState" in container:
        state = container["requestState"]
        if not isinstance(state, str) or len(state.encode("utf-8", errors="surrogatepass")) > MAX_STATE_BYTES:
            return "requestState must be a string of at most 64 KiB"
    return None


def _map_issue(value: Any, field: str) -> str | None:
    if (
        not isinstance(value, Mapping)
        or len(value) > MAX_INPUTS
        or any(
            not isinstance(key, str) or not key or len(key.encode("utf-8", errors="surrogatepass")) > 256
            for key in value
        )
        or any(not isinstance(item, Mapping) for item in value.values())
    ):
        return f"{field} requires a map of at most 32 objects with non-empty bounded string keys"
    if len(json.dumps(value, ensure_ascii=True).encode()) > MAX_INPUT_BYTES:
        return f"{field} exceeds the 256 KiB limit"
    return None


def continuation_issue(method: str, params: Mapping[str, Any]) -> str | None:
    if not {"requestState", "inputResponses"}.intersection(params):
        return None
    if method not in MRTR_METHODS:
        return "This method does not support MRTR continuations"
    return _state_issue(params) or (
        _map_issue(params["inputResponses"], "inputResponses") if "inputResponses" in params else None
    )


def input_required_issue(result: Mapping[str, Any], request: Mapping[str, Any]) -> str | None:
    if request.get("method") not in MRTR_METHODS:
        return "This method does not support input_required results"
    if not {"inputRequests", "requestState"}.intersection(result):
        return "input_required needs inputRequests or requestState"
    if "task" in result:
        return "Tasks extensions are not supported"
    issue = _state_issue(result)
    if issue:
        return issue
    inputs = result.get("inputRequests", {})
    issue = _map_issue(inputs, "inputRequests")
    if issue:
        return issue
    capabilities = request["params"]["_meta"].get("io.modelcontextprotocol/clientCapabilities", {})
    for item in inputs.values():
        method = item.get("method")
        if not isinstance(method, str) or method not in INPUT_METHODS or set(item) - {"method", "params"}:
            return "Unsupported or malformed MRTR input request"
        params = item.get("params", {})
        if not isinstance(params, Mapping):
            return "MRTR input request params must be an object"
        feature = method.split("/", 1)[0]
        capability = capabilities.get(feature)
        if not isinstance(capability, Mapping):
            return "MRTR input request exceeds declared client capabilities"
        if method == "elicitation/create":
            mode = params.get("mode", "form")
            if mode not in ("form", "url") or not isinstance(params.get("message"), str):
                return "Invalid elicitation mode or message"
            if not isinstance(capability.get(mode), Mapping):
                return "Elicitation mode is not supported by this client"
            if mode == "url" and (not isinstance(params.get("url"), str) or not params["url"]):
                return "URL elicitation requires a URL"
            if mode == "form" and not isinstance(params.get("requestedSchema"), Mapping):
                return "Form elicitation requires a schema"
        if method == "sampling/createMessage":
            if not isinstance(params.get("messages"), list) or type(params.get("maxTokens")) is not int:
                return "Sampling requires messages and an integer maxTokens"
            if params["maxTokens"] < 1:
                return "Sampling maxTokens must be positive"
            if params.get("tools") and not isinstance(capability.get("tools"), Mapping):
                return "Sampling tools are not supported by this client"
            if params.get("includeContext", "none") != "none" and not isinstance(capability.get("context"), Mapping):
                return "Sampling context is not supported by this client"
    return None


def mrtr_request_metadata(request: Mapping[str, Any]) -> dict[str, Any]:
    params = request.get("params", {})
    if not isinstance(params, Mapping) or not {"inputResponses", "requestState"}.intersection(params):
        return {}
    responses = params.get("inputResponses", {})
    return {
        "continuation": True,
        "state_present": "requestState" in params,
        "input_response_count": len(responses) if isinstance(responses, Mapping) else 0,
    }


def mrtr_result_metadata(payload: Any) -> dict[str, Any]:
    result = input_required(payload)
    if result is None:
        return {}
    inputs = result.get("inputRequests", {})
    return {
        "result_type": "input_required",
        "state_present": "requestState" in result,
        "input_request_count": len(inputs) if isinstance(inputs, Mapping) else 0,
        "methods": sorted(
            {
                item["method"]
                for item in inputs.values()
                if isinstance(item, Mapping) and isinstance(item.get("method"), str)
            }
        )
        if isinstance(inputs, Mapping)
        else [],
    }

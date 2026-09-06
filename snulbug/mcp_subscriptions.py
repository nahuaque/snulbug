"""Request-local subscription filters and correlation, without a global URI registry."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

LISTEN = "subscriptions/listen"
ACKNOWLEDGED = "notifications/subscriptions/acknowledged"
SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"
CHANGE_FILTERS = {
    "notifications/tools/list_changed": "toolsListChanged",
    "notifications/prompts/list_changed": "promptsListChanged",
    "notifications/resources/list_changed": "resourcesListChanged",
}
RESOURCE_UPDATED = "notifications/resources/updated"


def filter_issue(value: Any) -> str | None:
    if not isinstance(value, Mapping) or set(value) - {*CHANGE_FILTERS.values(), "resourceSubscriptions"}:
        return "Subscription notifications must be a filter with known fields"
    if any(type(value[key]) is not bool for key in CHANGE_FILTERS.values() if key in value):
        return "Subscription change filters must be booleans"
    if "resourceSubscriptions" in value:
        uris = value["resourceSubscriptions"]
        if (
            not isinstance(uris, list)
            or len(uris) > 128
            or any(not isinstance(uri, str) or not uri or len(uri) > 4096 for uri in uris)
            or len(set(uris)) != len(uris)
        ):
            return "resourceSubscriptions requires at most 128 unique non-empty bounded URIs"
    return None


def request_issue(params: Mapping[str, Any]) -> str | None:
    if set(params) - {"_meta", "notifications"}:
        return "subscriptions/listen accepts only metadata and a notifications filter"
    return filter_issue(params.get("notifications"))


def matching_id(container: Mapping[str, Any], identifier: str | int) -> bool:
    meta = container.get("_meta")
    supplied = meta.get(SUBSCRIPTION_ID) if isinstance(meta, Mapping) else None
    return type(supplied) is type(identifier) and supplied == identifier


class Subscription:
    def __init__(self, request: Mapping[str, Any]):
        self.identifier = request["id"]
        self.requested = request["params"]["notifications"]
        self.accepted: dict[str, Any] | None = None
        self.counts: dict[str, int] = {}

    def notification_issue(self, message: Mapping[str, Any]) -> str | None:
        params = message.get("params")
        if not isinstance(params, Mapping) or not matching_id(params, self.identifier):
            return "MCP subscription notification has a missing or mismatched subscription ID"
        method = message.get("method")
        if method == ACKNOWLEDGED:
            if self.accepted is not None:
                return "MCP subscription was acknowledged more than once"
            accepted = params.get("notifications")
            issue = filter_issue(accepted)
            if issue:
                return issue
            if any(
                accepted.get(key) is True and self.requested.get(key) is not True for key in CHANGE_FILTERS.values()
            ):
                return "MCP subscription acknowledgment broadens the requested filter"
            if not set(accepted.get("resourceSubscriptions", [])).issubset(
                self.requested.get("resourceSubscriptions", [])
            ):
                return "MCP subscription acknowledgment broadens the requested URIs"
            self.accepted = dict(accepted)
        elif self.accepted is None:
            return "MCP subscription must be acknowledged before delivering changes"
        elif method in CHANGE_FILTERS:
            if self.accepted.get(CHANGE_FILTERS[method]) is not True:
                return "MCP subscription change was not acknowledged by this stream"
        elif method == RESOURCE_UPDATED:
            if not isinstance(params.get("uri"), str) or params["uri"] not in self.accepted.get(
                "resourceSubscriptions", []
            ):
                return "MCP resource update is outside this subscription's acknowledged URIs"
        else:
            return "MCP notification is not permitted on a subscription stream"
        self.counts[method] = self.counts.get(method, 0) + 1
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "acknowledged": self.accepted is not None,
            "requested_changes": [key for key in CHANGE_FILTERS.values() if self.requested.get(key) is True],
            "requested_resources": len(self.requested.get("resourceSubscriptions", [])),
            "accepted_changes": [key for key in CHANGE_FILTERS.values() if (self.accepted or {}).get(key) is True],
            "accepted_resources": len((self.accepted or {}).get("resourceSubscriptions", [])),
            "events": dict(self.counts),
        }

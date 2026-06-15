from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SNULBUG_INFORMATION_URI = "https://github.com/lbruhacs/snulbug"


def sarif_for_policy_diff(diff: Mapping[str, Any]) -> dict[str, Any]:
    """Build a SARIF report for `snulbug mcp evidence diff`."""

    builder = _SarifBuilder(
        invocation="snulbug mcp evidence diff",
        automation_id="snulbug/evidence-diff",
    )
    builder.add_rule(
        "snulbug.policy.regression",
        name="Policy regression",
        short_description="A candidate policy newly blocks or errors a replay fixture.",
        level="error",
    )
    builder.add_rule(
        "snulbug.policy.newly_allowed_capability",
        name="Newly allowed MCP capability",
        short_description="A candidate policy newly allows a tool, path, method, or argument shape.",
        level="warning",
    )

    for regression in _mapping_sequence(diff.get("regressions")):
        fixture = regression.get("fixture")
        builder.add_result(
            "snulbug.policy.regression",
            level="error",
            message=str(regression.get("reason") or "candidate policy regressed a fixture"),
            uri=str(fixture or diff.get("new_policy") or "policy-diff"),
            properties={
                "old_policy": diff.get("old_policy"),
                "new_policy": diff.get("new_policy"),
                "fixture": fixture,
                "differences": regression.get("differences", []),
            },
        )

    examples = _mapping_sequence(_mapping(diff.get("capability_delta")).get("examples"))
    for item in _mapping_sequence(_mapping(diff.get("capability_delta")).get("items")):
        kind = str(item.get("kind") or "capability")
        value = str(item.get("value") or "")
        fixture = _capability_item_fixture(item, examples) or diff.get("new_policy") or "policy-diff"
        builder.add_result(
            "snulbug.policy.newly_allowed_capability",
            level="warning",
            message=f"candidate policy newly allows {kind.replace('_', ' ')} `{value}`",
            uri=str(fixture),
            properties={
                "old_policy": diff.get("old_policy"),
                "new_policy": diff.get("new_policy"),
                "kind": kind,
                "value": value,
                "parent": item.get("parent"),
                "keys": item.get("keys"),
            },
        )
    return builder.build()


def sarif_for_schema_diff(diff: Mapping[str, Any]) -> dict[str, Any]:
    """Build a SARIF report for `snulbug mcp policy schemas diff`."""

    fail_on = {str(item) for item in _sequence(diff.get("fail_on"))}
    builder = _SarifBuilder(
        invocation="snulbug mcp policy schemas diff",
        automation_id="snulbug/schema-diff",
    )
    for kind in ("added", "changed", "removed"):
        builder.add_rule(
            f"snulbug.schema.{kind}",
            name=f"MCP schema {kind}",
            short_description=f"An MCP schema catalog item was {kind}.",
            level="error" if kind in fail_on else "warning",
        )

    for kind in ("added", "changed", "removed"):
        level = "error" if kind in fail_on else "warning"
        default_uri = _schema_change_uri(diff, kind)
        for change in _mapping_sequence(diff.get(kind)):
            surface = change.get("surface")
            item_id = change.get("id")
            message = f"MCP schema {kind}: {surface} `{item_id}`"
            if kind == "changed":
                fields = ", ".join(str(item) for item in _sequence(change.get("changed_fields"))) or "hash"
                message = f"{message} changed fields: {fields}"
            builder.add_result(
                f"snulbug.schema.{kind}",
                level=level,
                message=message,
                uri=default_uri,
                properties={
                    "surface": surface,
                    "id": item_id,
                    "change": kind,
                    "hash": change.get("hash"),
                    "before_hash": change.get("before_hash"),
                    "after_hash": change.get("after_hash"),
                    "changed_fields": change.get("changed_fields"),
                },
            )
    return builder.build()


def sarif_for_share_doctor(result: Mapping[str, Any]) -> dict[str, Any]:
    """Build a SARIF report for `snulbug mcp share doctor`."""

    builder = _SarifBuilder(
        invocation="snulbug mcp share doctor",
        automation_id="snulbug/share-doctor",
    )
    builder.add_rule(
        "snulbug.share.doctor_failed_check",
        name="Share doctor failed check",
        short_description="A share readiness check failed.",
        level="error",
    )
    builder.add_rule(
        "snulbug.share.doctor_warning_check",
        name="Share doctor warning check",
        short_description="A share readiness check emitted a warning.",
        level="warning",
    )
    default_uri = str(result.get("config") or result.get("share") or "share-doctor")
    for check in _mapping_sequence(result.get("checks")):
        status = check.get("status")
        if status not in {"fail", "warn"}:
            continue
        level = "error" if status == "fail" else "warning"
        rule_id = "snulbug.share.doctor_failed_check" if status == "fail" else "snulbug.share.doctor_warning_check"
        uri = _doctor_check_uri(check) or default_uri
        builder.add_result(
            rule_id,
            level=level,
            message=f"{check.get('id')}: {check.get('message')}",
            uri=uri,
            properties={
                "check_id": check.get("id"),
                "component": check.get("component"),
                "status": status,
                "details": check.get("details"),
            },
        )
    return builder.build()


def _schema_change_uri(diff: Mapping[str, Any], kind: str) -> str:
    if kind == "removed":
        return str(_mapping(diff.get("baseline")).get("path") or "baseline-schema")
    return str(_mapping(diff.get("current")).get("path") or "current-schema")


def _doctor_check_uri(check: Mapping[str, Any]) -> str | None:
    details = _mapping(check.get("details"))
    for key in ("path", "config", "manifest", "policy", "file"):
        value = details.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _capability_item_fixture(item: Mapping[str, Any], examples: Sequence[Mapping[str, Any]]) -> str | None:
    kind = item.get("kind")
    value = item.get("value")
    for example in examples:
        if kind == "path_pattern" and example.get("path_pattern") == value:
            return _string_or_none(example.get("fixture"))
        if kind == "method" and example.get("method") == value:
            return _string_or_none(example.get("fixture"))
        if kind == "tool" and example.get("tool") == value:
            return _string_or_none(example.get("fixture"))
        if kind == "resource" and example.get("resource") == value:
            return _string_or_none(example.get("fixture"))
        if kind == "prompt" and example.get("prompt") == value:
            return _string_or_none(example.get("fixture"))
        if kind == "argument_shape" and _mapping(example.get("argument_shape")).get("shape") == value:
            return _string_or_none(example.get("fixture"))
    return None


class _SarifBuilder:
    def __init__(self, *, invocation: str, automation_id: str) -> None:
        self.invocation = invocation
        self.automation_id = automation_id
        self.rules: dict[str, dict[str, Any]] = {}
        self.results: list[dict[str, Any]] = []

    def add_rule(
        self,
        rule_id: str,
        *,
        name: str,
        short_description: str,
        level: str,
    ) -> None:
        self.rules[rule_id] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": short_description},
            "fullDescription": {"text": short_description},
            "defaultConfiguration": {"level": level},
        }

    def add_result(
        self,
        rule_id: str,
        *,
        level: str,
        message: str,
        uri: str,
        properties: Mapping[str, Any] | None = None,
    ) -> None:
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(uri)},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        cleaned_properties = _drop_none(dict(properties or {}))
        if cleaned_properties:
            result["properties"] = cleaned_properties
        self.results.append(result)

    def build(self) -> dict[str, Any]:
        return {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "snulbug",
                            "informationUri": SNULBUG_INFORMATION_URI,
                            "rules": list(self.rules.values()),
                        }
                    },
                    "automationDetails": {"id": self.automation_id},
                    "invocations": [{"executionSuccessful": True, "commandLine": self.invocation}],
                    "results": self.results,
                }
            ],
        }


def _sarif_uri(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        try:
            return path.as_posix()
        except ValueError:
            return str(path)
    return value


def _drop_none(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value if item is not None]
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in _sequence(value) if isinstance(item, Mapping)]


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    return []


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None

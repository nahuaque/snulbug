from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

from snulbug.json_schema import DIALECT, MAX_ISSUES, MAX_NODES, validate_schema
from snulbug.schema_policy import (
    SchemaPolicyConfig,
    enforce_mcp_request_schema_policy,
    enforce_mcp_response_schema_policy,
    observe_mcp_tool_schemas,
)
from snulbug.state import MemoryStateStore

REMOTE_GROUPS = {
    "strict-tree schema, guards against misspelled properties",
    "tests for implementation dynamic anchor and reference link",
    "$ref and $dynamicAnchor are independent of order - $defs first",
    "$ref and $dynamicAnchor are independent of order - $ref first",
    "$ref to $dynamicRef finds detached $dynamicAnchor",
}


def official_cases():
    directory = Path(__file__).parent / "fixtures/json_schema_2020_12"
    for file in sorted(directory.glob("*.json")):
        for group in json.loads(file.read_text()):
            for case in group["tests"]:
                marks = []
                if file.stem == "dynamicRef" and group["description"] in REMOTE_GROUPS:
                    marks = [pytest.mark.skip(reason="external schema retrieval is deliberately disabled")]
                yield pytest.param(
                    group["schema"],
                    case["data"],
                    case["valid"],
                    id=f"{file.stem}: {group['description']}: {case['description']}",
                    marks=marks,
                )


@pytest.mark.parametrize("schema,value,valid", official_cases())
def test_official_2020_12_fixtures(schema, value, valid):
    issues = validate_schema(value, schema)
    assert (not issues) == valid, issues


@pytest.mark.parametrize(
    "schema,valid,invalid",
    [
        ({"$defs": {"number": {"type": "number"}}, "$ref": "#/$defs/number", "minimum": 10}, 12, 2),
        ({"$defs": {"t": {"$anchor": "text", "type": "string"}}, "$ref": "#text"}, "x", 3),
        ({"type": "integer"}, 1.0, True),
        ({"enum": [True]}, True, 1),
        ({"const": False}, False, 0),
        ({"not": {"type": "string"}}, 1, "x"),
        ({"dependentRequired": {"a": ["b"]}}, {"a": 1, "b": 2}, {"a": 1}),
        ({"propertyNames": {"pattern": "^[a-z]+$"}}, {"good": 1}, {"BAD": 1}),
        ({"patternProperties": {"^x": {"type": "integer"}}, "additionalProperties": False}, {"x1": 2}, {"y": 2}),
        ({"contains": {"type": "integer"}, "minContains": 2, "maxContains": 2}, [1, 2, "x"], [1, "x"]),
        ({"uniqueItems": True}, [False, 0], [0, 0.0]),
        ({"multipleOf": 3}, 9, 10),
        ({"minProperties": 1, "maxProperties": 2}, {"a": 1}, {}),
        ({"prefixItems": [{"type": "string"}], "unevaluatedItems": False}, ["a"], ["a", 2]),
    ],
)
def test_additional_keywords_and_json_type_semantics(schema, valid, invalid):
    assert not validate_schema(valid, schema)
    assert validate_schema(invalid, schema)


def test_recursive_schemas_validate_finite_instances_and_cycles_fail_safely():
    schema = {"type": "object", "properties": {"value": {"type": "integer"}, "next": {"$ref": "#"}}}
    assert not validate_schema({"value": 1, "next": {"value": 2}}, schema)
    assert validate_schema({"next": {"value": "wrong"}}, schema)[0]["path"] == "$.next.value"
    assert validate_schema({}, {"$ref": "#"})[0]["reason_code"] == "schema.ref_cycle"


@pytest.mark.parametrize(
    "uri", ["http://127.0.0.1:9/private", "https://example.com/schema", "file:///etc/passwd", "#missing"]
)
def test_unresolvable_references_never_fetch_or_echo_locations(monkeypatch, uri):
    def forbidden(*args, **kwargs):
        pytest.fail("schema validation attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    issues = validate_schema({}, {"$ref": uri})
    assert issues[0]["reason_code"] == "schema.ref_unresolved"
    assert uri not in json.dumps(issues)


@pytest.mark.parametrize(
    "schema", [None, [], 4, {"type": "unknown"}, {"required": "x"}, {"pattern": "["}, {"items": []}]
)
def test_invalid_schemas_are_not_treated_as_unconstrained(schema):
    assert validate_schema({}, schema)[0]["reason_code"] == "schema.invalid"


def test_schema_dialect_and_annotation_behavior():
    assert not validate_schema("not-an-email", {"$schema": DIALECT, "type": "string", "format": "email"})
    assert not validate_schema({}, {"examples": [{"$schema": "not-a-dialect"}], "x-mcp-header": "ignored-here"})
    assert (
        validate_schema({}, {"$schema": "https://example.com/custom"})[0]["reason_code"] == "schema.dialect_unsupported"
    )
    assert validate_schema({}, {"$defs": {"other": {"$schema": "http://json-schema.org/draft-07/schema#"}}})


def test_limits_and_diagnostics_do_not_echo_values():
    secret = "super-secret-example-value"
    for schema in ({"const": secret}, {"enum": [secret]}, {"pattern": secret}):
        issues = validate_schema("different-secret", schema)
        assert secret not in json.dumps(issues)
        assert "different-secret" not in json.dumps(issues)
    assert len(validate_schema(["x"] * 100, {"items": {"type": "integer"}})) == MAX_ISSUES
    assert validate_schema([0] * MAX_NODES, True)[0]["reason_code"] == "schema.validation_limit"
    assert validate_schema(float("nan"), True)[0]["reason_code"] == "schema.non_json"
    assert validate_schema({}, {"description": "x" * (256 * 1024)})[0]["reason_code"] == "schema.validation_limit"


@pytest.mark.parametrize("action", ["block", "warn"])
@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "dependentRequired": {"path": ["project"]}},
        {"allOf": [{"properties": {"project": {"type": "string"}}}], "unevaluatedProperties": False},
        None,
    ],
)
def test_input_output_policy_integration_reuses_decisions_and_never_drops_invalid_declarations(action, schema):
    store = MemoryStateStore()
    config = SchemaPolicyConfig(action=action)

    def observe(definition):
        payload = {"result": {"tools": [{"name": "inspect", "inputSchema": definition, "outputSchema": definition}]}}
        observe_mcp_tool_schemas(
            {"status": 200, "body": json.dumps(payload).encode()},
            request={"method": "tools/list"},
            config=config,
            tool_schema_store=store,
        )

    observe({})
    observe(schema)
    request = {"id": 1, "method": "tools/call", "params": {"name": "inspect", "arguments": {"path": "private"}}}
    allowed, metadata = enforce_mcp_request_schema_policy(request, config=config, tool_schema_store=store)
    assert allowed == (action == "warn")
    assert metadata["valid"] is False
    response = {"status": 200, "body": json.dumps({"result": {"structuredContent": {"path": "private"}}}).encode()}
    updated, metadata = enforce_mcp_response_schema_policy(
        response, request=request, config=config, tool_schema_store=store
    )
    assert metadata["valid"] is False
    if action == "block":
        assert json.loads(updated["body"])["error"]["code"] == -32000
    else:
        assert updated == response

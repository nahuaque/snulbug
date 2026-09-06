from __future__ import annotations

import copy
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from test_mcp_protocol import post, running_gateway

from snulbug.mcp_parameter_headers import header_bindings, parameter_values, validate_parameter_headers
from snulbug.mcp_protocol import LATEST_MCP_SPEC_VERSION, encode_mcp_header, mcp_request
from snulbug.mcp_schemas import build_mcp_schema_catalog
from snulbug.proxy import create_proxy_application


def schema():
    return {
        "type": "object",
        "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "options": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "x-mcp-header": "Count"},
                    "dry": {"type": "boolean", "x-mcp-header": "Dry-Run"},
                },
            },
        },
    }


def test_nested_values_and_encoding_follow_header_contract():
    bindings = header_bindings(schema())
    arguments = {"region": " padded\nvalue ", "options": {"count": 42.0, "dry": False}}
    values = parameter_values(arguments, bindings)
    assert values == {"mcp-param-region": " padded\nvalue ", "mcp-param-count": "42", "mcp-param-dry-run": "false"}
    headers = {key: encode_mcp_header(value) for key, value in values.items()}
    headers["mcp-param-count"] = "42.0"
    validate_parameter_headers(headers, arguments, bindings)
    assert parameter_values({"region": None}, bindings) == {}
    assert parameter_values({"options": []}, bindings) == {}
    for value in ("", "hello\tworld", "=?base64?literal?=", "\u6771\u4eac"):
        validate_parameter_headers({"mcp-param-region": encode_mcp_header(value)}, {"region": value}, bindings)


@pytest.mark.parametrize("where", ["items", "allOf", "$defs", "if", "additionalProperties", "root", "ref"])
def test_annotations_must_be_statically_reachable_through_properties(where):
    leaf = {"type": "string", "x-mcp-header": "Tenant"}
    definitions = {
        "items": {"properties": {"rows": {"type": "array", "items": leaf}}},
        "allOf": {"allOf": [{"properties": {"tenant": leaf}}]},
        "$defs": {"$defs": {"tenant": leaf}},
        "if": {"if": {"properties": {"tenant": leaf}}},
        "additionalProperties": {"additionalProperties": leaf},
        "root": leaf,
        "ref": {"properties": {"tenant": {"$ref": "#/$defs/tenant"}}, "$defs": {"tenant": leaf}},
    }
    with pytest.raises(ValueError):
        header_bindings(definitions[where])


@pytest.mark.parametrize("annotation", ["", "invalid space", "\r\nInjected", "\u00e9", "x" * 129, 3, None])
def test_header_annotation_names_are_bounded_http_tokens(annotation):
    with pytest.raises(ValueError):
        header_bindings({"properties": {"value": {"type": "string", "x-mcp-header": annotation}}})


@pytest.mark.parametrize("kind", ["number", "object", "array", ["string", "null"], None])
def test_only_declared_primitives_can_be_mirrored(kind):
    with pytest.raises(ValueError):
        header_bindings({"properties": {"value": {"type": kind, "x-mcp-header": "Value"}}})


def test_names_are_unique_case_insensitively_but_examples_are_not_schema_annotations():
    definition = schema()
    definition["properties"]["duplicate"] = {"type": "string", "x-mcp-header": "REGION"}
    with pytest.raises(ValueError, match="Duplicate"):
        header_bindings(definition)
    assert header_bindings({"const": {"x-mcp-header": ""}, "examples": [{"x-mcp-header": ""}]}) == ()


@pytest.mark.parametrize(
    "arguments,headers",
    [
        ({"region": "east"}, {}),
        ({"region": "east"}, {"mcp-param-region": "west"}),
        ({"region": "east"}, {"mcp-param-region": ["east", "east"]}),
        ({"region": "east"}, {"mcp-param-region": "=?base64?bad?="}),
        ({"region": "east"}, {"mcp-param-region": "east\r\n"}),
        ({"region": None}, {"mcp-param-region": "null"}),
        ({}, {"mcp-param-region": "east"}),
        ({"options": {"count": True}}, {"mcp-param-count": "1"}),
        ({"options": {"count": 2**53}}, {"mcp-param-count": str(2**53)}),
        ({"options": {"count": 1.5}}, {"mcp-param-count": "1.5"}),
        ({"options": {"count": 1}}, {"mcp-param-count": "NaN"}),
        ({"options": {"count": 1}}, {"mcp-param-count": "1_0"}),
        ({"options": {"dry": True}}, {"mcp-param-dry-run": "True"}),
    ],
)
def test_invalid_or_ambiguous_mirrors_fail_without_echoing_values(arguments, headers):
    with pytest.raises(ValueError) as error:
        validate_parameter_headers(headers, arguments, header_bindings(schema()))
    assert "east" not in str(error.value)


@pytest.fixture(params=["proxy", "facade", "no-schema"])
def header_gateway(request, tmp_path):
    seen = []
    tools = [
        {"name": "inspect", "inputSchema": schema()},
        {"name": "invalid", "inputSchema": {"properties": {"value": {"type": "number", "x-mcp-header": "Value"}}}},
    ]

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen.append((payload, {key.lower(): value for key, value in self.headers.items()}))
            result = {"tools": tools} if payload["method"] == "tools/list" else {"content": []}
            body = json.dumps(
                {"jsonrpc": "2.0", "id": payload["id"], "result": {"resultType": "complete", **result}}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = tmp_path / "policy.lua"
    policy.write_text("""return function(request)
      if request.headers["x-deny"] then return {action="reject", status=403, body="Lua reached"} end
      if request.headers["x-from-prompt"] then
        return {action="rewrite", headers={["mcp-method"]="tools/call"},
          body=(request.body:gsub('"prompts/get"', '"tools/call"'))}
      end
      if request.headers["x-rewrite"] then
        return {action="rewrite", body=(request.body:gsub('"east"', '"west"'))}
      end
      return {action="continue"}
    end""")
    facade = request.param == "facade"
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_proxy_application(
        None if facade else origin,
        policy,
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        schema_validation=request.param != "no-schema",
        lease_required=False,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    try:
        with running_gateway(app) as url:
            yield {"url": url, "seen": seen, "prefix": "files." if facade else "", "tools": tools}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def catalog(gateway):
    status, response = post(
        gateway["url"], mcp_request("tools/list", version=LATEST_MCP_SPEC_VERSION, request_id="list")
    )
    assert status == 200
    return response["result"]["tools"]


def call(gateway, arguments=None, name="inspect"):
    return mcp_request(
        "tools/call",
        version=LATEST_MCP_SPEC_VERSION,
        request_id="call",
        params={"name": gateway["prefix"] + name, "arguments": arguments or {"region": "east"}},
    )


def test_catalog_excludes_bad_annotations_and_cached_invalid_tools_cannot_be_called(header_gateway):
    gateway = header_gateway
    listed = catalog(gateway)
    assert [tool["name"] for tool in listed] == [gateway["prefix"] + "inspect"]
    assert listed[0]["inputSchema"]["properties"]["region"]["x-mcp-header"] == "Region"
    status, error = post(gateway["url"], call(gateway, name="invalid"))
    assert status == 400 and error["error"]["code"] == -32020
    assert len(gateway["seen"]) == 1


def test_header_validation_precedes_lua_and_forwarding(header_gateway):
    gateway = header_gateway
    catalog(gateway)
    status, error = post(gateway["url"], call(gateway), **{"Mcp-Param-Region": "west", "x-deny": "yes"})
    assert status == 400 and error["error"]["code"] == -32020
    assert "west" not in json.dumps(error)
    assert len(gateway["seen"]) == 1
    assert post(gateway["url"], call(gateway))[0] == 400
    assert len(gateway["seen"]) == 1


def test_valid_mirrors_survive_facade_routing_and_follow_lua_rewrites(header_gateway):
    gateway = header_gateway
    catalog(gateway)
    arguments = {"region": "east", "options": {"count": 42, "dry": False}}
    headers = {
        "MCP-PARAM-REGION": "east",
        "Mcp-Param-Count": "42.0",
        "Mcp-Param-Dry-Run": "false",
        "Mcp-Param-Unknown": "opaque",
        "x-rewrite": "yes",
    }
    assert post(gateway["url"], call(gateway, arguments), **headers)[0] == 200
    payload, forwarded = gateway["seen"][-1]
    assert payload["params"]["name"] == "inspect"
    assert payload["params"]["arguments"]["region"] == "west"
    assert forwarded["mcp-name"] == "inspect"
    assert forwarded["mcp-param-region"] == "west"
    assert forwarded["mcp-param-count"] == "42"
    assert forwarded["mcp-param-unknown"] == "opaque"


def test_unknown_schema_headers_pass_through_without_becoming_trusted(header_gateway):
    gateway = header_gateway
    assert post(gateway["url"], call(gateway), **{"Mcp-Param-Region": "west"})[0] == 200
    assert gateway["seen"][-1][1]["mcp-param-region"] == "west"
    catalog(gateway)
    assert post(gateway["url"], call(gateway), **{"Mcp-Param-Region": "west"})[0] == 400


def test_policy_rewrite_into_tool_call_resolves_target_bindings(header_gateway):
    gateway = header_gateway
    catalog(gateway)
    payload = call(gateway)
    payload["method"] = "prompts/get"
    assert post(gateway["url"], payload, **{"x-from-prompt": "yes"})[0] == 200
    forwarded, headers = gateway["seen"][-1]
    assert forwarded["method"] == "tools/call"
    assert headers["mcp-param-region"] == "east"


def test_duplicate_http_header_fields_are_rejected(header_gateway):
    gateway = header_gateway
    catalog(gateway)
    target = urlsplit(gateway["url"])
    body = json.dumps(call(gateway)).encode()
    connection = http.client.HTTPConnection(target.hostname, target.port, timeout=4)
    try:
        connection.putrequest("POST", target.path)
        for key, value in {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Content-Length": str(len(body)),
            "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": gateway["prefix"] + "inspect",
        }.items():
            connection.putheader(key, value)
        connection.putheader("Mcp-Param-Region", "east")
        connection.putheader("mcp-param-region", "east")
        connection.endheaders(body)
        response = connection.getresponse()
        assert response.status == 400
        assert json.load(response)["error"]["code"] == -32020
    finally:
        connection.close()


def test_header_binding_traversal_is_bounded():
    definition = schema()
    for _ in range(66):
        definition = {"properties": {"nested": copy.deepcopy(definition)}}
    with pytest.raises(ValueError, match="traversal limits"):
        header_bindings(definition)


def test_schema_discovery_uses_same_annotation_filter_only_for_modern_profile():
    tools = [
        {"name": "valid", "inputSchema": schema()},
        {"name": "invalid", "inputSchema": {"type": "string", "x-mcp-header": "Root"}},
    ]
    responses = {"tools/list": {"result": {"tools": tools}}}
    modern = build_mcp_schema_catalog(responses, methods=["tools/list"], protocol_version=LATEST_MCP_SPEC_VERSION)
    assert modern["summary"]["tools"] == 1
    assert modern["errors"][0]["reason_code"] == "schema.header_annotation_invalid"
    legacy = build_mcp_schema_catalog(responses, methods=["tools/list"])
    assert legacy["summary"]["tools"] == 2

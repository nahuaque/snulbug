from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from test_mcp_protocol import running_gateway
from test_mcp_stream import next_event

from snulbug import create_lease, list_leases, revoke_lease
from snulbug.mcp_mrtr import MAX_INPUTS, MAX_STATE_BYTES, continuation_issue
from snulbug.mcp_protocol import CLIENT_CAPABILITIES_META, LATEST_MCP_SPEC_VERSION, mcp_request, modern_response_issue
from snulbug.mcp_stream import json_response
from snulbug.proxy import create_proxy_application
from snulbug.redaction import redact_secrets
from snulbug.response_policy import ResponsePolicyConfig, enforce_mcp_response_policy

OPAQUE_STATE = "Bearer opaque-state-that-must-not-be-rewritten"


def operation(method="tools/call", name="read_file", **extra):
    params = {"name": name, "arguments": {}} if method != "resources/read" else {"uri": "file:///project/file"}
    request = mcp_request(method, version=LATEST_MCP_SPEC_VERSION, request_id="initial", params={**params, **extra})
    request["params"]["_meta"][CLIENT_CAPABILITIES_META] = {
        "elicitation": {"form": {}, "url": {}},
        "roots": {},
        "sampling": {"tools": {}, "context": {}},
    }
    return request


def interim(identifier="initial", method="elicitation/create"):
    params = {
        "elicitation/create": {"mode": "form", "message": "Confirm access", "requestedSchema": {"type": "object"}},
        "roots/list": {},
        "sampling/createMessage": {"messages": [], "maxTokens": 12},
    }[method]
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "result": {
            "resultType": "input_required",
            "requestState": OPAQUE_STATE,
            "inputRequests": {"secret_input_key": {"method": method, "params": params}},
        },
    }


@pytest.mark.parametrize("method", ["tools/call", "prompts/get", "resources/read"])
@pytest.mark.parametrize("input_method", ["elicitation/create", "roots/list", "sampling/createMessage"])
def test_interim_results_reuse_existing_request_policy_and_preserve_wire_state(method, input_method):
    request = operation(method)
    payload = interim(method=input_method)
    response = json_response(payload)
    assert modern_response_issue(response["body"], request) is None
    blocked, metadata = enforce_mcp_response_policy(response, request=request, config=ResponsePolicyConfig())
    assert metadata["server_to_client"]["blocked"]
    error = json.loads(blocked["body"])
    assert error["id"] == "initial" and "error" in error
    assert OPAQUE_STATE not in blocked["body"].decode()
    for action in ("allow", "warn"):
        allowed, metadata = enforce_mcp_response_policy(
            response, request=request, config=ResponsePolicyConfig(server_to_client_request_action=action)
        )
        wire = json.loads(allowed["body"])
        assert wire["result"]["requestState"] == OPAQUE_STATE
        assert wire["result"]["inputRequests"] == payload["result"]["inputRequests"]
        assert modern_response_issue(allowed["body"], request) is None
        assert metadata["server_to_client"]["requests"][0]["transport"] == "mrtr"


@pytest.mark.parametrize(
    "mutation",
    ["missing", "mode", "sampling_tools", "sampling_context", "unknown", "shape", "state", "count", "method"],
)
def test_mrtr_rejects_invalid_envelopes_or_missing_client_capabilities(mutation):
    request = operation()
    payload = interim()
    if mutation == "missing":
        request["params"]["_meta"][CLIENT_CAPABILITIES_META] = {}
    elif mutation == "mode":
        request["params"]["_meta"][CLIENT_CAPABILITIES_META]["elicitation"] = {"url": {}}
    elif mutation in ("sampling_tools", "sampling_context"):
        payload = interim(method="sampling/createMessage")
        request["params"]["_meta"][CLIENT_CAPABILITIES_META]["sampling"] = {}
        params = payload["result"]["inputRequests"]["secret_input_key"]["params"]
        params.update(tools=[{"name": "run"}] if mutation == "sampling_tools" else [])
        params["includeContext"] = "allServers" if mutation == "sampling_context" else "none"
    elif mutation == "unknown":
        payload["result"]["inputRequests"]["secret_input_key"]["method"] = "exec/run"
    elif mutation == "shape":
        payload["result"]["inputRequests"] = []
    elif mutation == "state":
        payload["result"]["requestState"] = "x" * (MAX_STATE_BYTES + 1)
    elif mutation == "count":
        payload["result"]["inputRequests"] = {str(i): {} for i in range(MAX_INPUTS + 1)}
    else:
        request["method"] = "tools/list"
    assert modern_response_issue(json_response(payload)["body"], request)


def test_state_only_round_and_url_elicitation_are_supported():
    request = operation()
    payload = interim()
    del payload["result"]["inputRequests"]
    response, _ = enforce_mcp_response_policy(json_response(payload), request=request, config=ResponsePolicyConfig())
    assert json.loads(response["body"]) == payload
    payload = interim()
    payload["result"]["inputRequests"]["secret_input_key"]["params"] = {
        "mode": "url",
        "message": "Log in",
        "url": "https://example.test/authorize",
    }
    assert modern_response_issue(json_response(payload)["body"], request) is None


def test_continuation_log_redaction_hides_state_and_answers_but_not_live_request():
    request = operation(
        requestState=OPAQUE_STATE, inputResponses={"answer": {"content": {"email": "private@example.test"}}}
    )
    recorded = redact_secrets({"body": json.dumps(request)})
    assert "private@example.test" not in json.dumps(recorded)
    assert OPAQUE_STATE not in json.dumps(recorded)
    assert request["params"]["requestState"] == OPAQUE_STATE
    assert continuation_issue("tools/call", request["params"]) is None
    assert continuation_issue("tools/list", request["params"])


@pytest.fixture(params=["proxy-json", "proxy-sse", "facade-json", "facade-sse", "stdio"])
def gateway(request, tmp_path, monkeypatch):
    import snulbug.proxy as proxy

    seen = []
    records = []
    monkeypatch.setattr(proxy, "append_record", lambda path, record: records.append(record))
    kind = request.param
    facade = kind.startswith("facade") or kind == "stdio"
    tool = "files.read_file" if facade else "read_file"
    leases = tmp_path / "leases.json"
    lease = create_lease(leases, task="MRTR test", allow_tools=[tool], ttl="30m", token="sbl_mrtr-lease")
    policy = tmp_path / "policy.lua"
    policy.write_text("""return function(request, context)
      if request.headers.authorization ~= "Bearer gateway-key" then
        return {action="reject", status=401, body="auth required"}
      end
      return {action="continue"}
    end""")

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen.append(message)
            if message["method"] == "tools/list":
                result = {
                    "resultType": "complete",
                    "tools": [
                        {
                            "name": "read_file",
                            "inputSchema": {"type": "object"},
                            "outputSchema": {"type": "object", "required": ["ok"]},
                        }
                    ],
                }
                payload = {"jsonrpc": "2.0", "id": message["id"], "result": result}
            elif "requestState" in message["params"]:
                payload = {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {"resultType": "complete", "structuredContent": {"ok": True}},
                }
            else:
                payload = interim(message["id"])
            data = json.dumps(payload).encode()
            sse = kind.endswith("sse")
            if sse:
                data = b"data: " + data + b"\n\n"
            self.send_response(200)
            self.send_header("content-type", "text/event-stream" if sse else "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    upstreams = [{"name": "files", "url": origin + "/mcp"}] if facade else None
    if kind == "stdio":
        script = tmp_path / "upstream.py"
        script.write_text("""import json, sys
for line in sys.stdin:
    request = json.loads(line)
    result = json.loads(sys.argv[1])
    result["id"] = request["id"]
    if "requestState" in request["params"]:
        assert request["params"]["requestState"] == result["result"]["requestState"]
        result["result"] = {"resultType": "complete", "structuredContent": {"ok": True}}
    print(json.dumps(result), flush=True)
""")
        upstreams = [
            {
                "name": "files",
                "transport": "stdio",
                "command": sys.executable,
                "args": [str(script), json.dumps(interim())],
            }
        ]
    app = create_proxy_application(
        None if facade else origin,
        policy,
        upstreams=upstreams,
        lease_file=leases,
        lease_required=True,
        record_out=tmp_path / "records.jsonl",
        server_to_client_request_action="allow",
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    try:
        with running_gateway(app) as url:
            yield {
                "url": url,
                "tool": tool,
                "seen": seen,
                "kind": kind,
                "leases": leases,
                "lease": lease,
                "records": records,
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def exchange(gateway, request, *, authenticated=True):
    from urllib.request import Request, urlopen

    from snulbug.mcp_protocol import modern_request_headers

    headers = modern_request_headers(
        {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "x-snulbug-lease": "sbl_mrtr-lease",
        },
        request,
    )
    if authenticated:
        headers["authorization"] = "Bearer gateway-key"
    with urlopen(Request(gateway["url"], data=json.dumps(request).encode(), headers=headers), timeout=4) as response:
        return next_event(response) if response.headers["content-type"] == "text/event-stream" else json.load(response)


def test_mrtr_round_trip_rechecks_auth_and_leases_and_preserves_facade_routing(gateway):
    from urllib.error import HTTPError

    if gateway["kind"] != "stdio":
        listing = operation("tools/list")
        listing["params"] = {"_meta": listing["params"]["_meta"]}
        assert "tools" in exchange(gateway, listing)["result"]
    request = operation(name=gateway["tool"])
    first = exchange(gateway, request)
    assert first["result"]["resultType"] == "input_required"
    assert first["result"]["requestState"] == OPAQUE_STATE
    retry = operation(
        name=gateway["tool"],
        requestState=first["result"]["requestState"],
        inputResponses={"secret_input_key": {"action": "accept", "content": {"answer": "private answer"}}},
    )
    retry["id"] = "retry"
    with pytest.raises(HTTPError) as exc:
        exchange(gateway, retry, authenticated=False)
    assert exc.value.code == 401
    final = exchange(gateway, retry)
    assert final["id"] == "retry" and final["result"]["structuredContent"] == {"ok": True}
    if gateway["seen"]:
        forwarded = gateway["seen"][-1]
        assert forwarded["params"]["name"] == "read_file"
        assert forwarded["params"]["requestState"] == OPAQUE_STATE
        assert forwarded["params"]["inputResponses"] == retry["params"]["inputResponses"]
    assert list_leases(gateway["leases"])["leases"][0]["use_count"] == 2
    revoke_lease(gateway["leases"], gateway["lease"]["lease"]["id"])
    count = len(gateway["seen"])
    denied = exchange(gateway, retry)
    assert "lease.revoked" in denied["error"]["message"]
    assert len(gateway["seen"]) == count
    assert "private answer" not in json.dumps(gateway["records"])
    assert OPAQUE_STATE not in json.dumps(gateway["records"])
    assert any(record.get("metadata", {}).get("mrtr", {}).get("continuation") for record in gateway["records"])

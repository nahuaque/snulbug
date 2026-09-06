from __future__ import annotations

import base64
import json
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import jwt
import pytest
import uvicorn

from snulbug import create_lease, list_leases, revoke_lease
from snulbug.mcp_auth import mcp_scope_target
from snulbug.mcp_protocol import (
    CLIENT_CAPABILITIES_META,
    DEFAULT_MCP_PROTOCOL_VERSION,
    IMPLEMENTATION_META,
    LATEST_MCP_SPEC_VERSION,
    PROTOCOL_VERSION_META,
    SERVER_INFO_META,
    decode_mcp_header,
    discovery_issues,
    discovery_request,
    discovery_result,
    encode_mcp_header,
    mcp_request,
    modern_request_headers,
    protocol_coverage,
    protocol_profile,
    validate_modern_request,
)
from snulbug.mcp_schemas import discover_mcp_schemas, normalize_mcp_schema_catalog, normalize_mcp_schema_methods
from snulbug.mcp_spec_conformance import run_mcp_spec_conformance
from snulbug.proxy import create_proxy_application
from snulbug.redaction import build_audit_event
from snulbug.share import ShareMcpSpecDoctorCheck
from snulbug.share_doctor import ShareDoctorContext


def test_profiles_distinguish_latest_from_default_and_coverage():
    assert DEFAULT_MCP_PROTOCOL_VERSION == "2025-11-25"
    assert LATEST_MCP_SPEC_VERSION == "2026-07-28"
    assert protocol_profile(DEFAULT_MCP_PROTOCOL_VERSION).discovery_method == "initialize"
    assert protocol_profile(LATEST_MCP_SPEC_VERSION).discovery_method == "server/discover"
    coverage = protocol_coverage(LATEST_MCP_SPEC_VERSION)
    assert coverage["complete"] is False
    assert {item["support"] for item in coverage["requirements"]} == {"supported", "untested"}
    assert (
        next(item for item in coverage["requirements"] if item["id"] == "subscriptions.stdio")["support"] == "supported"
    )
    with pytest.raises(ValueError, match="Unknown MCP"):
        protocol_profile("2099-01-01")


def test_requests_and_catalog_methods_follow_the_selected_revision():
    legacy = discovery_request(DEFAULT_MCP_PROTOCOL_VERSION)
    assert legacy["method"] == "initialize"
    assert legacy["params"]["protocolVersion"] == DEFAULT_MCP_PROTOCOL_VERSION
    assert "_meta" not in legacy["params"]
    modern = discovery_request(LATEST_MCP_SPEC_VERSION)
    assert modern["method"] == "server/discover"
    assert modern["params"]["_meta"][PROTOCOL_VERSION_META] == LATEST_MCP_SPEC_VERSION
    assert modern["params"]["_meta"][CLIENT_CAPABILITIES_META] == {}
    assert "initialize" not in normalize_mcp_schema_methods(None, protocol_version=LATEST_MCP_SPEC_VERSION)
    with pytest.raises(ValueError, match="instead of initialize"):
        mcp_request("initialize", version=LATEST_MCP_SPEC_VERSION, request_id=1)


@pytest.fixture(params=[False, True], ids=["proxy", "facade"])
def modern_gateway(request, tmp_path):
    policy = Path(__file__).parents[1] / "snulbug/builtin_presets/mcp/tunnel-safe.snulbug/policy.lua"
    record_path = tmp_path / "records.jsonl"
    app = create_proxy_application(
        None if request.param else "http://127.0.0.1:1",
        policy,
        upstreams=[{"name": "unreachable", "url": "http://127.0.0.1:1/mcp"}] if request.param else None,
        record_out=record_path,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
        # The modern profile must ignore obsolete session configuration.
        streamable_http_require_session_id=True,
    )
    with running_gateway(app) as url:
        yield url, record_path


@contextmanager
def running_gateway(app):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            assert server.started
            yield f"http://127.0.0.1:{port}/mcp"
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            assert not thread.is_alive()


def post(url, payload, *, response_headers=None, **header_overrides):
    headers = {
        "Authorization": "Bearer local-dev-secret",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": LATEST_MCP_SPEC_VERSION,
        "Mcp-Method": payload.get("method", "server/discover") if isinstance(payload, dict) else "server/discover",
    }
    if isinstance(payload, dict):
        params = payload.get("params", {})
        if payload.get("method") in {"tools/call", "prompts/get", "resources/read"}:
            headers["Mcp-Name"] = encode_mcp_header(params.get("name", params.get("uri", "")))
    headers.update(header_overrides)
    headers = {key: value for key, value in headers.items() if value is not None}
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=5) as response:
            if response_headers is not None:
                response_headers.update({key.lower(): value for key, value in response.headers.items()})
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        body = exc.read()
        return exc.code, json.loads(body) if body.startswith(b"{") else body.decode()


def test_discovery_runs_through_authenticated_gateway_and_records_evidence(modern_gateway, monkeypatch):
    from snulbug import proxy

    written = threading.Event()
    append = proxy.append_record

    def append_and_signal(*args, **kwargs):
        append(*args, **kwargs)
        written.set()

    monkeypatch.setattr(proxy, "append_record", append_and_signal)
    url, record_path = modern_gateway
    request = discovery_request(LATEST_MCP_SPEC_VERSION)
    status, payload = post(url, request, **{"MCP-Session-Id": "obsolete session"})
    assert status == 200
    assert discovery_issues(payload, version=LATEST_MCP_SPEC_VERSION, request_id=request["id"]) == []
    assert payload["result"]["_meta"][SERVER_INFO_META]["name"] == "snulbug"
    assert payload["result"]["_meta"][IMPLEMENTATION_META]["implementation"] == "request-stream-preview"
    assert payload["result"]["capabilities"]["tools"] == {}
    assert payload["result"]["cacheScope"] == "private"
    assert payload["result"]["ttlMs"] == 0
    assert written.wait(timeout=2)
    records = [json.loads(line) for line in record_path.read_text().splitlines()]
    assert len(records) == 1
    assert "server/discover" in json.dumps(records)
    audit = build_audit_event(records[0])
    assert audit["mcp"]["protocol_version"] == LATEST_MCP_SPEC_VERSION
    assert audit["mcp"]["client"]["name"] == "snulbug"
    assert "local-dev-secret" not in record_path.read_text()


def test_discovery_does_not_bypass_bearer_auth(modern_gateway):
    status, _ = post(modern_gateway[0], discovery_request(LATEST_MCP_SPEC_VERSION), Authorization=None)
    assert status == 401


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("wrong_method_header", -32020),
        ("missing_version_header", -32020),
        ("missing_capabilities", -32602),
        ("wrong_version", -32022),
        ("extra_params", -32602),
        ("boolean_id", -32600),
    ],
)
def test_modern_discovery_rejects_invalid_envelopes(modern_gateway, mutation, code):
    payload = discovery_request(LATEST_MCP_SPEC_VERSION)
    headers = {}
    if mutation == "wrong_method_header":
        headers["Mcp-Method"] = "tools/call"
    elif mutation == "missing_version_header":
        headers["MCP-Protocol-Version"] = None
    elif mutation == "missing_capabilities":
        del payload["params"]["_meta"][CLIENT_CAPABILITIES_META]
    elif mutation == "wrong_version":
        payload["params"]["_meta"][PROTOCOL_VERSION_META] = "2099-01-01"
        headers["MCP-Protocol-Version"] = "2099-01-01"
    elif mutation == "extra_params":
        payload["params"]["name"] = "unexpected"
    elif mutation == "boolean_id":
        payload["id"] = True
    status, response = post(modern_gateway[0], payload, **headers)
    assert status == 400
    assert response["error"]["code"] == code


def test_preview_rejects_unimplemented_methods_instead_of_forwarding(modern_gateway):
    request = mcp_request("tasks/list", version=LATEST_MCP_SPEC_VERSION, request_id=2)
    status, payload = post(modern_gateway[0], request)
    assert status == 404
    assert payload["error"]["code"] == -32601
    assert "not implemented" in payload["error"]["message"]


def test_schema_discovery_and_share_doctor_use_the_live_gateway(modern_gateway, tmp_path):
    url, _ = modern_gateway
    catalog = discover_mcp_schemas(
        url=url,
        methods=["server/discover"],
        protocol_version=LATEST_MCP_SPEC_VERSION,
        token="local-dev-secret",
    )
    assert catalog["ok"] is True
    assert catalog["server"]["serverInfo"]["name"] == "snulbug"
    assert catalog["server"]["supportedVersions"] == [LATEST_MCP_SPEC_VERSION]
    assert normalize_mcp_schema_catalog(catalog)["hash"] == catalog["hash"]
    context = ShareDoctorContext(
        share_dir=tmp_path,
        manifest={},
        session={},
        client={},
        config_path=tmp_path / "snulbug.toml",
        provider="generic",
        url=url,
        headers={"Authorization": "Bearer local-dev-secret"},
        timeout=5,
        live_checks=True,
        status={},
        proxy_config={"streamable_http_protocol_version": LATEST_MCP_SPEC_VERSION},
    )
    report = ShareMcpSpecDoctorCheck().run(context)
    checks = {item["id"]: item for item in report.checks}
    assert checks["mcp2026.server.discovery"]["status"] == "pass"
    assert checks["mcp2026.coverage.transport.streaming"]["status"] == "pass"
    assert checks["mcp2026.coverage.requests.multi_round_trip"]["status"] == "pass"
    assert checks["mcp2026.coverage.subscriptions.stdio"]["status"] == "pass"
    assert report.artifacts["mcp_spec"]["ok"] is True
    assert report.artifacts["mcp_spec"]["status"] == "review"
    assert report.artifacts["mcp_spec"]["conformance_complete"] is False
    assert not any("mcp2025" in item for item in checks)


def test_offline_doctor_never_probes_and_reports_unsupported_versions(monkeypatch):
    def unexpected_probe(*args, **kwargs):
        pytest.fail("offline doctor must not make network calls")

    monkeypatch.setattr("snulbug.mcp_spec_conformance.fetch_mcp_jsonrpc", unexpected_probe)
    result = run_mcp_spec_conformance(url="https://example.test/mcp", protocol_version=LATEST_MCP_SPEC_VERSION)
    checks = {item["id"]: item for item in result["checks"]}
    assert checks["mcp2026.server.discovery"]["details"]["verification"] == "untested"
    assert result["result"]["ok"] is True
    assert result["result"]["status"] == "review"
    assert result["result"]["conformance_complete"] is False
    unknown = run_mcp_spec_conformance(url="https://example.test/mcp", protocol_version="2099-01-01")
    assert unknown["result"]["ok"] is False
    assert unknown["checks"][0]["status"] == "fail"
    legacy = run_mcp_spec_conformance(url="http://localhost/mcp")
    assert legacy["result"]["spec_version"] == DEFAULT_MCP_PROTOCOL_VERSION
    assert legacy["result"]["latest_spec_version"] == LATEST_MCP_SPEC_VERSION


@pytest.mark.parametrize(
    "field,value",
    [("ttlMs", True), ("cacheScope", "shared"), ("cacheScope", []), ("cacheScope", {}), ("supportedVersions", [])],
)
def test_discovery_validation_rejects_invalid_success_results(field, value):
    result = discovery_result(LATEST_MCP_SPEC_VERSION)
    result[field] = value
    assert discovery_issues(
        {"jsonrpc": "2.0", "id": 1, "result": result}, version=LATEST_MCP_SPEC_VERSION, request_id=1
    )


def test_discovery_validation_rejects_boolean_response_id():
    assert discovery_issues(
        {"jsonrpc": "2.0", "id": True, "result": discovery_result(LATEST_MCP_SPEC_VERSION)},
        version=LATEST_MCP_SPEC_VERSION,
        request_id=1,
    )


def test_oauth_treats_discovery_as_protocol_setup_after_authentication():
    target = mcp_scope_target(json.dumps(discovery_request(LATEST_MCP_SPEC_VERSION)).encode())
    assert target["allow_without_scope_map"] is True


@pytest.fixture(params=[False, True], ids=["proxy", "facade"])
def forwarding_gateway(request, tmp_path):
    seen = []
    mode = {"response": "complete"}

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((payload, {k.lower(): v for k, v in self.headers.items()}))
            result = {"resultType": "complete"}
            if payload["method"] == "tools/list":
                result["tools"] = [{"name": "read_file", "inputSchema": {"type": "object"}}]
            else:
                result["content"] = [{"type": "text", "text": "done"}]
            if mode["response"] == "mrtr":
                result = {"resultType": "input_required", "inputRequests": {"private": {"method": "roots/list"}}}
            elif mode["response"] == "legacy":
                result.pop("resultType")
            body = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode()
            if mode["response"] == "oversized":
                body += b" " * (256 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if mode["response"] == "sse" else "application/json")
            self.send_header("Mcp-Session-Id", "must-not-escape")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    lease_file = tmp_path / "leases.json"
    tool = "files.read_file" if request.param else "read_file"
    lease = create_lease(lease_file, task="Read project", allow_tools=[tool], ttl="30m", token="sbl_test-token")
    policy = tmp_path / "policy.lua"
    policy.write_text("""return function(request, context)
      if request.headers.authorization ~= "Bearer local-dev-secret" then
        return {action="reject", status=401, body="unauthorized"}
      end
      if request.headers["x-deny"] == "yes" then
        return {action="reject", status=403, body="policy denied"}
      end
      return {action="continue"}
    end""")
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_proxy_application(
        None if request.param else origin,
        policy,
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if request.param else None,
        lease_file=lease_file,
        lease_required=True,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
        streamable_http_require_session_id=True,
    )
    try:
        with running_gateway(app) as url:
            yield {
                "url": url,
                "seen": seen,
                "mode": mode,
                "tool": tool,
                "lease_file": lease_file,
                "lease": lease,
                "origin": origin,
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def call_request(gateway, **params):
    return mcp_request(
        "tools/call",
        version=LATEST_MCP_SPEC_VERSION,
        request_id=7,
        params={"name": gateway["tool"], "arguments": {}, **params},
    )


def test_modern_calls_need_no_handshake_and_recheck_auth_and_lease(forwarding_gateway):
    gateway = forwarding_gateway
    payload = call_request(gateway)
    payload["params"]["_meta"][CLIENT_CAPABILITIES_META] = {"sampling": {}}
    status, response = post(
        gateway["url"],
        payload,
        **{"x-snulbug-lease": "sbl_test-token", "MCP-Session-Id": "obsolete", "Last-Event-ID": "obsolete"},
    )
    assert status == 200
    assert response["result"]["resultType"] == "complete"
    upstream, headers = gateway["seen"][0]
    assert upstream["params"]["name"] == "read_file"
    assert upstream["params"]["_meta"][CLIENT_CAPABILITIES_META] == {"sampling": {}}
    assert headers["mcp-name"] == "read_file"
    assert headers["mcp-method"] == "tools/call"
    assert "mcp-session-id" not in headers and "last-event-id" not in headers
    assert list_leases(gateway["lease_file"])["leases"][0]["use_count"] == 1
    assert post(gateway["url"], payload, Authorization=None)[0] == 401
    assert post(gateway["url"], payload, **{"x-snulbug-lease": "sbl_test-token", "x-deny": "yes"})[0] == 403
    assert "lease.missing" in post(gateway["url"], payload)[1]["error"]["message"]
    payload["params"]["_meta"][CLIENT_CAPABILITIES_META] = {}
    assert post(gateway["url"], payload, **{"x-snulbug-lease": "sbl_test-token"})[0] == 200
    assert gateway["seen"][1][0]["params"]["_meta"][CLIENT_CAPABILITIES_META] == {}
    revoke_lease(gateway["lease_file"], gateway["lease"]["lease"]["id"])
    assert (
        "lease.revoked" in post(gateway["url"], payload, **{"x-snulbug-lease": "sbl_test-token"})[1]["error"]["message"]
    )
    assert len(gateway["seen"]) == 2


def test_modern_list_fanout_preserves_result_type(forwarding_gateway):
    gateway = forwarding_gateway
    headers = {}
    status, response = post(
        gateway["url"],
        mcp_request("tools/list", version=LATEST_MCP_SPEC_VERSION, request_id=3),
        response_headers=headers,
    )
    assert status == 200
    assert response["result"]["resultType"] == "complete"
    assert response["result"]["tools"][0]["name"] == gateway["tool"]
    assert "mcp-session-id" not in headers


@pytest.mark.parametrize("name_header", [None, "wrong_tool", "=?base64?invalid!?="])
def test_name_mismatch_does_not_consume_lease_or_forward(forwarding_gateway, name_header):
    gateway = forwarding_gateway
    status, response = post(
        gateway["url"], call_request(gateway), **{"Mcp-Name": name_header, "x-snulbug-lease": "sbl_test-token"}
    )
    assert status == 400 and response["error"]["code"] == -32020
    assert not gateway["seen"]
    assert list_leases(gateway["lease_file"])["leases"][0]["use_count"] == 0


@pytest.mark.parametrize("field", ["inputResponses", "requestState", "task"])
def test_modern_preview_blocks_malformed_continuations_and_tasks(forwarding_gateway, field):
    gateway = forwarding_gateway
    status, response = post(
        gateway["url"], call_request(gateway, **{field: []}), **{"x-snulbug-lease": "sbl_test-token"}
    )
    assert status == 400 and response["error"]["code"] == -32602
    assert not gateway["seen"]


@pytest.mark.parametrize("mode", ["mrtr", "legacy", "oversized"])
def test_modern_preview_fails_closed_on_unsupported_upstream_response(forwarding_gateway, mode):
    gateway = forwarding_gateway
    gateway["mode"]["response"] = mode
    status, response = post(gateway["url"], call_request(gateway), **{"x-snulbug-lease": "sbl_test-token"})
    assert status == 502
    assert "error" in response and "inputRequests" not in json.dumps(response)


@pytest.mark.parametrize("name", ["read_file", "a b", " padded ", "=?base64?literal?=", "caf\u00e9", "line\nfeed"])
def test_modern_named_headers_roundtrip(name):
    payload = mcp_request("resources/read", version=LATEST_MCP_SPEC_VERSION, request_id=1, params={"uri": name})
    headers = modern_request_headers({}, payload)
    assert decode_mcp_header(headers["mcp-name"]) == name
    assert validate_modern_request(payload, headers, version=LATEST_MCP_SPEC_VERSION) is None


@pytest.mark.parametrize("header", ["mcp-name", "mcp-method", "mcp-protocol-version"])
def test_modern_rejects_ambiguous_duplicate_mirrors(header):
    payload = mcp_request("tools/call", version=LATEST_MCP_SPEC_VERSION, request_id=1, params={"name": "read_file"})
    headers = modern_request_headers({}, payload)
    headers[header] = [headers[header], headers[header]]
    assert validate_modern_request(payload, headers, version=LATEST_MCP_SPEC_VERSION)["error"]["code"] == -32020


@pytest.mark.parametrize("continuation", [False, True])
def test_modern_oauth_scopes_lease_and_lua_compose_on_every_call(forwarding_gateway, tmp_path, continuation):
    gateway = forwarding_gateway
    secret = "test-signing-key-for-modern-oauth-32-bytes"
    jwks = tmp_path / "jwks.json"
    jwks.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "oct",
                        "kid": "test",
                        "alg": "HS256",
                        "k": base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                    }
                ]
            }
        )
    )
    policy = tmp_path / "oauth.lua"
    policy.write_text("""return function(request, context)
      if auth.subject() ~= "user-1" then return {action="reject", status=403, body="wrong subject"} end
      return {action="continue"}
    end""")
    facade = gateway["tool"].startswith("files.")
    config = {
        "mode": "oauth-resource",
        "issuer": "https://issuer.example.test",
        "resource": "https://mcp.example.test/mcp",
        "audience": "https://mcp.example.test/mcp",
        "required_scopes": ["mcp:connect"],
        "jwks_path": jwks,
        "scope_map": {"mcp:read": ["tools/call:" + gateway["tool"]]},
    }
    app = create_proxy_application(
        None if facade else gateway["origin"],
        policy,
        upstreams=[{"name": "files", "url": gateway["origin"] + "/mcp"}] if facade else None,
        auth_config=config,
        lease_file=gateway["lease_file"],
        lease_required=True,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )

    def token(scope, subject="user-1"):
        return jwt.encode(
            {
                "iss": config["issuer"],
                "aud": config["audience"],
                "sub": subject,
                "scope": scope,
                "exp": int(time.time()) + 300,
            },
            secret,
            algorithm="HS256",
            headers={"kid": "test"},
        )

    payload = call_request(gateway)
    if continuation:
        payload["params"].update(requestState="opaque", inputResponses={"answer": {"action": "accept"}})
    with running_gateway(app) as url:
        headers = {"Authorization": "Bearer " + token("mcp:connect"), "x-snulbug-lease": "sbl_test-token"}
        assert post(url, payload, **headers)[0] == 403
        assert not gateway["seen"]
        headers["Authorization"] = "Bearer " + token("mcp:connect mcp:read")
        assert post(url, payload, **headers)[0] == 200
        assert "authorization" not in gateway["seen"][0][1]
        headers["Authorization"] = "Bearer " + token("mcp:connect mcp:read", "user-2")
        assert post(url, payload, **headers)[0] == 403
        assert len(gateway["seen"]) == 1

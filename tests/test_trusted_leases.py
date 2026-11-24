from __future__ import annotations

import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from test_proxy import (
    make_oauth_token,
    oauth_auth_config,
    run_asgi,
    start_mcp_upstream,
    start_upstream,
    write_hs256_jwks,
    write_policy,
)

from snulbug import (
    TRUSTED_LEASE_SCOPE_KEY,
    LeasePolicyConfig,
    TrustedLeaseSelection,
    create_lease,
    create_proxy_application,
    list_leases,
    revoke_lease,
    select_mcp_lease,
)
from snulbug.leases import enforce_mcp_lease_policy, preview_mcp_lease_catalog, preview_mcp_lease_policy
from snulbug.mcp_protocol import LATEST_MCP_SPEC_VERSION, mcp_request, modern_request_headers
from snulbug.upstream_transports import HttpUpstreamTransport

CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {}}}


def selected_scope(created, *, trusted, header="x-snulbug-lease", **scope):
    if trusted:
        return select_mcp_lease(scope, lease_id=created["lease"]["id"])
    return {**scope, "headers": [(header.encode(), created["token"].encode())]}


@pytest.fixture(params=[False, True], ids=["header", "trusted"])
def selection(request):
    return request.param


def test_selection_is_typed_request_local_and_cannot_silently_replace_another():
    parent = {"type": "http", "state": {}}
    selected = select_mcp_lease(parent, lease_id="lease_one")
    assert TRUSTED_LEASE_SCOPE_KEY not in parent
    assert selected[TRUSTED_LEASE_SCOPE_KEY] == TrustedLeaseSelection("lease_one")
    assert select_mcp_lease(selected, lease_id="lease_one") == selected
    with pytest.raises(ValueError, match="already has"):
        select_mcp_lease(selected, lease_id="lease_two")


@pytest.mark.parametrize("lease_id", [None, 1, "", " lease_one", "lease_one\n", "x" * 257])
def test_invalid_trusted_reference_is_not_accepted(lease_id):
    with pytest.raises(ValueError, match="lease_id"):
        select_mcp_lease({}, lease_id=lease_id)


def test_preview_discovery_and_execution_share_one_budget(tmp_path, selection):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"], max_calls=1)
    config = LeasePolicyConfig(path, required=True)
    scope = selected_scope(created, trusted=selection)
    assert preview_mcp_lease_policy(CALL, scope, config=config)[0]
    assert preview_mcp_lease_catalog(scope, config=config)["allowed"]
    for method in ["initialize", "tools/list", "resources/list", "prompts/list"]:
        assert enforce_mcp_lease_policy({"method": method, "params": {}}, scope, config=config)[0]
    assert list_leases(path)["leases"][0]["use_count"] == 0
    allowed, metadata = enforce_mcp_lease_policy(CALL, scope, config=config)
    assert allowed
    assert metadata["id"] == created["lease"]["id"]
    assert metadata["selection"] == ("trusted" if selection else "header")
    assert created["token"] not in json.dumps(metadata)
    assert metadata["use_count"] == 1
    allowed, metadata = enforce_mcp_lease_policy(CALL, scope, config=config)
    assert not allowed
    assert metadata["reason_code"] == "lease.max_calls_exceeded"
    assert not preview_mcp_lease_catalog(scope, config=config)["allowed"]
    assert list_leases(path)["leases"][0]["use_count"] == 1


@pytest.mark.parametrize(
    ("allow", "arguments", "reason"),
    [
        ({"allow_tools": ["other"]}, {}, "lease.tool_not_allowed"),
        ({"allow_paths": ["project"]}, {"path": "../private"}, "lease.path_not_allowed"),
        ({"allow_hosts": ["example.test"]}, {"url": "https://other.test"}, "lease.host_not_allowed"),
        ({"allow_commands": ["git"]}, {"command": "rm file"}, "lease.command_not_allowed"),
    ],
)
def test_both_selection_paths_enforce_restrictions(tmp_path, selection, allow, arguments, reason):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", **{"allow_tools": ["read_file"], **allow})
    request = {**CALL, "params": {"name": "read_file", "arguments": arguments}}
    allowed, metadata = enforce_mcp_lease_policy(
        request, selected_scope(created, trusted=selection), config=LeasePolicyConfig(path, required=True)
    )
    assert not allowed
    assert metadata["reason_code"] == reason
    assert list_leases(path)["leases"][0]["use_count"] == 0


AUTH = {
    "enabled": True,
    "subject": "user-1",
    "issuer": "https://issuer.test",
    "tenant": "tenant-a",
    "groups": ["devs"],
    "client_id": "agent",
    "profile_id": "primary",
}


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("subject", "user-2", "lease.subject_not_allowed"),
        ("issuer", "https://other.test", "lease.issuer_not_allowed"),
        ("tenant", "tenant-b", "lease.tenant_not_allowed"),
        ("groups", ["other"], "lease.group_not_allowed"),
        ("client_id", "other", "lease.client_id_not_allowed"),
        ("profile_id", "other", "lease.auth_profile_not_allowed"),
        ("enabled", False, "lease.auth_missing"),
    ],
)
def test_both_selection_paths_enforce_identity_bindings(tmp_path, selection, field, value, reason):
    path = tmp_path / "leases.json"
    created = create_lease(
        path,
        task="Inspect",
        allow_tools=["read_file"],
        allow_subjects=[AUTH["subject"]],
        allow_issuers=[AUTH["issuer"]],
        allow_tenants=[AUTH["tenant"]],
        allow_groups=AUTH["groups"],
        allow_client_ids=[AUTH["client_id"]],
        allow_auth_profiles=[AUTH["profile_id"]],
    )
    scope = selected_scope(created, trusted=selection, lua={"auth": {**AUTH, field: value}})
    config = LeasePolicyConfig(path, required=True)
    allowed, metadata = enforce_mcp_lease_policy(CALL, scope, config=config)
    assert not allowed
    assert metadata["reason_code"] == reason
    assert preview_mcp_lease_catalog(scope, config=config)["reason_code"] == reason
    scope["lua"]["auth"] = AUTH
    assert enforce_mcp_lease_policy(CALL, scope, config=config)[0]
    assert list_leases(path)["leases"][0]["use_count"] == 1


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_persisted_expiry_and_revocation_apply_to_both_selections(tmp_path, selection, state, monkeypatch):
    import snulbug.leases as leases

    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    scope = selected_scope(created, trusted=selection)
    config = LeasePolicyConfig(path, required=True)
    assert preview_mcp_lease_policy(CALL, scope, config=config)[0]
    if state == "revoked":
        revoke_lease(path, created["lease"]["id"])
    else:
        future = leases._now() + timedelta(days=1)
        monkeypatch.setattr(leases, "_now", lambda: future)
    assert enforce_mcp_lease_policy(CALL, scope, config=config)[1]["reason_code"] == f"lease.{state}"
    assert preview_mcp_lease_catalog(scope, config=config)["reason_code"] == f"lease.{state}"
    assert list_leases(path)["leases"][0]["use_count"] == 0


@pytest.mark.parametrize("presented", ["other", "invalid", "duplicate", "empty"])
def test_header_cannot_override_or_fall_back_from_a_trusted_selection(tmp_path, presented):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    other = create_lease(path, task="Other", allow_tools=["*"])
    token = {"other": other["token"], "invalid": "not-a-credential", "empty": ""}.get(presented, created["token"])
    headers = [(b"X-Snulbug-Lease", token.encode())]
    if presented == "duplicate":
        headers.append((b"x-snulbug-lease", created["token"].encode()))
    scope = select_mcp_lease({"headers": headers}, lease_id=created["lease"]["id"])
    config = LeasePolicyConfig(path, required=False)
    allowed, metadata = enforce_mcp_lease_policy(CALL, scope, config=config)
    assert not allowed
    assert metadata["reason_code"] in {"lease.selection_conflict", "lease.invalid"}
    assert not preview_mcp_lease_catalog(scope, config=config)["allowed"]
    assert all(lease["use_count"] == 0 for lease in list_leases(path)["leases"])


def test_matching_header_and_trusted_reference_consume_only_once(tmp_path):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"], max_calls=1)
    scope = select_mcp_lease(selected_scope(created, trusted=False), lease_id=created["lease"]["id"])
    assert enforce_mcp_lease_policy(CALL, scope, config=LeasePolicyConfig(path, required=True))[0]
    assert list_leases(path)["leases"][0]["use_count"] == 1


@pytest.mark.parametrize("facade", [False, True], ids=["proxy", "facade"])
def test_discovery_rejects_conflicting_selection_before_forwarding(tmp_path, facade):
    server, seen = start_upstream()
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    other = create_lease(path, task="Other", allow_tools=["*"])
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_proxy_application(
        None if facade else origin,
        write_policy(tmp_path, "continue"),
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        lease_file=path,
        lease_required=True,
    )

    async def host(scope, receive, send):
        await app(select_mcp_lease(scope, lease_id=created["lease"]["id"]), receive, send)

    try:
        response = run_asgi(
            host,
            headers=[(b"x-snulbug-lease", other["token"].encode())],
            body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
        )
        assert "lease.selection_conflict" in json.loads(response[1]["body"])["error"]["message"]
        assert seen["count"] == 0
        assert all(lease["use_count"] == 0 for lease in list_leases(path)["leases"])
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("facade", [False, True], ids=["proxy", "facade"])
def test_selected_catalog_projection_is_non_consuming_and_task_specific(tmp_path, selection, facade):
    server, _seen = start_mcp_upstream({"read_file": "Read", "write_file": "Write"})
    path = tmp_path / "leases.json"
    tool = "files.read_file" if facade else "read_file"
    created = create_lease(path, task="Inspect", allow_tools=[tool], max_calls=1)
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_proxy_application(
        None if facade else origin,
        write_policy(tmp_path, "continue"),
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        lease_file=path,
        lease_required=True,
        catalog_projection="policy-aware",
    )

    async def host(scope, receive, send):
        if selection:
            scope = select_mcp_lease(scope, lease_id=created["lease"]["id"])
        await app(scope, receive, send)

    headers = [] if selection else [(b"x-snulbug-lease", created["token"].encode())]
    try:
        response = run_asgi(host, headers=headers, body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
        assert [item["name"] for item in json.loads(response[1]["body"])["result"]["tools"]] == [tool]
        assert list_leases(path)["leases"][0]["use_count"] == 0
        run_asgi(host, headers=headers, body=json.dumps({**CALL, "params": {"name": tool, "arguments": {}}}).encode())
        assert list_leases(path)["leases"][0]["use_count"] == 1
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("state", ["revoked", "conflicting"])
def test_bodyless_stream_open_cannot_bypass_selection_denial(tmp_path, state):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    if state == "revoked":
        revoke_lease(path, created["lease"]["id"])
    app = create_proxy_application(
        "http://127.0.0.1:1",
        write_policy(tmp_path, "continue"),
        lease_file=path,
        lease_required=True,
        streamable_http_allow_get=True,
    )

    async def host(scope, receive, send):
        await app(select_mcp_lease(scope, lease_id=created["lease"]["id"]), receive, send)

    headers = [(b"accept", b"text/event-stream")]
    if state == "conflicting":
        headers.append((b"x-snulbug-lease", b"invalid-other-credential"))
    response = run_asgi(host, method="GET", headers=headers)
    assert response[0]["status"] == 403
    reason = "lease.revoked" if state == "revoked" else "lease.selection_conflict"
    assert reason in json.loads(response[1]["body"])["error"]["message"]
    assert list_leases(path)["leases"][0]["use_count"] == 0


@pytest.mark.parametrize("spoof", ["lease_one", {"lease_id": "lease_one"}, None])
def test_untyped_trusted_context_fails_closed_even_with_a_valid_header(tmp_path, spoof):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    scope = {**selected_scope(created, trusted=False), TRUSTED_LEASE_SCOPE_KEY: spoof}
    allowed, metadata = enforce_mcp_lease_policy(CALL, scope, config=LeasePolicyConfig(path))
    assert not allowed
    assert metadata["reason_code"] == "lease.selection_invalid"
    assert list_leases(path)["leases"][0]["use_count"] == 0


def test_unknown_exact_reference_never_falls_back_to_an_available_lease(tmp_path):
    path = tmp_path / "leases.json"
    create_lease(path, task="Inspect", allow_tools=["*"])
    scope = select_mcp_lease({}, lease_id="lease_missing")
    assert enforce_mcp_lease_policy(CALL, scope, config=LeasePolicyConfig(path))[1]["reason_code"] == "lease.invalid"


@pytest.mark.parametrize("broken", ["missing", "invalid"])
def test_selected_lease_requires_a_readable_valid_store(tmp_path, selection, broken):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    scope = selected_scope(created, trusted=selection)
    if broken == "missing":
        path.unlink()
    else:
        path.write_text("not json")
    config = LeasePolicyConfig(path, required=False)
    assert enforce_mcp_lease_policy(CALL, scope, config=config)[1]["reason_code"] == f"lease.store_{broken}"
    assert not preview_mcp_lease_catalog(scope, config=config)["allowed"]


def consume_in_worker(path, lease_id, token, trusted):
    scope = select_mcp_lease({}, lease_id=lease_id) if trusted else {"headers": [(b"x-snulbug-lease", token.encode())]}
    return enforce_mcp_lease_policy(CALL, scope, config=LeasePolicyConfig(path, required=True))[0]


@pytest.mark.parametrize("processes", [False, True], ids=["threads", "processes"])
def test_mixed_selection_workers_share_the_final_call_and_restart_state(tmp_path, processes):
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"], max_calls=1)
    args = (path, created["lease"]["id"], created["token"])
    executor = ProcessPoolExecutor if processes else ThreadPoolExecutor
    options = {"mp_context": multiprocessing.get_context("spawn")} if processes else {}
    with executor(max_workers=4, **options) as pool:
        futures = [pool.submit(consume_in_worker, *args, bool(index % 2)) for index in range(12)]
        assert sum(future.result(timeout=30) for future in futures) == 1
    assert list_leases(path)["leases"][0]["use_count"] == 1
    with ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn")) as pool:
        assert not pool.submit(consume_in_worker, *args, True).result(timeout=30)


@pytest.mark.parametrize("facade", [False, True], ids=["proxy", "facade"])
@pytest.mark.parametrize("header", ["x-snulbug-lease", "x-task-ticket"])
def test_gateway_uses_trusted_preview_and_does_not_forward_lease_headers(tmp_path, selection, facade, header):
    server, seen = start_upstream()
    path = tmp_path / "leases.json"
    tool = "files.read_file" if facade else "read_file"
    created = create_lease(path, task="Inspect", allow_tools=[tool], max_calls=1)
    policy = tmp_path / "policy.lua"
    policy.write_text('return function(request, context) return lease.require() or {action="continue"} end')
    records = tmp_path / "records.jsonl"
    origin = f"http://127.0.0.1:{server.server_port}"

    def gateway():
        return create_proxy_application(
            None if facade else origin,
            policy,
            upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
            lease_file=path,
            lease_required=True,
            lease_header=header,
            record_out=records,
        )

    app = gateway()

    async def hosting_gateway(scope, receive, send):
        if selection:
            scope = select_mcp_lease(scope, lease_id=created["lease"]["id"])
        await app(scope, receive, send)

    headers = [(b"content-type", b"application/json"), (b"x-snulbug-renewal", b"private-renewal")]
    if not selection:
        headers.append((header.encode(), created["token"].encode()))
    if header != "x-snulbug-lease":
        headers.append((b"X-Snulbug-Lease", b"do-not-forward"))
    request = {**CALL, "params": {"name": tool, "arguments": {}}}
    try:
        response = run_asgi(hosting_gateway, headers=headers, body=json.dumps(request).encode())
        assert response[0]["status"] == 200
        assert seen["count"] == 1
        payload = json.loads(response[1]["body"])
        forwarded = payload["headers"]
        assert header not in forwarded
        assert "x-snulbug-lease" not in forwarded
        assert "x-snulbug-renewal" not in forwarded
        assert "private-renewal" not in json.dumps(payload)
        assert created["token"] not in json.dumps(payload)
        record = json.loads(records.read_text().splitlines()[0])
        assert created["token"] not in records.read_text()
        assert record["metadata"]["lease"]["id"] == created["lease"]["id"]
        assert record["metadata"]["lease_preview"]["id"] == created["lease"]["id"]
        assert list_leases(path)["leases"][0]["use_count"] == 1
        # Reconstruct the whole gateway: the budget is persisted, not cached in the scope.
        app = gateway()
        run_asgi(hosting_gateway, headers=headers, body=json.dumps(request).encode())
        assert seen["count"] == 1
    finally:
        server.shutdown()
        server.server_close()


def test_custom_lease_header_is_redacted_in_audit_even_when_raw_replay_is_requested(tmp_path):
    server, _seen = start_upstream()
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    audit = tmp_path / "audit.jsonl"
    app = create_proxy_application(
        f"http://127.0.0.1:{server.server_port}",
        write_policy(tmp_path, "continue"),
        lease_file=path,
        lease_required=True,
        lease_header="x-task-ticket",
        redact_records=False,
        event_sinks=[{"type": "audit_jsonl", "path": audit}],
    )
    try:
        run_asgi(app, headers=[(b"x-task-ticket", created["token"].encode())], body=json.dumps(CALL).encode())
        assert created["token"] not in audit.read_text()
        assert json.loads(audit.read_text())["request"]["headers"]["x-task-ticket"] == "[REDACTED]"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("case", ["valid", "wrong-subject", "missing-oauth", "wrong-audience", "missing-scope"])
def test_trusted_selection_does_not_bypass_oauth_or_lease_identity(tmp_path, case):
    server, seen = start_upstream()
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"], allow_subjects=["user-1"], max_calls=1)
    jwks, secret = write_hs256_jwks(tmp_path)
    app = create_proxy_application(
        f"http://127.0.0.1:{server.server_port}",
        write_policy(tmp_path, "continue"),
        lease_file=path,
        lease_required=True,
        auth_config=oauth_auth_config(jwks),
    )

    async def host(scope, receive, send):
        await app(select_mcp_lease(scope, lease_id=created["lease"]["id"]), receive, send)

    headers = [(b"content-type", b"application/json")]
    if case != "missing-oauth":
        token = make_oauth_token(
            secret,
            scopes=[] if case == "missing-scope" else ["mcp:connect"],
            subject="user-2" if case == "wrong-subject" else "user-1",
            extra_claims={"aud": "https://other.test/mcp"} if case == "wrong-audience" else None,
        )
        headers.append((b"authorization", f"Bearer {token}".encode()))
    try:
        response = run_asgi(host, headers=headers, body=json.dumps(CALL).encode())
        if case == "valid":
            assert seen["count"] == 1
            assert response[0]["status"] == 200
        else:
            assert seen["count"] == 0
            if case == "wrong-subject":
                assert "lease.subject_not_allowed" in json.loads(response[1]["body"])["error"]["message"]
            else:
                assert response[0]["status"] in {401, 403}
        assert list_leases(path)["leases"][0]["use_count"] == int(case == "valid")
    finally:
        server.shutdown()
        server.server_close()


def test_transport_plugin_receives_filtered_headers_not_the_selector(tmp_path, monkeypatch):
    import snulbug.proxy as proxy_module

    seen = []

    class ObservedTransport(HttpUpstreamTransport):
        async def forward(self, context):
            seen.append(context.scope)
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}).encode()
            return {"status": 200, "headers": [(b"content-type", b"application/json")], "body": body}

    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["files.read_file"])
    app = create_proxy_application(
        None,
        write_policy(tmp_path, "continue"),
        upstreams=[{"name": "files", "url": "http://127.0.0.1:1/mcp"}],
        lease_file=path,
        lease_required=True,
        lease_header="x-task-ticket",
    )
    monkeypatch.setattr(proxy_module, "get_upstream_transport", lambda name: ObservedTransport())

    async def host(scope, receive, send):
        await app(select_mcp_lease(scope, lease_id=created["lease"]["id"]), receive, send)

    response = run_asgi(
        host,
        headers=[(b"x-task-ticket", created["token"].encode()), (b"x-snulbug-lease", b"private-other-token")],
        body=json.dumps({**CALL, "params": {"name": "files.read_file"}}).encode(),
    )
    assert response[0]["status"] == 200
    assert len(seen) == 1
    assert TRUSTED_LEASE_SCOPE_KEY not in seen[0]
    assert not {b"x-task-ticket", b"x-snulbug-lease"}.intersection(name.lower() for name, _ in seen[0]["headers"])
    assert list_leases(path)["leases"][0]["use_count"] == 1


@pytest.mark.parametrize("source", ["header", "credential-id", "query", "body", "lua"])
def test_public_inputs_never_create_trusted_selection(tmp_path, source):
    server, seen = start_upstream()
    path = tmp_path / "leases.json"
    created = create_lease(path, task="Inspect", allow_tools=["read_file"])
    app = create_proxy_application(
        f"http://127.0.0.1:{server.server_port}",
        write_policy(tmp_path, "continue"),
        lease_file=path,
        lease_required=True,
    )
    lease_id = created["lease"]["id"]
    request = {**CALL, "lease_id": lease_id, TRUSTED_LEASE_SCOPE_KEY: {"lease_id": lease_id}}
    headers = [(b"content-type", b"application/json")]
    if source == "header":
        headers.extend([(b"x-snulbug-lease-id", lease_id.encode()), (b"snulbug.trusted_lease", lease_id.encode())])
    elif source == "credential-id":
        headers.append((b"x-snulbug-lease", lease_id.encode()))

    async def untrusted_lua_context(scope, receive, send):
        if source == "lua":
            scope = {**scope, "lua": {TRUSTED_LEASE_SCOPE_KEY: {"lease_id": lease_id}, "lease_id": lease_id}}
        await app(scope, receive, send)

    try:
        response = run_asgi(
            untrusted_lua_context,
            headers=headers,
            body=json.dumps(request).encode(),
            query_string=f"lease_id={lease_id}".encode() if source == "query" else b"",
        )
        reason = "lease.invalid" if source == "credential-id" else "lease.missing"
        assert reason in json.loads(response[1]["body"])["error"]["message"]
        assert seen["count"] == 0
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("facade", [False, True], ids=["proxy", "facade"])
def test_streaming_forwarding_also_consumes_custom_lease_header(tmp_path, selection, facade):
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            captured.append({key.lower(): value for key, value in self.headers.items()})
            request = json.loads(self.rfile.read(int(self.headers["content-length"])))
            body = json.dumps(
                {"jsonrpc": "2.0", "id": request["id"], "result": {"resultType": "complete", "content": []}}
            ).encode()
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(body) + 8))
            self.end_headers()
            self.wfile.write(b"data: " + body + b"\n\n")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    path = tmp_path / "leases.json"
    tool = "files.read_file" if facade else "read_file"
    created = create_lease(path, task="Inspect", allow_tools=[tool], max_calls=1)
    origin = f"http://127.0.0.1:{server.server_port}"
    app = create_proxy_application(
        None if facade else origin,
        write_policy(tmp_path, "continue"),
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        lease_file=path,
        lease_required=True,
        lease_header="x-task-ticket",
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )

    async def host(scope, receive, send):
        if selection:
            scope = select_mcp_lease(scope, lease_id=created["lease"]["id"])
        await app(scope, receive, send)

    request = mcp_request("tools/call", version=LATEST_MCP_SPEC_VERSION, request_id=1, params={"name": tool})
    headers = modern_request_headers(
        {"content-type": "application/json", "accept": "application/json, text/event-stream"}, request
    )
    headers["X-Snulbug-Lease"] = "do-not-forward"
    if not selection:
        headers["X-Task-Ticket"] = created["token"]
    try:
        response = run_asgi(
            host,
            headers=[(key.encode(), value.encode()) for key, value in headers.items()],
            body=json.dumps(request).encode(),
        )
        body = b"".join(item.get("body", b"") for item in response)
        assert json.loads(body.removeprefix(b"data: ").strip())["result"]["resultType"] == "complete"
        assert len(captured) == 1
        assert "x-task-ticket" not in captured[0]
        assert "x-snulbug-lease" not in captured[0]
        assert list_leases(path)["leases"][0]["use_count"] == 1
    finally:
        server.shutdown()
        server.server_close()

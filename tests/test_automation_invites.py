from __future__ import annotations

import asyncio
import base64
import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest

import snulbug.leases as leases
from snulbug import (
    close_mcp_share,
    create_mcp_share,
    create_mcp_share_invite,
    create_proxy_application,
    list_mcp_share_invites,
    revoke_mcp_share_invite,
)
from snulbug.config import load_mcp_proxy_config
from snulbug.proxy import proxy_config_run_kwargs
from snulbug.share import cleanup_mcp_share_invites
from snulbug.simulator import main as cli_main


@pytest.fixture
def clock(monkeypatch):
    current = [datetime(2026, 10, 16, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr(leases, "_now", lambda: current[0])
    return current


def automation(tmp_path, **options):
    create_mcp_share(
        tmp_path, provider="generic", public_url="https://mcp.example.test/mcp", token="share-secret", validate=False
    )
    return create_mcp_share_invite(
        tmp_path,
        recipient="nightly bot",
        task="Inspect project",
        capabilities=["project_readonly"],
        ttl="10m",
        renewable=True,
        renewal_ttl="1d",
        **options,
    )


def renew(tmp_path, invite, **options):
    args = {
        "invite_id": invite["invite"]["id"],
        "renewal_token": invite["renewal_token"],
        "bearer": "share-secret",
        "policy_capabilities": ["project_readonly"],
    }
    return leases.renew_lease(tmp_path / "leases.json", **{**args, **options})


def use(tmp_path, token):
    return leases.enforce_mcp_lease_policy(
        {"method": "tools/call", "params": {"name": "safe_read_file", "arguments": {"path": "README.md"}}},
        {"headers": [(b"x-snulbug-lease", token.encode())]},
        config=leases.LeasePolicyConfig(lease_file=tmp_path / "leases.json", required=True),
    )


def gateway(tmp_path, **overrides):
    config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    kwargs = proxy_config_run_kwargs(config)
    # These kwargs belong to the server, not the application factory.
    for key in ("host", "port", "state"):
        kwargs.pop(key, None)
    kwargs.update(overrides)
    return create_proxy_application(**kwargs)


def rpc(app, invite, *, credential=None, bearer="share-secret", params=None, method=leases.LEASE_RENEWAL_METHOD):
    async def request():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.test"
        ) as client:
            return await client.post(
                "/mcp",
                headers={
                    "authorization": "Bearer " + bearer,
                    "x-snulbug-renewal": credential if credential is not None else invite["renewal_token"],
                    "accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": "renew",
                    "method": method,
                    "params": params if params is not None else {"invite_id": invite["invite"]["id"]},
                },
            )

    return asyncio.run(request())


def test_automation_uses_same_lease_and_stores_no_plaintext_secrets(tmp_path, clock):
    invite = automation(tmp_path, max_calls=4)
    raw = (tmp_path / "leases.json").read_text()
    assert invite["renewal_token"].startswith("sbr_")
    assert invite["renewal_token"] not in raw
    assert invite["lease_token"] not in raw
    assert "share-secret" not in raw
    assert use(tmp_path, invite["lease_token"])[0]
    clock[0] += timedelta(minutes=6)
    renewed = renew(tmp_path, invite)
    assert renewed["lease"]["id"] == invite["lease"]["id"]
    assert renewed["lease"]["capabilities"] == ["project_readonly"]
    assert renewed["lease"]["use_count"] == 1
    assert renewed["lease"]["max_calls"] == 4
    assert renewed["token"] != invite["lease_token"]
    assert renewed["lease"]["renewal"]["renewal_count"] == 1
    assert len(leases.list_leases(tmp_path / "leases.json")["leases"]) == 2
    listed = list_mcp_share_invites(tmp_path)
    assert invite["renewal_token"] not in json.dumps(listed)
    assert renewed["token"] not in json.dumps(listed)
    assert listed["invitations"][0]["lease_expires_at"] == renewed["lease"]["expires_at"]
    packet = list_mcp_share_invites(tmp_path, include_setup=True)["invitations"][0]
    assert packet["headers"]["x-snulbug-lease"] == renewed["token"]
    assert packet["setup_snippets"]["automation"]["env"]["SNULBUG_RENEWAL_TOKEN"] == invite["renewal_token"]


def test_retries_are_idempotent_and_previous_token_has_bounded_overlap(tmp_path, clock):
    invite = automation(tmp_path)
    assert renew(tmp_path, invite)["token"] == invite["lease_token"]
    clock[0] += timedelta(minutes=6)
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: renew(tmp_path, invite), range(12)))
    assert len({response["token"] for response in responses}) == 1
    assert all(response["lease"]["renewal"]["generation"] == 1 for response in responses)
    assert use(tmp_path, invite["lease_token"])[0]
    clock[0] += timedelta(seconds=31)
    assert not use(tmp_path, invite["lease_token"])[0]
    assert use(tmp_path, responses[0]["token"])[0]


def test_restart_recovery_after_access_expiry_survives_cleanup(tmp_path, clock):
    invite = automation(tmp_path)
    clock[0] += timedelta(hours=3)
    assert use(tmp_path, invite["lease_token"])[1]["reason_code"] == "lease.expired"
    assert leases.cleanup_inactive_leases(tmp_path / "leases.json")["retained_renewable_count"] == 1
    assert cleanup_mcp_share_invites(tmp_path, stale_active=True)["removed_count"] == 0
    recovered = renew(tmp_path, invite)
    assert recovered["lease"]["id"] == invite["lease"]["id"]
    assert use(tmp_path, recovered["token"])[0]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"renewal_token": "wrong"}, "lease.renewal_invalid"),
        ({"invite_id": "invite_someone_else"}, "lease.renewal_invalid"),
        ({"bearer": None}, "lease.renewal_auth_required"),
        ({"bearer": "wrong"}, "lease.renewal_auth_required"),
        ({"policy_capabilities": []}, "lease.renewal_capability_removed"),
    ],
)
def test_renewal_cannot_change_identity_or_permissions(tmp_path, clock, change, reason):
    invite = automation(tmp_path)
    before = (tmp_path / "leases.json").read_bytes()
    assert renew(tmp_path, invite, **change)["reason_code"] == reason
    assert (tmp_path / "leases.json").read_bytes() == before


@pytest.mark.parametrize("keep_lease", [True, False])
def test_revocation_also_revokes_recovery_when_keep_lease_is_requested(tmp_path, clock, keep_lease):
    invite = automation(tmp_path)
    revoke_mcp_share_invite(tmp_path, invite_id=invite["invite"]["id"], revoke_lease=not keep_lease)
    assert renew(tmp_path, invite)["reason_code"] == "lease.revoked"
    assert use(tmp_path, invite["lease_token"])[0] is keep_lease


def test_direct_lease_revocation_cannot_be_renewed_or_reactivated(tmp_path, clock):
    invite = automation(tmp_path)
    leases.revoke_lease(tmp_path / "leases.json", invite["lease"]["id"])
    assert renew(tmp_path, invite)["reason_code"] == "lease.revoked"
    with pytest.raises(ValueError, match="new automation invite"):
        leases.reactivate_lease(tmp_path / "leases.json", invite["lease"]["id"])


def test_budget_is_not_reset_by_renewal_or_concurrent_consumption(tmp_path, clock):
    invite = automation(tmp_path, max_calls=5)
    with ThreadPoolExecutor(max_workers=8) as pool:
        allowed = list(pool.map(lambda _: use(tmp_path, invite["lease_token"])[0], range(24)))
    assert sum(allowed) == 5
    assert renew(tmp_path, invite)["reason_code"] == "lease.max_calls_exceeded"
    clock[0] += timedelta(hours=1)
    assert renew(tmp_path, invite)["reason_code"] == "lease.max_calls_exceeded"


def test_hard_authorization_expiry_is_never_extended(tmp_path, clock):
    invite = automation(tmp_path)
    clock[0] += timedelta(hours=23, minutes=57)
    renewed = renew(tmp_path, invite)
    assert renewed["lease"]["expires_at"] == invite["invite"]["renewal"]["authorization_expires_at"]
    assert renew(tmp_path, invite)["token"] == renewed["token"]
    clock[0] += timedelta(minutes=3)
    assert renew(tmp_path, invite)["reason_code"] == "lease.renewal_expired"
    assert not use(tmp_path, renewed["token"])[0]


@pytest.mark.parametrize(
    "auth,reason",
    [
        ({}, "lease.auth_missing"),
        ({"enabled": True, "issuer": "https://idp.test", "subject": "other"}, "lease.subject_not_allowed"),
        ({"enabled": True, "issuer": "https://evil.test", "subject": "bot"}, "lease.issuer_not_allowed"),
    ],
)
def test_identity_bound_renewal_reuses_lease_auth_checks(tmp_path, clock, auth, reason):
    created = leases.create_lease(
        tmp_path / "leases.json",
        task="bot",
        allow_tools=["safe_read_file"],
        invite={"id": "invite_bot"},
        renewal_ttl="7d",
        allow_issuers=["https://idp.test"],
        allow_subjects=["bot"],
    )
    assert (
        leases.renew_lease(
            tmp_path / "leases.json", invite_id="invite_bot", renewal_token=created["renewal_token"], auth_context=auth
        )["reason_code"]
        == reason
    )


def test_identity_bound_renewal_succeeds_without_static_share_bearer(tmp_path, clock):
    created = leases.create_lease(
        tmp_path / "leases.json",
        task="bot",
        allow_tools=["safe_read_file"],
        invite={"id": "invite_bot"},
        renewal_ttl="7d",
        allow_issuers=["https://idp.test"],
        allow_client_ids=["bot-client"],
    )
    clock[0] += timedelta(hours=2)
    renewed = leases.renew_lease(
        tmp_path / "leases.json",
        invite_id="invite_bot",
        renewal_token=created["renewal_token"],
        auth_context={"enabled": True, "issuer": "https://idp.test", "client_id": "bot-client"},
    )
    assert renewed["ok"]
    assert renewed["lease"]["auth_bound"]


@pytest.mark.parametrize("ttl", ["0s", "1s", "nan", "inf"])
def test_invalid_renewal_lifetime_does_not_write_lease(tmp_path, ttl):
    with pytest.raises(ValueError):
        leases.create_lease(
            tmp_path / "leases.json",
            task="bot",
            allow_tools=["read"],
            ttl="1m",
            invite={"id": "invite_bot"},
            renewal_ttl=ttl,
            renewal_bearer="secret",
        )
    assert not (tmp_path / "leases.json").exists()


@pytest.mark.parametrize("facade", [False, True])
def test_consumer_renewal_and_restart_recovery_on_existing_mcp_endpoint(tmp_path, clock, facade):
    invite = automation(tmp_path)
    options = {"upstream": None, "upstreams": [{"name": "files", "url": "http://127.0.0.1:1/mcp"}]} if facade else {}
    app = gateway(tmp_path, **options)
    clock[0] += timedelta(hours=2)
    response = rpc(app, invite)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    result = response.json()["result"]
    assert result["lease"]["id"] == invite["lease"]["id"]
    assert result["headers"]["x-snulbug-lease"] != invite["lease_token"]
    assert rpc(gateway(tmp_path, **options), invite).json()["result"]["headers"] == result["headers"]
    assert "renewal_token" not in result


@pytest.mark.parametrize(
    "params,credential,bearer,reason",
    [
        (None, "wrong", "share-secret", "lease.renewal_invalid"),
        (None, None, "wrong", "lease.renewal_auth_required"),
        ({"invite_id": "missing"}, None, "share-secret", "lease.renewal_invalid"),
        ({"invite_id": "missing", "ttl": "100d"}, None, "share-secret", "lease.renewal_invalid_request"),
        ({"invite_id": "missing", "capabilities": ["admin"]}, None, "share-secret", "lease.renewal_invalid_request"),
    ],
)
def test_consumer_renewal_rejects_unauthorized_requests(tmp_path, clock, params, credential, bearer, reason):
    invite = automation(tmp_path)
    response = rpc(gateway(tmp_path), invite, params=params, credential=credential, bearer=bearer)
    assert response.json()["error"]["data"]["reason_code"] == reason


def test_renewal_evidence_is_always_redacted_even_with_exact_recording(tmp_path, clock):
    invite = automation(tmp_path)
    path = tmp_path / "renewal.jsonl"
    audit = tmp_path / "renewal-audit.jsonl"
    response = rpc(
        gateway(tmp_path, record_out=path, redact_records=False, event_sinks=[{"type": "audit_jsonl", "path": audit}]),
        invite,
    )
    assert response.json()["result"]
    record = json.loads(audit.read_text())
    assert record["metadata"]["lease_renewal"]["invite"]["recipient"] == "nightly bot"
    assert record["decision"]["reason_code"] == "lease.recovered"
    assert invite["renewal_token"] not in audit.read_text()
    assert "share-secret" not in audit.read_text()
    assert response.json()["result"]["headers"]["x-snulbug-lease"] not in audit.read_text()
    assert not path.exists()


def test_cli_automation_invite_contains_consumer_setup(tmp_path, capsys):
    create_mcp_share(tmp_path, provider="generic", token="share-secret", validate=False)
    result = cli_main(
        [
            "mcp",
            "share",
            "invite",
            "create",
            str(tmp_path),
            "--recipient",
            "bot",
            "--task",
            "Read",
            "--capability",
            "project_readonly",
            "--renewable",
            "--ttl",
            "10m",
            "--renewal-ttl",
            "2d",
        ]
    )
    assert result == 0
    created = json.loads(capsys.readouterr().out)
    assert created["invite"]["renewal"]["lease_ttl_seconds"] == 600
    assert created["setup_snippets"]["automation"]["renew"]["method"] == leases.LEASE_RENEWAL_METHOD
    compile(created["setup_snippets"]["automation"]["python"], "bot.py", "exec")


def _consume_in_worker(arguments):
    from pathlib import Path

    directory, token = arguments
    return use(Path(directory), token)[0]


def test_call_budget_is_atomic_across_gateway_processes(tmp_path):
    invite = automation(tmp_path, max_calls=3)
    with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_consume_in_worker, [(str(tmp_path), invite["lease_token"])] * 9))
    assert sum(results) == 3
    assert renew(tmp_path, invite)["reason_code"] == "lease.max_calls_exceeded"


def test_oauth_renewal_requires_fresh_verified_identity_and_required_scopes(tmp_path, clock):
    invite = automation(tmp_path)
    secret = "local-automation-test-signing-key-32-bytes"
    jwks = tmp_path / "jwks.json"
    jwks.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kty": "oct",
                        "kid": "automation",
                        "alg": "HS256",
                        "k": base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
                    }
                ]
            }
        )
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        config.read_text() + '\n[mcp.auth]\nmode = "oauth-resource"\n'
        'resource = "https://mcp.example.test/mcp"\nissuer = "https://issuer.example.test"\n'
        'audience = "https://mcp.example.test/mcp"\nrequired_scopes = ["mcp:connect"]\n'
        f'jwks_path = {json.dumps(str(jwks))}\n[mcp.auth.scope_map]\n"mcp:read" = ["tools/call:safe_read_file"]\n'
    )
    invite = create_mcp_share_invite(
        tmp_path,
        recipient="oauth bot",
        task="Read",
        renewable=True,
        capabilities=["project_readonly"],
        allow_issuers=["https://issuer.example.test"],
        allow_subjects=["bot"],
        allow_client_ids=["bot-client"],
    )

    def token(**updates):
        return jwt.encode(
            {
                "iss": "https://issuer.example.test",
                "sub": "bot",
                "client_id": "bot-client",
                "aud": "https://mcp.example.test/mcp",
                "scope": "mcp:connect",
                "exp": int(time.time()) + 300,
                **updates,
            },
            secret,
            algorithm="HS256",
            headers={"kid": "automation"},
        )

    assert invite["bearer_token"] == "${SNULBUG_ACCESS_TOKEN}"
    assert invite["lease"]["auth_bound"]
    clock[0] += timedelta(hours=2)
    response = rpc(gateway(tmp_path), invite, bearer=token())
    assert response.json()["result"]["lease"]["id"] == invite["lease"]["id"]
    mismatch = rpc(gateway(tmp_path), invite, bearer=token(sub="another-bot"))
    assert mismatch.json()["error"]["data"]["reason_code"] == "lease.subject_not_allowed"
    for invalid, status in (("not-a-jwt", 401), (token(scope=""), 403), (token(exp=int(time.time()) - 300), 401)):
        assert rpc(gateway(tmp_path), invite, bearer=invalid).status_code == status
    with pytest.raises(ValueError, match="OAuth automation invites require"):
        create_mcp_share_invite(tmp_path, recipient="unbound", task="Read", renewable=True)


def test_renewal_is_independent_of_upstream_mcp_session(tmp_path, clock):
    invite = automation(tmp_path)
    response = rpc(gateway(tmp_path, streamable_http_require_session_id=True), invite)
    assert response.json()["result"]["lease"]["id"] == invite["lease"]["id"]


def test_renewal_reserved_method_never_reaches_upstream_without_store(tmp_path, clock):
    invite = automation(tmp_path)
    response = rpc(gateway(tmp_path, lease_file=None), invite)
    assert response.json()["error"]["data"]["reason_code"] == "lease.renewal_unavailable"


def test_removed_capability_or_broken_policy_blocks_consumer_renewal(tmp_path, clock):
    invite = automation(tmp_path)
    config = load_mcp_proxy_config(tmp_path / "snulbug.toml")
    policy = config["policy"]
    app = gateway(tmp_path)
    policy.write_text('return function() return {action="continue"} end')
    assert rpc(app, invite).json()["error"]["data"]["reason_code"] == "lease.renewal_capability_removed"
    policy.write_text("this is not valid Lua")
    assert rpc(app, invite).json()["error"]["data"]["reason_code"] == "lease.renewal_unavailable"


def test_automation_cannot_choose_an_undeclared_capability(tmp_path):
    create_mcp_share(tmp_path, provider="generic", token="share-secret", validate=False)
    with pytest.raises(ValueError, match="declared by the active Lua policy"):
        create_mcp_share_invite(tmp_path, recipient="bot", task="Read", renewable=True, capabilities=["superuser"])


def test_concurrent_renewal_cannot_overwrite_revocation(tmp_path, clock):
    invite = automation(tmp_path)
    clock[0] += timedelta(minutes=6)
    with ThreadPoolExecutor(max_workers=8) as pool:
        attempts = [pool.submit(renew, tmp_path, invite) for _ in range(12)]
        revoked = pool.submit(leases.revoke_lease, tmp_path / "leases.json", invite["lease"]["id"])
        responses = [attempt.result() for attempt in attempts]
        assert revoked.result()["ok"]
    assert renew(tmp_path, invite)["reason_code"] == "lease.revoked"
    for response in responses:
        if response["ok"]:
            assert not use(tmp_path, response["token"])[0]


def test_access_token_is_not_a_renewal_credential(tmp_path, clock):
    invite = automation(tmp_path)
    assert renew(tmp_path, invite, renewal_token=invite["lease_token"])["reason_code"] == "lease.renewal_invalid"


def test_gateway_cannot_renew_revoked_invite_or_extend_authorization(tmp_path, clock):
    invite = automation(tmp_path)
    app = gateway(tmp_path)
    revoke_mcp_share_invite(tmp_path, invite_id=invite["invite"]["id"])
    assert rpc(app, invite).json()["error"]["data"]["reason_code"] == "lease.revoked"


def test_generated_python_recovers_and_caches_current_lease(tmp_path, clock, monkeypatch, capsys):
    import io
    import urllib.request

    clock[0] = datetime.now(timezone.utc)
    invite = automation(tmp_path)
    snippet = invite["setup_snippets"]["automation"]
    for name, value in {**snippet["env"], "SNULBUG_BEARER_TOKEN": "share-secret"}.items():
        monkeypatch.setenv(name, value)
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert timeout == 15
            assert request.get_header("Authorization") == "Bearer share-secret"
            result = renew(tmp_path, invite)
            return io.BytesIO(
                json.dumps(
                    {"result": {"lease": result["lease"], "headers": {"x-snulbug-lease": result["token"]}}}
                ).encode()
            )

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args: Opener())
    first = {}
    exec(compile(snippet["python"], "bot.py", "exec"), first)
    first["lease_headers"]()
    assert len(calls) == 1
    second = {}
    exec(compile(snippet["python"], "bot-restarted.py", "exec"), second)
    assert len(calls) == 2
    assert first["lease_headers"]() == second["lease_headers"]()
    assert capsys.readouterr().out == ""


def test_share_close_revokes_automation_recovery(tmp_path, clock):
    invite = automation(tmp_path)
    closed = close_mcp_share(tmp_path, report=False)
    assert closed["ok"]
    assert closed["invites_revoked"] == 1
    assert renew(tmp_path, invite)["reason_code"] == "lease.revoked"
    assert not use(tmp_path, invite["lease_token"])[0]


def test_unauthorized_renewal_does_not_compile_policy(tmp_path, clock, monkeypatch):
    invite = automation(tmp_path)
    app = gateway(tmp_path)

    def must_not_compile(*_args):
        raise AssertionError("unauthenticated renewal must not execute the policy loader")

    monkeypatch.setattr("snulbug.proxy.compile_lua_file", must_not_compile)
    assert rpc(app, invite, credential="wrong").json()["error"]["data"]["reason_code"] == "lease.renewal_invalid"
    assert rpc(app, invite, bearer="wrong").json()["error"]["data"]["reason_code"] == "lease.renewal_auth_required"

from __future__ import annotations

import json
from dataclasses import replace

import httpx
import pytest

import snulbug.ngrok_drift as drift
from snulbug import create_mcp_share
from snulbug.config import load_mcp_proxy_config
from snulbug.share_doctor import ShareDoctorContext
from snulbug.tunnel import _ngrok_traffic_policy


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.delenv("NGROK_API_KEY", raising=False)
    directory = tmp_path / "share"
    create_mcp_share(
        directory,
        provider="ngrok",
        public_url="https://example.ngrok-free.dev/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    config = directory / "snulbug.toml"
    return ShareDoctorContext(
        share_dir=directory,
        manifest={},
        session={},
        client={},
        config_path=config,
        provider="ngrok",
        url="https://example.ngrok-free.dev/mcp",
        headers={},
        timeout=1,
        live_checks=True,
        status={},
        proxy_config=load_mcp_proxy_config(config),
    )


def endpoint(context, **changes):
    source = (context.share_dir / "tunnel/ngrok-traffic-policy.yml").read_text()
    return {
        "id": "ep_test",
        "url": "https://example.ngrok-free.dev",
        "type": "cloud",
        "bindings": ["public"],
        "traffic_policy": source,
        **changes,
    }


def mock_api(monkeypatch, handler):
    original = httpx.Client
    requests = []

    def respond(request):
        requests.append(request)
        assert request.method == "GET"
        assert request.url.host == "api.ngrok.com"
        assert request.headers["Authorization"] == "Bearer api-secret"
        assert request.headers["Ngrok-Version"] == "2"
        return handler(request)

    monkeypatch.setenv("NGROK_API_KEY", "api-secret")
    monkeypatch.setattr(
        drift.httpx, "Client", lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(respond))
    )
    return requests


def run(context):
    return drift.ShareNgrokDoctorCheck().run(context).artifacts["ngrok"]


def test_matching_cloud_policy_ignores_names_mapping_order_and_yaml_format(context, monkeypatch):
    actual = drift.parse_traffic_policy(endpoint(context)["traffic_policy"])
    for index, rule in enumerate(actual["on_http_request"]):
        rule["name"] = f"Dashboard rule {index}"
    requests = mock_api(
        monkeypatch,
        lambda _: httpx.Response(
            200, json={"endpoints": [endpoint(context, traffic_policy=json.dumps(actual, sort_keys=True))]}
        ),
    )
    result = run(context)
    assert result["state"] == "matched"
    assert result["ok"] is True
    assert result["cloud_checked"] is True
    assert result["local"]["matches"] is True
    assert len(requests) == 1
    assert "api-secret" not in json.dumps(result)


@pytest.mark.parametrize("live", [True, False])
def test_unconfigured_or_offline_never_contacts_api_or_claims_cloud_match(context, monkeypatch, live):
    monkeypatch.setattr(drift.httpx, "Client", lambda **_: pytest.fail("unexpected API access"))
    if not live:
        monkeypatch.setattr(drift, "credential_header", lambda *_: pytest.fail("resolved an offline credential"))
    result = run(replace(context, live_checks=live))
    assert result["state"] == "unchecked"
    assert result["ok"] is None
    cloud_check = next(item for item in result["checks"] if item["id"] == "ngrok.cloud_policy")
    assert cloud_check["status"] == ("warn" if live else "skip")


@pytest.mark.parametrize("change", ["target", "order", "extra", "secret"])
def test_cloud_drift_is_actionable_but_never_contains_deployed_values(context, monkeypatch, change):
    policy = drift.parse_traffic_policy(endpoint(context)["traffic_policy"])
    if change == "target":
        policy["on_http_request"][-1]["actions"][0]["config"]["url"] = "https://wrong.internal"
    elif change == "order":
        policy["on_http_request"].reverse()
    elif change == "extra":
        policy["on_http_response"] = [{"actions": [{"type": "deny"}]}]
    else:
        policy["on_http_request"][0]["actions"][0]["config"]["headers"]["private-secret-key"] = "deployed-secret-value"
    mock_api(
        monkeypatch,
        lambda _: httpx.Response(200, json={"endpoints": [endpoint(context, traffic_policy=json.dumps(policy))]}),
    )
    result = run(context)
    assert result["state"] == "drifted"
    assert result["ok"] is False
    assert result["local"]["matches"] is True
    assert result["deployed"]["differences"]
    output = json.dumps(result)
    for secret in ("api-secret", "private-secret-key", "deployed-secret-value", "wrong.internal"):
        assert secret not in output


def test_stale_generated_policy_compares_against_current_routes_not_local_file(context, monkeypatch):
    proxy = {**context.proxy_config, "http_routes": [{"prefix": "/app", "upstream_url": "http://localhost:3000"}]}
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    result = run(replace(context, proxy_config=proxy))
    assert result["local"]["matches"] is False
    assert result["deployed"]["matches"] is False
    assert result["route_prefixes"] == ["/app"]


@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500])
def test_api_errors_are_not_passes_and_do_not_expose_error_bodies(context, monkeypatch, status):
    requests = mock_api(monkeypatch, lambda _: httpx.Response(status, text="api-secret echoed in an error"))
    result = run(context)
    assert result["ok"] is not True
    assert result["cloud_checked"] is False
    assert "api-secret" not in json.dumps(result)
    assert len(requests) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://wrong.example"},
        {"type": "agent"},
        {"bindings": ["internal"]},
        {"traffic_policy": "not: [valid"},
        {"traffic_policy": None},
    ],
)
def test_pinned_endpoint_validation(context, monkeypatch, changes):
    with context.config_path.open("a") as stream:
        stream.write('\n[mcp.ngrok]\nendpoint_id = "ep_test"\n')
    requests = mock_api(monkeypatch, lambda _: httpx.Response(200, json=endpoint(context, **changes)))
    result = run(context)
    assert result["ok"] is False
    assert requests[0].url.path == "/endpoints/ep_test"


@pytest.mark.parametrize("endpoints", [[], [1], [{"url": "https://other.example"}]])
def test_missing_or_invalid_active_endpoints_are_not_verified(context, monkeypatch, endpoints):
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": endpoints}))
    assert run(context)["ok"] is not True


def test_ambiguous_endpoints_require_explicit_selection(context, monkeypatch):
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context), endpoint(context)]}))
    assert run(context)["ok"] is False


def test_same_origin_pagination_is_bounded_and_finds_endpoint(context, monkeypatch):
    def handler(request):
        if request.url.params.get("after_id"):
            return httpx.Response(200, json={"endpoints": [endpoint(context)], "next_page_uri": None})
        return httpx.Response(
            200, json={"endpoints": [], "next_page_uri": "https://api.ngrok.com/endpoints?after_id=ep_previous"}
        )

    requests = mock_api(monkeypatch, handler)
    assert run(context)["ok"] is True
    assert len(requests) == 2


@pytest.mark.parametrize(
    "next_page",
    [
        "https://attacker.example/endpoints",
        "http://api.ngrok.com/endpoints",
        "/apikeys",
        "//attacker.example/endpoints",
        "/endpoints?limit=100",
        "/endpoints#fragment",
    ],
)
def test_pagination_never_sends_credential_to_another_origin_or_resource(context, monkeypatch, next_page):
    requests = mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [], "next_page_uri": next_page}))
    assert run(context)["ok"] is not True
    assert len(requests) == 1


def test_api_timeout_and_oversized_responses_are_sanitized(context, monkeypatch):
    def timeout(_):
        raise httpx.ReadTimeout("api-secret")

    mock_api(monkeypatch, timeout)
    result = run(context)
    assert result["ok"] is None
    assert "api-secret" not in json.dumps(result)
    mock_api(monkeypatch, lambda _: httpx.Response(200, content=b"x" * (drift._MAX_BYTES + 1)))
    assert run(context)["ok"] is not True


@pytest.mark.parametrize(
    "source",
    [
        "x: &x [*x]",
        "on_http_request: {}",
        "on_http_request: [wrong]",
        "x: 1\nx: 2",
        "x: .nan",
        "x: !!python/object:evil {}",
        "[]",
        "x: " + "[" * 40 + "0" + "]" * 40,
    ],
)
def test_unsafe_or_invalid_yaml_is_rejected(source):
    with pytest.raises(ValueError):
        drift.parse_traffic_policy(source)


@pytest.mark.parametrize("mode", ["oauth-resource", "enterprise-managed"])
def test_oauth_baseline_allows_metadata_and_preserves_gateway_challenges(mode):
    policy = drift.parse_traffic_policy(
        _ngrok_traffic_policy(
            "https://example.ngrok-free.dev/mcp",
            internal_url="https://snulbug-mcp.internal",
            auth_mode=mode,
            http_routes=[{"prefix": "/app"}],
        )
    )
    rules = policy["on_http_request"]
    assert not any(rule.get("actions", [{}])[0].get("config", {}).get("status_code") == 401 for rule in rules)
    assert "/.well-known/oauth-protected-resource" in rules[1]["expressions"][0]
    assert "/app" in rules[1]["expressions"][0]
    assert all(rule["expressions"][0] == 'req.url.path == "/mcp"' for rule in rules[2:-1])


def test_file_credential_uses_existing_broker_and_cannot_override_authorization_scheme(context, monkeypatch):
    credential = context.config_path.parent / "ngrok-key"
    credential.write_text("api-secret")
    with context.config_path.open("a") as stream:
        stream.write('\n[mcp.ngrok.api_credential]\ntype = "file"\npath = "ngrok-key"\nscheme = "raw"\n')
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    assert run(context)["ok"] is True


def test_cached_inspection_invalidates_after_local_edits_without_network(context, monkeypatch):
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    saved = run(context)
    monkeypatch.setattr(drift.httpx, "Client", lambda **_: pytest.fail("cached read contacted API"))
    args = {"directory": context.share_dir, "config_path": context.config_path, "public_url": context.url}
    assert drift.cached_ngrok_inspection(saved, **args)["ok"] is True
    with context.config_path.open("a") as stream:
        stream.write("\n# edited\n")
    stale = drift.cached_ngrok_inspection(saved, **args)
    assert stale["state"] == "stale"
    assert stale["ok"] is None
    assert "desired_policy" not in stale


def test_other_providers_have_no_ngrok_checks(context):
    assert drift.ShareNgrokDoctorCheck().run(replace(context, provider="ssh")).checks == ()


def test_doctor_persists_only_safe_inspection_and_status_report_reuse_it(context, monkeypatch):
    import snulbug.share as share
    from snulbug.share_doctor import run_share_doctor_checks

    status = share.share_status
    monkeypatch.setattr(share, "share_status", lambda directory, **kwargs: status(directory, live_checks=False))
    monkeypatch.setattr(
        share, "run_share_doctor_checks", lambda ctx: run_share_doctor_checks(ctx, checks=["config", "ngrok"])
    )
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    result = share.doctor_mcp_share(context.share_dir)
    assert result["ngrok"]["ok"] is True
    monkeypatch.setattr(drift.httpx, "Client", lambda **_: pytest.fail("status/report contacted API"))
    current = share.share_status(context.share_dir)
    assert current["ngrok"]["ok"] is True
    assert "ngrok policy inspection: `matched`" in share.share_report(context.share_dir)["report"]
    assert "api-secret" not in (context.share_dir / "share.json").read_text()


def test_console_reuses_saved_inspection_and_gates_readiness_on_drift(context, monkeypatch):
    import snulbug.share as share
    import snulbug.share_console as console

    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    saved = run(context)
    share._update_share_manifest(context.share_dir, health={"ngrok": saved})
    monkeypatch.setattr(drift.httpx, "Client", lambda **_: pytest.fail("console contacted cloud API"))
    monkeypatch.setattr(console, "_provider_console", lambda *_args, **_kwargs: None)
    snapshot = console.build_share_console_snapshot(context.share_dir)
    assert snapshot["tunnel_provider"]["drift"]["ok"] is True
    checks = {item["id"]: item for item in snapshot["readiness_gate"]["checks"]}
    assert checks["tunnel.ngrok_policy"]["status"] == "pass"
    saved.update({"state": "drifted", "ok": False})
    share._update_share_manifest(context.share_dir, health={"ngrok": saved})
    snapshot = console.build_share_console_snapshot(context.share_dir)
    checks = {item["id"]: item for item in snapshot["readiness_gate"]["checks"]}
    assert checks["tunnel.ngrok_policy"]["status"] == "fail"
    assert snapshot["readiness_gate"]["decision"] == "blocked"


def test_missing_yaml_dependency_is_unchecked_not_a_drift_failure(context, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "yaml", None)
    result = run(context)
    assert result["ok"] is None
    assert result["state"] == "unchecked"
    assert result["checks"][-1]["status"] == "warn"
    assert "snulbug[discovery]" in result["checks"][-1]["message"]


def test_policy_change_and_public_url_drift_invalidate_saved_result(context, monkeypatch):
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    saved = run(context)
    args = {"directory": context.share_dir, "config_path": context.config_path, "public_url": context.url}
    assert drift.cached_ngrok_inspection(saved, **{**args, "public_url": "https://new.ngrok.app/mcp"})["ok"] is None
    with (context.share_dir / "tunnel/ngrok-traffic-policy.yml").open("a") as stream:
        stream.write("\n# changed\n")
    assert drift.cached_ngrok_inspection(saved, **args)["ok"] is None


def test_diff_caps_output_and_masks_unknown_field_names():
    changes = drift.compare_traffic_policies({}, {f"private-value-{index}": index for index in range(200)})
    assert len(changes["differences"]) == 100
    assert "private-value" not in json.dumps(changes)


def test_configured_public_url_drift_cannot_verify_old_matching_endpoint(context, monkeypatch):
    mock_api(monkeypatch, lambda _: httpx.Response(200, json={"endpoints": [endpoint(context)]}))
    proxy = {**context.proxy_config, "tunnel_public_url": "https://new.ngrok-free.dev/mcp"}
    result = run(replace(context, proxy_config=proxy))
    assert result["ok"] is False
    assert next(check for check in result["checks"] if check["id"] == "ngrok.public_url")["status"] == "fail"

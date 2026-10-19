from __future__ import annotations

import io
import json
from dataclasses import replace

import httpx
import pytest

from snulbug import create_mcp_share, doctor_mcp_share, run_mcp_share, share_contract, share_report, share_status
from snulbug.cli.rich_share import write_share_status_rich
from snulbug.config import load_mcp_proxy_config
from snulbug.http_mounts import ShareHttpMountsDoctorCheck, cached_http_mounts, inspect_http_mounts
from snulbug.share_console import build_share_console_snapshot
from snulbug.share_doctor import ShareDoctorContext


def config(**contract):
    return {"timeout": 30.0, "http_routes": [{"prefix": "/app", "upstream": "https://app.test/base", **contract}]}


def mock_health(monkeypatch, status=200, *, error=None):
    requests = []
    original = httpx.Client

    class NoBody(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail("health probe read a response body")
            yield b""

    def handler(request):
        requests.append(request)
        assert request.method == "GET"
        assert request.url == "https://app.test/ready"
        for header in ("authorization", "cookie", "x-snulbug-lease", "dpop"):
            assert header not in request.headers
        if error:
            raise error
        return httpx.Response(status, headers={"location": "https://elsewhere.test/private-value"}, stream=NoBody())

    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return original(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("snulbug.http_mounts.httpx.Client", client)
    return requests


def test_undeclared_auth_is_not_silently_assumed_to_be_mcp_protected():
    result = inspect_http_mounts(config())
    assert result["state"] == "blocked"
    assert result["ok"] is False
    assert result["checks"][0]["status"] == "fail"
    assert "MCP authentication does not protect" in result["checks"][0]["message"]


def test_public_mount_uses_safe_defaults_but_still_requires_exposure_review():
    result = inspect_http_mounts(config(auth="public"))
    assert result["state"] == "review"
    item = result["items"][0]
    assert item["forward_authorization"] is False
    assert item["forward_cookies"] is False
    assert any(check["id"].endswith(".public") for check in result["checks"])


@pytest.mark.parametrize("status", [200, 204, 302, 401, 500])
def test_dedicated_health_checks_only_inspect_status_not_auth_or_response_body(monkeypatch, status):
    requests = mock_health(monkeypatch, status)
    result = inspect_http_mounts(config(auth="upstream", health_path="/ready"), live_checks=True, timeout=2)
    assert len(requests) == 1
    assert requests[0].extensions["timeout"]["read"] == 2
    assert result["items"][0]["health"]["ok"] is (status == 200)
    assert result["ok"] is (status == 200)
    assert "private-value" not in json.dumps(result)


def test_expected_health_status_and_timeout_are_explicit(monkeypatch):
    requests = mock_health(monkeypatch, 204)
    result = inspect_http_mounts(
        config(auth="upstream", health_path="/ready", health_status=204, timeout=0.5), live_checks=True
    )
    assert result["state"] == "ready"
    assert requests[0].extensions["timeout"]["read"] == 0.5


def test_health_exceptions_are_fixed_messages_without_provider_details(monkeypatch):
    mock_health(monkeypatch, error=httpx.ConnectError("private-value with token and internal error"))
    result = inspect_http_mounts(config(auth="upstream", health_path="/ready"), live_checks=True)
    assert result["ok"] is False
    assert "private-value" not in json.dumps(result)


def test_offline_and_passive_inspections_never_make_health_requests(monkeypatch):
    mock_health(monkeypatch)
    proxy = config(auth="upstream", health_path="/ready")
    saved = inspect_http_mounts(proxy, live_checks=True)
    monkeypatch.setattr("snulbug.http_mounts.httpx.Client", lambda **_: pytest.fail("passive network request"))
    assert inspect_http_mounts(proxy)["items"][0]["health"]["checked"] is False
    assert cached_http_mounts(saved, proxy) == saved
    assert cached_http_mounts(saved, proxy) == saved
    changed = config(auth="upstream", health_path="/ready", forward_cookies=False)
    current = cached_http_mounts(saved, changed)
    assert current["stale"] is True
    assert current["items"][0]["health"]["checked"] is False
    assert current["state"] == "review"


def test_semantically_equal_declarations_have_equal_digests():
    first = inspect_http_mounts(config(auth="upstream", methods=["HEAD", "GET"]))
    second = inspect_http_mounts(config(auth="upstream", methods=["GET", "HEAD"], forward_cookies=True, timeout=30.0))
    assert first["input_digest"] == second["input_digest"]


@pytest.fixture
def context(tmp_path):
    directory = tmp_path / "share"
    create_mcp_share(
        directory,
        provider="generic",
        token="private-share-token",
        allowed_tools=["read"],
        validate=False,
        http_routes=[
            {
                "prefix": "/app",
                "upstream": "https://app.test/base",
                "auth": "upstream",
                "health_path": "/ready",
                "methods": ["GET", "HEAD"],
            }
        ],
    )
    path = directory / "snulbug.toml"
    return ShareDoctorContext(
        share_dir=directory,
        manifest={},
        session={},
        client={},
        config_path=path,
        provider="generic",
        url="https://share.test/mcp",
        headers={"authorization": "private-client-token"},
        timeout=2,
        live_checks=True,
        status={},
        proxy_config=load_mcp_proxy_config(path),
    )


def test_doctor_plugin_uses_declared_config_without_forwarding_context_tokens(context, monkeypatch):
    requests = mock_health(monkeypatch)
    plugin = ShareHttpMountsDoctorCheck()
    result = plugin.run(context)
    assert result.artifacts["http_mounts"]["state"] == "ready"
    assert len(requests) == 1
    plugin.run(replace(context, live_checks=False))
    assert len(requests) == 1


def test_share_workflow_reuses_diagnostics_and_binds_mount_changes(context, monkeypatch):
    requests = mock_health(monkeypatch)
    monkeypatch.setattr(
        "snulbug.share._probe_mcp_url", lambda *_args, **_kwargs: {"checked": True, "reachable": True, "status": 200}
    )
    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", lambda **_: {"ok": True, "checks": [], "recommendations": []})
    result = doctor_mcp_share(context.share_dir)
    assert result["http_mounts"]["state"] == "ready"
    assert len(requests) == 1
    monkeypatch.setattr("snulbug.http_mounts.httpx.Client", lambda **_: pytest.fail("passive health probe"))
    status = share_status(context.share_dir, live_checks=False)
    assert status["http_mounts"]["state"] == "ready"
    snapshot = build_share_console_snapshot(context.share_dir)
    check = next(item for item in snapshot["readiness_gate"]["checks"] if item["id"] == "http_mounts.contracts")
    assert check["status"] == "pass"
    report = share_report(context.share_dir, live_checks=False)["report"]
    assert "HTTP Mount Contracts" in report
    output = io.StringIO()
    write_share_status_rich(status, stream=output)
    assert "HTTP Mount Contracts" in output.getvalue()
    first = share_contract(context.share_dir, live_checks=False, sign=True, secret="contract-secret")["contract"]
    assert first["http_mounts"][0]["auth"] == "upstream"
    assert "health" not in first["http_mounts"][0]
    assert all(
        secret not in json.dumps(result["http_mounts"]) + report
        for secret in ("private-share-token", "private-client-token")
    )
    source = context.config_path.read_text()
    context.config_path.write_text(
        source.replace('health_path = "/ready"', 'health_path = "/ready"\nforward_cookies = false')
    )
    second = share_contract(context.share_dir, live_checks=False)["contract"]
    assert first["binding_digest"] != second["binding_digest"]
    changed = build_share_console_snapshot(context.share_dir)
    assert changed["readiness_gate"]["review_digest"] != snapshot["readiness_gate"]["review_digest"]
    assert changed["status"]["http_mounts"]["items"][0]["health"]["checked"] is False


@pytest.mark.parametrize(
    "before,after",
    [
        ('auth = "upstream"', 'auth = "public"'),
        ('upstream = "https://app.test/base"', 'upstream = "https://other.test/base"'),
        ('methods = ["GET", "HEAD"]', 'methods = ["GET", "HEAD", "POST"]'),
        ('health_path = "/ready"', 'health_path = "/ready"\nforward_authorization = false'),
        ('health_path = "/ready"', 'health_path = "/ready"\ntimeout = 10.0'),
    ],
)
def test_required_share_contract_rejects_changed_http_mounts_before_startup(context, before, after):
    contract_path = context.share_dir / "contract.json"
    share_contract(context.share_dir, output=contract_path, live_checks=False, sign=True, secret="contract-secret")
    assert run_mcp_share(context.share_dir, dry_run=True, require_contract=contract_path)["ok"] is True
    source = context.config_path.read_text()
    assert before in source
    context.config_path.write_text(source.replace(before, after))
    with pytest.raises(ValueError, match="required share contract has drifted"):
        run_mcp_share(context.share_dir, dry_run=True, require_contract=contract_path)


def test_health_timestamps_do_not_change_readiness_review_digest(context, monkeypatch):
    mock_health(monkeypatch)
    result = inspect_http_mounts(context.proxy_config, live_checks=True)
    manifest_path = context.share_dir / "share.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.setdefault("health", {})["http_mounts"] = result
    manifest_path.write_text(json.dumps(manifest))
    first = build_share_console_snapshot(context.share_dir)
    result["checked_at"] = "2026-10-19T12:34:56+00:00"
    result["items"][0]["health"]["checked_at"] = result["checked_at"]
    manifest_path.write_text(json.dumps(manifest))
    second = build_share_console_snapshot(context.share_dir)
    assert first["readiness_gate"]["review_digest"] == second["readiness_gate"]["review_digest"]

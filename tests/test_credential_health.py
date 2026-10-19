from __future__ import annotations

import io
import json
import os
from dataclasses import replace

import pytest

from snulbug import create_mcp_share, doctor_mcp_share, share_report, share_status
from snulbug.cli.rich_share import write_share_status_rich
from snulbug.config import load_mcp_proxy_config
from snulbug.credential_health import (
    ShareCredentialsDoctorCheck,
    cached_upstream_credentials,
    inspect_upstream_credentials,
)
from snulbug.credentials import (
    MAX_CREDENTIAL_BYTES,
    CredentialResolutionError,
    EnvCredentialBroker,
    FileCredentialBroker,
    credential_header,
    credential_status,
)
from snulbug.share_console import _console_html, build_share_console_snapshot
from snulbug.share_doctor import ShareDoctorContext


def file_reference(path):
    return {"id": "service", "type": "file", "path": str(path)}


def proxy_config(credential, *, url="https://service.example.test/mcp"):
    return {"upstream": url, "upstream_credential": credential, "auth": {"strip_authorization_upstream": True}}


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "credential.empty"),
        (b"   \n", "credential.empty"),
        (b"private-token\r\nx-injected: bad", "credential.invalid_value"),
        (b"private\x00token", "credential.invalid_value"),
        (b"private\xfftoken", "credential.invalid_encoding"),
        (b"x" * (MAX_CREDENTIAL_BYTES + 1), "credential.too_large"),
    ],
)
def test_file_sources_fail_closed_with_bounded_secret_free_errors(tmp_path, raw, code):
    path = tmp_path / "service-token"
    path.write_bytes(raw)
    reference = file_reference(path)
    with pytest.raises(CredentialResolutionError) as exc:
        credential_header(reference)
    assert exc.value.code == code
    status = credential_status(reference)
    assert status["available"] is False
    assert status["reason_code"] == code
    assert "private" not in status["error"]


def test_missing_directory_and_fifo_sources_do_not_hang(tmp_path):
    assert credential_status(file_reference(tmp_path / "missing"))["reason_code"] == "credential.missing"
    assert credential_status(file_reference(tmp_path))["reason_code"] == "credential.not_regular_file"
    if hasattr(os, "mkfifo"):
        path = tmp_path / "fifo"
        os.mkfifo(path)
        assert credential_status(file_reference(path))["reason_code"] == "credential.not_regular_file"


@pytest.mark.parametrize("value", ["", "  ", "bad\r\nvalue", "bad\tvalue", "bad\x7fvalue", "\ud800", "x" * 16385])
def test_env_values_cannot_inject_headers_or_allocate_unbounded_headers(monkeypatch, value):
    # Use a plugin return value for strings the OS environment cannot represent.
    monkeypatch.setattr(EnvCredentialBroker, "resolve", lambda *_: value)
    result = credential_status({"id": "service", "type": "env", "env": "SERVICE_TOKEN"})
    assert result["available"] is False
    assert "bad" not in json.dumps(result)


def test_plugin_exceptions_never_cross_the_credential_boundary(monkeypatch):
    def fail(*_):
        raise RuntimeError("provider returned private-token and a secret HTTP body")

    monkeypatch.setattr(EnvCredentialBroker, "resolve", fail)
    result = credential_status({"id": "service", "type": "env", "env": "SERVICE_TOKEN"})
    assert result["reason_code"] == "credential.resolution_failed"
    assert "private-token" not in json.dumps(result)


def test_file_read_permissions_fail_safely_and_symlinks_to_regular_files_are_supported(tmp_path, monkeypatch):
    path = tmp_path / "service-token"
    path.write_text("private-token")
    alias = tmp_path / "projected-secret"
    alias.symlink_to(path)
    assert credential_header(file_reference(alias)) == ("Authorization", "Bearer private-token")

    def denied(*_, **__):
        raise PermissionError("private-token in an operating system error")

    monkeypatch.setattr("snulbug.credentials.os.open", denied)
    result = credential_status(file_reference(path))
    assert result["reason_code"] == "credential.unreadable"
    assert "private-token" not in json.dumps(result)


def test_file_rotation_reads_replacements_and_never_uses_a_stale_secret(tmp_path):
    path = tmp_path / "service-token"
    path.write_text("first-token\n")
    reference = file_reference(path)
    assert credential_header(reference) == ("Authorization", "Bearer first-token")
    replacement = tmp_path / "replacement"
    replacement.write_text("next-token\n")
    replacement.replace(path)
    assert credential_header(reference) == ("Authorization", "Bearer next-token")
    path.unlink()
    assert credential_status(reference)["available"] is False


def test_live_checks_are_secret_free_and_cache_only_reference_and_stat_changes(tmp_path, monkeypatch):
    path = tmp_path / "service-token"
    path.write_text("private-token")
    path.chmod(0o600)
    config = proxy_config(file_reference(path))
    saved = inspect_upstream_credentials(config, live_checks=True)
    assert saved["state"] == "available"
    if os.name == "posix":
        assert saved["items"][0]["file_mode"] == "0600"
    assert saved["summary"]["available"] == 1
    assert "private-token" not in json.dumps(saved)
    monkeypatch.setattr(FileCredentialBroker, "resolve", lambda *_: pytest.fail("passive refresh resolved a secret"))
    assert cached_upstream_credentials(saved, config) == saved
    assert cached_upstream_credentials(saved, config) == saved
    replacement = tmp_path / "replacement"
    replacement.write_text("changed-token")
    replacement.chmod(0o600)
    replacement.replace(path)
    current = cached_upstream_credentials(saved, config)
    assert current["state"] == "stale"
    assert current["checked"] is False
    assert current["items"][0]["available"] is None
    assert current["input_digest"] != saved["input_digest"]
    path.unlink()
    assert cached_upstream_credentials(saved, config)["state"] == "stale"


def test_rotation_during_inspection_is_not_certified(tmp_path, monkeypatch):
    path = tmp_path / "service-token"
    path.write_text("first-token")
    original = FileCredentialBroker.resolve

    def resolve(self, reference):
        value = original(self, reference)
        replacement = tmp_path / "replacement"
        replacement.write_text("next-token")
        replacement.replace(path)
        return value

    monkeypatch.setattr(FileCredentialBroker, "resolve", resolve)
    result = inspect_upstream_credentials(proxy_config(file_reference(path)), live_checks=True)
    assert result["state"] == "stale"
    assert result["items"][0]["available"] is None


def test_hygiene_warnings_are_not_false_assertions_of_upstream_acceptance(tmp_path):
    path = tmp_path / "service-token"
    path.write_text("private-token")
    path.chmod(0o644)
    config = proxy_config(file_reference(path), url="http://upstream.example.test/mcp")
    config["auth"]["strip_authorization_upstream"] = False
    result = inspect_upstream_credentials(config, live_checks=True)
    assert result["state"] == "review"
    assert result["ok"] is True
    assert any("non-loopback HTTP" in check["message"] for check in result["checks"])
    assert any("passthrough" in check["message"] for check in result["checks"])
    if os.name == "posix":
        assert any("0600" in check["message"] for check in result["checks"])
    assert "upstream acceptance is not verified" in result["checks"][0]["message"]
    output = io.StringIO()
    write_share_status_rich({"upstream_credentials": result}, stream=output)
    assert "non-loopback HTTP" in output.getvalue()
    assert "private-token" not in output.getvalue()


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:9000", "http://[::1]:9000", "http://localhost:9000", "https://service.test"]
)
def test_private_loopback_or_https_does_not_warn_about_cleartext_egress(monkeypatch, url):
    monkeypatch.setenv("SERVICE_TOKEN", "private-token")
    result = inspect_upstream_credentials(
        proxy_config({"id": "service", "type": "env", "env": "SERVICE_TOKEN"}, url=url), live_checks=True
    )
    assert result["state"] == "available"
    assert "restart the gateway" in result["items"][0]["rotation"]


def test_facade_inventory_groups_shared_sources_and_redacts_upstream_url_credentials(monkeypatch):
    monkeypatch.setenv("SERVICE_TOKEN", "private-token")
    reference = {"id": "service", "type": "env", "env": "SERVICE_TOKEN"}
    config = {
        "upstreams": [
            {"name": name, "credential": reference, "url": "https://user:password@service.test/mcp?token=hidden"}
            for name in ("a", "b")
        ]
    }
    result = inspect_upstream_credentials(config, live_checks=True)
    assert result["summary"]["count"] == 1
    assert len(result["items"][0]["upstreams"]) == 2
    assert all(secret not in json.dumps(result) for secret in ("password", "hidden", "private-token"))


@pytest.fixture
def context(tmp_path):
    directory = tmp_path / "share"
    create_mcp_share(directory, provider="generic", token="share-value", allowed_tools=["read"], validate=False)
    config = directory / "snulbug.toml"
    source = config.read_text()
    source = source.replace("[mcp.proxy]\n", '[mcp.proxy]\nupstream_credential = "service"\n', 1)
    source += '\n[mcp.fabric.credentials.service]\ntype = "env"\nenv = "SERVICE_TOKEN"\n'
    config.write_text(source)
    return ShareDoctorContext(
        share_dir=directory,
        manifest={},
        session={},
        client={},
        config_path=config,
        provider="generic",
        url="https://share.example.test/mcp",
        headers={},
        timeout=1,
        live_checks=True,
        status={},
        proxy_config=load_mcp_proxy_config(config),
    )


def test_doctor_plugin_checks_sources_only_when_live(context, monkeypatch):
    monkeypatch.delenv("SERVICE_TOKEN", raising=False)
    result = ShareCredentialsDoctorCheck().run(context)
    assert result.artifacts["upstream_credentials"]["state"] == "unavailable"
    assert result.checks[0]["status"] == "fail"
    monkeypatch.setattr(EnvCredentialBroker, "resolve", lambda *_: pytest.fail("offline check resolved a secret"))
    offline = ShareCredentialsDoctorCheck().run(replace(context, live_checks=False))
    assert offline.artifacts["upstream_credentials"]["state"] == "unchecked"
    assert offline.checks[0]["status"] == "skip"


def test_share_workflow_persists_safe_diagnostics_and_passive_console_does_not_resolve(context, monkeypatch):
    monkeypatch.setenv("SERVICE_TOKEN", "private-token")
    calls = []
    original = EnvCredentialBroker.resolve

    def resolve(self, reference):
        calls.append(reference["id"])
        return original(self, reference)

    monkeypatch.setattr(EnvCredentialBroker, "resolve", resolve)
    monkeypatch.setattr(
        "snulbug.share._probe_mcp_url", lambda *_args, **_kwargs: {"checked": True, "reachable": True, "status": 200}
    )
    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", lambda **_: {"ok": True, "checks": [], "recommendations": []})
    result = doctor_mcp_share(context.share_dir)
    assert result["upstream_credentials"]["state"] == "available"
    assert calls == ["service"]
    monkeypatch.setattr(EnvCredentialBroker, "resolve", lambda *_: pytest.fail("passive refresh resolved a secret"))
    current = share_status(context.share_dir, live_checks=False)
    assert current["upstream_credentials"]["state"] == "available"
    report = share_report(context.share_dir, live_checks=False)
    assert "Upstream Credentials" in report["report"]
    snapshot = build_share_console_snapshot(context.share_dir)
    check = next(check for check in snapshot["readiness_gate"]["checks"] if check["id"] == "auth.upstream_credentials")
    assert check["status"] == "pass"
    assert "private-token" not in json.dumps(result) + report["report"] + json.dumps(snapshot)
    for path in context.share_dir.rglob("*.json"):
        assert "private-token" not in path.read_text()
    html = _console_html()
    assert 'data-state-key="upstream-credentials"' in html
    assert "upstreamCredentialsHtml" in html


def test_offline_share_doctor_does_not_resolve_through_fabric(context, monkeypatch):
    monkeypatch.setattr(EnvCredentialBroker, "resolve", lambda *_: pytest.fail("offline doctor resolved a secret"))
    result = doctor_mcp_share(context.share_dir, live_checks=False)
    assert result["upstream_credentials"]["state"] == "unchecked"

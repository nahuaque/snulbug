from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

import snulbug.share_console as share_console
from snulbug import (
    ShareConsoleServer,
    append_record,
    build_mcp_schema_catalog,
    build_share_console_snapshot,
    create_lease,
    create_mcp_share,
    learn_mcp_policy,
    list_leases,
    load_share_session_model,
    record_policy_request,
)
from snulbug.cli.share import _run_share_setup_console, _start_share_run_console, _stop_share_run_console
from snulbug.simulator import main as simulator_main


def test_share_console_snapshot_reads_existing_share_artifacts(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_capability_request_log(tmp_path)

    snapshot = build_share_console_snapshot(tmp_path)
    timeline = snapshot["decision_timeline"]
    readiness = snapshot["readiness_gate"]
    readiness_checks = {check["id"]: check for check in readiness["checks"]}
    policy_visibility = snapshot["policy_visibility"]
    policy_source = policy_visibility["source"]

    assert snapshot["ok"] is True
    assert snapshot["mode"] == "share"
    assert "setup_wizard" not in snapshot
    assert snapshot["share"] == str(tmp_path)
    assert snapshot["status"]["state"] == "created"
    assert snapshot["capability_requests"]["summary"]["pending"] == 1
    assert snapshot["capability_requests"]["requests"][0]["tool"] == "safe_read_file"
    assert snapshot["capability_requests"]["requests"][0]["argument_keys"] == ["path"]
    assert timeline["exists"] is True
    assert timeline["summary"]["shown"] == 1
    assert timeline["summary"]["capability_requested"] == 1
    assert timeline["events"][0]["outcome"] == "capability_requested"
    assert timeline["events"][0]["tool"] == "safe_read_file"
    assert timeline["events"][0]["auth_subject"] == "user-1"
    assert readiness["schema"] == "snulbug.share-readiness-gate.v1"
    assert readiness["decision"] in {"review", "blocked"}
    assert readiness["summary"]["warnings"] >= 1
    assert readiness_checks["capability_requests.pending"]["status"] == "warn"
    assert readiness["attestation"]["schema"] == "snulbug.share-readiness-attestation.v1"
    assert readiness["attestation"]["digest"].startswith("sha256:")
    assert readiness["attestation"]["session"]["public_url"] == "https://mcp.example.test/mcp"
    assert policy_visibility["ok"] is True
    assert policy_visibility["policy"]["lifecycle_state"] == "observed"
    assert policy_visibility["bundle_manifest"]["entrypoint"] == "policy.lua"
    assert policy_source["displayable"] is True
    assert policy_source["language"] == "lua"
    assert policy_source["redacted"] is True
    assert policy_source["sha256"].startswith("sha256:")
    assert "safe_read_file" in policy_source["source"]
    assert 'local token = "[REDACTED]"' in policy_source["source"]
    assert {"value": "mcp.docs_capability_requested", "count": 1} in policy_visibility["reason_codes"]["summary"]
    assert any(row["family"] == "mcp" for row in policy_visibility["helper_usage"])
    encoded = json.dumps(snapshot)
    assert "share-secret" not in encoded
    assert "sbl_" not in encoded
    assert "timeline-secret" not in encoded
    assert snapshot["status"]["client"]["headers"]["Authorization"] == "[REDACTED]"
    assert snapshot["status"]["client"]["headers"]["x-snulbug-lease"] == "[REDACTED]"


def test_share_console_policy_visibility_resolves_cwd_relative_share_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    create_mcp_share(
        Path("relative-share"),
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    snapshot = build_share_console_snapshot(Path("relative-share"))
    source = snapshot["policy_visibility"]["source"]

    assert source["displayable"] is True
    assert source["exists"] is True
    assert source["path"] == "relative-share/policy.snulbug/policy.lua"
    assert "active policy file is missing" not in json.dumps(snapshot["policy_visibility"])
    assert "share-secret" not in json.dumps(snapshot["policy_visibility"])


def test_share_setup_console_snapshot_does_not_require_share_session(tmp_path):
    snapshot = share_console.build_share_setup_console_snapshot(tmp_path)
    wizard = snapshot["setup_wizard"]

    assert snapshot["ok"] is True
    assert snapshot["mode"] == "setup"
    assert "status" not in snapshot
    assert snapshot["setup_defaults"]["directory"] == ".snulbug/share"
    assert snapshot["existing_shares"] == []
    assert wizard["schema"] == "snulbug.share-setup-wizard.v1"
    assert wizard["total"] == 6
    assert wizard["next_step"]["id"] == "create_share"
    assert wizard["next_step"]["primary_action"]["kind"] == "create_share"


def test_share_console_compacts_repeated_live_decisions(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_repeated_upstream_failure_log(tmp_path)

    snapshot = build_share_console_snapshot(tmp_path)
    timeline = snapshot["decision_timeline"]
    compacted = timeline["compacted_events"]

    assert timeline["summary"]["shown"] == 3
    assert timeline["summary"]["upstream_failed"] == 3
    assert len(compacted) == 1
    assert compacted[0]["count"] == 3
    assert compacted[0]["outcome"] == "upstream_failed"
    assert compacted[0]["reason_code"] == "mcp.tunnel_safe_rate_limit"
    assert compacted[0]["earliest_line"] == 1
    assert compacted[0]["latest_line"] == 3


def test_share_console_ignores_internal_status_probes_in_live_decisions(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    probe = upstream_failure_event(1)
    probe["metadata"] = {
        **dict(probe["metadata"]),
        "internal_probe": {"kind": "share-status"},
    }
    real_event = upstream_failure_event(3)
    (traces / "audit.jsonl").write_text(
        "\n".join(
            [
                json.dumps(real_event, sort_keys=True),
                *[json.dumps(probe, sort_keys=True) for _index in range(30)],
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    snapshot = build_share_console_snapshot(tmp_path)
    timeline = snapshot["decision_timeline"]

    assert timeline["summary"]["shown"] == 1
    assert timeline["events"][0]["line"] == 1


def test_share_console_ignores_client_disconnect_while_sending_error():
    class BrokenPipeHandler:
        called = False

        def send_response(self, status):
            self.called = True
            raise BrokenPipeError()

    handler = BrokenPipeHandler()

    share_console._handle_handler_exception(handler, ValueError("boom"))

    assert handler.called is True


def test_share_console_ignores_client_disconnect_without_error_response():
    class Handler:
        called = False

        def send_response(self, status):
            self.called = True

    handler = Handler()

    share_console._handle_handler_exception(handler, BrokenPipeError())

    assert handler.called is False


def test_share_console_readiness_digest_ignores_refresh_and_live_traffic_churn(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_repeated_upstream_failure_log(tmp_path)
    now = {"value": "2026-06-14T00:10:00+00:00"}
    monkeypatch.setattr(share_console, "_now_iso", lambda: now["value"])

    first = build_share_console_snapshot(tmp_path)
    append_upstream_failure_event(tmp_path, line_second=7)
    now["value"] = "2026-06-14T00:10:02+00:00"
    second = build_share_console_snapshot(tmp_path)

    first_attestation = first["readiness_gate"]["attestation"]
    second_attestation = second["readiness_gate"]["attestation"]
    assert first_attestation["generated_at"] != second_attestation["generated_at"]
    assert first_attestation["digest"] == second_attestation["digest"]
    assert first_attestation["content_digest"] == second_attestation["content_digest"]
    assert first["status"]["traffic"]["event_count"] == 3
    assert second["status"]["traffic"]["event_count"] == 4


def test_share_console_snapshot_includes_ngrok_local_console_link(tmp_path, monkeypatch):
    unused_port = unused_local_port()
    monkeypatch.setitem(
        share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
        "ngrok",
        {
            "label": "ngrok local web console",
            "url": f"http://127.0.0.1:{unused_port}",
            "description": "Inspect ngrok tunnel requests, headers, and replay details.",
        },
    )
    create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    snapshot = build_share_console_snapshot(tmp_path)
    provider_console = snapshot["provider_console"]
    tunnel_provider = snapshot["tunnel_provider"]

    assert provider_console["provider"] == "ngrok"
    assert provider_console["label"] == "ngrok local web console"
    assert provider_console["url"] == f"http://127.0.0.1:{unused_port}"
    assert provider_console["checked"] is True
    assert provider_console["reachable"] is False
    assert provider_console["status"] is None
    assert provider_console["error"]
    assert tunnel_provider["provider"] == "ngrok"
    assert tunnel_provider["label"] == "ngrok"
    assert tunnel_provider["public_url"] == "https://mcp-dev.ngrok.app/mcp"
    assert tunnel_provider["local_console"]["url"] == f"http://127.0.0.1:{unused_port}"
    assert tunnel_provider["auth"]["mode"] == "bearer"
    assert tunnel_provider["auth"]["lease_required"] is True
    assert any(command["kind"] == "provider" for command in tunnel_provider["commands"])


def test_share_console_caches_provider_console_probe_between_refreshes(tmp_path, monkeypatch):
    share_console._PROVIDER_CONSOLE_CACHE.clear()
    calls = []
    monkeypatch.setitem(
        share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
        "ngrok",
        {
            "label": "ngrok local web console",
            "url": "http://127.0.0.1:4040",
            "description": "Inspect ngrok tunnel requests, headers, and replay details.",
        },
    )

    def fake_probe(url, *, timeout):
        calls.append((url, timeout))
        return {"checked": True, "reachable": True, "status": 200, "error": None}

    monkeypatch.setattr(share_console, "_probe_provider_console", fake_probe)
    create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    first = build_share_console_snapshot(tmp_path)
    second = build_share_console_snapshot(tmp_path)

    assert len(calls) == 1
    assert first["provider_console"]["cached"] is False
    assert second["provider_console"]["cached"] is True
    assert second["provider_console"]["reachable"] is True


@pytest.mark.parametrize(
    ("provider", "public_url"),
    [
        ("ngrok", "https://mcp-dev.ngrok.app/mcp"),
        ("cloudflare", "https://mcp.example.com/mcp"),
        ("tailscale", "https://demo.tailnet.ts.net/mcp"),
        ("pinggy", "https://demo.pinggy-free.link/mcp"),
        ("holepunch", "http://127.0.0.1:18080/mcp"),
    ],
)
def test_share_console_snapshot_summarizes_tunnel_provider_panel(tmp_path, monkeypatch, provider, public_url):
    if provider == "ngrok":
        unused_port = unused_local_port()
        monkeypatch.setitem(
            share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
            "ngrok",
            {
                "label": "ngrok local web console",
                "url": f"http://127.0.0.1:{unused_port}",
                "description": "Inspect ngrok tunnel requests, headers, and replay details.",
            },
        )
    share_dir = tmp_path / provider
    create_mcp_share(
        share_dir,
        provider=provider,
        public_url=public_url,
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    snapshot = build_share_console_snapshot(share_dir)
    panel = snapshot["tunnel_provider"]

    assert panel["provider"] == provider
    assert panel["public_url"] == public_url
    assert panel["client_url"] == public_url
    assert panel["auth"]["mode"] == "bearer"
    assert panel["auth"]["lease_required"] is True
    assert panel["doctor"]["checked"] is False
    assert any(command["kind"] == "run" for command in panel["commands"])
    assert any(command["kind"] == "provider" for command in panel["commands"])
    assert any(command["kind"] == "doctor" for command in panel["commands"])
    assert "share-secret" not in json.dumps(panel)
    assert "Bearer " not in json.dumps(panel)
    if provider == "ngrok":
        assert panel["local_console"]["url"].startswith("http://127.0.0.1:")
    else:
        assert panel["local_console"]["configured"] is False


def test_share_console_serves_dashboard_and_approves_capability_request(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_capability_request_log(tmp_path)
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        prism_js = read_text(f"{server.url}/assets/prism.js")
        prism_css = read_text(f"{server.url}/assets/prism.css")
        snapshot = read_json(f"{server.url}/api/snapshot")
        report_body, report_headers = read_response(f"{server.url}/api/report/download")
        request_id = snapshot["capability_requests"]["requests"][0]["id"]
        approved = post_json(
            f"{server.url}/api/requests/{request_id}/approve",
            {"ttl": "12m", "max_calls": 2, "reviewer": "ui"},
        )
        after = read_json(f"{server.url}/api/requests?status=all")
        session_model = load_share_session_model(tmp_path)
    finally:
        server.stop()

    assert "snulbug share console" in html
    assert 'class="section-nav"' in html
    assert 'class="toolbar-group"' in html
    assert 'class="overview-grid"' in html
    assert 'aria-live="polite"' in html
    assert 'href="#readinessSection"' in html
    assert 'href="#policySection"' in html
    assert 'href="#providerSection"' in html
    assert 'id="readinessSection"' in html
    assert 'id="setupSection"' in html
    assert 'id="policySection"' in html
    assert 'id="decisionsSection"' in html
    assert 'id="requestsSection"' in html
    assert 'id="leasesSection"' in html
    assert 'id="schemaSection"' in html
    assert 'id="evidenceSection"' in html
    assert "Share Readiness" in html
    assert "Share Setup" in html
    assert "renderSetupWizard" in html
    assert "wizardActionHtml" in html
    assert "createShareFromSetup" in html
    assert "selectExistingShare" in html
    assert "copyWizardCommand" in html
    assert "renderReadinessGate" in html
    assert "readinessChecksTable" in html
    assert "setShowAllReadiness" in html
    assert "Show all" in html
    assert "passing checks hidden" in html
    assert "copyReadinessAttestation" in html
    assert "captureScrollState" in html
    assert "restoreScrollState" in html
    assert "scrollPreserveSelectors" in html
    assert "details[data-state-key]" in html
    assert "element.open = Boolean" in html
    assert "Policy Visibility" in html
    assert "renderPolicyVisibility" in html
    assert "policySourceHtml" in html
    assert "policyRecentDecisionsDetails" in html
    assert 'data-state-key="policy-recent-decisions"' in html
    assert 'data-state-key="policy-source"' in html
    assert "<summary>Recent Decisions" in html
    assert "<summary>${esc(sourceLabel)}</summary>" in html
    assert "language-lua" in html
    assert "/assets/prism.js" in html
    assert "/assets/prism.css" in html
    assert 'class="console-output"' in html
    assert 'class="token"' not in html
    assert "Capability Requests" in html
    assert "Live Decisions" in html
    assert "Tunnel Provider" in html
    assert "renderTunnelProvider" in html
    assert "providerCommandsTable" in html
    assert 'data-state-key="provider-generated-commands"' in html
    assert "Download Report" in html
    assert "/api/report/download" in html
    assert "downloadReport" in html
    assert "saveTextAsFile" in html
    assert "Active Leases" in html
    assert "renderLeases" in html
    assert "revokeLease" in html
    assert "Auth Visibility" in html
    assert "renderAuthVisibility" in html
    assert "scopeMatchText" in html
    assert "Tool And Schema Changes" in html
    assert "renderToolSchemaVisibility" in html
    assert "schemaCatalogTable" in html
    assert "Run Doctor" in html
    assert 'id="doctorPanel"' in html
    assert "renderDoctor" in html
    assert 'id="requestDrawer"' in html
    assert "selectRequest" in html
    assert "renderRequestDrawer" in html
    assert "drawer-task" in html
    assert "requestField" in html
    assert "renderDecisionTimeline" in html
    assert "setInterval(loadSnapshot, 2000)" in html
    assert "window.Prism" in prism_js
    assert "highlightAllUnder" in prism_js
    assert ".token.keyword" in prism_css
    assert snapshot["ok"] is True
    assert snapshot["policy_visibility"]["source"]["displayable"] is True
    assert "share-secret" not in snapshot["policy_visibility"]["source"]["source"]
    assert "share-secret" not in json.dumps(snapshot)
    assert "sbl_" not in json.dumps(snapshot)
    assert report_headers["content-type"].startswith("text/markdown")
    assert report_headers["content-disposition"].startswith("attachment;")
    assert report_headers["content-disposition"].endswith('report.md"')
    assert "# snulbug MCP share report" in report_body
    assert "share-secret" not in report_body
    assert "Bearer " not in report_body
    assert approved["ok"] is True
    assert approved["headers"]["x-snulbug-lease"].startswith("sbl_")
    assert approved["review"]["reviewer"] == "ui"
    assert after["summary"]["approved"] == 1
    assert session_model["capability_requests"]["last_review"]["lease_id"] == approved["review"]["lease_id"]


def test_share_console_runs_inline_share_doctor(tmp_path, monkeypatch):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )

    def fake_doctor_tunnel(**kwargs):
        return {
            "ok": True,
            "url": kwargs["url"],
            "local_url": "http://127.0.0.1:8080/mcp",
            "checks": [],
            "summary": {"passed": 1, "failed": 0, "warnings": 0, "skipped": 0},
        }

    monkeypatch.setattr("snulbug.tunnel.doctor_tunnel", fake_doctor_tunnel)
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        result = post_json(f"{server.url}/api/doctor", {"live_checks": False})
        snapshot = read_json(f"{server.url}/api/snapshot")
        session_model = load_share_session_model(tmp_path)
    finally:
        server.stop()

    encoded = json.dumps(result)
    assert result["ok"] is True
    assert result["summary"]["failed"] == 0
    assert any(check["id"] == "status.gateway_reachable" for check in result["checks"])
    assert "share-secret" not in encoded
    assert "Bearer " not in encoded
    assert session_model["health"]["share_doctor"]["ok"] is True
    assert snapshot["tunnel_provider"]["doctor"]["checked"] is True
    assert snapshot["tunnel_provider"]["doctor"]["ok"] is True
    assert snapshot["tunnel_provider"]["doctor"]["summary"]["failed"] == 0
    readiness_checks = {check["id"]: check for check in snapshot["readiness_gate"]["checks"]}
    assert readiness_checks["tunnel.doctor"]["status"] == "pass"


def test_share_console_lists_and_revokes_active_leases(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    created = create_lease(
        tmp_path / "leases.json",
        task="Read README for issue triage",
        allow_tools=["files.read_file", "git.status"],
        allow_subjects=["user-1"],
        allow_tenants=["tenant-a"],
        ttl="30m",
        max_calls=3,
        token="sbl_console-lease",
    )
    lease_id = created["lease"]["id"]
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        snapshot = read_json(f"{server.url}/api/snapshot")
        revoked = post_json(f"{server.url}/api/leases/{lease_id}/revoke", {})
        after = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    before_lease = next(item for item in snapshot["status"]["leases"]["leases"] if item["id"] == lease_id)
    after_lease = next(item for item in after["status"]["leases"]["leases"] if item["id"] == lease_id)
    listed = list_leases(tmp_path / "leases.json")
    listed_lease = next(item for item in listed["leases"] if item["id"] == lease_id)

    assert before_lease["active"] is True
    assert before_lease["task"] == "Read README for issue triage"
    assert before_lease["allow_subjects"] == ["user-1"]
    assert before_lease["allow_tenants"] == ["tenant-a"]
    assert before_lease["allow_tools"] == ["files.read_file", "git.status"]
    assert before_lease["max_calls"] == 3
    assert before_lease["use_count"] == 0
    assert revoked["ok"] is True
    assert revoked["lease"]["active"] is False
    assert after_lease["active"] is False
    assert listed_lease["active"] is False
    assert "sbl_console-lease" not in json.dumps(snapshot)
    assert "sbl_console-lease" not in json.dumps(revoked)


def test_share_console_snapshot_summarizes_auth_visibility(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    write_auth_visibility_log(tmp_path)

    snapshot = build_share_console_snapshot(tmp_path)
    auth = snapshot["auth_visibility"]

    assert auth["exists"] is True
    assert auth["summary"]["auth_events"] == 2
    assert auth["summary"]["denied"] == 1
    assert auth["current"]["subject"] == "user-1"
    assert auth["current"]["issuer"] == "https://issuer.example"
    assert auth["current"]["tenant"] == "tenant-a"
    assert auth["current"]["scopes"] == ["mcp:tools.read"]
    assert auth["current"]["groups"] == ["dev"]
    assert auth["scope_match"]["allowed"] is False
    assert auth["scope_match"]["target_tool"] == "git.push"
    assert auth["scope_match"]["reason_code"] == "oauth.scope_map_denied"
    assert auth["jwks"]["entries"] == 1
    assert auth["jwks"]["hits"] == 2
    assert auth["jwks"]["misses"] == 1
    assert auth["denials"]["total"] == 1
    assert {"value": "oauth.scope_map_denied", "count": 1} in auth["denials"]["reason_codes"]
    assert {"value": "tools/call:git.push", "count": 1} in auth["denials"]["scope_denials"]
    assert {"value": "mcp:tools.read", "count": 2} in auth["scopes"]
    assert "share-secret" not in json.dumps(auth)
    assert "Bearer " not in json.dumps(auth)


def test_share_console_snapshot_summarizes_tool_schema_changes(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["run_command"],
        validate=False,
    )
    write_tool_schema_change_artifacts(tmp_path)

    snapshot = build_share_console_snapshot(tmp_path)
    visibility = snapshot["tool_schema_visibility"]
    tools = {tool["name"]: tool for tool in visibility["tools"]}
    alert_kinds = {alert["kind"] for alert in visibility["drift_alerts"]}

    assert visibility["summary"]["catalog_count"] == 2
    assert visibility["summary"]["schema_tool_count"] == 1
    assert visibility["summary"]["drift_alerts"] >= 2
    assert visibility["schemas"]["source_count"] >= 2
    assert "run_command" in tools
    assert tools["run_command"]["risk"] == "high"
    assert tools["run_command"]["schema_variants"] == 2
    assert len(tools["run_command"]["schema_hashes"]) == 2
    assert tools["run_command"]["catalog_hashes"]
    assert "schema.variant_conflict" in tools["run_command"]["drift_signals"]
    assert "schema_variants" in alert_kinds
    assert "tool_pinning_changed" in alert_kinds
    assert "response.tool_description_changed" in alert_kinds
    readiness_checks = {check["id"]: check for check in snapshot["readiness_gate"]["checks"]}
    assert readiness_checks["schemas.drift"]["status"] == "fail"
    assert snapshot["readiness_gate"]["decision"] == "blocked"
    assert "share-secret" not in json.dumps(visibility)
    assert "Bearer " not in json.dumps(visibility)


def test_share_console_previews_policy_amendment_without_recording_candidate(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["files.read_file"],
        validate=False,
    )
    allow_policy = tmp_path / "allow.lua"
    allow_policy.write_text(
        """
        return function(request, context, state)
          return {
            action = "continue",
            reason = "observed",
            reason_code = "test.observed"
          }
        end
        """,
        encoding="utf-8",
    )
    observed_log = tmp_path / "observed.jsonl"
    append_record(
        observed_log,
        record_policy_request(
            allow_policy,
            {
                "method": "POST",
                "path": "/mcp",
                "body": (
                    '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                    '"params":{"name":"files.read_file","arguments":{"path":"README.md"}}}'
                ),
            },
            response={"status": 200},
        ),
    )
    learn_mcp_policy(observed_log, tmp_path / "policy.snulbug", force=True)
    audit_log = tmp_path / "traces" / "audit.jsonl"
    append_record(
        audit_log,
        record_policy_request(
            tmp_path / "policy.snulbug" / "policy.lua",
            {
                "method": "POST",
                "path": "/mcp",
                "body": (
                    '{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                    '"params":{"name":"git.status","arguments":{"staged":true}}}'
                ),
            },
            response={"status": 403},
        ),
    )
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        result = post_json(f"{server.url}/api/policy/amend-preview", {"source": "blocked", "validate": True})
        session_model = load_share_session_model(tmp_path)
    finally:
        server.stop()

    assert "Preview Amendment" in html
    assert 'id="amendPreviewPanel"' in html
    assert "renderAmendmentPreview" in html
    assert result["ok"] is True
    assert result["preview"]["preview"] is True
    assert result["preview"]["candidate_event_count"] == 1
    assert result["amendment"]["capability_delta"]["summary"]["newly_allowed_tools"] == 1
    assert {"kind": "tool", "value": "git.status", "reason_code": "mcp.learn.tool_not_observed"} in (
        result["amendment"]["additions"]
    )
    assert "Capability delta: newly allows 1 tool" in result["report_text"]
    assert (Path(result["output"]) / "policy.lua").is_file()
    assert session_model.get("amendments", {}).get("candidates", []) == []


def test_share_console_serves_provider_console_metadata_for_ngrok(tmp_path, monkeypatch):
    unused_port = unused_local_port()
    monkeypatch.setitem(
        share_console.DEFAULT_TUNNEL_PROVIDER_CONSOLES,
        "ngrok",
        {
            "label": "ngrok local web console",
            "url": f"http://127.0.0.1:{unused_port}",
            "description": "Inspect ngrok tunnel requests, headers, and replay details.",
        },
    )
    create_mcp_share(
        tmp_path,
        provider="ngrok",
        public_url="https://mcp-dev.ngrok.app/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    server = ShareConsoleServer(directory=tmp_path, port=0)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        snapshot = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    assert "providerConsole" in html
    assert "externalLink(url, url)" in html
    assert 'target="_blank"' in html
    assert snapshot["provider_console"]["provider"] == "ngrok"
    assert snapshot["provider_console"]["url"] == f"http://127.0.0.1:{unused_port}"
    assert snapshot["provider_console"]["reachable"] is False


def test_share_run_help_exposes_automatic_console_controls(capsys):
    with pytest.raises(SystemExit) as exc:
        simulator_main(["mcp", "share", "run", "--help"])
    output = capsys.readouterr().out

    assert exc.value.code == 0
    assert "--no-console" in output
    assert "--console-port" in output
    assert "local share web console" in output


def test_share_run_console_starts_as_sidecar(tmp_path):
    create_mcp_share(
        tmp_path,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    args = share_run_args(console_port=0)
    server = _start_share_run_console(tmp_path, args)
    try:
        assert server is not None
        html = read_text(f"{server.url}/")
    finally:
        _stop_share_run_console(server)

    assert "snulbug share console" in html
    assert "Capability Requests" in html


def test_share_run_setup_console_serves_wizard_without_session(tmp_path):
    server = ShareConsoleServer(directory=tmp_path, port=0, setup_only=True)
    server.start()
    try:
        html = read_text(f"{server.url}/")
        snapshot = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    assert "Share Setup" in html
    assert snapshot["mode"] == "setup"
    assert snapshot["setup_wizard"]["next_step"]["id"] == "create_share"
    assert snapshot["setup_defaults"]["directory"] == ".snulbug/share"


def test_share_setup_console_creates_share_and_requests_gateway_start(tmp_path):
    server = ShareConsoleServer(directory=tmp_path, port=0, setup_only=True)
    server.start()
    try:
        created = post_json(
            f"{server.url}/api/setup/create-share",
            {
                "directory": ".snulbug/share",
                "provider": "generic",
                "upstream": "http://127.0.0.1:9000",
                "public_url": "http://127.0.0.1:8080/mcp",
                "allowed_tools": "safe_read_file",
                "allowed_paths": ".",
                "validate": False,
                "start_gateway": True,
            },
        )
        snapshot = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    share_dir = tmp_path / ".snulbug" / "share"
    assert created["ok"] is True
    assert created["share"] == str(share_dir)
    assert created["run_requested"] is True
    assert server.wait_for_gateway_start(timeout=0)
    assert snapshot["mode"] == "share"
    assert snapshot["share"] == str(share_dir)
    assert load_share_session_model(share_dir)["share"]["directory"] == str(share_dir)


def test_share_setup_console_lists_and_selects_existing_share(tmp_path):
    existing = tmp_path / ".snulbug" / "shares" / "existing"
    create_mcp_share(
        existing,
        provider="generic",
        public_url="https://mcp.example.test/mcp",
        token="share-secret",
        allowed_tools=["safe_read_file"],
        validate=False,
    )
    server = ShareConsoleServer(directory=tmp_path, port=0, setup_only=True)
    server.start()
    try:
        setup_snapshot = read_json(f"{server.url}/api/snapshot")
        selected = post_json(
            f"{server.url}/api/setup/select-share",
            {"directory": str(existing), "start_gateway": False},
        )
        selected_snapshot = read_json(f"{server.url}/api/snapshot")
    finally:
        server.stop()

    listed = setup_snapshot["existing_shares"]
    assert any(share["directory"] == str(existing) for share in listed)
    assert selected["ok"] is True
    assert selected["share"] == str(existing)
    assert selected["run_requested"] is False
    assert not server.wait_for_gateway_start(timeout=0)
    assert selected_snapshot["mode"] == "share"
    assert selected_snapshot["share"] == str(existing)


def test_share_run_without_session_starts_setup_wizard(tmp_path, monkeypatch):
    calls = []

    def fake_setup_console(args):
        calls.append(args)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("snulbug.cli.share._run_share_setup_console", fake_setup_console)

    status = simulator_main(["mcp", "share", "run"])

    assert status == 0
    assert len(calls) == 1


def test_share_run_setup_console_runs_selected_share(tmp_path, monkeypatch):
    calls = []

    class FakeSetupServer:
        def __init__(self, directory, **kwargs):
            self.directory = Path(directory) / ".snulbug" / "share"
            self.url = "http://127.0.0.1:0"

        def start(self):
            calls.append(("start", self.directory))

        def wait_for_gateway_start(self, timeout=None):
            return True

        def stop(self):
            calls.append(("stop", self.directory))

    def fake_run_mcp_share(directory):
        calls.append(("run", Path(directory)))

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("snulbug.share_console.ShareConsoleServer", FakeSetupServer)
    monkeypatch.setattr("snulbug.share.run_mcp_share", fake_run_mcp_share)

    status = _run_share_setup_console(share_run_args(console_port=0))

    share_dir = tmp_path / ".snulbug" / "share"
    assert status == 0
    assert ("start", share_dir) in calls
    assert ("run", share_dir) in calls
    assert ("stop", share_dir) in calls


def test_share_run_console_respects_no_console(tmp_path):
    args = share_run_args(no_console=True)

    assert _start_share_run_console(tmp_path, args) is None


def read_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - local test server.
        return response.read().decode("utf-8")


def read_response(url: str) -> tuple[str, dict[str, str]]:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - local test server.
        headers = {key.lower(): value for key, value in response.headers.items()}
        return response.read().decode("utf-8"), headers


def read_json(url: str) -> dict[str, object]:
    return json.loads(read_text(url))


def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - local test server.
        return json.loads(response.read().decode("utf-8"))


def unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def share_run_args(
    *,
    no_console: bool = False,
    dry_run: bool = False,
    console_port: int = 8765,
) -> object:
    return type(
        "ShareRunArgs",
        (),
        {
            "no_console": no_console,
            "dry_run": dry_run,
            "console_host": "127.0.0.1",
            "console_port": console_port,
            "console_timeout": 1.0,
            "console_live_checks": False,
        },
    )()


def write_capability_request_log(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    event = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:03:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/call", "tool": "safe_read_file"},
        "decision": {
            "action": "reject",
            "allowed": False,
            "reason": "Bearer timeline-secret",
            "reason_code": "mcp.docs_capability_requested",
        },
        "metadata": {
            "auth": {
                "subject": "user-1",
                "issuer": "https://issuer.example",
                "tenant": "tenant-a",
                "client_id": "client-1",
                "groups": ["dev"],
                "profile_id": "tenant-a",
            },
            "capability_request": {
                "requested": True,
                "reason_code": "mcp.docs_capability_requested",
                "capability_request": {
                    "schema": "snulbug.capability_request.v1",
                    "kind": "task_lease",
                    "task": "Read project docs",
                    "reason_code": "mcp.docs_capability_requested",
                    "method": "tools/call",
                    "tool": "safe_read_file",
                    "argument_keys": ["path"],
                    "suggested_lease": {
                        "task": "Read project docs",
                        "ttl": "10m",
                        "max_calls": 2,
                        "allow_tools": ["safe_read_file"],
                        "allow_paths": ["README.md", "docs"],
                    },
                },
            },
        },
        "response": {"status": 403},
    }
    (traces / "audit.jsonl").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def write_repeated_upstream_failure_log(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    lines = []
    for second in (1, 3, 5):
        lines.append(json.dumps(upstream_failure_event(second), sort_keys=True))
    (traces / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def append_upstream_failure_event(tmp_path: Path, *, line_second: int) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    with (traces / "audit.jsonl").open("a", encoding="utf-8") as file:
        file.write(json.dumps(upstream_failure_event(line_second), sort_keys=True) + "\n")


def upstream_failure_event(second: int) -> dict[str, object]:
    return {
        "type": "snulbug.audit",
        "version": 1,
        "time": f"2026-06-14T00:00:{second:02d}+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/list"},
        "decision": {
            "action": "rate_limit",
            "allowed": True,
            "reason": "MCP request is allowed by the tunnel-safe profile",
            "reason_code": "mcp.tunnel_safe_rate_limit",
        },
        "metadata": {"tunnel": {"source_ip": "127.0.0.1"}},
        "response": {"status": 502},
    }


def write_auth_visibility_log(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    allowed = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:01:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/list"},
        "decision": {"action": "continue", "allowed": True, "reason_code": "test.allowed"},
        "auth": {
            "allowed": True,
            "reason_code": "oauth.allowed",
            "subject": "user-1",
            "issuer": "https://issuer.example",
            "tenant": "tenant-a",
            "groups": ["dev"],
            "scopes": ["mcp:tools.read"],
            "scope_map": {
                "enabled": True,
                "allowed": True,
                "reason_code": "oauth.scope_map_allowed",
                "matched_scope": "mcp:tools.read",
                "matched_selector": "tools/list",
                "target": {"method": "tools/list", "selectors": ["tools/list"]},
            },
            "runtime": {
                "caches": {"jwks": {"entries": 1, "hits": 1, "misses": 1, "fetches": 1, "failures": 0}},
                "decisions": {"total": 1, "allowed": 1, "reason_codes": {"oauth.allowed": 1}},
            },
        },
        "response": {"status": 200},
    }
    denied = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:02:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/call", "tool": "git.push"},
        "decision": {"action": "reject", "allowed": False, "reason_code": "oauth.scope_map_denied"},
        "auth": {
            "allowed": False,
            "reason_code": "oauth.scope_map_denied",
            "subject": "user-1",
            "issuer": "https://issuer.example",
            "tenant": "tenant-a",
            "groups": ["dev"],
            "scopes": ["mcp:tools.read"],
            "scope_map": {
                "enabled": True,
                "allowed": False,
                "reason_code": "oauth.scope_map_denied",
                "target": {"method": "tools/call", "tool": "git.push", "selectors": ["tools/call:git.push"]},
            },
            "runtime": {
                "caches": {"jwks": {"entries": 1, "hits": 2, "misses": 1, "fetches": 1, "failures": 0}},
                "decisions": {
                    "total": 2,
                    "allowed": 1,
                    "denied": 1,
                    "reason_codes": {"oauth.allowed": 1, "oauth.scope_map_denied": 1},
                    "scope_denials": {"tools/call:git.push": 1},
                },
            },
        },
        "response": {"status": 403},
    }
    lines = [json.dumps(allowed, sort_keys=True), json.dumps(denied, sort_keys=True)]
    (traces / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_tool_schema_change_artifacts(tmp_path: Path) -> None:
    first = build_mcp_schema_catalog(
        {
            "tools/list": {
                "result": {
                    "tools": [
                        {
                            "name": "run_command",
                            "description": "Run a shell command",
                            "inputSchema": {
                                "type": "object",
                                "required": ["command"],
                                "properties": {"command": {"type": "string"}},
                                "additionalProperties": False,
                            },
                        }
                    ]
                }
            }
        },
        methods=("tools/list",),
        label="baseline",
    )
    second = build_mcp_schema_catalog(
        {
            "tools/list": {
                "result": {
                    "tools": [
                        {
                            "name": "run_command",
                            "description": "Run a shell command with cwd",
                            "inputSchema": {
                                "type": "object",
                                "required": ["command", "cwd"],
                                "properties": {
                                    "command": {"type": "string"},
                                    "cwd": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                        }
                    ]
                }
            }
        },
        methods=("tools/list",),
        label="current",
    )
    traces = tmp_path / "traces"
    traces.mkdir(exist_ok=True)
    (traces / "schemas.json").write_text(json.dumps(first, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    schemas = tmp_path / "schemas"
    schemas.mkdir(exist_ok=True)
    (schemas / "current.json").write_text(json.dumps(second, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event = {
        "type": "snulbug.audit",
        "version": 1,
        "time": "2026-06-14T00:04:00+00:00",
        "request": {"method": "POST", "path": "/mcp", "headers": {}},
        "mcp": {"method": "tools/list"},
        "decision": {"action": "continue", "allowed": False, "reason_code": "response.tool_description_changed"},
        "metadata": {
            "response_policy": {
                "checked": True,
                "reason_code": "response.tool_description_changed",
                "reason": "pinned tool descriptions changed",
                "tool_pinning": {
                    "changed": [
                        {
                            "tool": "run_command",
                            "previous_hash": first["surfaces"]["tools"][0]["hash"],
                            "current_hash": second["surfaces"]["tools"][0]["hash"],
                        }
                    ]
                },
            }
        },
        "response": {"status": 200},
    }
    (traces / "audit.jsonl").write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

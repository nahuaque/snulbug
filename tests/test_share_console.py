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
from snulbug.cli.share import _start_share_run_console, _stop_share_run_console
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

    assert snapshot["ok"] is True
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
    encoded = json.dumps(snapshot)
    assert "share-secret" not in encoded
    assert "sbl_" not in encoded
    assert "timeline-secret" not in encoded
    assert snapshot["status"]["client"]["headers"]["Authorization"] == "[REDACTED]"
    assert snapshot["status"]["client"]["headers"]["x-snulbug-lease"] == "[REDACTED]"


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
        snapshot = read_json(f"{server.url}/api/snapshot")
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
    assert "Capability Requests" in html
    assert "Live Decisions" in html
    assert "Tunnel Provider" in html
    assert "renderTunnelProvider" in html
    assert "providerCommandsTable" in html
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
    assert snapshot["ok"] is True
    assert "share-secret" not in json.dumps(snapshot)
    assert "sbl_" not in json.dumps(snapshot)
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


def test_share_run_console_respects_no_console(tmp_path):
    args = share_run_args(no_console=True)

    assert _start_share_run_console(tmp_path, args) is None


def read_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - local test server.
        return response.read().decode("utf-8")


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

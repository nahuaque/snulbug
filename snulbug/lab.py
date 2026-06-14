from __future__ import annotations

import asyncio
import base64
import http.client
import io
import json
import secrets
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import jwt

from .config import load_mcp_proxy_config
from .events import ConsoleEventSink, EventDispatcher, JsonlEventSink
from .inspection import format_mcp_inspection_report, inspect_mcp_log
from .learn import amend_mcp_policy, learn_mcp_policy
from .leases import create_lease, list_leases
from .proxy import create_proxy_application
from .recorder import append_record, record_policy_request
from .share import doctor_mcp_share_auth
from .simulator import simulate_policy

DEFAULT_LAB_DIR = Path(".snulbug-lab")
DEFAULT_AUTH_LAB_DIR = Path(".snulbug-auth-lab")


def run_mcp_lab(output_dir: str | Path = DEFAULT_LAB_DIR, *, force: bool = True, emit: bool = True) -> dict[str, Any]:
    """Run a deterministic local MCP policy lab and write all artifacts to disk."""

    output = Path(output_dir)
    if output.exists():
        if not force:
            raise FileExistsError(f"lab output already exists: {output}")
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    traces = output / "traces"
    traces.mkdir(parents=True, exist_ok=True)

    starter_policy = output / "starter-policy.lua"
    starter_policy.write_text(_starter_policy(), encoding="utf-8")

    files_server = _create_server(
        {
            "read_file": "Read a project file.",
            "shell_exec": "Unsafe shell execution demo.",
        }
    )
    git_server = _create_server({"status": "Show git status."})
    files_thread = threading.Thread(target=files_server.serve_forever, daemon=True)
    git_thread = threading.Thread(target=git_server.serve_forever, daemon=True)
    files_thread.start()
    git_thread.start()

    files_url = f"http://127.0.0.1:{files_server.server_port}/mcp"
    git_url = f"http://127.0.0.1:{git_server.server_port}/mcp"
    record_log = traces / "session.jsonl"
    audit_log = traces / "audit.jsonl"
    blocked_log = traces / "blocked.jsonl"
    report_path = traces / "session-report.md"
    console = io.StringIO()
    try:
        app = create_proxy_application(
            None,
            starter_policy,
            upstreams=[
                {"name": "files", "url": files_url, "default": True},
                {"name": "git", "url": git_url},
            ],
            record_out=record_log,
            event_dispatcher=EventDispatcher(
                [
                    JsonlEventSink(audit_log, events=("snulbug.audit",)),
                    ConsoleEventSink(console, output_format="text"),
                ]
            ),
            timeout=5.0,
        )
        listed = _send_mcp(app, "list-tools", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        observed = _send_mcp(
            app,
            "observed-files-read",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "files.read_file", "arguments": {"path": "README.md"}},
            },
        )
        risky = _send_mcp(
            app,
            "blocked-risky-shell",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "files.shell_exec", "arguments": {"command": "pwd"}},
            },
        )

        inspection = inspect_mcp_log(audit_log, kind="audit")
        report_path.write_text(format_mcp_inspection_report(inspection), encoding="utf-8")
        learned_dir = output / "learned-policy.snulbug"
        learned = learn_mcp_policy(record_log, learned_dir)

        git_request = {
            "method": "POST",
            "path": "/mcp",
            "body": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "git.status", "arguments": {"staged": True}},
                },
                sort_keys=True,
            ),
        }
        learned_block = record_policy_request(learned_dir / "policy.lua", git_request, response={"status": 403})
        append_record(blocked_log, learned_block)
        candidate_dir = output / "candidate-policy.snulbug"
        amended = amend_mcp_policy(learned_dir, blocked_log, candidate_dir)
        candidate_result = simulate_policy(candidate_dir / "policy.lua", git_request)
    finally:
        files_server.shutdown()
        files_server.server_close()
        git_server.shutdown()
        git_server.server_close()

    tools = _tool_names(listed)
    result = {
        "ok": (
            listed["status"] == 200
            and observed["status"] == 200
            and risky["status"] == 403
            and learned_block["result"]["action"] == "reject"
            and candidate_result["action"] == "continue"
            and learned["ok"]
            and amended["ok"]
        ),
        "output_dir": str(output),
        "proxy_url": "http://127.0.0.1:8080/mcp",
        "upstreams": {"files": files_url, "git": git_url},
        "tools": tools,
        "steps": [
            {"name": "listed_tools", "ok": listed["status"] == 200, "tools": tools},
            {"name": "allowed_observed_call", "ok": observed["status"] == 200, "tool": "files.read_file"},
            {
                "name": "blocked_risky_call",
                "ok": risky["status"] == 403,
                "tool": "files.shell_exec",
                "status": risky["status"],
            },
            {"name": "learned_policy", "ok": learned["ok"], "path": learned["output"]},
            {
                "name": "learned_blocked_unobserved_call",
                "ok": learned_block["result"]["action"] == "reject",
                "tool": "git.status",
                "reason_code": learned_block["result"]["decision"].get("reason_code"),
            },
            {"name": "amended_candidate", "ok": amended["ok"], "path": amended["output"]},
            {"name": "candidate_allowed_call", "ok": candidate_result["action"] == "continue", "tool": "git.status"},
        ],
        "artifacts": {
            "starter_policy": str(starter_policy),
            "record_log": str(record_log),
            "audit_log": str(audit_log),
            "blocked_log": str(blocked_log),
            "session_report": str(report_path),
            "learned_policy": learned["output"],
            "candidate_policy": amended["output"],
            "amend_report": amended["report"],
        },
        "responses": [listed, observed, risky],
        "learned": learned,
        "amended": amended,
        "decision_console": console.getvalue().strip().splitlines(),
    }
    if emit:
        _print_lab(result)
    return result


def run_mcp_auth_lab(
    output_dir: str | Path = DEFAULT_AUTH_LAB_DIR,
    *,
    force: bool = True,
    emit: bool = True,
) -> dict[str, Any]:
    """Run a deterministic OAuth + lease + Lua auth lab and write artifacts."""

    output = Path(output_dir)
    if output.exists():
        if not force:
            raise FileExistsError(f"auth lab output already exists: {output}")
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    auth_dir = output / "auth"
    traces = output / "traces"
    requests_dir = output / "requests"
    auth_dir.mkdir(parents=True, exist_ok=True)
    traces.mkdir(parents=True, exist_ok=True)
    requests_dir.mkdir(parents=True, exist_ok=True)

    policy = output / "policy.lua"
    policy.write_text(_auth_lab_policy(), encoding="utf-8")

    secret = secrets.token_urlsafe(32)
    jwks = _auth_lab_jwks(secret)
    jwks_path = auth_dir / "jwks.json"
    jwks_path.write_text(json.dumps(jwks, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lease = create_lease(
        output / "leases.json",
        task="Inspect git status for the auth lab",
        allow_tools=["git.status"],
        ttl="30m",
        max_calls=5,
    )
    lease_token = str(lease["token"])

    upstream_server = _create_server({"git.status": "Show git status."})
    issuer_server = _create_auth_issuer_server(jwks)
    bridge_server = _create_asgi_bridge_server()
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    issuer_thread = threading.Thread(target=issuer_server.serve_forever, daemon=True)
    bridge_thread = threading.Thread(target=bridge_server.serve_forever, daemon=True)
    upstream_thread.start()
    issuer_thread.start()

    upstream_url = f"http://127.0.0.1:{upstream_server.server_port}/mcp"
    issuer_url = f"http://127.0.0.1:{issuer_server.server_port}"
    proxy_url = f"http://127.0.0.1:{bridge_server.server_port}/mcp"
    issuer_server.issuer_url = issuer_url
    issuer_server.jwks = jwks
    tokens = {
        "allowed": _auth_lab_token(
            secret,
            scopes=["mcp:connect", "mcp:tools.read", "mcp:tool.git.status"],
            subject="user-1",
            issuer=issuer_url,
            audience=proxy_url,
            extra_claims={
                "email": "user@example.test",
                "groups": ["platform-dev", "mcp-users"],
                "tid": "tenant-a",
            },
        ),
        "missing_tool_scope": _auth_lab_token(
            secret,
            scopes=["mcp:connect", "mcp:tools.read"],
            subject="user-2",
            issuer=issuer_url,
            audience=proxy_url,
            extra_claims={
                "email": "user2@example.test",
                "groups": ["platform-dev", "mcp-users"],
                "tid": "tenant-a",
            },
        ),
    }
    tokens_path = auth_dir / "tokens.json"
    tokens_path.write_text(json.dumps(tokens, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    config = output / "snulbug.toml"
    record_log = traces / "session.jsonl"
    audit_log = traces / "audit.jsonl"
    report_path = output / "AUTH_LAB.md"
    config.write_text(
        _auth_lab_config(
            upstream_url=upstream_url,
            proxy_url=proxy_url,
            issuer_url=issuer_url,
        ),
        encoding="utf-8",
    )
    proxy_config = load_mcp_proxy_config(config)
    app = _auth_lab_proxy_app(proxy_config)
    bridge_server.app = app
    bridge_thread.start()

    allowed_request = {
        "jsonrpc": "2.0",
        "id": "allowed-call",
        "method": "tools/call",
        "params": {"name": "git.status", "arguments": {"staged": True}},
    }
    missing_lease_request = {
        "jsonrpc": "2.0",
        "id": "missing-lease",
        "method": "tools/call",
        "params": {"name": "git.status", "arguments": {"staged": True}},
    }
    scope_denied_request = {
        "jsonrpc": "2.0",
        "id": "scope-denied",
        "method": "tools/call",
        "params": {"name": "git.status", "arguments": {"staged": True}},
    }
    (requests_dir / "allowed-call.json").write_text(
        json.dumps(allowed_request, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (requests_dir / "missing-lease.json").write_text(
        json.dumps(missing_lease_request, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (requests_dir / "scope-denied.json").write_text(
        json.dumps(scope_denied_request, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    try:
        doctor = doctor_mcp_share_auth(
            config=config,
            public_url=proxy_url,
            token=tokens["allowed"],
            timeout=5.0,
        )
        allowed = _post_auth_lab_mcp(
            proxy_url,
            allowed_request,
            token=tokens["allowed"],
            lease_token=lease_token,
        )
        missing_lease = _post_auth_lab_mcp(
            proxy_url,
            missing_lease_request,
            token=tokens["allowed"],
        )
        scope_denied = _post_auth_lab_mcp(
            proxy_url,
            scope_denied_request,
            token=tokens["missing_tool_scope"],
            lease_token=lease_token,
        )
    finally:
        bridge_server.shutdown()
        bridge_server.server_close()
        issuer_server.shutdown()
        issuer_server.server_close()
        upstream_server.shutdown()
        upstream_server.server_close()
        bridge_thread.join(timeout=2)
        issuer_thread.join(timeout=2)
        upstream_thread.join(timeout=2)

    access_events = _auth_lab_access_events(audit_log)
    access_by_id = {
        str(event.get("request_id")): event for event in access_events if event.get("request_id") is not None
    }
    session_text = record_log.read_text(encoding="utf-8") if record_log.exists() else ""
    audit_text = audit_log.read_text(encoding="utf-8") if audit_log.exists() else ""
    token_redacted = all(token not in session_text and token not in audit_text for token in tokens.values())
    active_leases = list_leases(output / "leases.json")

    steps = [
        {"name": "auth_doctor", "ok": doctor["ok"], "summary": doctor.get("summary")},
        {
            "name": "allowed_oauth_scope_lease_lua",
            "ok": allowed["status"] == 200 and _access_allowed(access_by_id.get("allowed-call")),
            "status": allowed["status"],
            "access": access_by_id.get("allowed-call"),
        },
        {
            "name": "blocked_missing_task_lease",
            "ok": missing_lease["status"] == 403
            and _access_reason(access_by_id.get("missing-lease")) == "lease.missing",
            "status": missing_lease["status"],
            "access": access_by_id.get("missing-lease"),
        },
        {
            "name": "blocked_missing_oauth_tool_scope",
            "ok": scope_denied["status"] == 403
            and _access_reason(access_by_id.get("scope-denied")) == "oauth.scope_map_denied",
            "status": scope_denied["status"],
            "access": access_by_id.get("scope-denied"),
        },
        {"name": "raw_tokens_redacted_from_logs", "ok": token_redacted},
    ]
    result = {
        "ok": all(bool(step["ok"]) for step in steps),
        "output_dir": str(output),
        "proxy_url": proxy_url,
        "issuer_url": issuer_url,
        "upstream_url": upstream_url,
        "steps": steps,
        "doctor": doctor,
        "responses": {
            "allowed": allowed,
            "missing_lease": missing_lease,
            "scope_denied": scope_denied,
        },
        "access_events": access_events,
        "leases": active_leases,
        "token_redacted": token_redacted,
        "artifacts": {
            "config": str(config),
            "policy": str(policy),
            "jwks": str(jwks_path),
            "tokens": str(tokens_path),
            "leases": str(output / "leases.json"),
            "requests": str(requests_dir),
            "record_log": str(record_log),
            "audit_log": str(audit_log),
            "report": str(report_path),
        },
        "commands": {
            "doctor": (
                f"uv run snulbug mcp share auth doctor --config {config} --url {proxy_url} --token '<allowed-token>'"
            ),
            "inspect": f"uv run snulbug mcp evidence inspect {audit_log}",
        },
    }
    result["report"] = format_mcp_auth_lab_report(result)
    report_path.write_text(result["report"], encoding="utf-8")
    if emit:
        _print_auth_lab(result)
    return result


def format_mcp_auth_lab_report(result: dict[str, Any]) -> str:
    lines = [
        "# snulbug MCP OAuth auth lab",
        "",
        f"Result: {'pass' if result.get('ok') else 'fail'}",
        f"Proxy URL: `{result.get('proxy_url')}`",
        f"Issuer URL: `{result.get('issuer_url')}`",
        f"Upstream URL: `{result.get('upstream_url')}`",
        "",
        "## Checks",
    ]
    for step in result.get("steps", []):
        if isinstance(step, dict):
            lines.append(f"- [{'pass' if step.get('ok') else 'fail'}] {step.get('name')}")

    lines.extend(["", "## Access Decisions"])
    for event in result.get("access_events", []):
        if not isinstance(event, dict):
            continue
        lines.append(
            "- "
            f"`{event.get('request_id')}` "
            f"{event.get('method') or '-'} "
            f"{event.get('tool') or '-'}: "
            f"`{event.get('reason_code') or '-'}` "
            f"allowed={str(bool(event.get('allowed'))).lower()}"
        )

    lines.extend(["", "## Artifacts"])
    for name, path in result.get("artifacts", {}).items():
        lines.append(f"- `{name}`: `{path}`")

    commands = result.get("commands", {})
    if commands:
        lines.extend(["", "## Next Commands"])
        for name, command in commands.items():
            lines.append(f"- `{name}`: `{command}`")
    return "\n".join(lines).rstrip() + "\n"


def _send_mcp(app: Any, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    sent = _run_asgi(
        app,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 1234),
            "state": {},
        },
        body,
    )
    response_body = sent[1].get("body", b"")
    return {
        "name": name,
        "status": sent[0]["status"],
        "body": response_body.decode("utf-8", errors="replace"),
    }


def _run_asgi(app: Any, scope: dict[str, Any], body: bytes) -> list[dict[str, Any]]:
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent


def _tool_names(response: dict[str, Any]) -> list[str]:
    try:
        payload = json.loads(response["body"])
        tools = payload["result"]["tools"]
    except Exception:
        return []
    return [tool["name"] for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)]


def _create_server(tools: dict[str, str]) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            try:
                request = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                return

            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            if method == "tools/list":
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "tools": [
                                {
                                    "name": name,
                                    "description": description,
                                    "inputSchema": {"type": "object"},
                                }
                                for name, description in tools.items()
                            ]
                        },
                    }
                )
                return
            if method == "tools/call":
                tool = str(params.get("name", ""))
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [{"type": "text", "text": f"called {tool}"}],
                        },
                    }
                )
                return
            self._send_json({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "not found"}})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, payload: Any) -> None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def _starter_policy() -> str:
    return """
return function(request, context, state)
  if request.path ~= "/mcp" then
    return {
      action = "reject",
      status = 404,
      body = "unknown MCP endpoint",
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "lab.endpoint_not_found"
    }
  end

  local method = mcp.method(request)
  if method == "tools/list" then
    return {
      action = "continue",
      reason = "Lab allows tool discovery",
      reason_code = "lab.tools_list_allowed",
      context = { method = method }
    }
  end

  local tool = mcp.tool_name(request)
  if tool == "files.read_file" then
    return {
      action = "continue",
      reason = "Lab allows observed file reads",
      reason_code = "lab.tool_allowed",
      context = { method = method or "", tool = tool }
    }
  end

  return {
    action = "reject",
    status = 403,
    body = "tool not allowed in lab starter policy",
    reason = "Tool is outside the lab starter allowlist",
    reason_code = "lab.tool_not_allowed",
    context = { method = method or "", tool = tool or "" }
  }
end
"""


def _print_lab(result: dict[str, Any]) -> None:
    print("snulbug MCP policy lab")
    print("")
    print(f"proxy:     {result['proxy_url']}")
    upstreams = result["upstreams"]
    print(f"upstreams: files={upstreams['files']}, git={upstreams['git']}")
    print("")
    print(f"1. Listed tools through facade: {', '.join(result['tools'])}")
    print("2. Allowed observed call: files.read_file")
    print("3. Blocked risky call: files.shell_exec")
    print(f"4. Learned policy: {result['artifacts']['learned_policy']}")
    print("5. Learned policy blocked unobserved call: git.status")
    print(f"6. Amended candidate: {result['artifacts']['candidate_policy']}")
    print("7. Candidate allowed: git.status")
    print("")
    print("Artifacts:")
    for label, path in result["artifacts"].items():
        print(f"- {label}: {path}")


def _print_auth_lab(result: dict[str, Any]) -> None:
    print("snulbug MCP OAuth auth lab")
    print("")
    print(f"proxy:    {result['proxy_url']}")
    print(f"issuer:   {result['issuer_url']}")
    print(f"upstream: {result['upstream_url']}")
    print("")
    for step in result["steps"]:
        status = "pass" if step.get("ok") else "fail"
        print(f"- [{status}] {step.get('name')}")
    print("")
    print("Artifacts:")
    for label, path in result["artifacts"].items():
        print(f"- {label}: {path}")


def _auth_lab_jwks(secret: str) -> dict[str, Any]:
    key = base64.urlsafe_b64encode(secret.encode("utf-8")).rstrip(b"=").decode("ascii")
    return {"keys": [{"kty": "oct", "kid": "auth-lab-key", "alg": "HS256", "k": key}]}


def _auth_lab_token(
    secret: str,
    *,
    scopes: list[str],
    subject: str,
    issuer: str,
    audience: str,
    extra_claims: Mapping[str, Any] | None = None,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "client_id": "auth-lab-agent",
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + 600,
            **dict(extra_claims or {}),
        },
        secret,
        algorithm="HS256",
        headers={"kid": "auth-lab-key"},
    )


def _auth_lab_config(*, upstream_url: str, proxy_url: str, issuer_url: str) -> str:
    return f"""[mcp.proxy]
upstream = {json.dumps(upstream_url)}
policy = "policy.lua"
record_out = "traces/session.jsonl"
lease_file = "leases.json"
lease_required = true
lease_header = "x-snulbug-lease"
tunnel_provider = "generic"
tunnel_public_url = {json.dumps(proxy_url)}
tool_pinning = false
schema_validation = false
response_redact_secrets = true
redact_records = true
timeout = 5.0

[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(proxy_url)}
issuer = {json.dumps(issuer_url)}
authorization_servers = [{json.dumps(issuer_url)}]
audience = {json.dumps(proxy_url)}
required_scopes = ["mcp:connect"]
jwks_url = {json.dumps(f"{issuer_url}/jwks")}
jwks_cache_seconds = 300
jwks_fetch_timeout = 5
strip_authorization_upstream = true

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list"]
"mcp:tool.git.status" = ["tools/call:git.status"]
"""


def _auth_lab_policy() -> str:
    return """
return function(request, context, state)
  if request.path ~= "/mcp" then
    return decision.reject(404, "unknown MCP endpoint", {
      reason = "Request path is not the configured MCP endpoint",
      reason_code = "auth_lab.endpoint_not_found"
    })
  end

  local method = mcp.method(request)
  if method == "tools/list" then
    return {
      action = "continue",
      reason = "Lab allows scoped tool discovery",
      reason_code = "auth_lab.tools_list_allowed",
      context = {
        method = method,
        auth_subject = auth.subject() or ""
      }
    }
  end

  local tool = mcp.tool_name(request)
  if method == "tools/call" and tool == "git.status" then
    local missing_scope = auth.require("tools/call:git.status", {
      reason_code = "auth_lab.git_status_scope_required",
      body = "git.status scope required"
    })
    if missing_scope then
      return missing_scope
    end

    local wrong_tenant = auth.require_tenant("tenant-a", {
      reason_code = "auth_lab.tenant_required",
      body = "tenant-a required"
    })
    if wrong_tenant then
      return wrong_tenant
    end

    local missing_group = auth.require_group("platform-dev", {
      reason_code = "auth_lab.platform_group_required",
      body = "platform-dev group required"
    })
    if missing_group then
      return missing_group
    end

    local wrong_subject = auth.require_subject({"user-1", "breakglass-user"}, {
      reason_code = "auth_lab.subject_required",
      body = "approved OAuth subject required"
    })
    if wrong_subject then
      return wrong_subject
    end

    local missing_lease = lease.require({
      reason_code = "auth_lab.active_lease_required",
      body = "active task lease required"
    })
    if missing_lease then
      return missing_lease
    end

    return {
      action = "continue",
      reason = "OAuth subject has git.status scope and an active task lease",
      reason_code = "auth_lab.allowed",
      context = {
        method = method,
        tool = tool,
        auth_subject = auth.subject() or "",
        auth_tenant = auth.tenant() or "",
        auth_group = "platform-dev",
        lease_active = lease.active(),
        lease_id = lease.id() or "",
        lease_task = lease.task() or ""
      }
    }
  end

  return decision.reject(403, "tool not allowed in auth lab", {
    reason = "Tool is outside the auth lab allowlist",
    reason_code = "auth_lab.tool_not_allowed",
    context = {
      method = method or "",
      tool = tool or ""
    }
  })
end
"""


def _auth_lab_proxy_app(proxy_config: Mapping[str, Any]) -> Any:
    return create_proxy_application(
        proxy_config["upstream"],
        proxy_config["policy"],
        upstream_credential=proxy_config.get("upstream_credential"),
        upstreams=proxy_config["upstreams"],
        trace=proxy_config["trace"],
        max_body_bytes=proxy_config["max_body_bytes"],
        timeout=proxy_config["timeout"],
        record_out=proxy_config["record_out"],
        redact_records=proxy_config["redact_records"],
        response_max_bytes=proxy_config["response_max_bytes"],
        response_redact_secrets=proxy_config["response_redact_secrets"],
        response_block_instructions=proxy_config["response_block_instructions"],
        tool_pinning=proxy_config["tool_pinning"],
        tool_pinning_action=proxy_config["tool_pinning_action"],
        schema_validation=proxy_config["schema_validation"],
        schema_validation_action=proxy_config["schema_validation_action"],
        facade_health_routing=proxy_config["facade_health_routing"],
        facade_health_failure_threshold=proxy_config["facade_health_failure_threshold"],
        facade_health_cooldown_seconds=proxy_config["facade_health_cooldown_seconds"],
        facade_health_exclude_unhealthy=proxy_config["facade_health_exclude_unhealthy"],
        lease_file=proxy_config["lease_file"],
        lease_required=proxy_config["lease_required"],
        lease_header=proxy_config["lease_header"],
        tunnel_provider=proxy_config["tunnel_provider"],
        tunnel_public_url=proxy_config["tunnel_public_url"],
        cloudflare_access=proxy_config["cloudflare_access"],
        cloudflare_access_require_jwt=proxy_config["cloudflare_access_require_jwt"],
        cloudflare_access_require_email=proxy_config["cloudflare_access_require_email"],
        cloudflare_access_require_cf_ray=proxy_config["cloudflare_access_require_cf_ray"],
        cloudflare_access_allowed_emails=proxy_config["cloudflare_access_allowed_emails"],
        cloudflare_access_allowed_domains=proxy_config["cloudflare_access_allowed_domains"],
        auth_config=proxy_config.get("auth", {}),
        event_sinks=proxy_config["event_sinks"],
    )


def _create_auth_issuer_server(jwks: Mapping[str, Any]) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            issuer = getattr(self.server, "issuer_url", "")
            if self.path in {"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"}:
                self._send_json({"issuer": issuer, "jwks_uri": f"{issuer}/jwks"})
                return
            if self.path == "/jwks":
                self._send_json(getattr(self.server, "jwks", jwks))
                return
            self._send_json({"error": "not found"}, status=404)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, payload: Any, *, status: int = 200) -> None:
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.jwks = jwks  # type: ignore[attr-defined]
    return server


def _create_asgi_bridge_server() -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self) -> None:  # noqa: N802
            self._handle_asgi()

        def do_GET(self) -> None:  # noqa: N802
            self._handle_asgi()

        def do_POST(self) -> None:  # noqa: N802
            self._handle_asgi()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _handle_asgi(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            parsed = urlsplit(self.path)
            app = getattr(self.server, "app")
            sent = _run_asgi(
                app,
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": self.command,
                    "scheme": "http",
                    "path": parsed.path or "/",
                    "raw_path": (parsed.path or "/").encode("ascii", errors="ignore"),
                    "query_string": parsed.query.encode("ascii", errors="ignore"),
                    "headers": [
                        (name.lower().encode("latin-1"), value.encode("latin-1"))
                        for name, value in self.headers.items()
                    ],
                    "client": self.client_address,
                    "state": {},
                },
                body,
            )
            start = next((message for message in sent if message.get("type") == "http.response.start"), None)
            if not isinstance(start, dict):
                self.send_response(500)
                self.end_headers()
                return
            response_body = b"".join(
                message.get("body", b"") for message in sent if message.get("type") == "http.response.body"
            )
            self.send_response(int(start.get("status", 500)))
            for name, value in start.get("headers", []):
                header_name = name.decode("latin-1")
                if header_name.lower() in {"connection", "transfer-encoding"}:
                    continue
                self.send_header(header_name, value.decode("latin-1"))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


def _post_auth_lab_mcp(
    url: str,
    payload: Mapping[str, Any],
    *,
    token: str,
    lease_token: str | None = None,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {token}",
    }
    if lease_token is not None:
        headers["x-snulbug-lease"] = lease_token
    try:
        connection.request("POST", _auth_lab_request_target(parsed), body=raw, headers=headers)
        response = connection.getresponse()
        body = response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()
    try:
        parsed_body = json.loads(body)
    except json.JSONDecodeError:
        parsed_body = None
    return {
        "status": int(response.status),
        "body": body,
        "json": parsed_body,
    }


def _auth_lab_request_target(parsed: Any) -> str:
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return target


def _auth_lab_access_events(audit_log: Path) -> list[dict[str, Any]]:
    if not audit_log.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        mcp = event.get("mcp") if isinstance(event.get("mcp"), Mapping) else {}
        access = event.get("access") if isinstance(event.get("access"), Mapping) else {}
        if mcp.get("request_id") is None and mcp.get("method") is None:
            continue
        auth = access.get("auth") if isinstance(access.get("auth"), Mapping) else {}
        scope = access.get("scope") if isinstance(access.get("scope"), Mapping) else {}
        lease = access.get("lease") if isinstance(access.get("lease"), Mapping) else {}
        lua = access.get("lua") if isinstance(access.get("lua"), Mapping) else {}
        events.append(
            {
                "request_id": mcp.get("request_id"),
                "method": mcp.get("method"),
                "tool": mcp.get("tool"),
                "allowed": access.get("allowed"),
                "reason_code": access.get("reason_code"),
                "auth_subject": auth.get("subject"),
                "auth_tenant": auth.get("tenant"),
                "auth_groups": auth.get("groups"),
                "scope_matched": scope.get("matched_scope"),
                "scope_selector": scope.get("matched_selector"),
                "lease_id": lease.get("id"),
                "lease_required": lease.get("required"),
                "lease_required_for_request": lease.get("required_for_request"),
                "lua_reason_code": lua.get("reason_code"),
            }
        )
    return events


def _access_allowed(event: Mapping[str, Any] | None) -> bool:
    return isinstance(event, Mapping) and event.get("allowed") is True


def _access_reason(event: Mapping[str, Any] | None) -> str | None:
    if not isinstance(event, Mapping):
        return None
    reason_code = event.get("reason_code")
    return str(reason_code) if reason_code is not None else None

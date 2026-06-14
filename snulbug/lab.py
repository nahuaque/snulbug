from __future__ import annotations

import asyncio
import io
import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .events import ConsoleEventSink, EventDispatcher, JsonlEventSink
from .inspection import format_mcp_inspection_report, inspect_mcp_log
from .learn import amend_mcp_policy, learn_mcp_policy
from .proxy import create_proxy_application
from .recorder import append_record, record_policy_request
from .simulator import simulate_policy

DEFAULT_LAB_DIR = Path(".snulbug-lab")


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

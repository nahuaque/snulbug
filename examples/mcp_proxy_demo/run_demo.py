from __future__ import annotations

import argparse
import asyncio
import io
import json
import shutil
import threading
from pathlib import Path
from typing import Any

from snulbug import (
    ConsoleEventSink,
    EventDispatcher,
    JsonlEventSink,
    create_mcp_quickstart,
    create_proxy_application,
    inspect_mcp_log,
    load_record_log,
)

try:
    from .upstream import create_server
except ImportError:  # pragma: no cover - used when running this file directly.
    from upstream import create_server  # type: ignore[no-redef]

BASE_DIR = Path(__file__).parent
DEFAULT_OUTPUT_DIR = BASE_DIR / ".run"
TOKEN = "local-dev-secret"
ALLOWED_TOOLS = ["safe_read_file", "list_project_files"]


def run_demo(output_dir: str | Path = DEFAULT_OUTPUT_DIR, *, emit: bool = True) -> dict[str, Any]:
    output = Path(output_dir)
    if output.exists():
        shutil.rmtree(output)

    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    upstream = f"http://127.0.0.1:{server.server_port}"
    try:
        starter = create_mcp_quickstart(
            output,
            upstream=upstream,
            token=TOKEN,
            allowed_tools=ALLOWED_TOOLS,
            force=True,
        )
        console = io.StringIO()
        audit_log = Path(starter["proxy"]["event_sinks"][0]["path"])
        if not audit_log.is_absolute():
            audit_log = output / audit_log
        app = create_proxy_application(
            upstream,
            starter["policy_file"],
            record_out=starter["proxy"]["record_out"],
            event_dispatcher=EventDispatcher(
                [
                    JsonlEventSink(audit_log, events=("snulbug.audit",)),
                    ConsoleEventSink(console, output_format="text"),
                ]
            ),
            timeout=5.0,
        )

        cases = [
            (
                "missing-auth",
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                None,
            ),
            (
                "allowed-safe-tool",
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "safe_read_file", "arguments": {"path": "README.md"}},
                },
                f"Bearer {TOKEN}",
            ),
            (
                "blocked-shell-tool",
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "shell_exec", "arguments": {"cmd": "echo unsafe"}},
                },
                f"Bearer {TOKEN}",
            ),
        ]
        responses = [
            _send_mcp_request(app, name=name, payload=payload, authorization=authorization)
            for name, payload, authorization in cases
        ]
        records = load_record_log(starter["proxy"]["record_out"])
        inspection = inspect_mcp_log(audit_log, kind="audit")
        result = {
            "ok": _expected_responses(responses) and inspection["event_count"] == 3,
            "upstream": f"{upstream}/mcp",
            "proxy_client_url": starter["client"]["url"],
            "authorization": starter["client"]["headers"]["Authorization"],
            "config": starter["config"],
            "policy": starter["policy"],
            "record_log": starter["proxy"]["record_out"],
            "audit_log": str(audit_log),
            "responses": responses,
            "record_count": len(records),
            "inspection": inspection,
            "decision_console": console.getvalue().strip().splitlines(),
        }
    finally:
        server.shutdown()
        server.server_close()

    if emit:
        _print_result(result)
    return result


def _send_mcp_request(
    app: Any,
    *,
    name: str,
    payload: dict[str, Any],
    authorization: str | None,
) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = [(b"content-type", b"application/json")]
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("latin-1")))

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
            "headers": headers,
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


def _expected_responses(responses: list[dict[str, Any]]) -> bool:
    expected = {
        "missing-auth": 401,
        "allowed-safe-tool": 200,
        "blocked-shell-tool": 403,
    }
    return all(response["status"] == expected[response["name"]] for response in responses)


def _print_result(result: dict[str, Any]) -> None:
    print("snulbug MCP proxy demo")
    print(f"upstream server: {result['upstream']}")
    print(f"proxy client URL: {result['proxy_client_url']}")
    print(f"client header: Authorization: {result['authorization']}")
    print("")
    for response in result["responses"]:
        print(f"{response['name']}: HTTP {response['status']} {response['body']}")
    print("")
    print("live decisions:")
    for line in result["decision_console"]:
        print(f"  {line}")
    print("")
    print(f"replay records: {result['record_log']}")
    print(f"audit log: {result['audit_log']}")
    print(
        "inspection: "
        f"{result['inspection']['event_count']} events, "
        f"{result['inspection']['decisions']['allowed']} allowed, "
        f"{result['inspection']['decisions']['blocked']} blocked"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the end-to-end snulbug MCP proxy demo")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON instead of text")
    args = parser.parse_args(argv)

    result = run_demo(args.output_dir, emit=not args.compact)
    if args.compact:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

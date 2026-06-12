from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

TOOLS = [
    {
        "name": "safe_read_file",
        "description": "Read an allowed project file.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "list_project_files",
        "description": "List files visible to the demo server.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "shell_exec",
        "description": "Unsafe demo tool. The proxy policy should block this.",
        "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
    },
]


class DemoMcpHandler(BaseHTTPRequestHandler):
    server_version = "asgi-lua-demo-mcp/0.1"

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("content-length", "0"))
        raw_body = self.rfile.read(length)
        try:
            request = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._send_json(400, _json_rpc_error(None, -32700, f"parse error: {exc.msg}"))
            return

        self._send_json(200, handle_json_rpc(request))

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_server(host: str = "127.0.0.1", port: int = 9000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), DemoMcpHandler)


def handle_json_rpc(request: Any) -> Any:
    if isinstance(request, list):
        return [handle_json_rpc(item) for item in request]
    if not isinstance(request, dict):
        return _json_rpc_error(None, -32600, "invalid request")

    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": _tool_result(str(tool_name), arguments),
        }

    return _json_rpc_error(request_id, -32601, "method not found")


def _tool_result(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "safe_read_file":
        path = arguments.get("path", "README.md")
        return {
            "tool": tool_name,
            "content": [{"type": "text", "text": f"demo contents for {path}"}],
        }
    if tool_name == "list_project_files":
        return {
            "tool": tool_name,
            "content": [{"type": "text", "text": "README.md\npyproject.toml\nasgi_lua/"}],
        }
    return {
        "tool": tool_name,
        "unsafe": True,
        "content": [{"type": "text", "text": f"upstream would have accepted {tool_name}"}],
        "arguments": arguments,
    }


def _json_rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the demo HTTP MCP upstream server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args(argv)

    server = create_server(args.host, args.port)
    print(f"demo MCP upstream listening on http://{args.host}:{server.server_port}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

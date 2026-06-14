from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {
        "name": "keycloak_demo.safe_read_file",
        "description": "Read a demo file through the Keycloak OAuth demo",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "keycloak_demo.list_project_files",
        "description": "List demo files through the Keycloak OAuth demo",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "keycloak_demo.write_file",
        "description": "Dangerous demo tool that should be blocked by scope policy",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
]


class Handler(BaseHTTPRequestHandler):
    server_version = "snulbug-keycloak-demo-mcp/1"

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return

        method = request.get("method")
        if method == "tools/list":
            self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": {"tools": TOOLS}})
            return
        if method == "tools/call":
            self._handle_tool_call(request)
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": {}})

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _handle_tool_call(self, request: dict[str, object]) -> None:
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        tool = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        upstream_auth_seen = bool(self.headers.get("authorization"))
        if tool == "keycloak_demo.safe_read_file":
            path = arguments.get("path") or "README.md"
            text = f"demo content for {path}; upstream_authorization_seen={str(upstream_auth_seen).lower()}"
        elif tool == "keycloak_demo.list_project_files":
            text = "README.md\nsnulbug.toml\npolicy.snulbug/policy.lua"
        elif tool == "keycloak_demo.write_file":
            text = "write_file reached upstream; this means scope policy is misconfigured"
        else:
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": f"unknown tool: {tool}"},
                }
            )
            return
        self._json(
            {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"content": [{"type": "text", "text": text}]},
            }
        )

    def _json(self, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "snulbug-mock-mcp/1"

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        try:
            request = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return

        method = request.get("method")
        if self.path != "/mcp":
            self.send_error(404)
            return
        if method == "tools/list":
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "safe_read_file",
                                "description": f"Read a demo file from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"path": {"type": "string"}},
                                    "required": ["path"],
                                    "additionalProperties": False,
                                },
                            },
                            {
                                "name": "list_project_files",
                                "description": f"List demo files from {self.server.server_name_label}",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "additionalProperties": False,
                                },
                            },
                        ]
                    },
                }
            )
            return
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            tool = params.get("name")
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"{self.server.server_name_label} handled {tool}",
                            }
                        ]
                    },
                }
            )
            return
        self._json({"jsonrpc": "2.0", "id": request.get("id"), "result": {}})

    def log_message(self, format: str, *args: object) -> None:
        return

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
    parser.add_argument("--name", default="local")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.server_name_label = args.name
    server.serve_forever()


if __name__ == "__main__":
    main()

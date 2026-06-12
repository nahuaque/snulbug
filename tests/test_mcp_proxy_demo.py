from __future__ import annotations

import http.client
import json
import threading

from examples.mcp_proxy_demo.run_demo import run_demo
from examples.mcp_proxy_demo.upstream import create_server


def test_mcp_proxy_demo_runs_end_to_end(tmp_path):
    result = run_demo(tmp_path / "demo", emit=False)
    statuses = {response["name"]: response["status"] for response in result["responses"]}

    assert result["ok"] is True
    assert statuses == {
        "missing-auth": 401,
        "allowed-safe-tool": 200,
        "blocked-shell-tool": 403,
    }
    assert result["record_count"] == 3
    assert result["inspection"]["event_count"] == 3
    assert result["inspection"]["decisions"]["allowed"] == 1
    assert result["inspection"]["decisions"]["blocked"] == 2
    assert {"value": "mcp.auth_required", "count": 1} in result["inspection"]["decisions"]["reason_codes"]
    assert {"value": "mcp.tool_not_allowed", "count": 1} in result["inspection"]["decisions"]["reason_codes"]
    assert any("mcp.tool=shell_exec" in line for line in result["decision_console"])
    assert "local-dev-secret" not in "\n".join(result["decision_console"])


def test_demo_upstream_accepts_unsafe_tool_without_proxy():
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = _post_json(
            server.server_port,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "shell_exec", "arguments": {"cmd": "echo unsafe"}},
            },
        )
    finally:
        server.shutdown()
        server.server_close()

    assert response["status"] == 200
    assert response["body"]["result"]["tool"] == "shell_exec"
    assert response["body"]["result"]["unsafe"] is True


def _post_json(port: int, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/mcp",
            body=body,
            headers={"content-type": "application/json", "content-length": str(len(body))},
        )
        response = connection.getresponse()
        return {"status": response.status, "body": json.loads(response.read().decode("utf-8"))}
    finally:
        connection.close()

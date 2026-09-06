from __future__ import annotations

import asyncio
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

import pytest
from test_mcp_protocol import running_gateway

from snulbug.mcp_progress import ProgressPolicyConfig
from snulbug.mcp_protocol import LATEST_MCP_SPEC_VERSION, mcp_request, modern_request_headers
from snulbug.mcp_stream import McpStreamError, McpStreamSession, SseDecoder
from snulbug.proxy import ManagedStdioMcpClient, create_proxy_application
from snulbug.response_policy import ResponsePolicyConfig


def request_message(method="tools/call", name="read_file"):
    request = mcp_request(
        method,
        version=LATEST_MCP_SPEC_VERSION,
        request_id="stream-call",
        params={"name": name, "arguments": {}} if method == "tools/call" else {},
    )
    request["params"]["_meta"]["progressToken"] = "work-1"
    return request


def open_request(url, request):
    headers = modern_request_headers(
        {"content-type": "application/json", "accept": "application/json, text/event-stream"}, request
    )
    return urlopen(Request(url, data=json.dumps(request).encode(), headers=headers), timeout=4)


def next_event(response):
    data = []
    while True:
        line = response.readline()
        if not line:
            raise AssertionError("EOF before SSE event")
        if line in (b"\n", b"\r\n") and data:
            return json.loads(b"\n".join(data))
        if line.startswith(b"data:"):
            data.append(line[5:].strip())


@pytest.fixture(params=["proxy", "facade", "rewrite"])
def stream_gateway(request, tmp_path):
    release = threading.Event()
    disconnected = threading.Event()
    sent_final = threading.Event()
    mode = {"value": "good"}

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["content-length"])))
            if payload["method"] == "tools/list":
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "result": {
                            "resultType": "complete",
                            "tools": [
                                {
                                    "name": "read_file",
                                    "inputSchema": {"type": "object"},
                                    "outputSchema": {
                                        "type": "object",
                                        "properties": {"value": {"type": "string"}},
                                        "required": ["value"],
                                    },
                                }
                            ],
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def chunk(data):
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

            notification = {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {
                    "progressToken": "work-1",
                    "progress": 1,
                    "total": 2,
                    "message": "Bearer private-credential",
                },
            }
            if mode["value"] == "wrong_token":
                notification["params"]["progressToken"] = "other-request"
            if mode["value"] == "server_request":
                notification = {"jsonrpc": "2.0", "id": 88, "method": "roots/list", "params": {}}
            try:
                chunk(b": Bearer comment-credential\r\n\r\n")
                raw = b"data: " + json.dumps(notification).encode() + b"\r\n\r\n"
                for offset in range(0, len(raw), 7):
                    chunk(raw[offset : offset + 7])
                if mode["value"] == "disconnect":
                    self.connection.settimeout(3)
                    if not self.connection.recv(1):
                        disconnected.set()
                    return
                release.wait(timeout=4)
                if mode["value"] == "truncated":
                    self.close_connection = True
                    return
                if mode["value"] == "regression":
                    notification["params"]["progress"] = 0
                    chunk(b"data: " + json.dumps(notification).encode() + b"\n\n")
                result = {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "Bearer result-credential"}],
                    "structuredContent": {"value": 123 if mode["value"] == "invalid_schema" else "ok"},
                }
                if mode["value"] == "mrtr":
                    result = {"resultType": "input_required", "requestState": {"invalid": "private-state"}}
                chunk(
                    b"data: " + json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode() + b"\n\n"
                )
                sent_final.set()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = tmp_path / "policy.lua"
    policy.write_text(
        'return function(request, context) return {action="rewrite", body=request.body} end'
        if request.param == "rewrite"
        else 'return function(request, context) return {action="continue"} end'
    )
    origin = f"http://127.0.0.1:{server.server_port}"
    facade = request.param == "facade"
    records = tmp_path / "records.jsonl"
    app = create_proxy_application(
        None if facade else origin,
        policy,
        upstreams=[{"name": "files", "url": origin + "/mcp"}] if facade else None,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
        progress_policy_action="block",
        facade_health_routing=True,
        record_out=records,
    )
    try:
        with running_gateway(app) as url:
            yield {
                "url": url,
                "release": release,
                "disconnected": disconnected,
                "sent_final": sent_final,
                "mode": mode,
                "name": "files.read_file" if facade else "read_file",
                "records": records,
            }
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_stream_forwards_filtered_progress_before_upstream_finishes(stream_gateway):
    gateway = stream_gateway
    with open_request(gateway["url"], request_message(name=gateway["name"])) as response:
        assert response.headers["content-type"] == "text/event-stream"
        progress = next_event(response)
        assert progress["method"] == "notifications/progress"
        assert progress["params"]["progressToken"] == "work-1"
        assert "private-credential" not in json.dumps(progress)
        assert not gateway["sent_final"].is_set()
        gateway["release"].set()
        final = next_event(response)
        assert final["id"] == "stream-call"
        assert final["result"]["resultType"] == "complete"
        assert "result-credential" not in json.dumps(final)
        assert response.read() == b""


@pytest.mark.parametrize("mode", ["wrong_token", "server_request", "truncated", "mrtr", "regression", "invalid_schema"])
def test_stream_failures_do_not_leak_unmediated_messages(stream_gateway, mode):
    gateway = stream_gateway
    gateway["mode"]["value"] = mode
    if mode == "invalid_schema":
        with open_request(gateway["url"], request_message("tools/list")) as response:
            assert "tools" in json.load(response)["result"]
    gateway["release"].set()
    with open_request(gateway["url"], request_message(name=gateway["name"])) as response:
        first = next_event(response)
        final = first if "error" in first else next_event(response)
        assert "error" in final
        assert final["id"] == "stream-call"
        assert "private-state" not in json.dumps(final)
        assert response.read() == b""


def test_client_disconnect_closes_upstream_stream(stream_gateway):
    gateway = stream_gateway
    gateway["mode"]["value"] = "disconnect"
    response = open_request(gateway["url"], request_message(name=gateway["name"]))
    assert next_event(response)["method"] == "notifications/progress"
    response.close()
    assert gateway["disconnected"].wait(timeout=3)


@pytest.mark.parametrize("width", [1, 2, 7, 200])
def test_sse_decoder_handles_fragmented_utf8_crlf_and_multiline_data(width):
    raw = '\ufeff: comment\r\ndata: {"text":\r\ndata: "caf\u00e9"}\r\n\r\n'.encode()
    decoder = SseDecoder(1024)
    events = []
    for offset in range(0, len(raw), width):
        events.extend(decoder.feed(raw[offset : offset + width]))
    assert [json.loads(event) for event in events if event is not None] == [{"text": "caf\u00e9"}]


def test_sse_decoder_bounds_unfinished_lines_and_comments():
    decoder = SseDecoder(16)
    with pytest.raises(McpStreamError, match="limit"):
        list(decoder.feed(b":" + b"x" * 20))


def test_notification_send_applies_backpressure():
    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        async def send(message):
            if message["type"] == "http.response.body":
                entered.set()
                await release.wait()

        stream = McpStreamSession(
            request_message(), send, response_policy=ResponsePolicyConfig(), progress_policy=ProgressPolicyConfig()
        )
        task = asyncio.create_task(
            stream.notification(
                {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hello"}}
            )
        )
        await asyncio.wait_for(entered.wait(), 1)
        assert not task.done()
        release.set()
        await task

    asyncio.run(run())


@pytest.mark.parametrize("token", [123, "work-1"])
def test_notification_redaction_preserves_verified_progress_correlation(token):
    async def run():
        messages = []

        async def send(message):
            messages.append(message)

        request = request_message()
        request["params"]["_meta"]["progressToken"] = token
        stream = McpStreamSession(
            request, send, response_policy=ResponsePolicyConfig(), progress_policy=ProgressPolicyConfig()
        )
        await stream.notification(
            {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": token, "progress": 1, "message": "Bearer private-credential"},
            }
        )
        payload = json.loads(messages[-1]["body"][6:])
        assert payload["params"]["progressToken"] == token
        assert type(payload["params"]["progressToken"]) is type(token)
        assert "private-credential" not in payload["params"]["message"]

    asyncio.run(run())


def test_sse_decoder_accepts_final_cr_delimiter():
    decoder = SseDecoder(1024)
    assert list(decoder.feed(b'data: {"done":true}\r\r')) == []
    assert list(decoder.finish()) == [b'{"done":true}']


def test_stream_event_and_result_limits():
    async def run():
        async def send(message):
            pass

        stream = McpStreamSession(
            request_message(), send, response_policy=ResponsePolicyConfig(), progress_policy=ProgressPolicyConfig()
        )
        stream.metadata["events"] = 1024
        with pytest.raises(McpStreamError, match="event limit"):
            await stream.notification({"method": "notifications/message"})
        with pytest.raises(McpStreamError, match="result exceeds"):
            stream.terminal(b"x" * (stream.limit + 1))

    asyncio.run(run())


@pytest.mark.parametrize("mode,status", [("good", "complete"), ("mrtr", "failed"), ("disconnect", "disconnected")])
def test_stream_record_contains_summary_not_notification_payloads(stream_gateway, monkeypatch, mode, status):
    import snulbug.proxy as proxy

    recorded = threading.Event()
    original = proxy.append_record

    def append(path, record):
        original(path, record)
        recorded.set()

    monkeypatch.setattr(proxy, "append_record", append)
    gateway = stream_gateway
    gateway["mode"]["value"] = mode
    gateway["release"].set()
    with open_request(gateway["url"], request_message(name=gateway["name"])) as response:
        if mode == "disconnect":
            next_event(response)
        else:
            response.read()
    assert recorded.wait(3)
    records = [json.loads(line) for line in gateway["records"].read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["metadata"]["stream"]["status"] == status
    assert records[0]["metadata"]["stream"]["notifications"] == 1
    if gateway["name"].startswith("files.") and mode == "mrtr":
        assert records[0]["metadata"]["upstream_health"]["failures"][0]["upstream"] == "files"
    assert "private-credential" not in gateway["records"].read_text()


def test_managed_stdio_streams_through_gateway_before_terminal_result(tmp_path):
    release = tmp_path / "release"
    policy = tmp_path / "policy.lua"
    policy.write_text('return function(request, context) return {action="continue"} end')
    app = create_proxy_application(
        None,
        policy,
        upstreams=[
            {
                "name": "files",
                "transport": "stdio",
                "command": sys.executable,
                "args": [
                    "-u",
                    "-c",
                    """import json, pathlib, sys, time
for line in sys.stdin:
    r=json.loads(line)
    notification={"jsonrpc":"2.0","method":"notifications/message",
                  "params":{"level":"info","data":"Bearer private-credential"}}
    print(json.dumps(notification),flush=True)
    deadline=time.monotonic()+4
    while not pathlib.Path(sys.argv[1]).exists() and time.monotonic()<deadline:
        time.sleep(0.01)
    print(json.dumps({"jsonrpc":"2.0","id":r["id"],"result":{"resultType":"complete","content":[{"type":"text","text":r["params"]["name"]}]}}),flush=True)
""",
                    str(release),
                ],
            }
        ],
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    with running_gateway(app) as url:
        with open_request(url, request_message(name="files.read_file")) as response:
            notification = next_event(response)
            assert notification["method"] == "notifications/message"
            assert "private-credential" not in json.dumps(notification)
            release.touch()
            final = next_event(response)
            assert final["result"]["content"][0]["text"] == "read_file"
            assert response.read() == b""


def test_stdio_interleaved_notifications_are_delivered_and_cancel_reaps_process():
    async def run():
        client = ManagedStdioMcpClient(
            sys.executable,
            [
                "-u",
                "-c",
                """import json, sys, time
r=json.loads(sys.stdin.readline())
print(json.dumps({"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"started"}}),flush=True)
time.sleep(30)
""",
            ],
        )
        seen = asyncio.Event()

        async def notify(message):
            assert message["method"] == "notifications/message"
            seen.set()

        task = asyncio.create_task(client.request(request_message(), on_notification=notify))
        try:
            await asyncio.wait_for(seen.wait(), 3)
            process = client._process
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            assert process.returncode is not None
            assert client._process is None
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()

    asyncio.run(run())


def test_stdio_timeout_reaps_process():
    async def run():
        client = ManagedStdioMcpClient(sys.executable, ["-c", "import time; time.sleep(30)"], timeout=0.05)
        process = await client._ensure_process()
        try:
            with pytest.raises(asyncio.TimeoutError):
                await client.request(request_message())
            assert process.returncode is not None
            assert client._process is None
        finally:
            await client.aclose()

    asyncio.run(run())

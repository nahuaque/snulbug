from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest
from test_mcp_protocol import post, running_gateway
from test_mcp_stream import next_event, open_request
from test_mcp_subscriptions import listen

from snulbug.mcp_protocol import LATEST_MCP_SPEC_VERSION, mcp_request
from snulbug.mcp_stdio import ManagedStdioMcpClient
from snulbug.mcp_stream import McpStreamError
from snulbug.mcp_subscriptions import SUBSCRIPTION_ID
from snulbug.proxy import create_proxy_application

PEER = Path(__file__).parent / "fixtures/stdio_subscriptions.py"


def call(name="status", identifier=1):
    return mcp_request("tools/call", version=LATEST_MCP_SPEC_VERSION, request_id=identifier, params={"name": name})


def test_subscriptions_share_process_without_blocking_calls_and_ids_are_private():
    async def run():
        client = ManagedStdioMcpClient(sys.executable, ["-u", str(PEER)], timeout=0.2)
        events = [[], []]
        ready = [asyncio.Event(), asyncio.Event()]

        async def notify(index, message):
            events[index].append(message)
            ready[index].set()

        tasks = [
            asyncio.create_task(
                client.request(
                    listen("same", resourceSubscriptions=[f"file:///project/{i}"]),
                    on_notification=lambda message, i=i: notify(i, message),
                )
            )
            for i in range(2)
        ]
        try:
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in ready)), 3)
            await asyncio.sleep(0.3)
            assert all(not task.done() for task in tasks)  # Idle after ACK ignores ordinary read timeout.
            status = json.loads((await client.request(call()))["body"])
            assert status["id"] == 1
            wire_ids = status["result"]["subscriptions"]
            assert len(set(wire_ids)) == 2 and "same" not in wire_ids
            process = client._process
            await client.request(call("emit"))
            for _ in range(100):
                if all(len(items) == 2 for items in events):
                    break
                await asyncio.sleep(0.01)
            for i, items in enumerate(events):
                assert items[-1]["params"]["uri"] == f"file:///project/{i}"
                assert all(item["params"]["_meta"][SUBSCRIPTION_ID] == "same" for item in items)
            tasks[0].cancel()
            await asyncio.gather(tasks[0], return_exceptions=True)
            assert client._process is process and process.returncode is None
            remaining = json.loads((await client.request(call()))["body"])["result"]["subscriptions"]
            assert len(remaining) == 1
            await client.request(call("finish"))
            final = json.loads((await asyncio.wait_for(tasks[1], 3))["body"])
            assert final["id"] == "same"
            assert final["result"]["_meta"][SUBSCRIPTION_ID] == "same"
            assert client._queued_bytes == 0
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.aclose()
        assert process.returncode is not None
        assert client._reader_task is None

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["crash", "bad-id", "server-request"])
def test_process_failures_wake_all_waiters_and_next_call_restarts(failure):
    async def run():
        client = ManagedStdioMcpClient(sys.executable, ["-u", str(PEER)], timeout=1)
        ready = asyncio.Event()

        async def notify(message):
            ready.set()

        task = asyncio.create_task(client.request(listen(), on_notification=notify))
        try:
            await asyncio.wait_for(ready.wait(), 3)
            process = client._process
            with pytest.raises(McpStreamError):
                await client.request(call(failure))
            with pytest.raises(McpStreamError):
                await asyncio.wait_for(task, 3)
            response = json.loads((await client.request(call()))["body"])
            assert response["result"]["subscriptions"] == []
            assert client._process is not process
            # Reader shutdown may still be reaping the old generation.
            await asyncio.wait_for(process.wait(), 3)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()

    asyncio.run(run())


def test_slow_subscription_does_not_block_reader_and_overflow_is_bounded():
    async def run():
        client = ManagedStdioMcpClient(sys.executable, ["-u", str(PEER)], timeout=1)
        ready = asyncio.Event()
        blocked = asyncio.Event()

        async def notify(message):
            ready.set()
            await blocked.wait()

        task = asyncio.create_task(client.request(listen(), on_notification=notify))
        try:
            await asyncio.wait_for(ready.wait(), 3)
            assert json.loads((await client.request(call()))["body"])["result"]["pid"]
            with pytest.raises(McpStreamError):
                await client.request(call("flood"))
            blocked.set()
            with pytest.raises(McpStreamError):
                await asyncio.wait_for(task, 3)
            assert client._queued_bytes == 0
            assert not client._pending
        finally:
            blocked.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await client.aclose()

    asyncio.run(run())


def test_terminal_response_survives_clean_process_exit():
    async def run():
        client = ManagedStdioMcpClient(
            sys.executable,
            [
                "-c",
                "import json,sys; r=json.loads(sys.stdin.readline()); "
                'print(json.dumps({"jsonrpc":"2.0","id":r["id"],"result":{"resultType":"complete","content":[]}}))',
            ],
        )
        try:
            assert json.loads((await client.request(call()))["body"])["id"] == 1
            await asyncio.sleep(0.05)
            assert client._queued_bytes == 0
        finally:
            await client.aclose()

    asyncio.run(run())


def test_pending_limit_reserves_an_ordinary_call_slot(monkeypatch):
    from snulbug import mcp_stdio

    monkeypatch.setattr(mcp_stdio, "MAX_PENDING", 3)

    async def run():
        client = ManagedStdioMcpClient(sys.executable, ["-u", str(PEER)])
        ready = [asyncio.Event(), asyncio.Event()]

        async def notify(index, message):
            ready[index].set()

        tasks = [
            asyncio.create_task(client.request(listen(), on_notification=lambda m, i=i: notify(i, m))) for i in range(2)
        ]
        try:
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in ready)), 3)
            with pytest.raises(McpStreamError, match="limit"):
                await client.request(listen(), on_notification=lambda m: notify(0, m))
            assert json.loads((await client.request(call()))["body"])["result"]["pid"]
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.aclose()
        assert not client._reapers

    asyncio.run(run())


def test_gateway_disconnect_cancels_only_its_stdio_subscription(tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function(request) return {action="continue"} end')
    app = create_proxy_application(
        None,
        policy,
        upstreams=[{"name": "local", "transport": "stdio", "command": sys.executable, "args": ["-u", str(PEER)]}],
        lease_required=False,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    with running_gateway(app) as url:
        with open_request(url, listen()) as first, open_request(url, listen()) as second:
            next_event(first)
            next_event(second)
            _, before = post(url, call("local.status"))
            first.close()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                _, after = post(url, call("local.status"))
                if len(after["result"]["subscriptions"]) == 1:
                    break
                time.sleep(0.02)
            assert len(after["result"]["subscriptions"]) == 1
            assert before["result"]["pid"] == after["result"]["pid"]
            post(url, call("local.finish"))
            assert "result" in next_event(second)


def test_gateway_subscription_lifetime_cancels_stdio_request(tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function(request) return {action="continue"} end')
    app = create_proxy_application(
        None,
        policy,
        upstreams=[{"name": "local", "transport": "stdio", "command": sys.executable, "args": ["-u", str(PEER)]}],
        lease_required=False,
        resource_subscription_ttl_seconds=0.2,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    with running_gateway(app) as url:
        with open_request(url, listen()) as response:
            next_event(response)
            final = next_event(response)
            assert "lifetime" in final["error"]["message"]
        _, after = post(url, call("local.status"))
        assert after["result"]["subscriptions"] == []


@pytest.mark.parametrize("finish", ["finish", "violate"])
def test_gateway_reuses_subscription_filters_sse_and_audit(tmp_path, finish):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function(request) return {action="continue"} end')
    records = tmp_path / "records.jsonl"
    app = create_proxy_application(
        None,
        policy,
        upstreams=[{"name": "local", "transport": "stdio", "command": sys.executable, "args": ["-u", str(PEER)]}],
        lease_required=False,
        record_out=records,
        streamable_http_protocol_version=LATEST_MCP_SPEC_VERSION,
    )
    with running_gateway(app) as url:
        with open_request(url, listen(identifier=7)) as response:
            ack = next_event(response)
            assert ack["params"]["_meta"][SUBSCRIPTION_ID] == 7
            status, _ = post(url, call("local.emit"))
            assert status == 200
            change = next_event(response)
            assert change["params"]["uri"] == "file:///project/a"
            post(url, call("local." + finish))
            final = next_event(response)
            if finish == "finish":
                assert final["result"]["_meta"][SUBSCRIPTION_ID] == 7
            else:
                assert "error" in final
                assert "file:///outside" not in json.dumps(final)
    entries = [json.loads(line) for line in records.read_text().splitlines()]
    subscription = next(entry for entry in entries if entry.get("metadata", {}).get("stream", {}).get("subscription"))
    assert subscription["metadata"]["stream"]["subscription"]["acknowledged"] is True
    assert "snulbug-stdio-" not in json.dumps(subscription)

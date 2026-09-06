"""Managed stdio requests and bounded modern subscription multiplexing."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .mcp_protocol import is_modern_request, modern_response_issue
from .mcp_stream import McpStreamError, json_response
from .mcp_subscriptions import ACKNOWLEDGED, CHANGE_FILTERS, LISTEN, RESOURCE_UPDATED, SUBSCRIPTION_ID

MAX_PENDING = 32
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_QUEUED_BYTES = 8 * 1024 * 1024
MAX_QUEUE_EVENTS = 32
SUBSCRIPTION_METHODS = {*CHANGE_FILTERS, ACKNOWLEDGED, RESOURCE_UPDATED}


@dataclass
class _Pending:
    request: Mapping[str, Any]
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=MAX_QUEUE_EVENTS))
    queued_bytes: int = 0
    completed: bool = False

    @property
    def subscription(self) -> bool:
        return self.request.get("method") == LISTEN


class ManagedStdioMcpClient:
    """One process/reader per upstream; subscriptions never hold the ordinary-call lock."""

    def __init__(
        self,
        command: str,
        args: Sequence[str] = (),
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.command, self.args, self.cwd = command, tuple(args), cwd
        self.env = dict(env) if env is not None else None
        self.timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._process_loop = None
        self._lock = None
        self._lock_loop = None
        self._ordinary_lock = None
        self._reader_task = None
        self._pending: dict[str, _Pending] = {}
        self._sequence = 0
        self._queued_bytes = 0
        self._reapers: set[asyncio.Task] = set()

    def _lock_for_loop(self):
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._ordinary_lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    async def request(self, request: Mapping[str, Any], *, on_notification=None) -> dict[str, Any]:
        self._lock_for_loop()
        if not is_modern_request(request):
            async with self._ordinary_lock:
                return await self._legacy_request(request, on_notification=on_notification)
        if request.get("method") == LISTEN:
            if on_notification is None:
                raise McpStreamError("stdio subscriptions require a mediated notification receiver")
            return await self._modern_request(request, on_notification=on_notification)
        async with self._ordinary_lock:
            return await self._modern_request(request, on_notification=on_notification)

    async def _modern_request(self, request, *, on_notification):
        entry = _Pending(request)
        process = None
        wire_id = None
        finished = False
        try:
            async with self._lock_for_loop():
                if len(self._pending) >= MAX_PENDING or (
                    entry.subscription and sum(item.subscription for item in self._pending.values()) >= MAX_PENDING - 1
                ):
                    raise McpStreamError("stdio in-flight request limit reached")
                process = await self._ensure_process()
                self._sequence += 1
                wire_id = f"snulbug-stdio-{self._sequence}"
                self._pending[wire_id] = entry
                if self._reader_task is None:
                    self._reader_task = asyncio.create_task(self._read_loop(process))
                await self._write(process, {**request, "id": wire_id})
            acknowledged = False
            while True:
                timeout = None if entry.subscription and acknowledged else self.timeout
                item = await asyncio.wait_for(entry.queue.get(), timeout=timeout)
                if isinstance(item, Exception):
                    raise item
                message, size = item
                entry.queued_bytes -= size
                if self._pending.get(wire_id) is entry:
                    self._queued_bytes -= size
                if "method" in message:
                    if on_notification is None:
                        raise McpStreamError("Unmediated stdio server-to-client notification")
                    await asyncio.wait_for(on_notification(message), timeout=self.timeout)
                    acknowledged = True
                    continue
                response = json_response(message)
                issue = modern_response_issue(response["body"], request)
                if issue:
                    raise McpStreamError(issue)
                finished = True
                return response
        finally:
            if wire_id is not None and self._pending.get(wire_id) is entry:
                del self._pending[wire_id]
                self._queued_bytes -= entry.queued_bytes
                if not finished and process is self._process:
                    try:
                        await self._write(
                            process,
                            {
                                "jsonrpc": "2.0",
                                "method": "notifications/cancelled",
                                "params": {"requestId": wire_id, "reason": "Gateway request closed"},
                            },
                        )
                    except (OSError, asyncio.TimeoutError):
                        await self.aclose()
                    # Untagged ordinary notifications cannot be safely drained after cancellation.
                    if not entry.subscription or not self._pending:
                        await self.aclose()

    async def _write(self, process, message):
        assert process.stdin is not None
        body = json.dumps(message, separators=(",", ":")).encode() + b"\n"
        if len(body) > MAX_LINE_BYTES:
            raise McpStreamError("stdio request exceeds the line limit")
        # write() is synchronous: each complete line is enqueued before yielding to drain().
        process.stdin.write(body)
        await asyncio.wait_for(process.stdin.drain(), timeout=self.timeout)

    async def _read_loop(self, process):
        failure = "stdio MCP server closed stdout"
        try:
            assert process.stdout is not None
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                    raise McpStreamError("stdio MCP frame exceeds the limit or is incomplete")
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeError, RecursionError) as exc:
                    raise McpStreamError("stdio MCP server emitted malformed JSON") from exc
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise McpStreamError("stdio MCP server emitted an invalid message")
                entry = self._route(message)
                if entry.completed:
                    raise McpStreamError("stdio MCP server emitted a message after its terminal response")
                if "method" not in message:
                    entry.completed = True
                if (
                    entry.queue.full()
                    or entry.queued_bytes + len(line) > MAX_LINE_BYTES
                    or self._queued_bytes + len(line) > MAX_QUEUED_BYTES
                ):
                    raise McpStreamError("stdio MCP notification queue limit exceeded")
                entry.queued_bytes += len(line)
                self._queued_bytes += len(line)
                entry.queue.put_nowait((message, len(line)))
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            failure = "stdio MCP reader stopped"
        except Exception as exc:
            failure = str(exc) if isinstance(exc, McpStreamError) else "stdio MCP reader failed"
        finally:
            if process is self._process:
                await self.aclose(reason=failure, keep_completed=failure == "stdio MCP server closed stdout")

    def _route(self, message):
        if "method" not in message:
            identifier = message.get("id")
            entry = self._pending.get(identifier) if isinstance(identifier, str) else None
            if entry is None:
                raise McpStreamError("stdio MCP server emitted an unrelated response")
            message["id"] = entry.request.get("id")
            if entry.subscription and isinstance(message.get("result"), dict):
                self._restore_subscription_id(message["result"], identifier, entry)
            return entry
        if "id" in message or "result" in message or "error" in message:
            raise McpStreamError("Unmediated stdio server-to-client message")
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        identifier = meta.get(SUBSCRIPTION_ID) if isinstance(meta, dict) else None
        if message["method"] in SUBSCRIPTION_METHODS or isinstance(meta, dict) and SUBSCRIPTION_ID in meta:
            entry = self._pending.get(identifier) if isinstance(identifier, str) else None
            if entry is None or not entry.subscription:
                raise McpStreamError("stdio notification has an unknown subscription ID")
            self._restore_subscription_id(params, identifier, entry)
            return entry
        ordinary = [entry for entry in self._pending.values() if not entry.subscription and not entry.completed]
        if len(ordinary) != 1:
            raise McpStreamError("stdio notification has no unambiguous ordinary request")
        return ordinary[0]

    @staticmethod
    def _restore_subscription_id(container, identifier, entry):
        meta = container.get("_meta")
        if not isinstance(meta, dict) or meta.get(SUBSCRIPTION_ID) != identifier:
            raise McpStreamError("stdio subscription result has a mismatched subscription ID")
        meta[SUBSCRIPTION_ID] = entry.request["id"]

    async def aclose(self, *, reason="stdio MCP process stopped", keep_completed=False) -> None:
        process, reader = self._process, self._reader_task
        self._process = self._process_loop = self._reader_task = None
        entries, self._pending = self._pending, {}
        self._queued_bytes = 0
        for entry in entries.values():
            if keep_completed and entry.completed:
                continue
            while not entry.queue.empty():
                entry.queue.get_nowait()
            entry.queued_bytes = 0
            entry.queue.put_nowait(McpStreamError(reason))
        if reader is not None and reader is not asyncio.current_task():
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        if process is not None:
            reaper = asyncio.create_task(self._stop_process(process))
            self._reapers.add(reaper)
            reaper.add_done_callback(self._reapers.discard)
        if self._reapers:
            await asyncio.shield(asyncio.gather(*tuple(self._reapers)))

    @staticmethod
    async def _stop_process(process):
        if process.stdin is not None:
            process.stdin.close()
        try:
            try:
                await asyncio.wait_for(process.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except ProcessLookupError:
                    pass
                except asyncio.TimeoutError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    await process.wait()
        except asyncio.CancelledError:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            raise
        finally:
            if process.stdin is not None:
                try:
                    await asyncio.wait_for(process.stdin.wait_closed(), timeout=0.2)
                except asyncio.TimeoutError:
                    process.stdin.transport.abort()
                except (BrokenPipeError, ConnectionResetError):
                    pass

    async def _ensure_process(self):
        loop = asyncio.get_running_loop()
        if self._process is not None and (self._process_loop is not loop or self._process.returncode is not None):
            await self.aclose()
        if self._process is None:
            self._process = await asyncio.create_subprocess_exec(
                self.command,
                *self.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                limit=MAX_LINE_BYTES,
                cwd=self.cwd,
                env=None if self.env is None else {**os.environ, **self.env},
            )
            self._process_loop = loop
        return self._process

    async def _legacy_request(self, request, *, on_notification):
        async with self._lock_for_loop():
            if self._reader_task is not None:
                raise McpStreamError("Cannot mix legacy and modern requests on one stdio process")
            process = await self._ensure_process()
            try:
                await self._write(process, request)
                if "id" not in request:
                    return {"status": 202, "headers": [(b"content-length", b"0")], "body": b""}
                assert process.stdout is not None
                while True:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=self.timeout)
                    if not line:
                        raise McpStreamError("stdio MCP server closed stdout")
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise McpStreamError("stdio MCP server emitted a non-object message")
                    if "method" in message:
                        if on_notification is None or "id" in message:
                            raise McpStreamError("Unmediated stdio server-to-client message")
                        await on_notification(message)
                        continue
                    if type(message.get("id")) is not type(request.get("id")) or message.get("id") != request.get("id"):
                        raise McpStreamError("stdio MCP server emitted an unrelated response")
                    return json_response(message)
            except BaseException:
                await self.aclose()
                raise

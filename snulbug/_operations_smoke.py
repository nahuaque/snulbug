"""Private installed-artifact release check; no real tunnel or provider access."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx

_CALLER = "operations-smoke-caller-token"
_FIRST = "operations-smoke-upstream-first"
_NEXT = "operations-smoke-upstream-next"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _installed_operations_smoke() -> None:
    from importlib import import_module
    from importlib.metadata import version

    from . import __version__, create_mcp_share
    from .release_qa import OPERATIONS_MODULES, OPERATIONS_SMOKE_SUCCESS
    from .share import create_mcp_share_lease

    _require(os.name == "posix", "installed operations smoke requires POSIX process/signal support")
    _require(version("snulbug") == __version__, "installed metadata and package versions differ")
    for name in OPERATIONS_MODULES:
        import_module(f"snulbug.{name}")
    with tempfile.TemporaryDirectory(prefix="snulbug-operations-") as temporary, _backend() as backend:
        root = Path(temporary)
        directory = root / "share"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        created = create_mcp_share(
            directory,
            provider="ssh",
            upstream=backend["url"],
            public_url=f"http://127.0.0.1:{port}/mcp",
            port=port,
            token=_CALLER,
            allowed_tools=["safe_read_file"],
            validate=True,
            http_routes=[{"prefix": "/app", "upstream": backend["url"], "auth": "public", "methods": ["GET", "HEAD"]}],
        )
        credential = directory / "upstream-token"
        credential.write_text(_FIRST, encoding="utf-8")
        credential.chmod(0o600)
        config = directory / "snulbug.toml"
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "[mcp.proxy]\n", '[mcp.proxy]\nupstream_credential = "service"\n', 1
            )
            + '\n[mcp.fabric.credentials.service]\ntype = "file"\npath = "upstream-token"\n',
            encoding="utf-8",
        )
        lease = create_mcp_share_lease(
            directory,
            task="release QA",
            capabilities=["project_readonly"],
            allow_tools=["safe_read_file"],
            allow_paths=["."],
        )
        headers = {
            **created["client"]["headers"],
            **lease["headers"],
            "accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        }
        url = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=url, timeout=3, trust_env=False, follow_redirects=False) as client:
            for attempt in range(2):
                probe = root / f"run-{attempt}"
                probe.mkdir()
                _fake_bridge(directory, probe)
                with _gateway(directory, probe, client):
                    _exercise_gateway(
                        client,
                        directory,
                        credential,
                        headers,
                        backend,
                        lease_id=lease["lease"]["id"],
                        restarted=bool(attempt),
                    )
        audit = directory / "traces" / "audit.jsonl"
        events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line.strip()]
        _require(
            any(
                event.get("explanation", {}).get("reason_code") == "upstream.credentials_unavailable"
                for event in events
            ),
            "missing credential failure was not recorded in audit evidence",
        )
        _require(
            any(event.get("explanation", {}).get("reason_code") == "lease.revoked" for event in events),
            "revoked lease failure was not recorded in audit evidence",
        )
        logs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [*directory.glob("traces/*.jsonl"), *root.glob("run-*/gateway.log")]
        )
        _require(
            not any(secret in logs for secret in (_CALLER, _FIRST, _NEXT, *lease["headers"].values())),
            "operations smoke credentials leaked into evidence or console logs",
        )
    print(OPERATIONS_SMOKE_SUCCESS)


def _exercise_gateway(client, directory, credential, headers, backend, *, lease_id: str, restarted: bool) -> None:
    from .leases import revoke_lease

    def mcp(method="tools/list", **changes):
        request_headers = {**headers, **changes}
        params = {"name": "safe_read_file", "arguments": {"path": "README.md"}} if method == "tools/call" else {}
        return client.post(
            "/mcp",
            headers=request_headers,
            json={"jsonrpc": "2.0", "id": "operations", "method": method, "params": params},
        )

    response = mcp()
    _require(
        response.status_code == 200 and response.json().get("result", {}).get("tools"),
        "installed gateway did not list MCP tools",
    )
    _require(mcp("tools/call").status_code == 200, "installed gateway did not admit the leased tool call")
    seen = backend["calls"]
    _require(
        mcp(Authorization="Bearer invalid-smoke-token").status_code == 401 and backend["calls"] == seen,
        "invalid caller authentication reached the upstream",
    )
    web = client.get("/app/", headers={"authorization": f"Bearer {_CALLER}", "cookie": "app=private-value"})
    _require(
        web.status_code == 200 and web.text == "operations web" and "set-cookie" not in web.headers,
        "public HTTP mount contract was not enforced",
    )
    seen_web = backend["web_calls"]
    _require(
        client.post("/app/", content=b"blocked method").status_code == 405 and backend["web_calls"] == seen_web,
        "HTTP mount method denial reached the backend",
    )
    if restarted:
        # The same persisted lease must work after restart, then fail immediately
        # after revocation; neither the owner nor the consumer mints a replacement.
        revoke_lease(directory / "leases.json", lease_id)
        seen = backend["calls"]
        _require(
            mcp("tools/call").status_code == 403 and backend["calls"] == seen, "revoked persisted lease was forwarded"
        )
        _require(client.get("/app/").status_code == 200, "MCP lease revocation unexpectedly changed HTTP mount access")
        return
    replacement = credential.with_suffix(".next")
    replacement.write_text(_NEXT, encoding="utf-8")
    replacement.chmod(0o600)
    replacement.replace(credential)
    backend["token"] = _NEXT
    _require(mcp("tools/call").status_code == 200, "file credential rotation required a gateway restart")
    credential.unlink()
    seen = backend["calls"]
    _require(
        mcp("tools/call").status_code == 502 and backend["calls"] == seen, "missing credential did not fail closed"
    )
    replacement.write_text(_NEXT, encoding="utf-8")
    replacement.chmod(0o600)
    replacement.replace(credential)
    _require(mcp("tools/call").status_code == 200, "restored credential was not picked up without restart")


@contextmanager
def _backend():
    state: dict[str, Any] = {"token": _FIRST, "calls": 0, "web_calls": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            state["calls"] += 1
            if self.path != "/mcp" or self.headers.get("authorization") != f"Bearer {state['token']}":
                self.reply(401, b"upstream authentication failed")
                return
            request = json.loads(body)
            if request["method"] == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": "safe_read_file",
                            "description": "Read a demo file",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"],
                                "additionalProperties": False,
                            },
                        }
                    ]
                }
            else:
                result = {"content": [{"type": "text", "text": "release QA contents"}]}
            self.reply(200, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())

        def do_GET(self) -> None:
            state["web_calls"] += 1
            valid = self.path == "/" and not self.headers.get("authorization") and not self.headers.get("cookie")
            self.reply(200 if valid else 400, b"operations web", cookie=True)

        def reply(self, status: int, body: bytes, *, cookie: bool = False) -> None:
            self.send_response(status)
            self.send_header("content-type", "application/json" if not cookie else "text/plain")
            self.send_header("content-length", str(len(body)))
            if cookie:
                self.send_header("set-cookie", "app=private-value; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _fake_bridge(directory: Path, probe: Path) -> None:
    # Use the existing managed SSH argv surface with a harmless Python child.
    # There is no PATH shim, SSH connection, ngrok binary, or production hook.
    manifest_path = directory / "share.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tunnel"]["bridge"]["command_argv"] = [
        sys.executable,
        "-c",
        "from snulbug._operations_smoke import _fake_tunnel; _fake_tunnel()",
        str(probe),
    ]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


@contextmanager
def _gateway(directory: Path, probe: Path, client: httpx.Client):
    env = {**os.environ, "SNULBUG_SHARE_TOKEN": _CALLER, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
    # The wheel wrapper already removes these. Also protect direct invocations.
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    command = [sys.executable, "-m", "snulbug", "mcp", "share", "run", str(directory), "--no-console"]
    with (probe / "gateway.log").open("wb") as output:
        process = subprocess.Popen(
            command, cwd=probe, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT
        )
        try:

            def ready():
                try:
                    return (probe / "agent-started.json").is_file() and client.get("/app/").status_code == 200
                except httpx.TransportError:
                    return False

            _wait(ready, process=process, message="headless gateway and fake tunnel did not start")
            yield process
            process.terminate()
            _require(process.wait(timeout=12) in (0, -signal.SIGTERM), "headless gateway did not shut down cleanly")
            _wait(
                lambda: (probe / "agent-exited").is_file() and not _agent_alive(probe),
                message="gateway left an orphaned managed tunnel",
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            # Fallback cleanup happens only after the ownership assertion above.
            (probe / "cleanup").touch()
            _wait(lambda: not _agent_alive(probe), message="fake tunnel cleanup failed")


def _wait(predicate, *, process=None, message: str, timeout: float = 12) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{message}: gateway exited with status {process.returncode}")
        time.sleep(0.05)
    raise RuntimeError(message)


def _agent_alive(probe: Path) -> bool:
    path = probe / "agent-started.json"
    if not path.is_file():
        return False
    pid = json.loads(path.read_text(encoding="utf-8"))["pid"]
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _fake_tunnel() -> None:
    probe = Path(sys.argv[1])

    def terminate(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    temporary = probe / "agent-starting.json"
    temporary.write_text(json.dumps({"pid": os.getpid(), "parent": os.getppid()}), encoding="utf-8")
    temporary.replace(probe / "agent-started.json")
    try:
        deadline = time.monotonic() + 60
        while not (probe / "cleanup").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        (probe / "agent-exited").write_text(str(os.getpid()), encoding="utf-8")

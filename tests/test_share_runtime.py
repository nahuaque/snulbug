from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import snulbug.share_runtime as share_runtime
from snulbug import create_mcp_share
from snulbug.share_runtime import ShareRuntime, ShareRuntimeConfig


def create_ngrok_share(directory: Path, *, port=8080) -> Path:
    create_mcp_share(
        directory,
        provider="ngrok",
        public_url="https://runtime-test.ngrok.app/mcp",
        token="test-share-secret",
        allowed_tools=["safe_read_file"],
        port=port,
        validate=False,
    )
    agent_config = directory / "tunnel" / "ngrok-agent.yml"
    agent_config.write_text(
        agent_config.read_text(encoding="utf-8").replace("YOUR_NGROK_AUTHTOKEN", "test-agent-token"),
        encoding="utf-8",
    )
    return agent_config


def wait_for_child(predicate, process, log_path: Path, *, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        assert process.poll() is None, log_path.read_text(encoding="utf-8")
        time.sleep(0.02)
    pytest.fail(f"timed out waiting for share subprocess:\n{log_path.read_text(encoding='utf-8')}")


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX executable and SIGTERM")
@pytest.mark.parametrize(
    ("autostart", "crash_recovery"),
    [(True, False), (True, True), (False, False)],
    ids=["sigterm-reaps-agent", "autonomous-crash-recovery", "no-tunnel"],
)
def test_headless_share_run_owns_agent_until_sigterm(tmp_path, autostart, crash_recovery):
    directory = tmp_path / "share"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        agent_config = create_ngrok_share(directory, port=reservation.getsockname()[1])
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "ngrok"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, signal, sys, time\n"
        "from pathlib import Path\n"
        "root = Path(os.environ['SNULBUG_TEST_AGENT_DIR'])\n"
        "def terminate(signum, frame):\n"
        "    (root / 'terminated').write_text(str(signum))\n"
        "    raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, terminate)\n"
        "try:\n"
        "    data = {'pid': os.getpid(), 'parent': os.getppid(),\n"
        "            'argv': sys.argv[1:], 'cwd': os.getcwd()}\n"
        "    (root / 'starting.json').write_text(json.dumps(data))\n"
        "    (root / 'starting.json').replace(root / 'started.json')\n"
        "    deadline = time.monotonic() + 60\n"
        "    while not (root / 'cleanup').exists() and time.monotonic() < deadline:\n"
        "        if (root / 'crash').exists():\n"
        "            (root / 'crash').unlink()\n"
        "            raise SystemExit(1)\n"
        "        time.sleep(0.02)\n"
        "finally:\n"
        "    (root / 'exited').write_text(str(os.getpid()))\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(bin_dir) + os.pathsep + os.defpath,
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "SNULBUG_TEST_AGENT_DIR": str(tmp_path),
    }
    command = [sys.executable, "-m", "snulbug", "mcp", "share", "run", str(directory), "--no-console"]
    if not autostart:
        command.append("--no-tunnel")
    log_path = tmp_path / "share-run.log"
    started_path = tmp_path / "started.json"
    with log_path.open("wb") as output:
        process = subprocess.Popen(command, cwd=tmp_path, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            wait_for_child(
                lambda: "Uvicorn running on http://127.0.0.1:" in log_path.read_text(encoding="utf-8"),
                process,
                log_path,
            )
            assert process.poll() is None
            if autostart:
                wait_for_child(started_path.is_file, process, log_path)
                agent = json.loads(started_path.read_text(encoding="utf-8"))
                assert agent["parent"] == process.pid
                assert agent["argv"] == ["start", "--config", str(agent_config), "--all"]
                assert agent["cwd"] == str(directory)
                assert pid_exists(agent["pid"])
                assert not (tmp_path / "exited").exists()
                if crash_recovery:
                    crashed_pid = agent["pid"]
                    (tmp_path / "crash").touch()
                    wait_for_child(
                        lambda: json.loads(started_path.read_text())["pid"] != crashed_pid,
                        process,
                        log_path,
                    )
                    agent = json.loads(started_path.read_text())
                    assert not pid_exists(crashed_pid)
                    assert pid_exists(agent["pid"])
            else:
                assert not started_path.exists()
                assert not (directory / ".snulbug" / "share" / "ngrok-agent.log").exists()

            process.send_signal(signal.SIGTERM)
            returncode = process.wait(timeout=10)
            assert returncode in (0, -signal.SIGTERM), log_path.read_text(encoding="utf-8")
            if autostart:
                assert (tmp_path / "terminated").read_text() == str(signal.SIGTERM)
                assert (tmp_path / "exited").read_text() == str(agent["pid"])
                # Check before fallback cleanup: the runtime must stop AND reap its child.
                assert not pid_exists(agent["pid"]), "share exited with an orphaned fake ngrok agent"
            else:
                assert not started_path.exists()
        finally:
            # The fake agent also accepts file-based cleanup if its owner crashes.
            (tmp_path / "cleanup").touch()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if started_path.exists():
                deadline = time.monotonic() + 5
                while not (tmp_path / "exited").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert (tmp_path / "exited").exists(), "fake agent did not acknowledge cleanup"


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeProcess:
    def __init__(self, pid, returncode=None):
        self.pid = pid
        self.returncode = returncode
        self.calls = []
        self.ignore_terminate = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append("terminate")
        if not self.ignore_terminate:
            self.returncode = -15

    def kill(self):
        self.calls.append("kill")
        self.returncode = -9

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake-ngrok", timeout)
        return self.returncode


class FakePopen:
    def __init__(self):
        self.calls = []
        self.processes = []
        self.exit_on_spawn = None
        self.error = None

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error is not None:
            raise self.error
        process = FakeProcess(1000 + len(self.processes), self.exit_on_spawn)
        self.processes.append(process)
        return process


@pytest.fixture
def fake_tunnel(monkeypatch):
    clock = FakeClock()
    popen = FakePopen()
    monkeypatch.setattr(share_runtime, "monotonic", clock)
    monkeypatch.setattr(share_runtime, "sleep", lambda seconds: None)
    monkeypatch.setattr(share_runtime.subprocess, "Popen", popen)
    monkeypatch.setattr(share_runtime.shutil, "which", lambda name: "/fake/bin/" + name)
    # Drive reconciliation via status() so clock boundaries are deterministic.
    monkeypatch.setattr(ShareRuntime, "_monitor", lambda self: None)
    return SimpleNamespace(clock=clock, popen=popen)


@pytest.fixture
def runtime_factory(tmp_path, fake_tunnel):
    directory = tmp_path / "share"
    create_ngrok_share(directory)
    runtimes = []

    def create(*, autostart_override=None, **settings):
        values = {
            "restart_initial_seconds": 1.0,
            "restart_max_seconds": 3.0,
            "restart_max_attempts": 4,
            "restart_reset_seconds": 10.0,
            "tunnel_shutdown_timeout": 0.25,
            **settings,
        }
        config_path = directory / f"runtime-{len(runtimes)}.toml"
        config_path.write_text(
            "[mcp.runtime]\n" + "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items()),
            encoding="utf-8",
        )
        runtime = ShareRuntime(directory, tunnel_autostart=autostart_override)
        runtimes.append(runtime)
        runtime.configure(config_path)
        return runtime

    try:
        yield create
    finally:
        for runtime in runtimes:
            runtime.close()


def test_start_is_idempotent_and_stop_reaps_process(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    initial = runtime.status()
    assert initial["state"] == initial["desired_state"] == "stopped"
    assert initial["running"] is False
    assert initial["pid"] is None

    started = runtime.start()
    process = fake_tunnel.popen.processes[0]
    assert started["ok"] is True
    assert started["process"]["state"] == started["process"]["desired_state"] == "running"
    assert started["process"]["pid"] == process.pid
    assert started["process"]["restart_attempts"] == 0
    assert started["process"]["retry_in_seconds"] is None
    argv, kwargs = fake_tunnel.popen.calls[0]
    assert argv == ["/fake/bin/ngrok", "start", "--config", str(runtime.directory / "tunnel/ngrok-agent.yml"), "--all"]
    assert kwargs["cwd"] == str(runtime.directory)
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.STDOUT
    log_file = kwargs["stdout"]
    assert not log_file.closed
    assert runtime.start()["process"]["pid"] == process.pid
    assert len(fake_tunnel.popen.calls) == 1

    stopped = runtime.stop()
    assert stopped["ok"] is True
    assert stopped["process"]["state"] == stopped["process"]["desired_state"] == "stopped"
    assert stopped["process"]["running"] is False
    assert stopped["process"]["pid"] is None
    assert stopped["process"]["error"] is None
    assert process.calls == ["terminate", ("wait", 0.25)]
    assert log_file.closed
    runtime.stop()
    assert process.calls == ["terminate", ("wait", 0.25)]
    assert runtime.start()["ok"] is True
    assert len(fake_tunnel.popen.processes) == 2


def test_restarts_use_bounded_exponential_backoff(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    assert runtime.start()["ok"] is True
    for attempts, delay in enumerate([1.0, 2.0, 3.0, 3.0]):
        fake_tunnel.popen.processes[-1].returncode = 7
        status = runtime.status()
        assert status["state"] == "backoff"
        assert status["desired_state"] == "running"
        assert status["running"] is False
        assert status["pid"] is None
        assert status["returncode"] == 7
        assert status["restart_attempts"] == attempts
        assert status["retry_in_seconds"] == delay
        assert fake_tunnel.popen.calls[-1][1]["stdout"].closed

        fake_tunnel.clock.advance(delay - 0.25)
        assert runtime.status()["retry_in_seconds"] == 0.25
        assert len(fake_tunnel.popen.processes) == attempts + 1
        fake_tunnel.clock.advance(0.25)
        restarted = runtime.status()
        assert restarted["state"] == "running"
        assert restarted["restart_attempts"] == attempts + 1
        assert restarted["retry_in_seconds"] is None
        assert restarted["returncode"] is None
        assert restarted["error"] is None
        assert len(fake_tunnel.popen.processes) == attempts + 2


@pytest.mark.parametrize("action", ["stop", "close"])
def test_stop_or_close_cancels_pending_restart(runtime_factory, fake_tunnel, action):
    runtime = runtime_factory()
    runtime.start()
    fake_tunnel.popen.processes[-1].returncode = 1
    assert runtime.status()["state"] == "backoff"
    getattr(runtime, action)()
    fake_tunnel.clock.advance(1000)
    status = runtime.status()
    assert status["state"] == status["desired_state"] == "stopped"
    assert status["running"] is False
    assert status["retry_in_seconds"] is None
    assert len(fake_tunnel.popen.calls) == 1
    if action == "stop":
        assert runtime.start()["ok"] is True
    else:
        runtime.close()
        with pytest.raises(RuntimeError, match="closed"):
            runtime.start()


@pytest.mark.parametrize("budget", [0, 2])
def test_retry_exhaustion_and_manual_start_reset(runtime_factory, fake_tunnel, budget):
    runtime = runtime_factory(restart_max_attempts=budget)
    fake_tunnel.popen.exit_on_spawn = 9
    result = runtime.start()
    assert result["ok"] is False
    for attempt in range(budget):
        status = runtime.status()
        assert status["state"] == "backoff"
        assert status["restart_attempts"] == attempt
        fake_tunnel.clock.advance(status["retry_in_seconds"])
        runtime.status()
    failed = runtime.status()
    assert failed["state"] == "failed"
    assert failed["desired_state"] == "running"
    assert failed["restart_attempts"] == failed["restart_max_attempts"] == budget
    assert failed["retry_in_seconds"] is None
    assert failed["returncode"] == 9
    assert "status 9" in failed["error"]
    fake_tunnel.clock.advance(1000)
    assert runtime.status()["state"] == "failed"
    assert len(fake_tunnel.popen.calls) == budget + 1

    fake_tunnel.popen.exit_on_spawn = None
    reset = runtime.start()
    assert reset["ok"] is True
    assert reset["process"]["restart_attempts"] == 0
    assert reset["process"]["error"] is None
    assert len(fake_tunnel.popen.calls) == budget + 2


def test_stable_process_resets_backoff_and_retry_budget(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    runtime.start()
    for delay in (1.0, 2.0):
        fake_tunnel.popen.processes[-1].returncode = 1
        assert runtime.status()["retry_in_seconds"] == delay
        fake_tunnel.clock.advance(delay)
        assert runtime.status()["state"] == "running"
    fake_tunnel.clock.advance(9.75)
    assert runtime.status()["restart_attempts"] == 2
    fake_tunnel.clock.advance(0.25)
    assert runtime.status()["restart_attempts"] == 0
    fake_tunnel.popen.processes[-1].returncode = 1
    status = runtime.status()
    assert status["state"] == "backoff"
    assert status["restart_attempts"] == 0
    assert status["retry_in_seconds"] == 1.0


def test_spawn_oserror_is_retried_and_closes_log(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    fake_tunnel.popen.error = OSError("private spawn detail")
    result = runtime.start()
    assert result["ok"] is False
    assert result["process"]["state"] == "backoff"
    assert result["process"]["retry_in_seconds"] == 1.0
    assert result["error"] == "could not start tunnel: OSError"
    assert fake_tunnel.popen.calls[-1][1]["stdout"].closed
    fake_tunnel.popen.error = None
    fake_tunnel.clock.advance(1.0)
    assert runtime.status()["state"] == "running"
    assert runtime.status()["restart_attempts"] == 1


@pytest.mark.parametrize("action", ["stop", "close"])
def test_shutdown_kills_and_reaps_unresponsive_process(runtime_factory, fake_tunnel, action):
    runtime = runtime_factory()
    runtime.start()
    process = fake_tunnel.popen.processes[-1]
    process.ignore_terminate = True
    getattr(runtime, action)()
    assert process.calls == ["terminate", ("wait", 0.25), "kill", ("wait", 0.25)]
    assert fake_tunnel.popen.calls[-1][1]["stdout"].closed
    assert runtime.status()["running"] is False
    getattr(runtime, action)()
    assert process.calls == ["terminate", ("wait", 0.25), "kill", ("wait", 0.25)]


@pytest.mark.parametrize(
    "settings",
    [
        'tunnel_autostart = "yes"',
        "restart_initial_seconds = 0",
        "restart_max_seconds = 0.5",
        "restart_max_attempts = -1",
        "restart_max_attempts = true",
        "graceful_shutdown_timeout = inf",
        "tunnel_shutdown_timeout = nan",
        "restart_reset_seconds = false",
        "unknown_option = true",
    ],
)
def test_runtime_config_rejects_invalid_settings(tmp_path, settings):
    config = tmp_path / "snulbug.toml"
    config.write_text("[mcp.runtime]\n" + settings + "\n")
    with pytest.raises(ValueError, match="mcp.runtime"):
        ShareRuntimeConfig.load(config)


@pytest.mark.parametrize("failure", ["missing-executable", "placeholder"])
def test_preflight_failure_does_not_spawn(runtime_factory, fake_tunnel, monkeypatch, failure):
    runtime = runtime_factory()
    if failure == "missing-executable":
        monkeypatch.setattr(share_runtime.shutil, "which", lambda _: None)
    else:
        (runtime.directory / "tunnel/ngrok-agent.yml").write_text("authtoken: YOUR_NGROK_AUTHTOKEN\n")
    with pytest.raises(RuntimeError, match="not found|YOUR_NGROK_AUTHTOKEN"):
        runtime.start_automatic()
    assert runtime.status()["state"] == "failed"
    assert fake_tunnel.popen.calls == []


@pytest.mark.parametrize(
    ("configured", "override", "expected"),
    [(True, None, True), (False, None, False), (True, False, False), (False, True, True)],
)
def test_autostart_obeys_config_and_cli_override(runtime_factory, fake_tunnel, configured, override, expected):
    runtime = runtime_factory(autostart_override=override, tunnel_autostart=configured)
    runtime.start_automatic()
    assert bool(fake_tunnel.popen.calls) is expected


def test_stop_before_gateway_startup_is_not_undone(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    runtime.stop()
    runtime.start_automatic()
    assert fake_tunnel.popen.calls == []
    assert runtime.status()["desired_state"] == "stopped"
    assert runtime.start()["ok"] is True


def test_begin_shutdown_keeps_tunnel_alive_but_disables_restarts(runtime_factory, fake_tunnel):
    runtime = runtime_factory()
    runtime.start()
    process = fake_tunnel.popen.processes[-1]
    runtime.begin_shutdown()
    assert runtime.status()["state"] == "draining"
    assert runtime.status()["running"] is True
    assert runtime.status()["desired_state"] == "stopped"
    assert process.calls == []
    process.returncode = 1
    fake_tunnel.clock.advance(100)
    assert runtime.status()["retry_in_seconds"] is None
    runtime.start_automatic()
    assert len(fake_tunnel.popen.calls) == 1


@pytest.mark.parametrize("corruption", ["deleted", "malformed"])
def test_config_only_restart_fails_visibly_and_can_recover(tmp_path, fake_tunnel, corruption):
    config = tmp_path / "snulbug.toml"
    source = '[mcp.proxy]\ntunnel_provider = "ngrok"\n'
    config.write_text(source)
    (tmp_path / "ngrok-agent.yml").write_text("version: 3\n")
    runtime = ShareRuntime(tmp_path)
    runtime.configure(config)
    try:
        runtime.start()
        fake_tunnel.popen.processes[-1].returncode = 1
        assert runtime.status()["state"] == "backoff"
        if corruption == "deleted":
            config.unlink()
        else:
            config.write_text("[invalid")
        fake_tunnel.clock.advance(1)
        status = runtime.status()
        assert status["state"] == "failed"
        assert "configuration_error" in status
        assert status["retry_in_seconds"] is None
        config.write_text(source)
        assert runtime.start()["ok"] is True
    finally:
        runtime.close()


def test_proxy_runtime_disables_restarts_before_drain_then_reaps(runtime_factory, fake_tunnel, monkeypatch):
    import uvicorn

    import snulbug.proxy as proxy

    runtime = runtime_factory(graceful_shutdown_timeout=7.0)
    queues = {}
    events = []

    async def app(scope, receive, send):
        assert (await receive())["type"] == "lifespan.startup"
        await send({"type": "lifespan.startup.complete"})
        assert (await receive())["type"] == "lifespan.shutdown"
        events.append("drained")
        await send({"type": "lifespan.shutdown.complete"})

    async def shutdown(server, sockets=None):
        assert runtime.status()["desired_state"] == "stopped"
        assert runtime.status()["running"] is True
        events.append("drain-started")
        await queues["messages"].put({"type": "lifespan.shutdown"})
        await queues["task"]

    def run(server):
        assert server.config.timeout_graceful_shutdown == 7.0

        async def exercise():
            messages = asyncio.Queue()
            startup = asyncio.Event()
            queues["messages"] = messages

            async def send(message):
                if message["type"] == "lifespan.startup.complete":
                    startup.set()

            await messages.put({"type": "lifespan.startup"})
            task = asyncio.create_task(server.config.app({"type": "lifespan"}, messages.get, send))
            queues["task"] = task
            await asyncio.wait_for(startup.wait(), timeout=1)
            await server.shutdown()
            assert runtime._closed

        asyncio.run(exercise())
        server.started = True

    monkeypatch.setattr(proxy, "create_proxy_application", lambda *args, **kwargs: app)
    monkeypatch.setattr(uvicorn.Server, "run", run)
    monkeypatch.setattr(uvicorn.Server, "shutdown", shutdown)
    proxy.run_proxy(upstream=None, policy="unused.lua", share_runtime=runtime)
    assert events == ["drain-started", "drained"]
    assert fake_tunnel.popen.processes[-1].calls == ["terminate", ("wait", 0.25)]
    assert fake_tunnel.popen.calls[-1][1]["stdout"].closed
    assert runtime.status()["running"] is False

from __future__ import annotations

import logging
import math
import os
import re
import shlex
import shutil
import subprocess
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from pathlib import Path
from time import monotonic, sleep
from typing import Any

from .config import tomllib
from .redaction import SECRET_REPLACEMENT
from .share_session import load_share_session_model

logger = logging.getLogger("snulbug.runtime")
MAX_TUNNEL_LOG_TAIL_BYTES = 8192
POLICY_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
POLICY_STANDALONE_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
]


@dataclass(frozen=True)
class ShareRuntimeConfig:
    tunnel_autostart: bool = True
    restart_initial_seconds: float = 1.0
    restart_max_seconds: float = 30.0
    restart_max_attempts: int = 5
    restart_reset_seconds: float = 60.0
    tunnel_shutdown_timeout: float = 5.0
    graceful_shutdown_timeout: float = 30.0

    @classmethod
    def load(cls, path: str | Path) -> ShareRuntimeConfig:
        with Path(path).open("rb") as file:
            raw = tomllib.load(file)
        mcp = raw.get("mcp", {})
        if not isinstance(mcp, Mapping):
            raise ValueError("config section [mcp] must be a table")
        values = mcp.get("runtime", {})
        if not isinstance(values, Mapping):
            raise ValueError("config section [mcp.runtime] must be a table")
        unknown = set(values) - {field.name for field in fields(cls)}
        if unknown:
            raise ValueError(f"unknown mcp.runtime settings: {', '.join(sorted(unknown))}")
        config = cls(**values)
        if not isinstance(config.tunnel_autostart, bool):
            raise ValueError("mcp.runtime.tunnel_autostart must be a boolean")
        if type(config.restart_max_attempts) is not int or config.restart_max_attempts < 0:
            raise ValueError("mcp.runtime.restart_max_attempts must be a non-negative integer")
        for name in (
            "restart_initial_seconds",
            "restart_max_seconds",
            "restart_reset_seconds",
            "tunnel_shutdown_timeout",
            "graceful_shutdown_timeout",
        ):
            value = getattr(config, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"mcp.runtime.{name} must be a finite positive number")
        if config.restart_max_seconds < config.restart_initial_seconds:
            raise ValueError("mcp.runtime.restart_max_seconds must be >= restart_initial_seconds")
        return config


class ShareRuntime:
    """Own a share's tunnel independently of the optional local web console."""

    def __init__(self, directory: str | Path, *, tunnel_autostart: bool | None = None) -> None:
        self.directory = Path(directory).resolve()
        self.config = ShareRuntimeConfig()
        self.tunnel_autostart = tunnel_autostart
        self._config_path: Path | None = None
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._process: Any = None
        self._log_file: Any = None
        self._last_returncode: int | None = None
        self._desired = "stopped"
        self._state = "stopped"
        self._error: str | None = None
        self._attempts = 0
        self._retry_at: float | None = None
        self._started_at: float | None = None
        self._closed = False
        self._operator_stopped = False
        self._last_plan: dict[str, Any] = {}

    def configure(self, config_path: str | Path) -> None:
        with self._lock:
            self._config_path = Path(config_path).resolve()
            self.config = ShareRuntimeConfig.load(self._config_path)

    def start_automatic(self) -> None:
        with self._lock:
            enabled = self.config.tunnel_autostart if self.tunnel_autostart is None else self.tunnel_autostart
            if self._closed or self._operator_stopped or not enabled or not self._plan().get("supported"):
                return
            result = self.start()
            if not result["ok"] and result["process"]["state"] == "failed":
                raise RuntimeError(result.get("error") or "managed tunnel failed to start")

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise RuntimeError("share runtime is closed")
            self._reconcile_locked()
            if self._process is not None:
                return {"ok": True, "message": "tunnel process is already running", "process": self._status_locked()}
            self._desired = "running"
            self._operator_stopped = False
            self._attempts = 0
            self._retry_at = None
            self._spawn_locked()
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._monitor, name="snulbug-tunnel", daemon=True)
                self._thread.start()
            self._wake.set()
            status = self._status_locked()
            return {"ok": status["running"], "error": status.get("error"), "process": status}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._operator_stopped = True
            self._desired = "stopped"
            self._retry_at = None
            self._terminate_locked()
            self._state = "stopped"
            self._error = None
            self._last_returncode = None
            self._wake.set()
            return {"ok": True, "message": "tunnel process stopped", "process": self._status_locked()}

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._desired = "stopped"
            self._retry_at = None
            self._wake.set()
            self._terminate_locked()
            self._state = "stopped"
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=self.config.tunnel_shutdown_timeout + 1)

    def begin_shutdown(self) -> None:
        with self._lock:
            self._operator_stopped = True
            self._desired = "stopped"
            self._retry_at = None
            self._state = "draining" if self._process is not None else "stopped"

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._reconcile_locked()
            return self._status_locked()

    async def serve(self, app: Any, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "lifespan":
            await app(scope, receive, send)
            return

        async def lifespan_send(message: Any) -> None:
            if message.get("type") == "lifespan.startup.complete":
                try:
                    self.start_automatic()
                except Exception as exc:
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
            await send(message)

        try:
            await app(scope, receive, lifespan_send)
        finally:
            # Lifespan shutdown runs after Uvicorn drains connections, but before
            # it re-raises SIGTERM. An outer CLI finally alone cannot clean up then.
            self.close()

    def _plan(self) -> dict[str, Any]:
        plan = tunnel_start_plan(self.directory, config_path=self._config_path)
        self._last_plan = plan
        return plan

    def _status_locked(self) -> dict[str, Any]:
        try:
            plan = self._plan()
        except (OSError, ValueError) as exc:
            plan = {**self._last_plan, "configuration_error": f"cannot read tunnel configuration: {type(exc).__name__}"}
        return {
            **plan,
            **_tunnel_log_status(plan, returncode=self._last_returncode),
            "state": self._state,
            "desired_state": self._desired,
            "running": self._process is not None and self._process.poll() is None,
            "pid": getattr(self._process, "pid", None),
            "returncode": self._last_returncode,
            "restart_attempts": self._attempts,
            "restart_max_attempts": self.config.restart_max_attempts,
            "retry_in_seconds": max(0.0, self._retry_at - monotonic()) if self._retry_at is not None else None,
            "error": self._error,
        }

    def _spawn_locked(self) -> None:
        try:
            plan = self._plan()
        except (OSError, ValueError) as exc:
            self._supervision_failed_locked(exc)
            return
        argv = [str(item) for item in _sequence(plan.get("command_argv"))]
        error = plan.get("error") if not plan.get("manageable") else None
        if not error and not argv:
            error = "managed tunnel command is missing"
        executable = shutil.which(argv[0]) if argv else None
        if not error and not executable:
            error = f"{argv[0]} executable not found on PATH"
        if (
            not error
            and plan.get("provider") == "ngrok"
            and _ngrok_agent_config_has_placeholder(Path(plan["agent_config"]))
        ):
            error = "ngrok agent config still contains YOUR_NGROK_AUTHTOKEN; configure it before starting the tunnel"
        if not error and plan.get("provider") == "ssh" and _ssh_tunnel_command_has_placeholder(argv):
            error = "SSH tunnel command still contains YOUR_SSH_USER@YOUR_SSH_HOST"
        if error:
            self._state, self._error = "failed", str(error)
            self._retry_at = None
            logger.error("snulbug tunnel failed: %s", self._error)
            return
        try:
            path = Path(plan["log_path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._log_file = os.fdopen(fd, "ab")
            self._process = subprocess.Popen(  # noqa: S603 - fixed executable/argv; never a shell command.
                [str(executable), *argv[1:]],
                cwd=str(self.directory),
                stdin=subprocess.DEVNULL,
                stdout=self._log_file,
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            self._close_log_locked()
            self._record_exit_locked(None, f"could not start tunnel: {type(exc).__name__}")
            return
        self._started_at = monotonic()
        self._last_returncode = None
        self._state, self._error = "running", None
        self._retry_at = None
        logger.info("snulbug tunnel started: provider=%s pid=%s", plan.get("provider"), self._process.pid)
        sleep(0.15)
        self._reconcile_locked()

    def _reconcile_locked(self) -> None:
        now = monotonic()
        if self._process is not None:
            if self._started_at is not None and now - self._started_at >= self.config.restart_reset_seconds:
                self._attempts = 0
            code = self._process.poll()
            if code is None:
                return
            self._process = None
            self._close_log_locked()
            self._record_exit_locked(code, f"tunnel process exited with status {code}")
        if self._desired == "running" and self._retry_at is not None and now >= self._retry_at and not self._closed:
            self._attempts += 1
            self._spawn_locked()

    def _record_exit_locked(self, code: int | None, error: str) -> None:
        self._last_returncode = code
        self._error = error
        if self._desired != "running":
            self._state = "stopped"
            self._retry_at = None
            return
        if self._desired == "running" and self._attempts < self.config.restart_max_attempts:
            delay = self.config.restart_initial_seconds
            for _ in range(self._attempts):
                delay = min(delay * 2, self.config.restart_max_seconds)
                if delay == self.config.restart_max_seconds:
                    break
            self._retry_at = monotonic() + delay
            self._state = "backoff"
            logger.warning("snulbug tunnel exited; retrying in %.1fs (%s)", delay, error)
        else:
            self._retry_at = None
            self._state = "failed"
            logger.error("snulbug tunnel stopped after exhausting restart budget: %s", error)

    def _terminate_locked(self) -> None:
        process = self._process
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.config.tunnel_shutdown_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.config.tunnel_shutdown_timeout)
        finally:
            self._process = None
            self._close_log_locked()

    def _close_log_locked(self) -> None:
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    def _monitor(self) -> None:
        while True:
            self._wake.wait(timeout=0.25)
            self._wake.clear()
            with self._lock:
                if self._closed:
                    return
                try:
                    self._reconcile_locked()
                except Exception as exc:
                    self._supervision_failed_locked(exc)

    def _supervision_failed_locked(self, exc: Exception) -> None:
        self._state = "failed"
        self._retry_at = None
        self._error = (
            f"tunnel supervision failed: {type(exc).__name__}; fix the configuration and explicitly start again"
        )
        logger.error("%s", self._error)


def _tunnel_log_status(
    plan: Mapping[str, Any],
    *,
    returncode: int | None = None,
) -> dict[str, Any]:
    log_path = plan.get("log_path")
    if not log_path:
        return {}
    raw_tail = _read_text_tail(Path(str(log_path)), MAX_TUNNEL_LOG_TAIL_BYTES)
    diagnosis = (
        _diagnose_tunnel_process(
            str(plan.get("provider") or "generic"),
            raw_tail,
            returncode=returncode,
        )
        if returncode is not None
        else {}
    )
    return _drop_empty(
        {
            "log_tail": _redact_tunnel_log_tail(raw_tail),
            "diagnosis": diagnosis,
            "error": diagnosis.get("message") if diagnosis else None,
        }
    )


def _read_text_tail(path: Path, max_bytes: int) -> str | None:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            data = handle.read(max_bytes)
    except OSError:
        return None
    if not data:
        return None
    return data.decode("utf-8", errors="replace").strip()


def _redact_tunnel_log_tail(value: str | None) -> str | None:
    if not value:
        return value
    redacted = POLICY_BEARER_PATTERN.sub("Bearer " + SECRET_REPLACEMENT, value)
    for pattern in POLICY_STANDALONE_SECRET_PATTERNS:
        redacted = pattern.sub(SECRET_REPLACEMENT, redacted)
    return re.sub(
        r"(?im)(\b(?:ngrok_)?authtoken\b\s*[:=]\s*)(\S+)",
        r"\1" + SECRET_REPLACEMENT,
        redacted,
    )


def _diagnose_tunnel_process(
    provider: str,
    log_tail: str | None,
    *,
    returncode: int | None,
) -> dict[str, str]:
    if provider == "ngrok":
        return _diagnose_ngrok_process(log_tail, returncode=returncode)
    if returncode is not None and returncode != 0:
        return {
            "code": "tunnel.process_exited",
            "message": f"Tunnel process exited with status {returncode}.",
            "recommendation": (
                "Open the recent tunnel log below and restart the tunnel after fixing the reported error."
            ),
        }
    return {}


def _diagnose_ngrok_process(log_tail: str | None, *, returncode: int | None) -> dict[str, str]:
    log = (log_tail or "").lower()
    if "err_ngrok_334" in log or "already online" in log:
        return {
            "code": "ngrok.endpoint_already_online",
            "message": "The configured ngrok endpoint is already online in another session.",
            "recommendation": (
                "Stop the existing ngrok endpoint/session, choose a different endpoint URL, or start ngrok "
                "with pooling only if you intentionally want load balancing."
            ),
        }
    if "err_ngrok_3200" in log or ("endpoint" in log and "offline" in log):
        return {
            "code": "ngrok.endpoint_offline",
            "message": "The ngrok cloud endpoint is offline or not connected to this local agent.",
            "recommendation": (
                "Start the generated ngrok agent from this panel, then make sure the ngrok Cloud Endpoint "
                "Traffic Policy forwards to the generated internal URL."
            ),
        }
    if "authtoken" in log or "authentication failed" in log or "authorization failed" in log:
        return {
            "code": "ngrok.auth_required",
            "message": "ngrok rejected the agent config or account authentication.",
            "recommendation": (
                "Run ngrok login or replace YOUR_NGROK_AUTHTOKEN in the generated agent config before "
                "starting the managed tunnel."
            ),
        }
    if "failed to start tunnel" in log:
        return {
            "code": "ngrok.start_failed",
            "message": "ngrok failed to start the managed tunnel.",
            "recommendation": "Review the recent tunnel log, fix the ngrok configuration, then start the tunnel again.",
        }
    if returncode is not None and returncode != 0:
        return {
            "code": "ngrok.agent_exited",
            "message": f"ngrok exited with status {returncode}.",
            "recommendation": "Review the recent tunnel log, fix the ngrok configuration, then start the tunnel again.",
        }
    return {}


def tunnel_start_plan(directory: str | Path, *, config_path: Path | None = None) -> dict[str, Any]:
    share_dir = Path(directory).resolve()
    provider, bridge, manifest = _tunnel_metadata(share_dir)
    if not provider and config_path is not None:
        with config_path.open("rb") as file:
            raw = tomllib.load(file)
        proxy = _mapping(_mapping(raw.get("mcp")).get("proxy"))
        provider = str(proxy.get("tunnel_provider") or "")
        bridge = {"public_url": proxy.get("tunnel_public_url")}
    if provider == "ngrok":
        return _ngrok_tunnel_start_plan(share_dir, bridge=bridge, manifest=manifest)
    if provider == "ssh":
        return _ssh_tunnel_start_plan(share_dir, bridge=bridge)
    return {
        "provider": provider or "generic",
        "manageable": False,
        "supported": False,
        "error": "managed tunnel start/stop is currently available for ngrok and ssh shares",
    }


def _ngrok_tunnel_start_plan(
    share_dir: Path,
    *,
    bridge: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    agent_config = _ngrok_agent_config_path(share_dir, bridge=bridge, manifest=manifest)
    traffic_policy = _ngrok_traffic_policy_path(share_dir, bridge=bridge, manifest=manifest)
    command_argv = ["ngrok", "start", "--config", str(agent_config), "--all"]
    log_path = share_dir / ".snulbug" / "share" / "ngrok-agent.log"
    exists = agent_config.is_file()
    policy_exists = traffic_policy.is_file()
    public_url = _tunnel_public_url(bridge=bridge, manifest=manifest)
    internal_url = bridge.get("internal_url") or bridge.get("ngrok_internal_url")
    return _drop_empty(
        {
            "provider": "ngrok",
            "manageable": exists,
            "supported": True,
            "agent_config": str(agent_config),
            "agent_config_exists": exists,
            "traffic_policy": str(traffic_policy),
            "traffic_policy_exists": policy_exists,
            "public_url": public_url,
            "internal_url": internal_url,
            "command_argv": command_argv,
            "command": _shell_command(command_argv),
            "log_path": str(log_path),
            "error": None if exists else f"ngrok agent config not found: {agent_config}",
        }
    )


def _ssh_tunnel_start_plan(share_dir: Path, *, bridge: Mapping[str, Any]) -> dict[str, Any]:
    command_argv = [str(item) for item in _sequence(bridge.get("command_argv"))]
    if not command_argv:
        return {
            "provider": "ssh",
            "manageable": False,
            "supported": True,
            "error": "SSH tunnel command is missing from the share metadata; regenerate the share",
        }
    log_path = share_dir / ".snulbug" / "share" / "ssh-tunnel.log"
    return _drop_empty(
        {
            "provider": "ssh",
            "manageable": True,
            "supported": True,
            "ssh_target": bridge.get("ssh_target"),
            "remote_bind": bridge.get("remote_bind"),
            "remote_port": bridge.get("remote_port"),
            "client_url": bridge.get("client_url"),
            "command_argv": command_argv,
            "command": _shell_command(command_argv),
            "log_path": str(log_path),
        }
    )


def _tunnel_metadata(share_dir: Path) -> tuple[str, Mapping[str, Any], Mapping[str, Any] | None]:
    from .share import load_mcp_share

    manifest: Mapping[str, Any] | None = None
    try:
        manifest = load_mcp_share(share_dir)
    except Exception:
        manifest = None
    tunnel = _mapping(manifest.get("tunnel")) if manifest is not None else {}
    bridge = _mapping(tunnel.get("bridge"))
    provider = str(tunnel.get("provider") or "").strip().lower()
    try:
        session_model = load_share_session_model(share_dir)
    except Exception:
        session_model = {}
    session_tunnel = _mapping(session_model.get("tunnel"))
    if not provider:
        provider = str(session_tunnel.get("provider") or "").strip().lower()
    if not bridge:
        bridge = _mapping(session_tunnel.get("bridge"))
    return provider, bridge, manifest


def _ngrok_agent_config_path(
    share_dir: Path,
    *,
    bridge: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> Path:
    tunnel = _mapping(manifest.get("tunnel")) if manifest is not None else {}
    traffic_policy = _mapping(tunnel.get("traffic_policy"))
    value = traffic_policy.get("agent_config") or bridge.get("agent_config") or "ngrok-agent.yml"
    path = Path(str(value))
    if path.is_absolute():
        return path
    if path.parent == Path("."):
        root_path = share_dir / path
        return root_path if root_path.is_file() else share_dir / "tunnel" / path
    return _resolve_share_path(share_dir, path)


def _ngrok_traffic_policy_path(
    share_dir: Path,
    *,
    bridge: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> Path:
    tunnel = _mapping(manifest.get("tunnel")) if manifest is not None else {}
    traffic_policy = _mapping(tunnel.get("traffic_policy"))
    value = traffic_policy.get("path") or bridge.get("traffic_policy") or "ngrok-traffic-policy.yml"
    path = Path(str(value))
    if path.is_absolute():
        return path
    if path.parent == Path("."):
        root_path = share_dir / path
        return root_path if root_path.is_file() else share_dir / "tunnel" / path
    return _resolve_share_path(share_dir, path)


def _tunnel_public_url(
    *,
    bridge: Mapping[str, Any],
    manifest: Mapping[str, Any] | None,
) -> str | None:
    tunnel = _mapping(manifest.get("tunnel")) if manifest is not None else {}
    value = tunnel.get("public_url") or bridge.get("public_url") or bridge.get("client_url")
    return str(value) if value else None


def _ngrok_agent_config_has_placeholder(path: Path) -> bool:
    try:
        return "YOUR_NGROK_AUTHTOKEN" in path.read_text(encoding="utf-8")
    except OSError:
        return False


def _ssh_tunnel_command_has_placeholder(command_argv: Sequence[str]) -> bool:
    return any("YOUR_SSH_USER@YOUR_SSH_HOST" in str(item) for item in command_argv)


def _shell_command(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in argv)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, (list, tuple)) else []


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


def _resolve_share_path(base: Path, value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    share_relative = base / path
    if share_relative.exists():
        return share_relative
    if path.exists():
        return path.resolve()
    return share_relative

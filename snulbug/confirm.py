from __future__ import annotations

import asyncio
import json
import select
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, TextIO

DEFAULT_CONFIRM_TIMEOUT_SECONDS = 30.0


@dataclass
class ConfirmationBroker:
    """Interactive approval broker for Lua `confirm` decisions."""

    enabled: bool = False
    input_stream: TextIO | None = None
    output_stream: TextIO | None = None
    session_approvals: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    async def __call__(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        scope: Mapping[str, Any],
    ) -> dict[str, Any]:
        return await asyncio.to_thread(self.decide, decision, request, scope)

    def decide(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        scope: Mapping[str, Any],
    ) -> dict[str, Any]:
        del scope
        remember_key = _optional_string(decision.get("remember_key"))
        if remember_key is not None:
            with self._lock:
                if remember_key in self.session_approvals:
                    return _approved("cached_session", decision, remember_key=remember_key)

        if not self.enabled:
            return _denied(decision, reason="confirmation is not enabled", reason_code="confirm.unavailable")
        if not self._can_prompt():
            return _denied(
                decision,
                reason="confirmation requires an interactive input stream",
                reason_code="confirm.noninteractive",
            )

        timeout = _timeout_seconds(decision.get("timeout_seconds"))
        self._write_prompt(decision, request, remember_key=remember_key, timeout=timeout)
        line = self._read_line(timeout)
        if line is None:
            return _denied(decision, reason="confirmation timed out", reason_code="confirm.timeout")

        choice = line.strip().lower()
        if choice in {"o", "once", "y", "yes", "allow"}:
            return _approved("once", decision, remember_key=remember_key)
        if choice in {"a", "always", "s", "session"}:
            if remember_key is not None:
                with self._lock:
                    self.session_approvals.add(remember_key)
                return _approved("session", decision, remember_key=remember_key)
            return _approved(
                "once",
                decision,
                remember_key=None,
                reason="session approval requested without remember_key; allowed once",
            )
        return _denied(decision, reason="confirmation denied", reason_code="confirm.denied")

    def _can_prompt(self) -> bool:
        input_stream = self._input
        if input_stream is not sys.stdin:
            return True
        try:
            return input_stream.isatty()
        except Exception:
            return False

    def _write_prompt(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        remember_key: str | None,
        timeout: float,
    ) -> None:
        summary = _mcp_summary(request)
        prompt = _optional_string(decision.get("prompt")) or _optional_string(decision.get("reason"))
        if prompt is None:
            prompt = "Allow this MCP request?"

        lines = [
            "",
            "snulbug confirm required",
            f"prompt: {prompt}",
        ]
        if decision.get("reason_code"):
            lines.append(f"reason_code: {decision['reason_code']}")
        if summary:
            fields = (f"{key}={json.dumps(value, separators=(',', ':'))}" for key, value in summary.items())
            lines.append("mcp: " + " ".join(fields))
        if remember_key is not None:
            lines.append(f"remember_key: {remember_key}")
        lines.append(f"timeout_seconds: {timeout:g}")
        lines.append("Allow once / always for this session / deny? [o/a/d]: ")

        output = self._output
        output.write("\n".join(lines))
        output.flush()

    def _read_line(self, timeout: float) -> str | None:
        input_stream = self._input
        if timeout <= 0:
            return None
        try:
            fileno = input_stream.fileno()
        except Exception:
            line = input_stream.readline()
            return line if line != "" else None
        try:
            readable, _, _ = select.select([fileno], [], [], timeout)
        except (OSError, ValueError):
            line = input_stream.readline()
            return line if line != "" else None
        if not readable:
            return None
        line = input_stream.readline()
        return line if line != "" else None

    @property
    def _input(self) -> TextIO:
        return self.input_stream or sys.stdin

    @property
    def _output(self) -> TextIO:
        return self.output_stream or sys.stderr


def _approved(
    mode: str,
    decision: Mapping[str, Any],
    *,
    remember_key: str | None,
    reason: str | None = None,
) -> dict[str, Any]:
    reason_code = {
        "once": "confirm.approved_once",
        "session": "confirm.approved_session",
        "cached_session": "confirm.cached_session",
    }.get(mode, "confirm.approved")
    return {
        "approved": True,
        "mode": mode,
        "remember_key": remember_key,
        "reason": reason or "confirmation approved",
        "reason_code": reason_code,
        "prompt": decision.get("prompt"),
    }


def _denied(decision: Mapping[str, Any], *, reason: str, reason_code: str) -> dict[str, Any]:
    return {
        "approved": False,
        "mode": "denied",
        "remember_key": _optional_string(decision.get("remember_key")),
        "reason": reason,
        "reason_code": reason_code,
        "prompt": decision.get("prompt"),
        "status": int(decision.get("status", 403)),
        "body": decision.get("body", "confirmation denied"),
    }


def _timeout_seconds(value: Any) -> float:
    if value is None:
        return DEFAULT_CONFIRM_TIMEOUT_SECONDS
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return DEFAULT_CONFIRM_TIMEOUT_SECONDS
    return max(0.0, timeout)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _mcp_summary(request: Mapping[str, Any]) -> dict[str, Any]:
    body = request.get("body")
    if not isinstance(body, str):
        return {}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, Mapping):
        return {}
    summary: dict[str, Any] = {}
    method = payload.get("method")
    if isinstance(method, str):
        summary["method"] = method
    params = payload.get("params")
    if isinstance(params, Mapping):
        target = params.get("name") or params.get("uri")
        if isinstance(target, str):
            summary["target"] = target
        arguments = params.get("arguments")
        if isinstance(arguments, Mapping):
            summary["argument_keys"] = sorted(str(key) for key in arguments)
    return summary

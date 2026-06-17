from __future__ import annotations

import base64
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from inspect import isawaitable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode

from .policy_backoff import (
    PolicyBackoffConfig,
    PolicyDenyBackoff,
    policy_backoff_active_decision,
    policy_backoff_headers,
)
from .promotion import compare_decisions
from .runtime import (
    CompiledLuaScript,
    LuaDecisionError,
    LuaDecisionTrace,
    compile_lua_file,
    compile_lua_script,
)
from .state import BoundedPolicyState, DryRunStateStore, PolicyStateStore, StateLimits

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
ScriptLoader = Callable[[Scope], CompiledLuaScript]
ConfirmHandler = Callable[
    [Mapping[str, Any], Mapping[str, Any], Scope],
    Awaitable[Mapping[str, Any]] | Mapping[str, Any],
]

DecisionAction = Literal[
    "continue",
    "set_context",
    "rewrite",
    "respond",
    "reject",
    "challenge",
    "redirect",
    "rate_limit",
    "confirm",
]


@dataclass(frozen=True)
class LuaConfig:
    """Runtime limits for Lua request policies."""

    read_body: bool = False
    max_body_bytes: int = 64 * 1024
    instruction_limit: int = 100_000
    memory_limit_bytes: int | None = 8 * 1024 * 1024
    context_scope_key: str = "lua"
    trace: bool = False
    trace_scope_key: str = "lua_trace"
    shadow_trace_scope_key: str = "lua_shadow_trace"


class LuaMiddleware:
    """ASGI middleware that runs a Lua policy before the downstream app."""

    def __init__(
        self,
        app: ASGIApp,
        script: str | Path | CompiledLuaScript | ScriptLoader,
        *,
        config: LuaConfig | None = None,
        shadow_script: str | Path | CompiledLuaScript | ScriptLoader | None = None,
        state_store: PolicyStateStore | None = None,
        state_limits: StateLimits | None = None,
        state_key_prefix: str = "",
        confirm_handler: ConfirmHandler | None = None,
        policy_backoff_config: PolicyBackoffConfig | None = None,
    ) -> None:
        self.app = app
        self.config = config or LuaConfig()
        self._script = self._coerce_script(script)
        self._shadow_script = self._coerce_script(shadow_script) if shadow_script is not None else None
        self.state_store = state_store
        self.state_limits = state_limits or StateLimits()
        self.state_key_prefix = state_key_prefix
        self.confirm_handler = confirm_handler
        self.policy_backoff = PolicyDenyBackoff(
            policy_backoff_config,
            store=state_store,
            key_prefix=state_key_prefix,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        child_scope = dict(scope)
        body = b""
        replay_receive = receive
        if self.config.read_body:
            body, replay_receive = await self._read_and_replay_body(receive, send)
            if replay_receive is None:
                return

        request = _scope_to_request(child_scope, body if self.config.read_body else None)
        preflight_backoff = self.policy_backoff.preflight(request, child_scope)
        if preflight_backoff.get("active"):
            decision = policy_backoff_active_decision(preflight_backoff)
            if self.config.trace:
                _attach_synthetic_trace(
                    child_scope,
                    self.config.trace_scope_key,
                    decision,
                    body_read=self.config.read_body,
                    policy_backoff=preflight_backoff,
                )
            _attach_policy_backoff(child_scope, preflight_backoff)
            await _send_response(
                send,
                status=int(decision["status"]),
                headers=policy_backoff_headers(preflight_backoff, include_retry_after=True),
                body=_body_bytes(decision["body"]),
            )
            return

        script = self._script(child_scope)
        context = child_scope.get(self.config.context_scope_key, {})
        policy_state = self._state_for_request()
        execution = script.decide_with_trace(request, context, policy_state)
        decision = execution.decision
        action = _validate_action(decision)
        if self.config.trace and action != "confirm":
            _attach_trace(child_scope, self.config.trace_scope_key, execution, body_read=self.config.read_body)
        if self._shadow_script is not None:
            _attach_shadow_trace(
                child_scope,
                self.config.shadow_trace_scope_key,
                self._shadow_script,
                request,
                context,
                active_decision=decision,
                body_read=self.config.read_body,
                shadow_state=self._shadow_state_for_request(),
            )

        if _confirmation_required(action, decision):
            await self._handle_confirmed_decision(
                decision,
                request,
                child_scope,
                replay_receive,
                send,
                execution,
            )
            return

        if action in {"continue", "set_context"}:
            _merge_context(child_scope, self.config.context_scope_key, decision.get("context"))
            await self.app(child_scope, replay_receive, send)
            return

        if action == "rewrite":
            replacement_body = _rewrite_body_bytes(decision, body_was_read=self.config.read_body)
            _apply_rewrite(child_scope, decision)
            if replacement_body is not None:
                replay_receive = _single_body_receive(replacement_body)
                child_scope["headers"] = _merge_headers(
                    child_scope.get("headers", []),
                    [(b"content-length", str(len(replacement_body)).encode("ascii"))],
                )
            _merge_context(child_scope, self.config.context_scope_key, decision.get("context"))
            if self.config.trace and replacement_body is not None:
                child_scope[self.config.trace_scope_key]["body_rewritten"] = True
            await self.app(child_scope, replay_receive, send)
            return

        if action == "challenge":
            backoff = self._record_policy_backoff(request, child_scope, decision)
            status, headers, body_bytes = _challenge_response(decision)
            if backoff.get("recorded"):
                headers.extend(policy_backoff_headers(backoff, include_retry_after=False))
            await _send_response(send, status=status, headers=headers, body=body_bytes)
            return

        if action == "redirect":
            status, headers, body_bytes = _redirect_response(decision)
            await _send_response(send, status=status, headers=headers, body=body_bytes)
            return

        if action == "rate_limit":
            rate_limit = self._enforce_rate_limit(decision)
            if self.config.trace:
                child_scope[self.config.trace_scope_key]["rate_limit"] = rate_limit
            if not rate_limit["allowed"]:
                headers = _rate_limit_headers(rate_limit)
                headers.extend(_decision_headers(decision.get("headers")))
                await _send_response(
                    send,
                    status=int(decision.get("status", 429)),
                    headers=headers,
                    body=_body_bytes(decision.get("body", "rate limit exceeded")),
                )
                return
            _merge_context(child_scope, self.config.context_scope_key, decision.get("context"))
            await self.app(child_scope, replay_receive, send)
            return

        if action in {"respond", "reject"}:
            status = int(decision.get("status", 403 if action == "reject" else 200))
            body_bytes = _body_bytes(decision.get("body", ""))
            headers = _decision_headers(decision.get("headers"))
            if action == "reject":
                backoff = self._record_policy_backoff(request, child_scope, decision)
                if backoff.get("recorded"):
                    headers.extend(policy_backoff_headers(backoff, include_retry_after=False))
            await _send_response(send, status=status, headers=headers, body=body_bytes)
            return

        raise LuaDecisionError(f"Unsupported Lua action: {action!r}")

    async def _confirm(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        scope: Scope,
    ) -> dict[str, Any]:
        if self.confirm_handler is None:
            return _normalize_confirmation_result(
                {
                    "approved": False,
                    "mode": "denied",
                    "reason": "confirmation is not enabled",
                    "reason_code": "confirm.unavailable",
                    "status": int(decision.get("status", 403)),
                    "body": decision.get("body", "confirmation denied"),
                    "prompt": decision.get("prompt"),
                    "remember_key": decision.get("remember_key"),
                }
            )
        result = self.confirm_handler(decision, request, scope)
        if isawaitable(result):
            result = await result
        return _normalize_confirmation_result(result)

    async def _handle_confirmed_decision(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        child_scope: Scope,
        replay_receive: Receive,
        send: Send,
        execution: LuaDecisionTrace,
    ) -> None:
        confirmation = await self._confirm(decision, request, child_scope)
        final_decision = _confirm_final_decision(decision, confirmation)
        if self.config.trace:
            _attach_trace_with_decision(
                child_scope,
                self.config.trace_scope_key,
                execution,
                final_decision,
                body_read=self.config.read_body,
                confirmation=confirmation,
            )
        if confirmation["approved"]:
            _merge_context(child_scope, self.config.context_scope_key, final_decision.get("context"))
            await self.app(child_scope, replay_receive, send)
            return
        status = int(final_decision.get("status", 403))
        body_bytes = _body_bytes(final_decision.get("body", "confirmation denied"))
        headers = _decision_headers(final_decision.get("headers"))
        backoff = self._record_policy_backoff(request, child_scope, final_decision)
        if backoff.get("recorded"):
            headers.extend(policy_backoff_headers(backoff, include_retry_after=False))
        await _send_response(send, status=status, headers=headers, body=body_bytes)

    def _record_policy_backoff(
        self,
        request: Mapping[str, Any],
        scope: Scope,
        decision: Mapping[str, Any],
    ) -> dict[str, Any]:
        backoff = self.policy_backoff.record_deny(request, scope, decision)
        if backoff.get("enabled"):
            _attach_policy_backoff(scope, backoff)
            if self.config.trace:
                trace = scope.get(self.config.trace_scope_key)
                if isinstance(trace, dict):
                    trace["policy_backoff"] = backoff
        return backoff

    def _coerce_script(self, script: str | Path | CompiledLuaScript | ScriptLoader) -> ScriptLoader:
        if isinstance(script, CompiledLuaScript):
            return lambda scope: script
        if isinstance(script, Path):
            compiled = compile_lua_file(
                script,
                instruction_limit=self.config.instruction_limit,
                memory_limit_bytes=self.config.memory_limit_bytes,
            )
            return lambda scope: compiled
        if isinstance(script, str):
            compiled = compile_lua_script(
                script,
                instruction_limit=self.config.instruction_limit,
                memory_limit_bytes=self.config.memory_limit_bytes,
            )
            return lambda scope: compiled
        return script

    def _state_for_request(self) -> BoundedPolicyState | None:
        if self.state_store is None:
            return None
        return BoundedPolicyState(
            self.state_store,
            limits=self.state_limits,
            key_prefix=self.state_key_prefix,
        )

    def _shadow_state_for_request(self) -> BoundedPolicyState | None:
        if self.state_store is None:
            return None
        return BoundedPolicyState(
            DryRunStateStore(self.state_store),
            limits=self.state_limits,
            key_prefix=self.state_key_prefix,
        )

    def _enforce_rate_limit(self, decision: Mapping[str, Any]) -> dict[str, Any]:
        if self.state_store is None:
            raise LuaDecisionError("Lua rate_limit action requires a configured state_store")

        key = decision.get("key")
        if key is None:
            raise LuaDecisionError("Lua rate_limit action requires field 'key'")
        limit = int(decision.get("limit", 0))
        window = int(decision.get("window", 0))
        if limit <= 0:
            raise LuaDecisionError("Lua rate_limit field 'limit' must be positive")
        if window <= 0:
            raise LuaDecisionError("Lua rate_limit field 'window' must be positive")

        now = time.time()
        bucket = int(now // window)
        reset_at = (bucket + 1) * window
        state_key = f"rate_limit:{key}:{bucket}"
        state = self._state_for_request()
        if state is None:
            raise LuaDecisionError("Lua rate_limit action requires a configured state_store")
        count = state.incr(state_key, 1, {"ttl": window * 2})
        remaining = max(0, limit - count)
        return {
            "allowed": count <= limit,
            "key": str(key),
            "state_key": f"{self.state_key_prefix}{state_key}",
            "limit": limit,
            "window": window,
            "count": count,
            "remaining": remaining,
            "reset_at": int(reset_at),
            "retry_after": max(1, int(reset_at - now)),
            "state_operations": state.operations,
        }

    async def _read_and_replay_body(self, receive: Receive, send: Send) -> tuple[bytes, Receive | None]:
        messages: list[Message] = []
        chunks: list[bytes] = []
        total = 0

        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break

            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.config.max_body_bytes:
                await _send_response(
                    send,
                    status=413,
                    headers=[(b"content-type", b"text/plain; charset=utf-8")],
                    body=b"request body too large for Lua middleware",
                )
                return b"", None

            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        return b"".join(chunks), replay


def _scope_to_request(scope: Scope, body: bytes | None) -> dict[str, Any]:
    headers = _headers_to_mapping(scope.get("headers", []))
    request: dict[str, Any] = {
        "method": scope.get("method", ""),
        "path": scope.get("path", ""),
        "raw_path": _decode_bytes(scope.get("raw_path", b"")),
        "query_string": _decode_bytes(scope.get("query_string", b"")),
        "headers": headers,
        "client": _sequence_or_none(scope.get("client")),
        "scheme": scope.get("scheme", "http"),
    }
    if body is not None:
        request["body"] = body.decode("utf-8", errors="replace")
        request["body_bytes_latin1"] = body.decode("latin-1")
    return request


def _validate_action(decision: Mapping[str, Any]) -> DecisionAction:
    action = decision.get("action", "continue")
    if action not in {
        "continue",
        "set_context",
        "rewrite",
        "respond",
        "reject",
        "challenge",
        "redirect",
        "rate_limit",
        "confirm",
    }:
        raise LuaDecisionError(
            "Lua action must be one of continue, set_context, rewrite, respond, reject, "
            f"challenge, redirect, rate_limit, confirm; got {action!r}"
        )
    return action  # type: ignore[return-value]


def _confirmation_required(action: DecisionAction, decision: Mapping[str, Any]) -> bool:
    return action == "confirm" or (action == "reject" and _rejection_confirmation_requested(decision))


def _rejection_confirmation_requested(decision: Mapping[str, Any]) -> bool:
    return decision.get("confirm") is True


def _merge_context(scope: Scope, key: str, context: Any) -> None:
    if context is None:
        return
    if not isinstance(context, Mapping):
        raise LuaDecisionError("Lua decision field 'context' must be a table/object")

    existing = scope.get(key)
    merged = dict(existing) if isinstance(existing, Mapping) else {}
    merged.update(context)
    scope[key] = merged

    state = scope.get("state")
    if isinstance(state, dict):
        state[key] = merged


def _attach_trace(scope: Scope, key: str, trace: LuaDecisionTrace, *, body_read: bool) -> None:
    payload = _trace_payload(trace, body_read=body_read)
    scope[key] = payload

    state = scope.get("state")
    if isinstance(state, dict):
        state[key] = payload


def _attach_shadow_trace(
    scope: Scope,
    key: str,
    shadow_script: ScriptLoader,
    request: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    active_decision: Mapping[str, Any],
    body_read: bool,
    shadow_state: BoundedPolicyState | None,
) -> None:
    try:
        shadow_trace = shadow_script(scope).decide_with_trace(request, context, shadow_state)
        _validate_action(shadow_trace.decision)
        comparison = compare_decisions(active_decision, shadow_trace.decision)
        payload = {
            "ok": True,
            "active_action": active_decision["action"],
            "shadow_action": shadow_trace.decision["action"],
            "shadow": _trace_payload(shadow_trace, body_read=body_read),
            **comparison,
        }
    except Exception as exc:
        payload = {
            "ok": False,
            "active_action": active_decision["action"],
            "shadow_action": "error",
            "changed": True,
            "regression": True,
            "reason": f"shadow policy failed: {exc}",
            "differences": [],
        }

    scope[key] = payload

    state = scope.get("state")
    if isinstance(state, dict):
        state[key] = payload


def _trace_payload(trace: LuaDecisionTrace, *, body_read: bool) -> dict[str, Any]:
    return {
        "action": trace.decision["action"],
        "decision": trace.decision,
        "body_read": body_read,
        **trace.to_dict(),
    }


def _attach_trace_with_decision(
    scope: Scope,
    key: str,
    trace: LuaDecisionTrace,
    decision: Mapping[str, Any],
    *,
    body_read: bool,
    confirmation: Mapping[str, Any] | None = None,
) -> None:
    payload = _trace_payload(trace, body_read=body_read)
    payload["action"] = decision["action"]
    payload["decision"] = dict(decision)
    if confirmation is not None:
        payload["confirmation"] = dict(confirmation)
    scope[key] = payload

    state = scope.get("state")
    if isinstance(state, dict):
        state[key] = payload


def _attach_synthetic_trace(
    scope: Scope,
    key: str,
    decision: Mapping[str, Any],
    *,
    body_read: bool,
    policy_backoff: Mapping[str, Any] | None = None,
) -> None:
    payload = {
        "action": decision["action"],
        "decision": dict(decision),
        "body_read": body_read,
        "duration_ms": 0.0,
        "instruction_count": 0,
        "scopes": [],
    }
    if policy_backoff is not None:
        payload["policy_backoff"] = dict(policy_backoff)
    scope[key] = payload

    state = scope.get("state")
    if isinstance(state, dict):
        state[key] = payload


def _attach_policy_backoff(scope: Scope, metadata: Mapping[str, Any]) -> None:
    state = scope.get("state")
    if isinstance(state, dict):
        state["snulbug_policy_backoff"] = dict(metadata)


def _normalize_confirmation_result(result: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        raise LuaDecisionError("confirm handler must return a table/object")
    confirmation = dict(result)
    confirmation["approved"] = bool(confirmation.get("approved", False))
    confirmation["mode"] = str(confirmation.get("mode") or ("approved" if confirmation["approved"] else "denied"))
    if "reason" in confirmation and confirmation["reason"] is not None:
        confirmation["reason"] = str(confirmation["reason"])
    if "reason_code" in confirmation and confirmation["reason_code"] is not None:
        confirmation["reason_code"] = str(confirmation["reason_code"])
    if "remember_key" in confirmation and confirmation["remember_key"] is not None:
        confirmation["remember_key"] = str(confirmation["remember_key"])
    if "prompt" in confirmation and confirmation["prompt"] is not None:
        confirmation["prompt"] = str(confirmation["prompt"])
    return confirmation


def _confirm_final_decision(decision: Mapping[str, Any], confirmation: Mapping[str, Any]) -> dict[str, Any]:
    final = dict(decision)
    final["confirmation"] = dict(confirmation)
    if confirmation["approved"]:
        final["action"] = "continue"
        final.pop("status", None)
        final.pop("body", None)
        final.pop("headers", None)
        return final

    final["action"] = "reject"
    final["status"] = int(confirmation.get("status", decision.get("status", 403)))
    final["body"] = confirmation.get("body", decision.get("body", "confirmation denied"))
    return final


def _apply_rewrite(scope: Scope, decision: Mapping[str, Any]) -> None:
    path = decision.get("path")
    if path is not None:
        if not isinstance(path, str) or not path.startswith("/"):
            raise LuaDecisionError("Lua rewrite field 'path' must be an absolute path string")
        scope["path"] = path
        scope["raw_path"] = path.encode("utf-8")

    query = decision.get("query")
    query_string = decision.get("query_string")
    if query is not None and query_string is not None:
        raise LuaDecisionError("Lua rewrite may set either 'query' or 'query_string', not both")
    if query is not None:
        if not isinstance(query, Mapping):
            raise LuaDecisionError("Lua rewrite field 'query' must be a table/object")
        query_string = urlencode({str(key): str(value) for key, value in query.items()})
    if query_string is not None:
        if not isinstance(query_string, str):
            raise LuaDecisionError("Lua rewrite field 'query_string' must be a string")
        scope["query_string"] = query_string.encode("ascii")

    header_updates = decision.get("headers")
    if header_updates is not None:
        scope["headers"] = _merge_headers(scope.get("headers", []), _decision_headers(header_updates))


def _headers_to_mapping(headers: list[tuple[bytes, bytes]]) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    for raw_name, raw_value in headers:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        existing = result.get(name)
        if existing is None:
            result[name] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            result[name] = [existing, value]
    return result


def _decision_headers(headers: Any) -> list[tuple[bytes, bytes]]:
    if headers is None:
        return []
    if not isinstance(headers, Mapping):
        raise LuaDecisionError("Lua decision field 'headers' must be a table/object")

    result: list[tuple[bytes, bytes]] = []
    for name, value in headers.items():
        raw_name = str(name).lower().encode("ascii")
        values = value if isinstance(value, list) else [value]
        for item in values:
            result.append((raw_name, str(item).encode("latin-1")))
    return result


def _challenge_response(decision: Mapping[str, Any]) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    status = int(decision.get("status", 401))
    scheme = str(decision.get("scheme", "Bearer"))
    challenge_parts = [scheme]
    for key in ("realm", "error", "error_description", "scope"):
        value = decision.get(key)
        if value is not None:
            challenge_parts.append(f'{key.replace("_", "-")}="{_header_quote(str(value))}"')
    headers = [(b"www-authenticate", ", ".join(challenge_parts).encode("latin-1"))]
    headers.extend(_decision_headers(decision.get("headers")))
    return status, headers, _body_bytes(decision.get("body", "authentication required"))


def _redirect_response(decision: Mapping[str, Any]) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    location = decision.get("location")
    if not isinstance(location, str) or not location:
        raise LuaDecisionError("Lua redirect action requires non-empty field 'location'")
    status = int(decision.get("status", 307))
    if status not in {301, 302, 303, 307, 308}:
        raise LuaDecisionError("Lua redirect field 'status' must be one of 301, 302, 303, 307, 308")
    headers = [(b"location", location.encode("latin-1"))]
    headers.extend(_decision_headers(decision.get("headers")))
    return status, headers, _body_bytes(decision.get("body", ""))


def _rate_limit_headers(rate_limit: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
    return [
        (b"retry-after", str(rate_limit["retry_after"]).encode("ascii")),
        (b"x-ratelimit-limit", str(rate_limit["limit"]).encode("ascii")),
        (b"x-ratelimit-remaining", str(rate_limit["remaining"]).encode("ascii")),
        (b"x-ratelimit-reset", str(rate_limit["reset_at"]).encode("ascii")),
    ]


def _header_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _merge_headers(
    existing: list[tuple[bytes, bytes]], updates: list[tuple[bytes, bytes]]
) -> list[tuple[bytes, bytes]]:
    update_names = {name.lower() for name, _ in updates}
    return [(name, value) for name, value in existing if name.lower() not in update_names] + updates


def _body_bytes(body: Any) -> bytes:
    if isinstance(body, bytes):
        return body
    if body is None:
        return b""
    return str(body).encode("utf-8")


def _decode_bytes(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _sequence_or_none(value: Any) -> list[Any] | None:
    if value is None:
        return None
    return list(value)


async def _send_response(send: Send, *, status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        }
    )


def _rewrite_body_bytes(decision: Mapping[str, Any], *, body_was_read: bool) -> bytes | None:
    has_body = "body" in decision
    has_body_base64 = "body_base64" in decision
    if not has_body and not has_body_base64:
        return None
    if has_body and has_body_base64:
        raise LuaDecisionError("Lua rewrite may set either 'body' or 'body_base64', not both")
    if not body_was_read:
        raise LuaDecisionError("Lua rewrite body replacement requires LuaConfig(read_body=True)")
    if has_body_base64:
        try:
            return base64.b64decode(str(decision["body_base64"]), validate=True)
        except Exception as exc:
            raise LuaDecisionError("Lua rewrite field 'body_base64' must be valid base64") from exc
    return _body_bytes(decision.get("body"))


def _single_body_receive(body: bytes) -> Receive:
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive

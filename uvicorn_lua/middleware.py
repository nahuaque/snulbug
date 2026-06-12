from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode

from .promotion import compare_decisions
from .runtime import CompiledLuaScript, LuaDecisionError, LuaDecisionTrace, LuaRuntimeError, compile_lua_file, compile_lua_script
from .state import BoundedPolicyState, DryRunStateStore, PolicyStateStore, StateLimits

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
ScriptLoader = Callable[[Scope], CompiledLuaScript]

DecisionAction = Literal["continue", "set_context", "rewrite", "respond", "reject"]


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
    ) -> None:
        self.app = app
        self.config = config or LuaConfig()
        self._script = self._coerce_script(script)
        self._shadow_script = self._coerce_script(shadow_script) if shadow_script is not None else None
        self.state_store = state_store
        self.state_limits = state_limits or StateLimits()
        self.state_key_prefix = state_key_prefix

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
        script = self._script(child_scope)
        context = child_scope.get(self.config.context_scope_key, {})
        policy_state = self._state_for_request()
        execution = script.decide_with_trace(request, context, policy_state)
        decision = execution.decision
        action = _validate_action(decision)
        if self.config.trace:
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

        if action in {"respond", "reject"}:
            status = int(decision.get("status", 403 if action == "reject" else 200))
            body_bytes = _body_bytes(decision.get("body", ""))
            headers = _decision_headers(decision.get("headers"))
            await _send_response(send, status=status, headers=headers, body=body_bytes)
            return

        raise LuaDecisionError(f"Unsupported Lua action: {action!r}")

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
    if action not in {"continue", "set_context", "rewrite", "respond", "reject"}:
        raise LuaDecisionError(f"Lua action must be one of continue, set_context, rewrite, respond, reject; got {action!r}")
    return action  # type: ignore[return-value]


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


def _merge_headers(existing: list[tuple[bytes, bytes]], updates: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
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

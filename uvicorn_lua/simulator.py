from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .runtime import LuaDecisionError, compile_lua_file
from .state import BoundedPolicyState, SnapshotStateStore

_ACTIONS = {"continue", "set_context", "rewrite", "respond", "reject", "challenge", "redirect", "rate_limit"}


def simulate_policy(
    script_path: str | Path,
    request: Mapping[str, Any],
    *,
    context: Mapping[str, Any] | None = None,
    state_snapshot: Mapping[str, Any] | None = None,
    instruction_limit: int = 100_000,
    memory_limit_bytes: int | None = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Replay one JSON request against one Lua policy and return a trace."""

    normalized_request, body_read = normalize_request(request)
    script = compile_lua_file(
        script_path,
        instruction_limit=instruction_limit,
        memory_limit_bytes=memory_limit_bytes,
    )
    snapshot_store = SnapshotStateStore.from_snapshot(state_snapshot) if state_snapshot is not None else None
    state = BoundedPolicyState(snapshot_store) if snapshot_store is not None else None
    trace = script.decide_with_trace(normalized_request, context or {}, state)
    action = trace.decision["action"]
    if action not in _ACTIONS:
        raise LuaDecisionError(
            "Lua action must be one of continue, set_context, rewrite, respond, reject, "
            f"challenge, redirect, rate_limit; got {action!r}"
        )
    result = {
        "action": action,
        "decision": trace.decision,
        "trace": trace.to_dict(),
        "body_read": body_read,
    }
    if snapshot_store is not None:
        result["state_snapshot"] = snapshot_store.snapshot()
    return result


def normalize_request(request: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    if not isinstance(request, Mapping):
        raise TypeError("request JSON must be an object")

    normalized: dict[str, Any] = {
        "method": str(request.get("method", "GET")).upper(),
        "path": str(request.get("path", "/")),
        "raw_path": str(request.get("raw_path", request.get("path", "/"))),
        "query_string": str(request.get("query_string", "")),
        "headers": _normalize_headers(request.get("headers", {})),
        "client": request.get("client"),
        "scheme": str(request.get("scheme", "http")),
    }

    body_read = False
    if "body_base64" in request:
        raw_body = base64.b64decode(str(request["body_base64"]))
        normalized["body"] = raw_body.decode("utf-8", errors="replace")
        normalized["body_bytes_latin1"] = raw_body.decode("latin-1")
        body_read = True
    elif "body" in request:
        body = str(request["body"])
        normalized["body"] = body
        normalized["body_bytes_latin1"] = body.encode("utf-8").decode("latin-1")
        body_read = True

    return normalized, body_read


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="uvicorn-lua")
    subparsers = parser.add_subparsers(dest="command", required=True)

    simulate = subparsers.add_parser("simulate", help="replay a JSON request against a Lua policy")
    simulate.add_argument("script", type=Path, help="path to a Lua policy file")
    simulate.add_argument("request", type=Path, help="path to a JSON request fixture")
    simulate.add_argument("--context", type=Path, help="optional JSON context fixture")
    simulate.add_argument("--state", type=Path, help="optional JSON state snapshot")
    simulate.add_argument("--instruction-limit", type=int, default=100_000)
    simulate.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    simulate.add_argument("--compact", action="store_true", help="emit compact JSON")

    diff = subparsers.add_parser("diff", help="compare two policies against JSON request fixtures")
    diff.add_argument("old_script", type=Path, help="path to the active Lua policy")
    diff.add_argument("new_script", type=Path, help="path to the candidate Lua policy")
    diff.add_argument("fixtures", type=Path, help="JSON fixture file or directory")
    diff.add_argument("--context", type=Path, help="optional JSON context fixture")
    diff.add_argument("--state-snapshots", type=Path, help="optional state snapshot file or directory")
    diff.add_argument("--instruction-limit", type=int, default=100_000)
    diff.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    diff.add_argument("--compact", action="store_true", help="emit compact JSON")
    diff.add_argument("--no-fail", action="store_true", help="return exit code 0 even when regressions are found")

    args = parser.parse_args(argv)
    if args.command == "simulate":
        request = _read_json(args.request)
        context = _read_json(args.context) if args.context else None
        state_snapshot = _read_json(args.state) if args.state else None
        memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
        result = simulate_policy(
            args.script,
            request,
            context=context,
            state_snapshot=state_snapshot,
            instruction_limit=args.instruction_limit,
            memory_limit_bytes=memory_limit,
        )
        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return 0

    if args.command == "diff":
        from .promotion import diff_policies

        context = _read_json(args.context) if args.context else None
        memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
        result = diff_policies(
            args.old_script,
            args.new_script,
            args.fixtures,
            context=context,
            state_snapshots_path=args.state_snapshots,
            instruction_limit=args.instruction_limit,
            memory_limit_bytes=memory_limit,
        )
        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return 0 if args.no_fail or result["safe_to_promote"] else 1

    parser.error(f"unknown command: {args.command}")
    return 2


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _normalize_headers(headers: Any) -> dict[str, str | list[str]]:
    if isinstance(headers, Mapping):
        return {str(name).lower(): _normalize_header_value(value) for name, value in headers.items()}
    if isinstance(headers, Sequence) and not isinstance(headers, str | bytes | bytearray):
        result: dict[str, str | list[str]] = {}
        for pair in headers:
            if not isinstance(pair, Sequence) or isinstance(pair, str | bytes | bytearray) or len(pair) != 2:
                raise TypeError("headers list entries must be [name, value] pairs")
            name = str(pair[0]).lower()
            value = str(pair[1])
            existing = result.get(name)
            if existing is None:
                result[name] = value
            elif isinstance(existing, list):
                existing.append(value)
            else:
                result[name] = [existing, value]
        return result
    raise TypeError("headers must be an object or list of [name, value] pairs")


def _normalize_header_value(value: Any) -> str | list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return str(value)

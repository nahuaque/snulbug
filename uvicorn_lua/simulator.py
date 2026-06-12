from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .runtime import LuaDecisionError, compile_lua_file

_ACTIONS = {"continue", "set_context", "rewrite", "respond", "reject"}


def simulate_policy(
    script_path: str | Path,
    request: Mapping[str, Any],
    *,
    context: Mapping[str, Any] | None = None,
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
    trace = script.decide_with_trace(normalized_request, context or {})
    action = trace.decision["action"]
    if action not in _ACTIONS:
        raise LuaDecisionError(
            f"Lua action must be one of continue, set_context, rewrite, respond, reject; got {action!r}"
        )
    return {
        "action": action,
        "decision": trace.decision,
        "trace": trace.to_dict(),
        "body_read": body_read,
    }


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
    simulate.add_argument("--instruction-limit", type=int, default=100_000)
    simulate.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    simulate.add_argument("--compact", action="store_true", help="emit compact JSON")

    args = parser.parse_args(argv)
    if args.command == "simulate":
        request = _read_json(args.request)
        context = _read_json(args.context) if args.context else None
        memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
        result = simulate_policy(
            args.script,
            request,
            context=context,
            instruction_limit=args.instruction_limit,
            memory_limit_bytes=memory_limit,
        )
        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return 0

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

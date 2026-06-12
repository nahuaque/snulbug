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
    parser = argparse.ArgumentParser(prog="asgi-lua")
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

    bundle = subparsers.add_parser("bundle", help="validate, test, and pack policy bundles")
    bundle_subparsers = bundle.add_subparsers(dest="bundle_command", required=True)

    bundle_validate = bundle_subparsers.add_parser("validate", help="validate a policy bundle manifest")
    bundle_validate.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_validate.add_argument("--compact", action="store_true", help="emit compact JSON")

    bundle_test = bundle_subparsers.add_parser("test", help="run bundle fixtures against the bundle policy")
    bundle_test.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_test.add_argument("--instruction-limit", type=int, default=100_000)
    bundle_test.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    bundle_test.add_argument("--compact", action="store_true", help="emit compact JSON")

    bundle_pack = bundle_subparsers.add_parser("pack", help="pack a policy bundle as a tar.gz archive")
    bundle_pack.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_pack.add_argument("output", type=Path, help="output tar.gz path")
    bundle_pack.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp = subparsers.add_parser("mcp", help="work with local-dev MCP policy helpers and presets")
    mcp_subparsers = mcp.add_subparsers(dest="mcp_command", required=True)

    mcp_presets = mcp_subparsers.add_parser("presets", help="list bundled MCP policy presets")
    mcp_presets.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_init = mcp_subparsers.add_parser("init", help="copy a bundled MCP policy preset")
    mcp_init.add_argument("preset", nargs="?", default="local-dev-safe", help="preset name to copy")
    mcp_init.add_argument("--output", type=Path, help="output bundle directory")
    mcp_init.add_argument("--force", action="store_true", help="overwrite the output directory when it exists")
    mcp_init.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_record = mcp_subparsers.add_parser("record", help="record one replayable MCP request decision")
    mcp_record.add_argument("script", type=Path, help="path to a Lua policy file")
    mcp_record.add_argument("request", type=Path, help="path to a JSON request fixture")
    mcp_record.add_argument("--out", type=Path, required=True, help="JSONL log path to append to")
    mcp_record.add_argument("--context", type=Path, help="optional JSON context fixture")
    mcp_record.add_argument("--state", type=Path, help="optional JSON state snapshot")
    mcp_record.add_argument("--response", type=Path, help="optional JSON response metadata to store with the record")
    mcp_record.add_argument("--metadata", type=Path, help="optional JSON metadata to store with the record")
    mcp_record.add_argument("--audit-out", type=Path, help="optional redacted audit JSONL path to append to")
    mcp_record.add_argument("--redact", action="store_true", help="redact secrets in the replay record itself")
    mcp_record.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_record.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_record.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_replay = mcp_subparsers.add_parser("replay", help="replay an MCP request JSONL log")
    mcp_replay.add_argument("log", type=Path, help="JSONL request log")
    mcp_replay.add_argument("--script", type=Path, help="override policy script for all records")
    mcp_replay.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_replay.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_replay.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_proxy = mcp_subparsers.add_parser("proxy", help="run a local-dev MCP reverse proxy")
    mcp_proxy.add_argument("--upstream", required=True, help="upstream MCP HTTP server URL")
    mcp_proxy.add_argument("--policy", type=Path, required=True, help="path to a Lua policy file")
    mcp_proxy.add_argument("--host", default="127.0.0.1", help="bind host")
    mcp_proxy.add_argument("--port", type=int, default=8080, help="bind port")
    mcp_proxy.add_argument("--state", default="memory", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")
    mcp_proxy.add_argument("--no-trace", action="store_true", help="disable Lua trace scope data")
    mcp_proxy.add_argument("--max-body-bytes", type=int, default=64 * 1024)
    mcp_proxy.add_argument("--timeout", type=float, default=30.0, help="upstream timeout in seconds")

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

    if args.command == "bundle":
        from .bundle import pack_bundle, test_bundle, validate_bundle

        if args.bundle_command == "validate":
            result = validate_bundle(args.bundle)
            status = 0 if result["ok"] else 1
        elif args.bundle_command == "test":
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = test_bundle(
                args.bundle,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            status = 0 if result["ok"] else 1
        elif args.bundle_command == "pack":
            result = pack_bundle(args.bundle, args.output)
            status = 0 if result["ok"] else 1
        else:
            parser.error(f"unknown bundle command: {args.bundle_command}")
            return 2

        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return status

    if args.command == "mcp":
        from .presets import copy_builtin_preset, list_builtin_presets
        from .recorder import append_record, record_audit_event, record_policy_request, replay_record_log
        from .redaction import append_audit_event

        if args.mcp_command == "presets":
            result = {"presets": list_builtin_presets()}
            status = 0
        elif args.mcp_command == "init":
            output = args.output or Path(f"{args.preset}.asgi-lua")
            try:
                result = copy_builtin_preset(args.preset, output, force=args.force)
                result["next_steps"] = [
                    f"uv run asgi-lua bundle validate {output}",
                    f"uv run asgi-lua bundle test {output}",
                ]
                status = 0
            except Exception as exc:
                result = {"ok": False, "preset": args.preset, "output": str(output), "error": str(exc)}
                status = 1
        elif args.mcp_command == "record":
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            request = _read_json(args.request)
            result = record_policy_request(
                args.script,
                request,
                context=_read_json(args.context) if args.context else None,
                state_snapshot=_read_json(args.state) if args.state else None,
                response=_read_json(args.response) if args.response else None,
                metadata=_read_json(args.metadata) if args.metadata else None,
                redact=args.redact,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            append_record(args.out, result)
            audit_event = None
            if args.audit_out is not None:
                audit_event = record_audit_event(result)
                append_audit_event(args.audit_out, audit_event)
            result = {
                "ok": True,
                "out": str(args.out),
                "audit_out": str(args.audit_out) if args.audit_out is not None else None,
                "redacted": bool(args.redact),
                "action": result["action"] if "action" in result else result["result"]["action"],
                "audit": audit_event,
                "record": result,
            }
            status = 0
        elif args.mcp_command == "replay":
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = replay_record_log(
                args.log,
                script_path=args.script,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            status = 0 if result["ok"] else 1
        elif args.mcp_command == "proxy":
            from .proxy import run_proxy

            try:
                run_proxy(
                    upstream=args.upstream,
                    policy=args.policy,
                    host=args.host,
                    port=args.port,
                    state=args.state,
                    trace=not args.no_trace,
                    max_body_bytes=args.max_body_bytes,
                    timeout=args.timeout,
                )
            except Exception as exc:
                sys.stderr.write(f"asgi-lua proxy failed: {exc}\n")
                return 1
            return 0
        else:
            parser.error(f"unknown mcp command: {args.mcp_command}")
            return 2

        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return status

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

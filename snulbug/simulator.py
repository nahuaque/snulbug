from __future__ import annotations

import argparse
import base64
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .cli.common import read_json
from .cli.evidence import add_mcp_evidence_command, handle_mcp_evidence_command
from .cli.fabric import add_mcp_fabric_command, handle_mcp_fabric_command
from .cli.policy import add_mcp_policy_command, handle_mcp_policy_command
from .cli.share import add_mcp_share_command, handle_mcp_share_command
from .cli_helpers import (
    add_compact_arg,
    write_generated_session_output,
    write_json_output,
    write_result_output,
)
from .runtime import LuaDecisionError, compile_lua_file
from .state import BoundedPolicyState, SnapshotStateStore

_ACTIONS = {
    "continue",
    "set_context",
    "rewrite",
    "respond",
    "reject",
    "challenge",
    "redirect",
    "rate_limit",
    "confirm",
}


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
            f"challenge, redirect, rate_limit, confirm; got {action!r}"
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
    parser = argparse.ArgumentParser(prog="snulbug")
    subparsers = parser.add_subparsers(dest="command", required=True)

    simulate = subparsers.add_parser("simulate", help="replay a JSON request against a Lua policy")
    simulate.add_argument("script", type=Path, help="path to a Lua policy file")
    simulate.add_argument("request", type=Path, help="path to a JSON request fixture")
    simulate.add_argument("--context", type=Path, help="optional JSON context fixture")
    simulate.add_argument("--state", type=Path, help="optional JSON state snapshot")
    simulate.add_argument("--instruction-limit", type=int, default=100_000)
    simulate.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(simulate)

    bundle = subparsers.add_parser("bundle", help="validate, test, and pack policy bundles")
    bundle_subparsers = bundle.add_subparsers(dest="bundle_command", required=True)

    bundle_validate = bundle_subparsers.add_parser("validate", help="validate a policy bundle manifest")
    bundle_validate.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    add_compact_arg(bundle_validate)

    bundle_test = bundle_subparsers.add_parser("test", help="run bundle fixtures against the bundle policy")
    bundle_test.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_test.add_argument("--instruction-limit", type=int, default=100_000)
    bundle_test.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(bundle_test)

    bundle_pack = bundle_subparsers.add_parser("pack", help="pack a policy bundle as a tar.gz archive")
    bundle_pack.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_pack.add_argument("output", type=Path, help="output tar.gz path")
    add_compact_arg(bundle_pack)

    release_qa = subparsers.add_parser("release-qa", help="run the local pre-release QA suite")
    release_qa.add_argument("--skip-bandit", action="store_true", help="skip the Bandit high-severity security scan")
    release_qa.add_argument("--skip-tests", action="store_true", help="skip the pytest suite")
    release_qa.add_argument("--skip-build", action="store_true", help="skip distribution build and inspection")
    release_qa.add_argument("--skip-smoke", action="store_true", help="skip source and built-wheel CLI smoke tests")
    release_qa.add_argument("--dry-run", action="store_true", help="print the release QA plan without running it")
    release_qa.add_argument("--keep-going", action="store_true", help="continue running gates after a failure")
    add_compact_arg(release_qa)

    bundle_states = ("observed", "proposed", "approved", "active")

    mcp = subparsers.add_parser("mcp", help="work with local-dev MCP policy helpers and presets")
    mcp_subparsers = mcp.add_subparsers(
        dest="mcp_command",
        required=True,
        metavar=("{guide,policy,share,fabric,evidence}"),
    )

    mcp_guide = mcp_subparsers.add_parser("guide", help="print agent-oriented MCP workflow guidance")
    mcp_guide.add_argument(
        "--workflow",
        choices=("all", "share", "learn-amend-impact", "leases", "facade"),
        default="all",
        help="workflow to print",
    )
    add_compact_arg(mcp_guide)

    add_mcp_policy_command(mcp_subparsers, bundle_states=bundle_states)

    add_mcp_share_command(mcp_subparsers)

    add_mcp_fabric_command(mcp_subparsers)

    add_mcp_evidence_command(mcp_subparsers)

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
        write_json_output(result, compact=args.compact)
        return 0

    if args.command == "bundle":
        from .bundle import (
            pack_bundle,
            test_bundle,
            validate_bundle,
        )

        try:
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
        except Exception as exc:
            result = {
                "ok": False,
                "bundle": str(getattr(args, "bundle", "")),
                "error": str(exc),
            }
            status = 1

        write_json_output(result, compact=args.compact)
        return status

    if args.command == "release-qa":
        from .release_qa import run_release_qa

        result, status = run_release_qa(
            include_bandit=not args.skip_bandit,
            include_tests=not args.skip_tests,
            include_build=not args.skip_build,
            include_smoke=not args.skip_smoke,
            dry_run=args.dry_run,
            keep_going=args.keep_going,
        )
        write_result_output(result, compact=args.compact)
        return status

    if args.command == "mcp":
        if args.mcp_command == "guide":
            from .guide import build_mcp_guide, format_mcp_guide

            try:
                result = build_mcp_guide(workflow=args.workflow)
            except Exception as exc:
                result = {"ok": False, "workflow": args.workflow, "error": str(exc)}
                status = 1
            else:
                status = 0
            formatter = format_mcp_guide if status == 0 else None
            write_result_output(result, compact=args.compact, formatter=formatter)
            return status
        elif args.mcp_command == "policy":
            result, status, formatter = handle_mcp_policy_command(args, parser)
        elif args.mcp_command == "share":
            return handle_mcp_share_command(args, parser)
        elif args.mcp_command == "fabric":
            return handle_mcp_fabric_command(args, parser)
        elif args.mcp_command == "evidence":
            return handle_mcp_evidence_command(args, parser)
        else:
            parser.error(f"unknown mcp command: {args.mcp_command}")
            return 2

        write_generated_session_output(result, compact=args.compact, formatter=formatter)
        return status

    parser.error(f"unknown command: {args.command}")
    return 2


def _read_json(path: Path) -> Any:
    return read_json(path)


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

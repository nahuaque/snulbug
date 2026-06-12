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

    mcp_quickstart = mcp_subparsers.add_parser("quickstart", help="create a local MCP policy proxy starter")
    mcp_quickstart.add_argument("--directory", "--dir", type=Path, default=Path("."), help="starter output directory")
    mcp_quickstart.add_argument("--preset", default="local-dev-safe", help="MCP preset to generate")
    mcp_quickstart.add_argument(
        "--policy-output", type=Path, default=Path("policy.asgi-lua"), help="policy bundle path"
    )
    mcp_quickstart.add_argument("--config-output", type=Path, default=Path("asgi-lua.toml"), help="config file path")
    mcp_quickstart.add_argument("--traces-dir", type=Path, default=Path("traces"), help="trace directory path")
    mcp_quickstart.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server URL")
    mcp_quickstart.add_argument("--token", help="bearer token to render into generated policy")
    mcp_quickstart.add_argument("--token-env", help="context key used by generated policy for env-derived token lookup")
    mcp_quickstart.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    mcp_quickstart.add_argument("--allow-path", action="append", default=[], help="allowed project path or prefix")
    mcp_quickstart.add_argument("--rate-limit", type=int, help="fixed-window request limit")
    mcp_quickstart.add_argument("--rate-window", type=int, help="fixed-window duration in seconds")
    mcp_quickstart.add_argument("--host", default="127.0.0.1", help="proxy bind host")
    mcp_quickstart.add_argument("--port", type=int, default=8080, help="proxy bind port")
    mcp_quickstart.add_argument(
        "--state", default="memory", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'"
    )
    mcp_quickstart.add_argument("--record-out", type=Path, default=Path("traces/session.jsonl"))
    mcp_quickstart.add_argument("--audit-out", type=Path, default=Path("traces/audit.jsonl"))
    mcp_quickstart.add_argument(
        "--redact-records",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact secrets in live replay records",
    )
    mcp_quickstart.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="print live redacted policy decisions while proxying",
    )
    mcp_quickstart.add_argument(
        "--decision-console-format",
        choices=("text", "json"),
        default="text",
        help="live decision console output format",
    )
    mcp_quickstart.add_argument("--max-body-bytes", type=int, default=65536)
    mcp_quickstart.add_argument("--timeout", type=float, default=30.0, help="upstream timeout in seconds")
    mcp_quickstart.add_argument("--force", action="store_true", help="overwrite generated policy and config")
    mcp_quickstart.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate and test the generated policy bundle",
    )
    mcp_quickstart.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_init = mcp_subparsers.add_parser("init", help="copy a bundled MCP policy preset")
    mcp_init.add_argument("preset", nargs="?", default="local-dev-safe", help="preset name to copy")
    mcp_init.add_argument("--output", type=Path, help="output bundle directory")
    mcp_init.add_argument("--force", action="store_true", help="overwrite the output directory when it exists")
    mcp_init.add_argument("--token", help="bearer token to render into generated policy")
    mcp_init.add_argument("--token-env", help="context key used by generated policy for env-derived token lookup")
    mcp_init.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    mcp_init.add_argument("--allow-path", action="append", default=[], help="allowed project path or prefix")
    mcp_init.add_argument("--rate-limit", type=int, help="fixed-window request limit")
    mcp_init.add_argument("--rate-window", type=int, help="fixed-window duration in seconds")
    mcp_init.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_config = mcp_subparsers.add_parser("config", help="work with MCP TOML config files")
    mcp_config_subparsers = mcp_config.add_subparsers(dest="config_command", required=True)
    mcp_config_init = mcp_config_subparsers.add_parser("init", help="write a starter asgi-lua.toml config")
    mcp_config_init.add_argument("--output", type=Path, default=Path("asgi-lua.toml"), help="config file path")
    mcp_config_init.add_argument("--force", action="store_true", help="overwrite the config file when it exists")
    mcp_config_init.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_record = mcp_subparsers.add_parser("record", help="record one replayable MCP request decision")
    mcp_record.add_argument("script", type=Path, help="path to a Lua policy file")
    mcp_record.add_argument("request", type=Path, help="path to a JSON request fixture")
    mcp_record.add_argument("--out", type=Path, required=True, help="JSONL log path to append to")
    mcp_record.add_argument("--context", type=Path, help="optional JSON context fixture")
    mcp_record.add_argument("--state", type=Path, help="optional JSON state snapshot")
    mcp_record.add_argument("--response", type=Path, help="optional JSON response metadata to store with the record")
    mcp_record.add_argument("--metadata", type=Path, help="optional JSON metadata to store with the record")
    mcp_record.add_argument("--audit-out", type=Path, help="optional redacted audit JSONL path to append to")
    mcp_record.add_argument(
        "--redact",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact secrets in the replay record itself; use --no-redact for exact replay artifacts",
    )
    mcp_record.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_record.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_record.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_replay = mcp_subparsers.add_parser("replay", help="replay an MCP request JSONL log")
    mcp_replay.add_argument("log", type=Path, help="JSONL request log")
    mcp_replay.add_argument("--script", type=Path, help="override policy script for all records")
    mcp_replay.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_replay.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_replay.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_inspect = mcp_subparsers.add_parser("inspect", help="summarize MCP replay or audit JSONL logs offline")
    mcp_inspect.add_argument("log", type=Path, help="JSONL replay or audit log")
    mcp_inspect.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    mcp_inspect.add_argument("--top", type=int, default=10, help="number of top values to include per category")
    mcp_inspect.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_proxy = mcp_subparsers.add_parser("proxy", help="run a local-dev MCP reverse proxy")
    mcp_proxy.add_argument("--config", type=Path, help="TOML config file")
    mcp_proxy.add_argument("--upstream", help="upstream MCP HTTP server URL")
    mcp_proxy.add_argument("--policy", type=Path, help="path to a Lua policy file")
    mcp_proxy.add_argument("--host", help="bind host")
    mcp_proxy.add_argument("--port", type=int, help="bind port")
    mcp_proxy.add_argument("--state", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")
    mcp_proxy.add_argument(
        "--no-trace", action="store_false", dest="trace", default=None, help="disable Lua trace scope data"
    )
    mcp_proxy.add_argument("--record-out", type=Path, help="optional live replay JSONL path to append to")
    mcp_proxy.add_argument("--audit-out", type=Path, help="optional redacted live audit JSONL path to append to")
    mcp_proxy.add_argument(
        "--redact-records",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="redact secrets in live replay records; use --no-redact-records for exact replay artifacts",
    )
    mcp_proxy.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="print live redacted policy decisions while proxying",
    )
    mcp_proxy.add_argument(
        "--decision-console-format",
        choices=("text", "json"),
        help="live decision console output format",
    )
    mcp_proxy.add_argument("--max-body-bytes", type=int)
    mcp_proxy.add_argument("--timeout", type=float, help="upstream timeout in seconds")

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
        from .config import (
            load_mcp_proxy_config,
            merge_mcp_proxy_config,
            normalize_mcp_proxy_config,
            write_sample_config,
        )
        from .inspection import inspect_mcp_log
        from .presets import McpPolicyOptions, generate_mcp_preset, list_builtin_presets
        from .recorder import append_record, record_audit_event, record_policy_request, replay_record_log
        from .redaction import append_audit_event

        if args.mcp_command == "presets":
            result = {"presets": list_builtin_presets()}
            status = 0
        elif args.mcp_command == "quickstart":
            from .quickstart import create_mcp_quickstart

            try:
                result = create_mcp_quickstart(
                    args.directory,
                    preset=args.preset,
                    policy_output=args.policy_output,
                    config_output=args.config_output,
                    traces_dir=args.traces_dir,
                    upstream=args.upstream,
                    token=args.token,
                    token_env=args.token_env,
                    allowed_tools=args.allow_tool or None,
                    allowed_paths=args.allow_path or None,
                    rate_limit=args.rate_limit,
                    rate_window=args.rate_window,
                    host=args.host,
                    port=args.port,
                    state=args.state,
                    record_out=args.record_out,
                    audit_out=args.audit_out,
                    redact_records=args.redact_records,
                    decision_console=args.decision_console,
                    decision_console_format=args.decision_console_format,
                    max_body_bytes=args.max_body_bytes,
                    timeout=args.timeout,
                    force=args.force,
                    validate=args.validate,
                )
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "directory": str(args.directory), "error": str(exc)}
                status = 1
        elif args.mcp_command == "init":
            output = args.output or Path(f"{args.preset}.asgi-lua")
            try:
                result = generate_mcp_preset(
                    args.preset,
                    output,
                    options=McpPolicyOptions(
                        token=args.token,
                        token_env=args.token_env,
                        allowed_tools=args.allow_tool or None,
                        allowed_paths=args.allow_path or None,
                        rate_limit=args.rate_limit,
                        rate_window=args.rate_window,
                    ),
                    force=args.force,
                )
                result["next_steps"] = [
                    f"uv run asgi-lua bundle validate {output}",
                    f"uv run asgi-lua bundle test {output}",
                ]
                status = 0
            except Exception as exc:
                result = {"ok": False, "preset": args.preset, "output": str(output), "error": str(exc)}
                status = 1
        elif args.mcp_command == "config":
            if args.config_command == "init":
                try:
                    result = write_sample_config(args.output, force=args.force)
                    result["next_steps"] = [
                        "uv run asgi-lua mcp init local-dev-safe --output policy.asgi-lua",
                        f"uv run asgi-lua mcp proxy --config {args.output}",
                    ]
                    status = 0
                except Exception as exc:
                    result = {"ok": False, "config": str(args.output), "error": str(exc)}
                    status = 1
            else:
                parser.error(f"unknown mcp config command: {args.config_command}")
                return 2
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
        elif args.mcp_command == "inspect":
            try:
                result = inspect_mcp_log(args.log, kind=args.kind, top=args.top)
                status = 0
            except Exception as exc:
                result = {"ok": False, "log": str(args.log), "error": str(exc)}
                status = 1
        elif args.mcp_command == "proxy":
            from .proxy import run_proxy

            try:
                overrides = {
                    "upstream": args.upstream,
                    "policy": args.policy,
                    "host": args.host,
                    "port": args.port,
                    "state": args.state,
                    "trace": args.trace,
                    "record_out": args.record_out,
                    "audit_out": args.audit_out,
                    "redact_records": args.redact_records,
                    "decision_console": args.decision_console,
                    "decision_console_format": args.decision_console_format,
                    "max_body_bytes": args.max_body_bytes,
                    "timeout": args.timeout,
                }
                if args.config is not None:
                    proxy_config = merge_mcp_proxy_config(load_mcp_proxy_config(args.config), overrides)
                else:
                    if args.upstream is None or args.policy is None:
                        sys.stderr.write(
                            "asgi-lua proxy failed: --upstream and --policy are required without --config\n"
                        )
                        return 1
                    proxy_config = normalize_mcp_proxy_config(overrides)
                run_proxy(
                    upstream=proxy_config["upstream"],
                    policy=proxy_config["policy"],
                    host=proxy_config["host"],
                    port=proxy_config["port"],
                    state=proxy_config["state"],
                    trace=proxy_config["trace"],
                    max_body_bytes=proxy_config["max_body_bytes"],
                    timeout=proxy_config["timeout"],
                    record_out=proxy_config["record_out"],
                    audit_out=proxy_config["audit_out"],
                    redact_records=proxy_config["redact_records"],
                    decision_console=proxy_config["decision_console"],
                    decision_console_format=proxy_config["decision_console_format"],
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

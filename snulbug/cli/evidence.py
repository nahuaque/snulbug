from __future__ import annotations

import argparse
from pathlib import Path

from ..cli_helpers import add_compact_arg, add_report_out_arg, write_json_output, write_report_output
from .common import read_json


def add_mcp_evidence_command(mcp_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_evidence = mcp_subparsers.add_parser(
        "evidence",
        help="record, replay, inspect, impact-check, and diff MCP evidence",
    )
    mcp_evidence_subparsers = mcp_evidence.add_subparsers(dest="evidence_command", required=True)
    mcp_evidence_record = mcp_evidence_subparsers.add_parser(
        "record",
        help="record one replayable MCP request decision",
    )
    mcp_evidence_record.add_argument("script", type=Path, help="path to a Lua policy file")
    mcp_evidence_record.add_argument("request", type=Path, help="path to a JSON request fixture")
    mcp_evidence_record.add_argument("--out", type=Path, required=True, help="JSONL log path to append to")
    mcp_evidence_record.add_argument("--context", type=Path, help="optional JSON context fixture")
    mcp_evidence_record.add_argument("--state", type=Path, help="optional JSON state snapshot")
    mcp_evidence_record.add_argument(
        "--response",
        type=Path,
        help="optional JSON response metadata to store with the record",
    )
    mcp_evidence_record.add_argument("--metadata", type=Path, help="optional JSON metadata to store with the record")
    mcp_evidence_record.add_argument("--audit-out", type=Path, help="optional redacted audit JSONL path to append to")
    mcp_evidence_record.add_argument(
        "--redact",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact secrets in the replay record itself; use --no-redact for exact replay artifacts",
    )
    mcp_evidence_record.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_evidence_record.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(mcp_evidence_record)

    mcp_evidence_replay = mcp_evidence_subparsers.add_parser("replay", help="replay an MCP request JSONL log")
    mcp_evidence_replay.add_argument("log", type=Path, help="JSONL request log")
    mcp_evidence_replay.add_argument("--script", type=Path, help="override policy script for all records")
    mcp_evidence_replay.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_evidence_replay.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(mcp_evidence_replay)

    mcp_evidence_inspect = mcp_evidence_subparsers.add_parser(
        "inspect",
        help="summarize MCP replay or audit JSONL logs offline",
    )
    mcp_evidence_inspect.add_argument("log", type=Path, help="JSONL replay or audit log")
    mcp_evidence_inspect.add_argument(
        "--kind",
        choices=("auto", "record", "audit"),
        default="auto",
        help="input log type",
    )
    mcp_evidence_inspect.add_argument(
        "--top",
        type=int,
        default=10,
        help="number of top values to include per category",
    )
    add_report_out_arg(mcp_evidence_inspect, help="optional Markdown session report path")
    mcp_evidence_inspect.add_argument(
        "--report-format",
        choices=("markdown",),
        default="markdown",
        help="session report output format",
    )
    add_compact_arg(mcp_evidence_inspect)

    mcp_evidence_impact = mcp_evidence_subparsers.add_parser(
        "impact",
        help="preview policy or lease impact against MCP replay logs",
    )
    mcp_evidence_impact.add_argument("log", type=Path, help="JSONL replay log")
    mcp_evidence_impact.add_argument("--policy", type=Path, help="candidate policy to replay against the log")
    mcp_evidence_impact.add_argument(
        "--lease",
        "--lease-file",
        dest="lease_file",
        type=Path,
        help="task lease JSON file",
    )
    mcp_evidence_impact.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_evidence_impact.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_report_out_arg(mcp_evidence_impact, help="optional Markdown impact report path")
    mcp_evidence_impact.add_argument(
        "--report-format",
        choices=("markdown",),
        default="markdown",
        help="impact report output format",
    )
    mcp_evidence_impact.add_argument(
        "--no-fail",
        action="store_true",
        help="return exit code 0 even when impact has errors",
    )
    add_compact_arg(mcp_evidence_impact)

    mcp_evidence_diff = mcp_evidence_subparsers.add_parser(
        "diff",
        help="compare two policies against JSON request fixtures",
    )
    mcp_evidence_diff.add_argument("old_script", type=Path, help="path to the active Lua policy")
    mcp_evidence_diff.add_argument("new_script", type=Path, help="path to the candidate Lua policy")
    mcp_evidence_diff.add_argument("fixtures", type=Path, help="JSON fixture file or directory")
    mcp_evidence_diff.add_argument("--context", type=Path, help="optional JSON context fixture")
    mcp_evidence_diff.add_argument("--state-snapshots", type=Path, help="optional state snapshot file or directory")
    mcp_evidence_diff.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_evidence_diff.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_evidence_diff.add_argument(
        "--no-fail",
        action="store_true",
        help="return exit code 0 even when regressions are found",
    )
    add_report_out_arg(mcp_evidence_diff, help="optional Markdown policy diff report path")
    mcp_evidence_diff.add_argument(
        "--report-format",
        choices=("markdown",),
        default="markdown",
        help="policy diff report output format",
    )
    add_compact_arg(mcp_evidence_diff)


def handle_mcp_evidence_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from ..inspection import format_mcp_inspection_report, inspect_mcp_log
    from ..recorder import append_record, record_audit_event, record_policy_request, replay_record_log
    from ..redaction import append_audit_event

    try:
        if args.evidence_command == "record":
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            request = read_json(args.request)
            recorded = record_policy_request(
                args.script,
                request,
                context=read_json(args.context) if args.context else None,
                state_snapshot=read_json(args.state) if args.state else None,
                response=read_json(args.response) if args.response else None,
                metadata=read_json(args.metadata) if args.metadata else None,
                redact=args.redact,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            append_record(args.out, recorded)
            audit_event = None
            if args.audit_out is not None:
                audit_event = record_audit_event(recorded)
                append_audit_event(args.audit_out, audit_event)
            result = {
                "ok": True,
                "out": str(args.out),
                "audit_out": str(args.audit_out) if args.audit_out is not None else None,
                "redacted": bool(args.redact),
                "action": recorded["action"] if "action" in recorded else recorded["result"]["action"],
                "audit": audit_event,
                "record": recorded,
            }
            status = 0
        elif args.evidence_command == "replay":
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = replay_record_log(
                args.log,
                script_path=args.script,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            status = 0 if result["ok"] else 1
        elif args.evidence_command == "inspect":
            result = inspect_mcp_log(args.log, kind=args.kind, top=args.top)
            if args.report_out is not None:
                report_text = format_mcp_inspection_report(result, output_format=args.report_format)
                write_report_output(
                    args.report_out,
                    report_text,
                    result,
                    report_format=args.report_format,
                )
            status = 0
        elif args.evidence_command == "impact":
            from ..impact import analyze_mcp_impact, format_mcp_impact_report

            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = analyze_mcp_impact(
                args.log,
                policy=args.policy,
                lease_file=args.lease_file,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            if args.report_out is not None:
                report_text = format_mcp_impact_report(result, output_format=args.report_format)
                write_report_output(
                    args.report_out,
                    report_text,
                    result,
                    report_format=args.report_format,
                )
            status = 0 if args.no_fail or result["ok"] else 1
        elif args.evidence_command == "diff":
            from ..promotion import diff_policies, format_policy_diff_report

            context = read_json(args.context) if args.context else None
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
            if args.report_out is not None:
                report_text = format_policy_diff_report(result)
                write_report_output(
                    args.report_out,
                    report_text,
                    result,
                    report_format=args.report_format,
                )
            status = 0 if args.no_fail or result["safe_to_promote"] else 1
        else:
            parser.error(f"unknown mcp evidence command: {args.evidence_command}")
            return 2
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        if hasattr(args, "log") and args.log is not None:
            result["log"] = str(args.log)
        if hasattr(args, "request") and args.request is not None:
            result["request"] = str(args.request)
        if hasattr(args, "fixtures") and args.fixtures is not None:
            result["fixtures"] = str(args.fixtures)
        status = 1

    write_json_output(result, compact=args.compact)
    return status

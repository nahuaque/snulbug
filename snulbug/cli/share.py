from __future__ import annotations

import argparse
from pathlib import Path

from ..cli_helpers import (
    add_allow_path_arg,
    add_compact_arg,
    add_force_arg,
    add_token_arg,
    add_validate_arg,
    write_json_output,
    write_result_output,
)

PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch")


def add_mcp_share_command(mcp_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_share = mcp_subparsers.add_parser(
        "share",
        help="create and manage bounded MCP share sessions",
    )
    _add_share_create_args(mcp_share)
    share_subparsers = mcp_share.add_subparsers(dest="share_command")

    share_create = share_subparsers.add_parser("create", help="create a bounded MCP share session")
    _add_share_create_args(share_create)

    share_run = share_subparsers.add_parser("run", help="run the proxy for a generated share session")
    share_run.add_argument("directory", type=Path, help="share session directory")
    share_run.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="override the generated share proxy decision console setting",
    )
    share_run.add_argument("--dry-run", action="store_true", help="print the run plan without starting the proxy")
    add_compact_arg(share_run)

    share_status = share_subparsers.add_parser("status", help="summarize a generated share session")
    share_status.add_argument("directory", type=Path, help="share session directory")
    add_compact_arg(share_status)

    share_doctor = share_subparsers.add_parser("doctor", help="verify a generated share session")
    share_doctor.add_argument("directory", type=Path, help="share session directory")
    share_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    add_compact_arg(share_doctor)

    share_client = share_subparsers.add_parser("client", help="print generated MCP client config")
    share_client.add_argument("directory", type=Path, help="share session directory")
    share_client.add_argument(
        "--format",
        choices=("json", "claude-desktop", "cursor", "path"),
        default="json",
        help="client output format",
    )
    add_compact_arg(share_client)

    share_close = share_subparsers.add_parser("close", help="close a share session and write closeout artifacts")
    share_close.add_argument("directory", type=Path, help="share session directory")
    share_close.add_argument("--revoke", action=argparse.BooleanOptionalAction, default=True, help="revoke the lease")
    share_close.add_argument(
        "--report",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="write a Markdown closeout report",
    )
    share_close.add_argument(
        "--learn",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="learn a policy bundle from the share replay log during closeout",
    )
    share_close.add_argument("--learn-out", type=Path, help="output path for --learn policy bundle")
    add_force_arg(share_close, help="overwrite generated closeout artifacts")
    add_compact_arg(share_close)


def handle_mcp_share_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from ..share import (
        close_mcp_share,
        create_mcp_share,
        doctor_mcp_share,
        run_mcp_share,
        share_client_config,
        share_status,
    )
    from ..tunnel import format_tunnel_doctor_report

    try:
        command = args.share_command or "create"
        if command == "create":
            result = create_mcp_share(
                args.directory,
                provider=args.provider,
                preset=args.preset,
                upstream=args.upstream,
                hostname=args.hostname,
                public_url=args.url,
                token=args.token,
                ttl=args.ttl,
                task=args.task,
                allowed_tools=args.allow_tool or None,
                allowed_paths=args.allow_path or None,
                allowed_hosts=args.allow_host or None,
                allowed_commands=args.allow_command or None,
                max_calls=args.max_calls,
                host=args.host,
                port=args.port,
                state=args.state,
                lease_required=args.lease_required,
                lease_header=args.lease_header,
                client_name=args.client_name,
                force=args.force,
                validate=args.validate,
            )
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "run":
            result = run_mcp_share(
                args.directory,
                dry_run=args.dry_run,
                decision_console=args.decision_console,
            )
            if result is not None:
                write_json_output(result, compact=args.compact)
            return 0

        if command == "status":
            result = share_status(args.directory)
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "doctor":
            result = doctor_mcp_share(args.directory, timeout=args.timeout)
            status = 0 if result["ok"] else 1
            write_result_output(result, compact=args.compact, formatter=format_tunnel_doctor_report)
            return status

        if command == "client":
            result = share_client_config(args.directory, output_format=args.format)
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "close":
            result = close_mcp_share(
                args.directory,
                revoke=args.revoke,
                report=args.report,
                learn=args.learn,
                learn_out=args.learn_out,
                force=args.force,
            )
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        parser.error(f"unknown mcp share command: {command}")
        return 2
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        if hasattr(args, "directory") and args.directory is not None:
            result["directory"] = str(args.directory)
        write_json_output(result, compact=getattr(args, "compact", False))
        return 1


def _add_share_create_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--directory", type=Path, help="share session directory")
    parser.add_argument(
        "--provider",
        choices=PROVIDERS,
        default="holepunch",
        help="tunnel or peer bridge provider",
    )
    parser.add_argument("--preset", default="tunnel-safe", help="MCP policy preset")
    parser.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server")
    parser.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    parser.add_argument("--url", "--public-url", dest="url", help="public tunnel or client bridge MCP URL")
    add_token_arg(parser, help="bearer token; defaults to a generated session token")
    parser.add_argument("--ttl", default="30m", help="share lease TTL, such as 30m, 2h, or 1d")
    parser.add_argument("--task", default="Ephemeral MCP share session", help="human-readable share task")
    parser.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    add_allow_path_arg(parser, help="allowed path or path prefix")
    parser.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    parser.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    parser.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    parser.add_argument("--host", default="127.0.0.1", help="proxy bind host")
    parser.add_argument("--port", type=int, default=8080, help="proxy bind port")
    parser.add_argument("--state", default="memory", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")
    parser.add_argument(
        "--lease-required",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require a valid task lease for MCP tools/call requests",
    )
    parser.add_argument(
        "--lease-header",
        default="x-snulbug-lease",
        help="HTTP header carrying the task lease token",
    )
    parser.add_argument("--client-name", default="snulbug-share", help="MCP client config server name")
    add_force_arg(parser, help="overwrite generated share files")
    add_validate_arg(parser, help="validate and test the generated policy bundle")
    add_compact_arg(parser)

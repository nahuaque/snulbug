from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..cli_helpers import (
    add_allow_path_arg,
    add_compact_arg,
    add_force_arg,
    add_token_arg,
    add_token_env_arg,
    add_validate_arg,
    write_generated_session_output,
    write_json_output,
    write_result_output,
)
from .common import read_required_env

PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch")
QUICKSTART_TUNNEL_PROVIDERS = ("auto", *PROVIDERS)
ATTACH_MEMBER_KINDS = ("codespaces", "devcontainer", "holepunch", "container", "generic")


def add_mcp_share_command(mcp_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_share = mcp_subparsers.add_parser(
        "share",
        help="create and manage bounded MCP share sessions",
    )
    share_subparsers = mcp_share.add_subparsers(dest="share_command", required=True)

    share_quickstart = share_subparsers.add_parser("quickstart", help="create a local MCP policy proxy starter")
    _add_quickstart_args(share_quickstart)

    share_create = share_subparsers.add_parser("create", help="create a bounded MCP share session")
    _add_share_create_args(share_create)

    share_run = share_subparsers.add_parser("run", help="run a generated share session or MCP proxy config")
    _add_share_run_args(share_run)

    share_config = share_subparsers.add_parser("config", help="work with MCP share TOML config files")
    share_config_subparsers = share_config.add_subparsers(dest="share_config_command", required=True)
    share_config_init = share_config_subparsers.add_parser("init", help="write a starter snulbug.toml config")
    share_config_init.add_argument("--output", type=Path, default=Path("snulbug.toml"), help="config file path")
    add_force_arg(share_config_init, help="overwrite the config file when it exists")
    add_compact_arg(share_config_init)

    share_lease = share_subparsers.add_parser("lease", help="create and manage task-scoped MCP capability leases")
    _add_share_lease_args(share_lease)

    share_attach = share_subparsers.add_parser("attach", help="attach a remote fabric member to a share session")
    _add_share_attach_args(share_attach)

    share_codespace = share_subparsers.add_parser("codespace", help="attach GitHub Codespace MCP upstreams")
    _add_share_codespace_args(share_codespace)

    share_lab = share_subparsers.add_parser("lab", help="run the one-command local MCP policy lab")
    share_lab.add_argument("--output-dir", type=Path, default=Path(".snulbug-lab"), help="lab artifact directory")
    share_lab.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite the lab artifact directory",
    )
    add_compact_arg(share_lab)

    share_status = share_subparsers.add_parser("status", help="summarize a generated share session")
    share_status.add_argument("directory", type=Path, help="share session directory")
    share_status.add_argument("--timeout", type=float, default=1.0, help="live check timeout in seconds")
    share_status.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="probe the local gateway and configured upstreams",
    )
    add_compact_arg(share_status)

    share_report = share_subparsers.add_parser("report", help="write or print a generated share session report")
    share_report.add_argument("directory", type=Path, help="share session directory")
    share_report.add_argument("--output", "--out", type=Path, help="write report to this Markdown path")
    share_report.add_argument("--timeout", type=float, default=1.0, help="live check timeout in seconds")
    share_report.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="probe the local gateway and configured upstreams",
    )
    add_force_arg(share_report, help="overwrite --output when it exists")
    add_compact_arg(share_report)

    share_promote = share_subparsers.add_parser("promote", help="promote the share policy bundle lifecycle")
    _add_share_lifecycle_args(share_promote, include_to=True)

    share_activate = share_subparsers.add_parser("activate", help="activate the share policy bundle")
    _add_share_lifecycle_args(share_activate, include_to=False)

    share_auth = share_subparsers.add_parser("auth", help="diagnose share authentication")
    share_auth_subparsers = share_auth.add_subparsers(dest="share_auth_command", required=True)
    share_auth_doctor = share_auth_subparsers.add_parser(
        "doctor",
        help="verify OAuth protected-resource readiness for a share or config",
    )
    share_auth_doctor.add_argument("directory", nargs="?", type=Path, help="share session directory")
    share_auth_doctor.add_argument("--config", type=Path, help="snulbug.toml config path")
    share_auth_doctor.add_argument(
        "--url",
        "--public-url",
        dest="url",
        help="public MCP URL clients connect to",
    )
    share_auth_doctor.add_argument("--header", action="append", default=[], help="HTTP header as 'Name: value'")
    add_token_arg(share_auth_doctor, help="bearer token for live tools/list scope-map validation")
    share_auth_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    share_auth_doctor.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="probe protected-resource metadata, issuer metadata, JWKS, and tools/list",
    )
    add_compact_arg(share_auth_doctor)

    share_doctor = share_subparsers.add_parser("doctor", help="verify a generated share session")
    share_doctor.add_argument("directory", type=Path, help="share session directory")
    share_doctor.add_argument(
        "--url",
        "--public-url",
        dest="url",
        help="public or client bridge MCP URL override printed by the provider",
    )
    share_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    share_doctor.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="probe the local gateway and configured upstreams",
    )
    share_doctor.add_argument("--conformance-pack", type=Path, help="generated fabric conformance pack to run")
    share_doctor.add_argument(
        "--require-conformance",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="fail when --conformance-pack is missing or does not pass",
    )
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
    from ..config import write_sample_config
    from ..leases import create_lease, list_leases, revoke_lease
    from ..quickstart import create_mcp_quickstart
    from ..share import (
        activate_mcp_share_policy,
        attach_mcp_share_member,
        close_mcp_share,
        create_mcp_share,
        doctor_mcp_share,
        doctor_mcp_share_auth,
        format_share_auth_doctor_report,
        format_share_doctor_report,
        format_share_status_report,
        promote_mcp_share_policy,
        run_mcp_share,
        share_client_config,
        share_report,
        share_status,
    )
    from ..share_session import share_session_model_path

    try:
        command = args.share_command
        if command == "quickstart":
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
                redact_records=args.redact_records,
                confirm=args.confirm,
                max_body_bytes=args.max_body_bytes,
                response_max_bytes=args.response_max_bytes,
                response_redact_secrets=args.response_redact_secrets,
                response_block_instructions=args.response_block_instructions,
                tool_pinning=args.tool_pinning,
                tool_pinning_action=args.tool_pinning_action,
                schema_validation=args.schema_validation,
                schema_validation_action=args.schema_validation_action,
                lease_file=args.lease_file,
                lease_required=args.lease_required,
                lease_header=args.lease_header,
                tunnel_provider=args.tunnel_provider,
                tunnel_public_url=args.tunnel_public_url,
                cloudflare_access=args.cloudflare_access,
                cloudflare_access_require_jwt=args.cloudflare_access_require_jwt,
                cloudflare_access_require_email=args.cloudflare_access_require_email,
                cloudflare_access_require_cf_ray=args.cloudflare_access_require_cf_ray,
                cloudflare_access_allowed_emails=args.cloudflare_access_allow_email,
                cloudflare_access_allowed_domains=args.cloudflare_access_allow_domain,
                timeout=args.timeout,
                force=args.force,
                validate=args.validate,
            )
            status = 0 if result["ok"] else 1
            write_generated_session_output(result, compact=args.compact)
            return status

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
            write_generated_session_output(result, compact=args.compact)
            return status

        if command == "run":
            if _has_proxy_run_args(args):
                if args.directory is not None:
                    parser.error("mcp share run cannot combine a share directory with proxy config arguments")
                    return 2
                return _run_proxy_from_share_args(args)
            directory = args.directory
            if directory is None and share_session_model_path(Path.cwd()).is_file():
                directory = Path.cwd()
            if directory is None:
                parser.error("mcp share run requires a share directory or --config")
                return 2
            result = run_mcp_share(
                directory,
                dry_run=args.dry_run,
            )
            if result is not None:
                write_json_output(result, compact=args.compact)
            return 0

        if command == "config":
            if args.share_config_command == "init":
                result = write_sample_config(args.output, force=args.force)
                result["next_steps"] = [
                    "uv run snulbug mcp policy preset local-dev-safe --output policy.snulbug",
                    f"uv run snulbug mcp share run --config {args.output}",
                ]
                write_generated_session_output(result, compact=args.compact)
                return 0
            parser.error(f"unknown mcp share config command: {args.share_config_command}")
            return 2

        if command == "lease":
            if args.share_lease_command == "create":
                result = create_lease(
                    args.file,
                    task=args.task,
                    allow_tools=args.allow_tool,
                    allow_paths=args.allow_path,
                    allow_hosts=args.allow_host,
                    allow_commands=args.allow_command,
                    ttl=args.ttl,
                    max_calls=args.max_calls,
                )
            elif args.share_lease_command == "list":
                result = list_leases(args.file, include_inactive=not args.active_only)
            elif args.share_lease_command == "revoke":
                result = revoke_lease(args.file, args.lease_id)
            else:
                parser.error(f"unknown mcp share lease command: {args.share_lease_command}")
                return 2
            status = 0 if result["ok"] else 1
            write_generated_session_output(result, compact=args.compact)
            return status

        if command == "attach":
            directory = _share_directory_arg(args)
            result = attach_mcp_share_member(
                directory,
                member_id=args.member_id,
                kind=args.kind,
                upstreams=_parse_facade_upstreams(args.upstream, option="--upstream") or [],
                metadata_file=args.metadata_file,
                registry=args.registry,
                registry_key=args.registry_key,
                role=args.role,
                status=args.status,
                ttl_seconds=args.ttl_seconds,
                labels=_parse_key_values(args.label),
                metadata=_parse_key_values(args.metadata),
                metadata_output=args.metadata_output,
                discovery_name=args.discovery_name,
                update_config=args.config_update,
            )
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "codespace":
            return _handle_share_codespace_command(args, parser)

        if command == "lab":
            from ..lab import run_mcp_lab

            result = run_mcp_lab(args.output_dir, force=args.force, emit=not args.compact)
            status = 0 if result["ok"] else 1
            if args.compact:
                write_generated_session_output(result, compact=True)
            return status

        if command == "status":
            result = share_status(args.directory, timeout=args.timeout, live_checks=args.live_checks)
            status = 0 if result["ok"] else 1
            write_result_output(result, compact=args.compact, formatter=format_share_status_report)
            return status

        if command == "report":
            result = share_report(
                args.directory,
                output=args.output,
                timeout=args.timeout,
                live_checks=args.live_checks,
                force=args.force,
            )
            status = 0 if result["ok"] else 1
            write_result_output(result, compact=args.compact, formatter=lambda value: value["report"])
            return status

        if command == "promote":
            directory = _share_directory_arg(args)
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = promote_mcp_share_policy(
                directory,
                to_state=args.to,
                secret=read_required_env(args.secret_env),
                key_id=args.key_id,
                actor=args.actor,
                note=args.note,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "activate":
            directory = _share_directory_arg(args)
            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            result = activate_mcp_share_policy(
                directory,
                secret=read_required_env(args.secret_env),
                key_id=args.key_id,
                actor=args.actor,
                note=args.note,
                instruction_limit=args.instruction_limit,
                memory_limit_bytes=memory_limit,
            )
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "auth":
            if args.share_auth_command == "doctor":
                directory = args.directory
                if directory is None and args.config is None and share_session_model_path(Path.cwd()).is_file():
                    directory = Path.cwd()
                result = doctor_mcp_share_auth(
                    directory,
                    config=args.config,
                    public_url=args.url,
                    headers=args.header,
                    token=args.token,
                    timeout=args.timeout,
                    live_checks=args.live_checks,
                )
                status = 0 if result["ok"] else 1
                write_result_output(result, compact=args.compact, formatter=format_share_auth_doctor_report)
                return status
            parser.error(f"unknown mcp share auth command: {args.share_auth_command}")
            return 2

        if command == "doctor":
            result = doctor_mcp_share(
                args.directory,
                timeout=args.timeout,
                public_url=args.url,
                live_checks=args.live_checks,
                conformance_pack=args.conformance_pack,
                require_conformance=args.require_conformance,
            )
            status = 0 if result["ok"] else 1
            write_result_output(result, compact=args.compact, formatter=format_share_doctor_report)
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
        if hasattr(args, "file") and args.file is not None:
            result["file"] = str(args.file)
        if hasattr(args, "output") and args.output is not None:
            result["config"] = str(args.output)
        if hasattr(args, "url") and args.url is not None:
            result["url"] = str(args.url)
        if hasattr(args, "output_dir") and args.output_dir is not None:
            result["output_dir"] = str(args.output_dir)
        write_json_output(result, compact=getattr(args, "compact", False))
        return 1


def _add_quickstart_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--directory", "--dir", type=Path, default=Path("."), help="starter output directory")
    parser.add_argument("--preset", default="local-dev-safe", help="MCP preset to generate")
    parser.add_argument("--policy-output", type=Path, default=Path("policy.snulbug"), help="policy bundle path")
    parser.add_argument("--config-output", type=Path, default=Path("snulbug.toml"), help="config file path")
    parser.add_argument("--traces-dir", type=Path, default=Path("traces"), help="trace directory path")
    parser.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server URL")
    add_token_arg(parser, help="bearer token to render into generated policy")
    add_token_env_arg(parser, help="context key used by generated policy for env-derived token lookup")
    parser.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    add_allow_path_arg(parser, help="allowed project path or prefix")
    parser.add_argument("--rate-limit", type=int, help="fixed-window request limit")
    parser.add_argument("--rate-window", type=int, help="fixed-window duration in seconds")
    parser.add_argument("--host", default="127.0.0.1", help="proxy bind host")
    parser.add_argument("--port", type=int, default=8080, help="proxy bind port")
    parser.add_argument("--state", default="memory", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")
    parser.add_argument("--record-out", type=Path, default=Path("traces/session.jsonl"))
    parser.add_argument(
        "--redact-records",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact secrets in live replay records",
    )
    parser.add_argument(
        "--confirm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="prompt before executing Lua confirm decisions or confirmable reject decisions",
    )
    parser.add_argument("--max-body-bytes", type=int, default=65536)
    parser.add_argument("--response-max-bytes", type=int, default=262144)
    parser.add_argument(
        "--response-redact-secrets",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact likely secrets from MCP tool/resource/prompt responses",
    )
    parser.add_argument(
        "--response-block-instructions",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="block MCP responses containing instruction-like text",
    )
    parser.add_argument(
        "--tool-pinning",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="pin tools/list descriptions and schemas on first sight",
    )
    parser.add_argument(
        "--tool-pinning-action",
        choices=("warn", "block"),
        default="block",
        help="what to do when a pinned tool description or schema changes",
    )
    parser.add_argument(
        "--schema-validation",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate tools/call arguments against cached MCP inputSchema definitions",
    )
    parser.add_argument(
        "--schema-validation-action",
        choices=("warn", "block"),
        default="block",
        help="what to do when tools/call arguments violate the cached inputSchema",
    )
    parser.add_argument("--lease-file", type=Path, default=Path("leases.json"), help="task lease JSON file")
    parser.add_argument(
        "--lease-required",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require a valid task lease for MCP tools/call requests",
    )
    parser.add_argument(
        "--lease-header",
        default="x-snulbug-lease",
        help="HTTP header carrying the task lease token",
    )
    parser.add_argument(
        "--tunnel-provider",
        choices=QUICKSTART_TUNNEL_PROVIDERS,
        default="auto",
        help="provider label for tunnel-aware audit fields",
    )
    parser.add_argument("--tunnel-public-url", help="public tunnel URL to include in audit fields")
    parser.add_argument(
        "--cloudflare-access",
        choices=("off", "audit", "enforce"),
        default="off",
        help="origin-side Cloudflare Access header mode",
    )
    parser.add_argument(
        "--cloudflare-access-require-jwt",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require CF-Access-Jwt-Assertion when Cloudflare Access enforcement is enabled",
    )
    parser.add_argument(
        "--cloudflare-access-require-email",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require CF-Access-Authenticated-User-Email when Cloudflare Access enforcement is enabled",
    )
    parser.add_argument(
        "--cloudflare-access-require-cf-ray",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require a CF-Ray header when Cloudflare Access enforcement is enabled",
    )
    parser.add_argument(
        "--cloudflare-access-allow-email",
        action="append",
        default=[],
        help="allowed Cloudflare Access authenticated user email; repeat for multiple emails",
    )
    parser.add_argument(
        "--cloudflare-access-allow-domain",
        action="append",
        default=[],
        help="allowed Cloudflare Access authenticated email domain; repeat for multiple domains",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="upstream timeout in seconds")
    add_force_arg(parser, help="overwrite generated policy and config")
    add_validate_arg(parser, help="validate and test the generated policy bundle")
    add_compact_arg(parser)


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


def _add_share_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        help="share session directory; defaults to cwd when .snulbug/share/session.json exists",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the run plan without starting the proxy")
    parser.add_argument("--config", type=Path, help="TOML config file")
    parser.add_argument("--upstream", help="upstream MCP HTTP server URL")
    parser.add_argument(
        "--facade-upstream",
        action="append",
        metavar="NAME=URL",
        help="add an MCP facade upstream; tools are exposed as NAME.tool_name",
    )
    parser.add_argument("--policy", type=Path, help="path to a Lua policy file")
    parser.add_argument("--host", help="bind host")
    parser.add_argument("--port", type=int, help="bind port")
    parser.add_argument("--record-out", type=Path, help="optional live replay JSONL path to append to")
    parser.add_argument(
        "--reload-fabric",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="hot-reload facade upstream routes from --config while the proxy runs",
    )
    parser.add_argument(
        "--fabric-reload-interval",
        type=float,
        default=None,
        help="fabric hot-reload polling interval in seconds",
    )
    add_compact_arg(parser)


def _add_share_lifecycle_args(parser: argparse.ArgumentParser, *, include_to: bool) -> None:
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        help="share session directory; defaults to cwd when .snulbug/share/session.json exists",
    )
    if include_to:
        parser.add_argument("--to", choices=("proposed", "approved"), required=True, help="target lifecycle state")
    parser.add_argument("--key-id", required=True, help="bundle signing key id")
    parser.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    parser.add_argument("--actor", help="actor to record in lifecycle history")
    parser.add_argument("--note", help="note to record in lifecycle history")
    parser.add_argument("--instruction-limit", type=int, default=100_000)
    parser.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(parser)


def _add_share_lease_args(parser: argparse.ArgumentParser) -> None:
    lease_subparsers = parser.add_subparsers(dest="share_lease_command", required=True)

    lease_create = lease_subparsers.add_parser("create", help="create a task-scoped MCP capability lease")
    lease_create.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    lease_create.add_argument("--task", required=True, help="human-readable task this lease grants")
    lease_create.add_argument("--allow-tool", action="append", required=True, help="allowed MCP tool name")
    add_allow_path_arg(lease_create, help="allowed path or path prefix")
    lease_create.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    lease_create.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    lease_create.add_argument("--ttl", default="1h", help="lease TTL, such as 30m, 2h, or 1d")
    lease_create.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    add_compact_arg(lease_create)

    lease_list = lease_subparsers.add_parser("list", help="list task-scoped MCP capability leases")
    lease_list.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    lease_list.add_argument("--active-only", action="store_true", help="show only active leases")
    add_compact_arg(lease_list)

    lease_revoke = lease_subparsers.add_parser("revoke", help="revoke a task-scoped MCP capability lease")
    lease_revoke.add_argument("lease_id", help="lease id to revoke")
    lease_revoke.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    add_compact_arg(lease_revoke)


def _add_share_attach_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        help="share session directory; defaults to cwd when .snulbug/share/session.json exists",
    )
    parser.add_argument("--member-id", "--id", dest="member_id", help="remote fabric member id")
    parser.add_argument(
        "--kind",
        choices=ATTACH_MEMBER_KINDS,
        default="container",
        help="remote member environment kind",
    )
    parser.add_argument(
        "--metadata-file",
        type=Path,
        help="JSON member metadata to consume instead of, or in addition to, CLI fields",
    )
    parser.add_argument(
        "--metadata-output",
        type=Path,
        help="write the normalized member metadata JSON inside the share directory",
    )
    parser.add_argument(
        "--upstream",
        action="append",
        default=[],
        metavar="NAME=URL",
        help="MCP upstream served by the member; repeat for multiple upstreams",
    )
    parser.add_argument(
        "--registry",
        help="fabric member registry path or shared state store such as sqlite:/path/to/members.sqlite3",
    )
    parser.add_argument("--registry-key", default="snulbug:fabric:members", help="state-backed registry key")
    parser.add_argument(
        "--role",
        choices=("data-plane", "data_plane", "control-plane", "control_plane", "observer"),
        default="data-plane",
        help="fabric member role",
    )
    parser.add_argument(
        "--status",
        choices=("active", "draining"),
        default="active",
        help="initial fabric member status",
    )
    parser.add_argument("--ttl-seconds", type=float, default=60.0, help="member heartbeat TTL")
    parser.add_argument("--label", action="append", default=[], metavar="KEY=VALUE", help="member label")
    parser.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE", help="member metadata")
    parser.add_argument("--discovery-name", default="share-members", help="fabric discovery provider name")
    parser.add_argument(
        "--config-update",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="append the members discovery provider to the share config",
    )
    add_compact_arg(parser)


def _add_share_codespace_args(parser: argparse.ArgumentParser) -> None:
    codespace_subparsers = parser.add_subparsers(dest="share_codespace_command", required=True)
    codespace_attach = codespace_subparsers.add_parser(
        "attach",
        help="start a local gateway for one Codespaces forwarded MCP URL",
    )
    codespace_attach.add_argument(
        "url",
        help="Codespaces forwarded MCP URL, such as https://NAME-9001.app.github.dev/mcp",
    )
    codespace_attach.add_argument("--name", default="codespace-files", help="facade upstream name")
    codespace_attach.add_argument(
        "--tool-prefix",
        default="codespace.files.",
        help="tool prefix exposed by the local facade",
    )
    codespace_attach.add_argument(
        "--directory",
        type=Path,
        default=Path(".snulbug/codespace-local"),
        help="generated local gateway artifact directory",
    )
    codespace_attach.add_argument("--host", default="127.0.0.1", help="local gateway bind host")
    codespace_attach.add_argument("--port", type=int, default=8080, help="local gateway bind port")
    codespace_attach.add_argument(
        "--state",
        default="memory",
        help="'memory', 'none', or sqlite:/path/to/state.sqlite3",
    )
    codespace_attach.add_argument(
        "--smoke-check",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="preflight the remote upstream with tools/list before starting the gateway",
    )
    codespace_attach.add_argument("--smoke-timeout", type=float, default=5.0, help="smoke-check timeout in seconds")
    codespace_attach.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite generated local gateway files",
    )
    codespace_attach.add_argument(
        "--dry-run",
        action="store_true",
        help="write artifacts and print the plan without starting the gateway",
    )
    add_compact_arg(codespace_attach)

    codespace_serve_demo = codespace_subparsers.add_parser(
        "serve-demo",
        help="run the bundled mock MCP server inside a Codespace",
    )
    codespace_serve_demo.add_argument("--host", default="0.0.0.0", help="demo MCP server bind host")
    codespace_serve_demo.add_argument("--port", type=int, default=9001, help="demo MCP server bind port")
    codespace_serve_demo.add_argument("--name", default="codespace", help="demo MCP server name")
    codespace_serve_demo.add_argument("--path", default="/mcp", help="MCP HTTP path")
    codespace_serve_demo.add_argument(
        "--ready-check",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="verify local tools/list before printing the laptop attach command",
    )
    codespace_serve_demo.add_argument("--ready-timeout", type=float, default=5.0, help="ready-check timeout")
    codespace_serve_demo.add_argument(
        "--dry-run",
        action="store_true",
        help="print the inferred URLs and commands without starting the server",
    )
    add_compact_arg(codespace_serve_demo)


def _handle_share_codespace_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from ..codespaces import (
        format_codespace_attach_report,
        format_codespace_demo_report,
        prepare_codespace_attach,
        prepare_codespace_demo,
        serve_codespace_demo,
        smoke_check_codespace_upstream,
    )

    if args.share_codespace_command == "attach":
        result = prepare_codespace_attach(
            args.url,
            directory=args.directory,
            name=args.name,
            tool_prefix=args.tool_prefix,
            host=args.host,
            port=args.port,
            state=args.state,
            force=args.force,
        )
        if args.smoke_check:
            result["smoke_check"] = smoke_check_codespace_upstream(args.url, timeout=args.smoke_timeout)
            if not result["smoke_check"]["ok"]:
                write_generated_session_output(
                    result,
                    compact=args.compact,
                    formatter=format_codespace_attach_report,
                )
                return 1
        result["dry_run"] = bool(args.dry_run)
        if args.dry_run:
            write_generated_session_output(
                result,
                compact=args.compact,
                formatter=format_codespace_attach_report,
            )
            return 0

        import os

        from ..config import load_mcp_fabric_config, load_mcp_proxy_config
        from ..proxy import run_mcp_proxy_config

        os.environ[result["env"]["name"]] = result["env"]["value"]
        proxy_config = load_mcp_proxy_config(result["config"])
        fabric_config = load_mcp_fabric_config(result["config"])
        fabric_config["proxy"] = proxy_config
        result["starting_proxy"] = True
        write_generated_session_output(
            result,
            compact=args.compact,
            formatter=format_codespace_attach_report,
        )
        sys.stdout.flush()
        run_mcp_proxy_config(proxy_config, fabric_config)
        return 0

    if args.share_codespace_command == "serve-demo":
        if args.dry_run:
            result = prepare_codespace_demo(
                host=args.host,
                port=args.port,
                name=args.name,
                path=args.path,
            )
            result["dry_run"] = True
            write_result_output(result, compact=args.compact, formatter=format_codespace_demo_report)
            return 0

        def emit_codespace_demo(payload: Mapping[str, Any]) -> None:
            write_result_output(payload, compact=args.compact, formatter=format_codespace_demo_report)
            sys.stdout.flush()

        result = serve_codespace_demo(
            host=args.host,
            port=args.port,
            name=args.name,
            path=args.path,
            ready_check=args.ready_check,
            ready_timeout=args.ready_timeout,
            emit=emit_codespace_demo,
        )
        return 0 if result["ok"] else 1

    parser.error(f"unknown mcp share codespace command: {args.share_codespace_command}")
    return 2


def _share_directory_arg(args: argparse.Namespace) -> Path:
    if args.directory is not None:
        return args.directory
    return Path.cwd()


def _has_proxy_run_args(args: argparse.Namespace) -> bool:
    return any(
        getattr(args, name, None) is not None
        for name in (
            "config",
            "upstream",
            "facade_upstream",
            "policy",
            "host",
            "port",
            "record_out",
            "reload_fabric",
            "fabric_reload_interval",
        )
    )


def _run_proxy_from_share_args(args: argparse.Namespace) -> int:
    from ..config import (
        load_mcp_fabric_config,
        load_mcp_proxy_config,
        merge_mcp_proxy_config,
        normalize_mcp_fabric_config,
        normalize_mcp_proxy_config,
    )
    from ..proxy import run_mcp_proxy_config, run_proxy

    try:
        overrides = {
            "upstream": args.upstream,
            "upstreams": _parse_facade_upstreams(args.facade_upstream),
            "policy": args.policy,
            "host": args.host,
            "port": args.port,
            "record_out": args.record_out,
        }
        overrides = {key: value for key, value in overrides.items() if value is not None}
        if args.dry_run:
            sys.stderr.write("snulbug share run failed: --dry-run is only supported for share directories\n")
            return 1
        if args.reload_fabric and args.config is None:
            sys.stderr.write("snulbug share run failed: --reload-fabric requires --config\n")
            return 1
        if args.config is not None:
            proxy_config = merge_mcp_proxy_config(load_mcp_proxy_config(args.config), overrides)
            fabric_config = load_mcp_fabric_config(args.config)
            fabric_config["proxy"] = proxy_config
        else:
            if args.policy is None or (args.upstream is None and not args.facade_upstream):
                sys.stderr.write(
                    "snulbug share run failed: --policy and either --upstream or "
                    "--facade-upstream are required without --config\n"
                )
                return 1
            proxy_config = normalize_mcp_proxy_config(overrides)
            fabric_config = normalize_mcp_fabric_config({}, proxy_config=proxy_config)
        run_mcp_proxy_config(
            proxy_config,
            fabric_config,
            runner=run_proxy,
            fabric_reload_config=args.config if args.reload_fabric else None,
            fabric_reload_interval=args.fabric_reload_interval or 2.0,
            fabric_reload_overrides=overrides if args.reload_fabric else None,
        )
    except Exception as exc:
        sys.stderr.write(f"snulbug share run failed: {exc}\n")
        return 1
    return 0


def _parse_facade_upstreams(
    values: Sequence[str] | None,
    *,
    option: str = "--facade-upstream",
) -> list[dict[str, Any]] | None:
    if not values:
        return None
    upstreams = []
    for value in values:
        name, separator, url = value.partition("=")
        if not separator or not name or not url:
            raise ValueError(f"{option} must use NAME=URL")
        upstreams.append({"name": name, "url": url, "tool_prefix": f"{name}."})
    return upstreams


def _parse_key_values(values: Sequence[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values or []:
        key, separator, item = value.partition("=")
        if not separator or not key:
            raise ValueError("metadata and label values must use KEY=VALUE")
        parsed[key] = item
    return parsed

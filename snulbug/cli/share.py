from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..cli_helpers import (
    add_allow_path_arg,
    add_compact_arg,
    add_force_arg,
    add_sarif_out_arg,
    add_token_arg,
    add_token_env_arg,
    add_validate_arg,
    write_generated_session_output,
    write_json_output,
    write_result_output,
    write_sarif_output,
)
from .common import read_required_env

PROVIDERS = ("generic", "ngrok", "cloudflare", "tailscale", "pinggy", "holepunch")
QUICKSTART_TUNNEL_PROVIDERS = ("auto", *PROVIDERS)
ATTACH_MEMBER_KINDS = ("codespaces", "devcontainer", "holepunch", "container", "generic")
CLOUDFLARE_ACCESS_PROFILES = ("access-gate", "service-token", "oauth-resource", "audit")
TAILSCALE_PROFILES = ("funnel-public", "serve-tailnet", "oauth-resource")


def _tunnel_provider_help(*, include_auto: bool = False) -> str:
    from ..tunnel import list_tunnel_providers

    providers = list_tunnel_providers()
    if include_auto:
        providers = ("auto", *providers)
    return ", ".join(providers)


def _auth_provider_help() -> str:
    from ..auth_providers import list_auth_providers

    return ", ".join(list_auth_providers())


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

    share_invite = share_subparsers.add_parser("invite", help="create and manage task-scoped MCP share invites")
    _add_share_invite_args(share_invite)

    share_requests = share_subparsers.add_parser("requests", help="review MCP just-in-time capability requests")
    _add_share_request_args(share_requests)

    share_member = share_subparsers.add_parser("member", help="attach remote members to a share session")
    _add_share_member_args(share_member)

    share_demo = share_subparsers.add_parser("demo", help="run local share workflow demos")
    _add_share_demo_args(share_demo)

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

    share_contract = share_subparsers.add_parser(
        "contract",
        help="write or print a secret-light share contract",
    )
    share_contract.add_argument("directory", type=Path, help="share session directory")
    share_contract.add_argument("--output", "--out", type=Path, help="write contract JSON to this path")
    share_contract.add_argument("--timeout", type=float, default=1.0, help="live check timeout in seconds")
    share_contract.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="probe the local gateway and configured upstreams",
    )
    share_contract.add_argument(
        "--include-doctor",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="run share doctor and include the readiness result in the contract",
    )
    share_contract.add_argument("--url", "--public-url", dest="url", help="public MCP URL override")
    share_contract.add_argument("--conformance-pack", type=Path, help="fabric conformance pack to run via share doctor")
    share_contract.add_argument(
        "--require-conformance",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="fail the included doctor result when no conformance pack is supplied",
    )
    share_contract.add_argument(
        "--sign",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="sign the contract with an HMAC secret",
    )
    share_contract.add_argument("--key-id", default="local-share", help="signature key identifier")
    share_contract.add_argument(
        "--secret-env",
        default="SNULBUG_SHARE_CONTRACT_SECRET",
        help="environment variable containing the contract signing secret",
    )
    add_force_arg(share_contract, help="overwrite --output when it exists")
    add_compact_arg(share_contract)

    share_policy = share_subparsers.add_parser("policy", help="amend, promote, and activate the share policy")
    _add_share_policy_args(share_policy)

    share_auth = share_subparsers.add_parser("auth", help="diagnose share authentication")
    share_auth_subparsers = share_auth.add_subparsers(dest="share_auth_command", required=True)
    share_auth_init = share_auth_subparsers.add_parser(
        "init",
        help="generate provider auth setup files for an MCP share",
    )
    share_auth_init.add_argument("--provider", required=True, help=f"auth provider ({_auth_provider_help()})")
    share_auth_init.add_argument(
        "--url",
        "--public-url",
        dest="url",
        required=True,
        help="public MCP URL clients connect to",
    )
    share_auth_init.add_argument("--issuer", help="provider issuer URL override")
    share_auth_init.add_argument("--audience", help="token audience/resource indicator override")
    share_auth_init.add_argument("--client-id", help="provider client/application id")
    share_auth_init.add_argument("--tenant", help="provider tenant id/name")
    share_auth_init.add_argument("--domain", help="provider domain/base URL")
    share_auth_init.add_argument("--realm", help="Keycloak realm")
    share_auth_init.add_argument("--auth-server-id", help="Okta authorization server id")
    share_auth_init.add_argument(
        "--scope",
        action="append",
        default=[],
        help="MCP OAuth scope to include; repeat for multiple scopes",
    )
    share_auth_init.add_argument(
        "--output-dir",
        "--dir",
        type=Path,
        help="directory for generated auth setup files; defaults to .snulbug/auth/<provider>",
    )
    add_force_arg(share_auth_init, help="overwrite generated auth setup files when they exist")
    add_compact_arg(share_auth_init)
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
    share_auth_conformance = share_auth_subparsers.add_parser(
        "conformance",
        help="generate or run OAuth auth conformance packs",
    )
    share_auth_conformance_subparsers = share_auth_conformance.add_subparsers(
        dest="auth_conformance_command",
        required=True,
    )
    share_auth_conformance_generate = share_auth_conformance_subparsers.add_parser(
        "generate",
        help="generate a secret-safe auth conformance pack",
    )
    share_auth_conformance_generate.add_argument("directory", nargs="?", type=Path, help="share session directory")
    share_auth_conformance_generate.add_argument("--config", type=Path, help="snulbug.toml config path")
    share_auth_conformance_generate.add_argument(
        "--url",
        "--public-url",
        dest="url",
        help="public MCP URL clients connect to",
    )
    share_auth_conformance_generate.add_argument(
        "--schema-catalog",
        action="append",
        required=True,
        type=Path,
        help="discovered MCP schema catalog JSON; repeat for multiple catalogs",
    )
    share_auth_conformance_generate.add_argument(
        "--log",
        action="append",
        required=True,
        type=Path,
        help="replay or audit JSONL log with OAuth auth evidence; repeat for multiple logs",
    )
    share_auth_conformance_generate.add_argument(
        "--kind",
        choices=("auto", "record", "audit"),
        default="auto",
        help="log kind for generated log profiles",
    )
    share_auth_conformance_generate.add_argument(
        "--token-env",
        action="append",
        required=True,
        help="expected-valid sample token env reference, as ENV or label=ENV",
    )
    share_auth_conformance_generate.add_argument(
        "--denied-token-env",
        action="append",
        default=[],
        help="expected-denied sample token env reference, as ENV or label=ENV",
    )
    share_auth_conformance_generate.add_argument(
        "--output-dir",
        "--out",
        type=Path,
        default=Path(".snulbug/auth-conformance"),
        help="output conformance pack directory",
    )
    add_force_arg(share_auth_conformance_generate, help="overwrite generated auth conformance files")
    add_compact_arg(share_auth_conformance_generate)
    share_auth_conformance_run = share_auth_conformance_subparsers.add_parser(
        "run",
        help="run a generated auth conformance pack",
    )
    share_auth_conformance_run.add_argument("pack", type=Path, help="auth conformance pack directory")
    share_auth_conformance_run.add_argument(
        "--token-env",
        action="append",
        default=[],
        help="override or add token env reference, as ENV or label=ENV",
    )
    share_auth_conformance_run.add_argument(
        "--url",
        "--public-url",
        dest="url",
        help="public MCP URL override",
    )
    share_auth_conformance_run.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header as 'Name: value'",
    )
    share_auth_conformance_run.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    share_auth_conformance_run.add_argument(
        "--live-checks",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run auth doctor live metadata and tools/list checks",
    )
    add_compact_arg(share_auth_conformance_run)
    share_auth_recipe = share_auth_subparsers.add_parser(
        "recipe",
        help="generate OAuth/Access provider setup guidance for an MCP share",
    )
    share_auth_recipe.add_argument("--provider", required=True, help=f"auth provider ({_auth_provider_help()})")
    share_auth_recipe.add_argument(
        "--url",
        "--public-url",
        dest="url",
        required=True,
        help="public MCP URL clients connect to",
    )
    share_auth_recipe.add_argument("--issuer", help="provider issuer URL override")
    share_auth_recipe.add_argument("--audience", help="token audience/resource indicator override")
    share_auth_recipe.add_argument("--client-id", help="provider client/application id")
    share_auth_recipe.add_argument("--tenant", help="provider tenant id/name")
    share_auth_recipe.add_argument("--domain", help="provider domain/base URL")
    share_auth_recipe.add_argument("--realm", help="Keycloak realm")
    share_auth_recipe.add_argument("--auth-server-id", help="Okta authorization server id")
    share_auth_recipe.add_argument(
        "--scope",
        action="append",
        default=[],
        help="MCP OAuth scope to include; repeat for multiple scopes",
    )
    share_auth_recipe.add_argument("--output", "--out", type=Path, help="write recipe Markdown to this path")
    add_force_arg(share_auth_recipe, help="overwrite --output when it exists")
    add_compact_arg(share_auth_recipe)

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
    add_sarif_out_arg(share_doctor, help="write a SARIF readiness gate report")
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

    share_inspector = share_subparsers.add_parser("inspector", help="generate MCP Inspector setup for a share")
    share_inspector.add_argument("directory", type=Path, help="share session directory")
    share_inspector.add_argument("--invite", "--invite-id", dest="invite_id", help="use a specific share invite")
    share_inspector.add_argument(
        "--include-secrets",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="include persisted invite bearer and lease tokens in generated commands",
    )
    share_inspector.add_argument("--output", "--out", type=Path, help="write mcp-inspector.json config payload")
    add_force_arg(share_inspector, help="overwrite --output when it exists")
    add_compact_arg(share_inspector)

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
    from ..auth_recipes import (
        format_mcp_auth_init_report,
        format_mcp_auth_recipe_report,
        generate_mcp_auth_init,
        generate_mcp_auth_recipe,
    )
    from ..config import write_sample_config
    from ..leases import create_lease, list_leases, revoke_lease
    from ..quickstart import create_mcp_quickstart
    from ..share import (
        activate_mcp_share_policy,
        amend_mcp_share_policy,
        approve_share_capability_request,
        attach_mcp_share_member,
        close_mcp_share,
        create_mcp_share,
        create_mcp_share_invite,
        deny_share_capability_request,
        doctor_mcp_share,
        doctor_mcp_share_auth,
        format_share_auth_conformance_report,
        generate_auth_conformance_pack,
        list_mcp_share_invites,
        promote_mcp_share_policy,
        revoke_mcp_share_invite,
        run_auth_conformance_pack,
        run_mcp_share,
        share_capability_requests,
        share_client_config,
        share_contract,
        share_inspector_setup,
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
                cloudflare_profile=args.cloudflare_profile,
                tailscale_profile=args.tailscale_profile,
                cloudflare_access=args.cloudflare_access,
                cloudflare_access_require_jwt=args.cloudflare_access_require_jwt,
                cloudflare_access_require_email=args.cloudflare_access_require_email,
                cloudflare_access_require_cf_ray=args.cloudflare_access_require_cf_ray,
                cloudflare_access_allowed_emails=args.cloudflare_access_allow_email,
                cloudflare_access_allowed_domains=args.cloudflare_access_allow_domain,
                cloudflare_access_validate_jwt=args.cloudflare_access_validate_jwt,
                cloudflare_access_team_domain=args.cloudflare_access_team_domain,
                cloudflare_access_issuer=args.cloudflare_access_issuer,
                cloudflare_access_audience=args.cloudflare_access_audience,
                cloudflare_access_certs_url=args.cloudflare_access_certs_url,
                cloudflare_access_jwks_cache_seconds=args.cloudflare_access_jwks_cache_seconds,
                cloudflare_access_jwks_fetch_timeout=args.cloudflare_access_jwks_fetch_timeout,
                cloudflare_access_leeway_seconds=args.cloudflare_access_leeway_seconds,
                auth_issuer=args.auth_issuer,
                auth_resource=args.auth_resource,
                auth_audience=args.auth_audience,
                auth_required_scopes=args.auth_scope or None,
                auth_jwks_url=args.auth_jwks_url,
                auth_token_validation=args.auth_token_validation,
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
                ngrok_internal_url=args.ngrok_internal_url,
                ngrok_endpoint_name=args.ngrok_endpoint_name,
                cloudflare_profile=args.cloudflare_profile,
                tailscale_profile=args.tailscale_profile,
                auth_issuer=args.auth_issuer,
                auth_resource=args.auth_resource,
                auth_audience=args.auth_audience,
                auth_required_scopes=args.auth_scope or None,
                auth_jwks_url=args.auth_jwks_url,
                auth_token_validation=args.auth_token_validation,
                cloudflare_access_allowed_emails=args.cloudflare_access_allow_email,
                cloudflare_access_allowed_domains=args.cloudflare_access_allow_domain,
                cloudflare_access_team_domain=args.cloudflare_access_team_domain,
                cloudflare_access_issuer=args.cloudflare_access_issuer,
                cloudflare_access_audience=args.cloudflare_access_audience,
                cloudflare_access_certs_url=args.cloudflare_access_certs_url,
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
                return _run_share_setup_console(args)
            console_server = _start_share_run_console(directory, args)
            try:
                result = run_mcp_share(
                    directory,
                    dry_run=args.dry_run,
                    require_contract=args.require_contract,
                )
                if result is not None:
                    write_json_output(result, compact=args.compact)
            finally:
                _stop_share_run_console(console_server)
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
                    allow_subjects=args.allow_subject,
                    allow_issuers=args.allow_issuer,
                    allow_tenants=args.allow_tenant,
                    allow_client_ids=args.allow_client_id,
                    allow_groups=args.allow_group,
                    allow_auth_profiles=args.allow_auth_profile,
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

        if command == "invite":
            if args.share_invite_command == "create":
                result = create_mcp_share_invite(
                    args.directory,
                    recipient=args.recipient,
                    task=args.task,
                    capabilities=args.capability,
                    allow_tools=args.allow_tool,
                    allow_paths=args.allow_path,
                    allow_hosts=args.allow_host,
                    allow_commands=args.allow_command,
                    ttl=args.ttl,
                    max_calls=args.max_calls,
                    client_name=args.client_name,
                )
            elif args.share_invite_command == "list":
                result = list_mcp_share_invites(args.directory, include_revoked=not args.active_only)
            elif args.share_invite_command == "revoke":
                result = revoke_mcp_share_invite(
                    args.directory,
                    invite_id=args.invite_id,
                    revoke_lease=not args.keep_lease,
                )
            else:
                parser.error(f"unknown mcp share invite command: {args.share_invite_command}")
                return 2
            status = 0 if result["ok"] else 1
            write_generated_session_output(result, compact=args.compact)
            return status

        if command == "requests":
            return _handle_share_requests_command(
                args,
                parser,
                share_capability_requests=share_capability_requests,
                approve_share_capability_request=approve_share_capability_request,
                deny_share_capability_request=deny_share_capability_request,
            )

        if command == "member":
            return _handle_share_member_command(args, parser, attach_mcp_share_member=attach_mcp_share_member)

        if command == "demo":
            return _handle_share_demo_command(args, parser)

        if command == "status":
            result = share_status(args.directory, timeout=args.timeout, live_checks=args.live_checks)
            status = 0 if result["ok"] else 1
            if args.compact:
                write_json_output(result, compact=True)
            else:
                from .rich_share import write_share_status_rich

                write_share_status_rich(result)
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
            if args.compact:
                write_json_output(result, compact=True)
            else:
                from .rich_reports import write_share_report_rich

                write_share_report_rich(result)
            return status

        if command == "contract":
            result = share_contract(
                args.directory,
                output=args.output,
                timeout=args.timeout,
                live_checks=args.live_checks,
                include_doctor=args.include_doctor,
                public_url=args.url,
                conformance_pack=args.conformance_pack,
                require_conformance=args.require_conformance,
                sign=args.sign,
                secret=read_required_env(args.secret_env) if args.sign else None,
                key_id=args.key_id,
                force=args.force,
            )
            status = 0 if result["ok"] else 1
            write_result_output(
                result,
                compact=args.compact,
                formatter=lambda value: json.dumps(value["contract"], indent=2, sort_keys=True),
            )
            return status

        if command == "policy":
            return _handle_share_policy_command(
                args,
                parser,
                activate_mcp_share_policy=activate_mcp_share_policy,
                amend_mcp_share_policy=amend_mcp_share_policy,
                promote_mcp_share_policy=promote_mcp_share_policy,
            )

        if command == "auth":
            if args.share_auth_command == "init":
                result = generate_mcp_auth_init(
                    args.provider,
                    public_url=args.url,
                    issuer=args.issuer,
                    audience=args.audience,
                    client_id=args.client_id,
                    tenant=args.tenant,
                    domain=args.domain,
                    realm=args.realm,
                    auth_server_id=args.auth_server_id,
                    scopes=args.scope or None,
                    output_dir=args.output_dir,
                    force=args.force,
                )
                write_result_output(result, compact=args.compact, formatter=format_mcp_auth_init_report)
                return 0
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
                if args.compact:
                    write_json_output(result, compact=True)
                else:
                    from .rich_reports import write_share_auth_doctor_rich

                    write_share_auth_doctor_rich(result)
                return status
            if args.share_auth_command == "conformance":
                if args.auth_conformance_command == "generate":
                    directory = args.directory
                    if directory is None and args.config is None and share_session_model_path(Path.cwd()).is_file():
                        directory = Path.cwd()
                    result = generate_auth_conformance_pack(
                        directory,
                        config=args.config,
                        public_url=args.url,
                        schema_catalogs=args.schema_catalog or [],
                        logs=args.log or [],
                        kind=args.kind,
                        token_envs=args.token_env or [],
                        denied_token_envs=args.denied_token_env or [],
                        output=args.output_dir,
                        force=args.force,
                    )
                    write_generated_session_output(result, compact=args.compact)
                    return 0
                if args.auth_conformance_command == "run":
                    result = run_auth_conformance_pack(
                        args.pack,
                        token_envs=args.token_env or [],
                        public_url=args.url,
                        headers=args.header,
                        timeout=args.timeout,
                        live_checks=args.live_checks,
                    )
                    status = 0 if result["ok"] else 1
                    write_result_output(result, compact=args.compact, formatter=format_share_auth_conformance_report)
                    return status
                parser.error(f"unknown mcp share auth conformance command: {args.auth_conformance_command}")
                return 2
            if args.share_auth_command == "recipe":
                result = generate_mcp_auth_recipe(
                    args.provider,
                    public_url=args.url,
                    issuer=args.issuer,
                    audience=args.audience,
                    client_id=args.client_id,
                    tenant=args.tenant,
                    domain=args.domain,
                    realm=args.realm,
                    auth_server_id=args.auth_server_id,
                    scopes=args.scope or None,
                    output=args.output,
                    force=args.force,
                )
                write_result_output(result, compact=args.compact, formatter=format_mcp_auth_recipe_report)
                return 0
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
            if args.sarif_out is not None:
                from ..sarif import sarif_for_share_doctor

                write_sarif_output(args.sarif_out, sarif_for_share_doctor(result), result)
            status = 0 if result["ok"] else 1
            if args.compact:
                write_json_output(result, compact=True)
            else:
                from .rich_reports import write_share_doctor_rich

                write_share_doctor_rich(result)
            return status

        if command == "client":
            result = share_client_config(args.directory, output_format=args.format)
            status = 0 if result["ok"] else 1
            write_json_output(result, compact=args.compact)
            return status

        if command == "inspector":
            result = share_inspector_setup(
                args.directory,
                invite_id=args.invite_id,
                include_secrets=args.include_secrets,
                output=args.output,
                force=args.force,
            )
            status = 0 if result["ok"] else 1
            write_result_output(result, compact=args.compact, formatter=format_share_inspector_setup_report)
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


def format_share_inspector_setup_report(result: Mapping[str, Any]) -> str:
    inspector = _cli_mapping(result.get("mcp_inspector"))
    ui = _cli_mapping(inspector.get("ui"))
    cli = _cli_mapping(inspector.get("cli"))
    config = _cli_mapping(inspector.get("config"))
    lines = [
        "# snulbug MCP Inspector setup",
        "",
        f"Share: `{result.get('share') or '-'}`",
        f"URL: `{inspector.get('url') or '-'}`",
        "",
        "## UI",
        "",
        "Start Inspector:",
        "",
        "```bash",
        str(ui.get("launch_command") or "npx @modelcontextprotocol/inspector"),
        "```",
        "",
        "Open:",
        "",
        f"`{ui.get('open_url') or '-'}`",
        "",
        "## CLI Smoke Tests",
        "",
        "```bash",
        str(cli.get("tools_list") or ""),
        "```",
        "",
        "```bash",
        str(cli.get("resources_list") or ""),
        "```",
        "",
        "## Config",
        "",
    ]
    if result.get("written"):
        lines.extend([f"Wrote `{result['written']}`.", ""])
    lines.extend(
        [
            "Run with config:",
            "",
            "```bash",
            str(config.get("command") or ""),
            "```",
        ]
    )
    return "\n".join(lines)


def _cli_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


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
        default=True,
        help="require a valid task lease for MCP tools/call requests",
    )
    parser.add_argument(
        "--lease-header",
        default="x-snulbug-lease",
        help="HTTP header carrying the task lease token",
    )
    parser.add_argument(
        "--tunnel-provider",
        default="auto",
        metavar="PROVIDER",
        help=f"provider label for tunnel-aware audit fields; built-ins: {_tunnel_provider_help(include_auto=True)}",
    )
    parser.add_argument("--tunnel-public-url", help="public tunnel URL to include in audit fields")
    _add_cloudflare_profile_args(parser)
    _add_tailscale_profile_args(parser)
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
    parser.add_argument(
        "--cloudflare-access-validate-jwt",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="cryptographically validate CF-Access-Jwt-Assertion against Cloudflare Access certs",
    )
    parser.add_argument(
        "--cloudflare-access-team-domain",
        help="Cloudflare Access team domain, such as your-team.cloudflareaccess.com",
    )
    parser.add_argument("--cloudflare-access-issuer", help="expected Access JWT issuer; defaults to team domain")
    parser.add_argument("--cloudflare-access-audience", help="Cloudflare Access application AUD tag")
    parser.add_argument(
        "--cloudflare-access-certs-url",
        help="JWKS URL for Access certs; defaults to <team-domain>/cdn-cgi/access/certs",
    )
    parser.add_argument(
        "--cloudflare-access-jwks-cache-seconds",
        type=float,
        default=300.0,
        help="seconds to cache Cloudflare Access JWKS",
    )
    parser.add_argument(
        "--cloudflare-access-jwks-fetch-timeout",
        type=float,
        default=5.0,
        help="timeout in seconds when fetching Cloudflare Access JWKS",
    )
    parser.add_argument(
        "--cloudflare-access-leeway-seconds",
        type=float,
        default=60.0,
        help="JWT clock-skew leeway for Cloudflare Access assertions",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="upstream timeout in seconds")
    add_force_arg(parser, help="overwrite generated policy and config")
    add_validate_arg(parser, help="validate and test the generated policy bundle")
    add_compact_arg(parser)


def _add_cloudflare_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cloudflare-profile",
        choices=CLOUDFLARE_ACCESS_PROFILES,
        help=(
            "Cloudflare Tunnel auth defaults: access-gate, service-token, oauth-resource, or audit. "
            "Defaults to access-gate when the provider is cloudflare."
        ),
    )
    parser.add_argument(
        "--auth-issuer",
        help="OAuth issuer URL for an oauth-resource tunnel profile",
    )
    parser.add_argument(
        "--auth-resource",
        help="OAuth resource indicator for an oauth-resource tunnel profile; defaults to the public MCP URL",
    )
    parser.add_argument(
        "--auth-audience",
        help="OAuth audience for an oauth-resource tunnel profile; defaults to the resource",
    )
    parser.add_argument(
        "--auth-scope",
        action="append",
        default=[],
        help="required OAuth scope for an oauth-resource tunnel profile; repeat for multiple scopes",
    )
    parser.add_argument("--auth-jwks-url", help="explicit OAuth JWKS URL; issuer discovery is used when omitted")
    parser.add_argument(
        "--auth-token-validation",
        choices=("jwt", "introspection", "jwt_or_introspection", "jwt_and_introspection"),
        default="jwt",
        help="OAuth token validation mode for oauth-resource tunnel profiles",
    )


def _add_tailscale_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tailscale-profile",
        choices=TAILSCALE_PROFILES,
        help=(
            "Tailscale posture defaults: funnel-public, serve-tailnet, or oauth-resource. "
            "Defaults to funnel-public when the provider is tailscale."
        ),
    )


def _add_cloudflare_access_setup_args(parser: argparse.ArgumentParser) -> None:
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
    parser.add_argument(
        "--cloudflare-access-team-domain",
        help="Cloudflare Access team domain, such as your-team.cloudflareaccess.com",
    )
    parser.add_argument("--cloudflare-access-issuer", help="expected Access JWT issuer; defaults to team domain")
    parser.add_argument("--cloudflare-access-audience", help="Cloudflare Access application AUD tag")
    parser.add_argument(
        "--cloudflare-access-certs-url",
        help="JWKS URL for Access certs; defaults to <team-domain>/cdn-cgi/access/certs",
    )


def _add_share_create_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--directory", type=Path, help="share session directory")
    parser.add_argument(
        "--provider",
        default="holepunch",
        metavar="PROVIDER",
        help=f"tunnel or peer bridge provider; built-ins: {_tunnel_provider_help()}",
    )
    parser.add_argument("--preset", default="tunnel-safe", help="MCP policy preset")
    parser.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server")
    parser.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    parser.add_argument("--url", "--public-url", dest="url", help="public tunnel or client bridge MCP URL")
    parser.add_argument(
        "--ngrok-internal-url",
        help="ngrok internal Agent Endpoint URL; must be an https://*.internal origin",
    )
    parser.add_argument(
        "--ngrok-endpoint-name",
        default="snulbug-mcp-internal",
        help="endpoint name in the generated ngrok v3 agent config",
    )
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
    _add_cloudflare_profile_args(parser)
    _add_tailscale_profile_args(parser)
    _add_cloudflare_access_setup_args(parser)
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
        "--require-contract",
        type=Path,
        help="require and expose an approved share contract JSON while proxying",
    )
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
    parser.add_argument(
        "--no-console",
        action="store_true",
        help="do not start the local share web console while the proxy runs",
    )
    parser.add_argument("--console-host", default="127.0.0.1", help="local share console bind host")
    parser.add_argument("--console-port", type=int, default=8765, help="local share console bind port")
    parser.add_argument(
        "--console-timeout",
        type=float,
        default=1.0,
        help="share console live check timeout in seconds",
    )
    parser.add_argument(
        "--console-live-checks",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="probe the local gateway and configured upstreams on every share console refresh",
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


def _add_share_policy_args(parser: argparse.ArgumentParser) -> None:
    policy_subparsers = parser.add_subparsers(dest="share_policy_command", required=True)

    policy_amend = policy_subparsers.add_parser(
        "amend",
        help="propose a candidate amendment for the share policy from share evidence",
    )
    policy_amend.add_argument(
        "directory",
        nargs="?",
        type=Path,
        help="share session directory; defaults to cwd when .snulbug/share/session.json exists",
    )
    policy_amend.add_argument(
        "--log",
        type=Path,
        help="JSONL replay or audit log; defaults to the share audit log when present",
    )
    policy_amend.add_argument(
        "--out",
        "--output",
        type=Path,
        help="candidate output policy bundle; defaults to updating the share policy bundle in place",
    )
    policy_amend.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    policy_amend.add_argument(
        "--source",
        choices=("blocked", "approved-confirmations"),
        default="blocked",
        help="evidence source to amend from",
    )
    policy_amend.add_argument(
        "--allow-risky",
        action="store_true",
        help="allow risky shell/exec-style tool names into the candidate policy",
    )
    add_force_arg(policy_amend, help="overwrite files in the output directory")
    add_validate_arg(policy_amend, help="validate the generated policy bundle")
    add_compact_arg(policy_amend)

    policy_promote = policy_subparsers.add_parser("promote", help="promote the share policy bundle lifecycle")
    _add_share_lifecycle_args(policy_promote, include_to=True)

    policy_activate = policy_subparsers.add_parser("activate", help="activate the share policy bundle")
    _add_share_lifecycle_args(policy_activate, include_to=False)


def _handle_share_policy_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    activate_mcp_share_policy: Any,
    amend_mcp_share_policy: Any,
    promote_mcp_share_policy: Any,
) -> int:
    if args.share_policy_command == "amend":
        directory = _share_directory_arg(args)
        result = amend_mcp_share_policy(
            directory,
            log=args.log,
            output=args.out,
            kind=args.kind,
            source=args.source,
            force=args.force,
            validate=args.validate,
            allow_risky=args.allow_risky,
        )
        status = 0 if result["ok"] else 1
        write_json_output(result, compact=args.compact)
        return status

    if args.share_policy_command == "promote":
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

    if args.share_policy_command == "activate":
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

    parser.error(f"unknown mcp share policy command: {args.share_policy_command}")
    return 2


def _add_share_lease_args(parser: argparse.ArgumentParser) -> None:
    lease_subparsers = parser.add_subparsers(dest="share_lease_command", required=True)

    lease_create = lease_subparsers.add_parser("create", help="create a task-scoped MCP capability lease")
    lease_create.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    lease_create.add_argument("--task", required=True, help="human-readable task this lease grants")
    lease_create.add_argument("--allow-tool", action="append", required=True, help="allowed MCP tool name")
    add_allow_path_arg(lease_create, help="allowed path or path prefix")
    lease_create.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    lease_create.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    lease_create.add_argument("--allow-subject", action="append", default=[], help="allowed OAuth subject claim")
    lease_create.add_argument("--allow-issuer", action="append", default=[], help="allowed OAuth issuer claim")
    lease_create.add_argument("--allow-tenant", action="append", default=[], help="allowed OAuth tenant claim")
    lease_create.add_argument("--allow-client-id", action="append", default=[], help="allowed OAuth client id claim")
    lease_create.add_argument("--allow-group", action="append", default=[], help="allowed OAuth group claim")
    lease_create.add_argument(
        "--allow-auth-profile",
        action="append",
        default=[],
        help="allowed snulbug auth issuer profile id",
    )
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


def _add_share_invite_args(parser: argparse.ArgumentParser) -> None:
    invite_subparsers = parser.add_subparsers(dest="share_invite_command", required=True)

    invite_create = invite_subparsers.add_parser(
        "create",
        help="create a task-scoped MCP client invite backed by a lease",
    )
    invite_create.add_argument("directory", type=Path, help="share session directory")
    invite_create.add_argument("--recipient", required=True, help="human-readable recipient or client label")
    invite_create.add_argument("--task", required=True, help="human-readable task this invite grants")
    invite_create.add_argument(
        "--capability",
        action="append",
        default=[],
        help="temporary capability label interpreted by Lua policy, such as project_readonly",
    )
    invite_create.add_argument("--allow-tool", action="append", default=[], help="low-level allowed MCP tool name")
    add_allow_path_arg(invite_create, help="allowed path or path prefix")
    invite_create.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    invite_create.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    invite_create.add_argument("--ttl", default="30m", help="invite lease TTL, such as 30m, 2h, or 1d")
    invite_create.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    invite_create.add_argument("--client-name", help="MCP client config server name")
    add_compact_arg(invite_create)

    invite_list = invite_subparsers.add_parser("list", help="list MCP share invites without revealing tokens")
    invite_list.add_argument("directory", type=Path, help="share session directory")
    invite_list.add_argument("--active-only", action="store_true", help="hide revoked invites")
    add_compact_arg(invite_list)

    invite_revoke = invite_subparsers.add_parser("revoke", help="revoke an MCP share invite")
    invite_revoke.add_argument("directory", type=Path, help="share session directory")
    invite_revoke.add_argument("invite_id", help="invite id to revoke")
    invite_revoke.add_argument(
        "--keep-lease",
        action="store_true",
        help="leave the invite's backing lease active",
    )
    add_compact_arg(invite_revoke)


def _add_share_request_args(parser: argparse.ArgumentParser) -> None:
    request_subparsers = parser.add_subparsers(dest="share_requests_command", required=True)

    requests_list = request_subparsers.add_parser("list", help="list observed MCP capability requests")
    requests_list.add_argument("directory", nargs="?", type=Path, help="share session directory")
    requests_list.add_argument(
        "--status",
        choices=("pending", "approved", "denied", "all"),
        default="pending",
        help="request review status to show",
    )
    requests_list.add_argument("--log", type=Path, help="audit or replay JSONL log override")
    add_compact_arg(requests_list)

    requests_approve = request_subparsers.add_parser(
        "approve",
        help="approve a capability request by minting a task-scoped lease",
    )
    requests_approve.add_argument("request_id", help="capability request id from `share requests list`")
    requests_approve.add_argument("--directory", "-d", type=Path, help="share session directory")
    requests_approve.add_argument("--log", type=Path, help="audit or replay JSONL log override")
    requests_approve.add_argument("--ttl", help="lease TTL override, such as 10m or 1h")
    requests_approve.add_argument("--max-calls", type=int, help="maximum allowed tools/call uses")
    requests_approve.add_argument("--task", help="human-readable lease task override")
    requests_approve.add_argument("--allow-tool", action="append", default=[], help="additional allowed MCP tool")
    requests_approve.add_argument(
        "--capability",
        action="append",
        default=[],
        help="policy-declared capability label to grant instead of raw tool/path fields",
    )
    add_allow_path_arg(requests_approve, help="additional allowed path or path prefix")
    requests_approve.add_argument("--allow-host", action="append", default=[], help="additional allowed URL host")
    requests_approve.add_argument("--allow-command", action="append", default=[], help="additional allowed command")
    requests_approve.add_argument(
        "--bind-auth",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="bind the lease to observed OAuth subject, issuer, tenant, client, groups, and auth profile",
    )
    requests_approve.add_argument("--reviewer", help="reviewer label to record in the request inbox")
    add_compact_arg(requests_approve)

    requests_deny = request_subparsers.add_parser("deny", help="deny a capability request")
    requests_deny.add_argument("request_id", help="capability request id from `share requests list`")
    requests_deny.add_argument("--directory", "-d", type=Path, help="share session directory")
    requests_deny.add_argument("--log", type=Path, help="audit or replay JSONL log override")
    requests_deny.add_argument("--reason", help="review reason")
    requests_deny.add_argument("--reviewer", help="reviewer label to record in the request inbox")
    add_compact_arg(requests_deny)


def _handle_share_requests_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    share_capability_requests: Any,
    approve_share_capability_request: Any,
    deny_share_capability_request: Any,
) -> int:
    if args.share_requests_command == "list":
        directory = args.directory
        if directory is None:
            directory = Path.cwd()
        result = share_capability_requests(
            directory,
            status=args.status,
            log=args.log,
        )
        status = 0 if result["ok"] else 1
        write_json_output(result, compact=args.compact)
        return status

    if args.share_requests_command == "approve":
        directory = args.directory or Path.cwd()
        result = approve_share_capability_request(
            directory,
            request_id=args.request_id,
            ttl=args.ttl,
            max_calls=args.max_calls,
            task=args.task,
            allow_tools=args.allow_tool or (),
            allow_paths=args.allow_path or (),
            allow_hosts=args.allow_host or (),
            allow_commands=args.allow_command or (),
            capabilities=args.capability or (),
            bind_auth=args.bind_auth,
            reviewer=args.reviewer,
            log=args.log,
        )
        status = 0 if result["ok"] else 1
        write_generated_session_output(result, compact=args.compact)
        return status

    if args.share_requests_command == "deny":
        directory = args.directory or Path.cwd()
        result = deny_share_capability_request(
            directory,
            request_id=args.request_id,
            reason=args.reason,
            reviewer=args.reviewer,
            log=args.log,
        )
        status = 0 if result["ok"] else 1
        write_json_output(result, compact=args.compact)
        return status

    parser.error(f"unknown mcp share requests command: {args.share_requests_command}")
    return 2


def _add_share_demo_args(parser: argparse.ArgumentParser) -> None:
    demo_subparsers = parser.add_subparsers(dest="share_demo_command", required=True)

    local_demo = demo_subparsers.add_parser("local", help="run the one-command local MCP policy lab")
    local_demo.add_argument("--output-dir", type=Path, default=Path(".snulbug-lab"), help="lab artifact directory")
    local_demo.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite the lab artifact directory",
    )
    add_compact_arg(local_demo)

    auth_demo = demo_subparsers.add_parser("auth", help="run a local OAuth scope + task lease auth lab")
    auth_demo.add_argument(
        "--output-dir",
        type=Path,
        default=Path(".snulbug-auth-lab"),
        help="auth lab artifact directory",
    )
    auth_demo.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite the auth lab artifact directory",
    )
    add_compact_arg(auth_demo)


def _handle_share_demo_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.share_demo_command == "local":
        from ..lab import run_mcp_lab

        result = run_mcp_lab(args.output_dir, force=args.force, emit=not args.compact)
        status = 0 if result["ok"] else 1
        if args.compact:
            write_generated_session_output(result, compact=True)
        return status

    if args.share_demo_command == "auth":
        from ..lab import run_mcp_auth_lab

        result = run_mcp_auth_lab(args.output_dir, force=args.force, emit=not args.compact)
        status = 0 if result["ok"] else 1
        if args.compact:
            write_generated_session_output(result, compact=True)
        return status

    parser.error(f"unknown mcp share demo command: {args.share_demo_command}")
    return 2


def _add_share_member_args(parser: argparse.ArgumentParser) -> None:
    member_subparsers = parser.add_subparsers(dest="share_member_command", required=True)
    member_attach = member_subparsers.add_parser("attach", help="attach a remote fabric member to a share session")
    _add_share_attach_args(member_attach)
    member_codespace = member_subparsers.add_parser("codespace", help="work with Codespaces as share members")
    _add_share_codespace_args(member_codespace)


def _handle_share_member_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    attach_mcp_share_member: Any,
) -> int:
    if args.share_member_command == "attach":
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

    if args.share_member_command == "codespace":
        return _handle_share_codespace_command(args, parser)

    parser.error(f"unknown mcp share member command: {args.share_member_command}")
    return 2


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

    parser.error(f"unknown mcp share member codespace command: {args.share_codespace_command}")
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


def _share_run_console_directory(args: argparse.Namespace, directory: Path | None = None) -> Path | None:
    if getattr(args, "no_console", False) or getattr(args, "dry_run", False):
        return None
    if directory is not None:
        return Path(directory)
    config = getattr(args, "config", None)
    if config is None:
        return None
    from ..share_session import share_session_model_path

    config_dir = Path(config).parent
    if share_session_model_path(config_dir).is_file():
        return config_dir
    return None


def _start_share_run_console(directory: Path | None, args: argparse.Namespace) -> Any:
    console_dir = _share_run_console_directory(args, directory)
    if console_dir is None:
        return None
    from ..share_console import DEFAULT_SHARE_CONSOLE_PORT, ShareConsoleServer

    host = str(getattr(args, "console_host", "127.0.0.1"))
    port = int(getattr(args, "console_port", DEFAULT_SHARE_CONSOLE_PORT))
    timeout = float(getattr(args, "console_timeout", 1.0))
    live_checks = bool(getattr(args, "console_live_checks", False))
    server = ShareConsoleServer(
        directory=console_dir,
        host=host,
        port=port,
        timeout=timeout,
        live_checks=live_checks,
    )
    try:
        server.start()
    except OSError as exc:
        if port != DEFAULT_SHARE_CONSOLE_PORT:
            raise
        sys.stderr.write(f"snulbug share console port {port} unavailable: {exc}; retrying with a dynamic port\n")
        server = ShareConsoleServer(
            directory=console_dir,
            host=host,
            port=0,
            timeout=timeout,
            live_checks=live_checks,
        )
        try:
            server.start()
        except OSError as retry_exc:
            sys.stderr.write(f"snulbug share console disabled: {retry_exc}\n")
            return None
    print(f"snulbug share console: {server.url}", flush=True)
    if getattr(server, "console_secret", None):
        print(f"snulbug share console secret: {server.console_secret}", flush=True)
    return server


def _stop_share_run_console(server: Any) -> None:
    if server is not None:
        server.stop()


def _run_share_setup_console(args: argparse.Namespace) -> int:
    if getattr(args, "no_console", False):
        sys.stderr.write(
            "snulbug share run failed: no share directory or --config was provided and --no-console is set\n"
        )
        return 1
    from ..share_console import DEFAULT_SHARE_CONSOLE_PORT, ShareConsoleServer

    host = str(getattr(args, "console_host", "127.0.0.1"))
    port = int(getattr(args, "console_port", DEFAULT_SHARE_CONSOLE_PORT))
    server = ShareConsoleServer(
        directory=Path.cwd(),
        host=host,
        port=port,
        timeout=float(getattr(args, "console_timeout", 1.0)),
        live_checks=False,
        setup_only=True,
    )
    try:
        server.start()
    except OSError as exc:
        if port != DEFAULT_SHARE_CONSOLE_PORT:
            sys.stderr.write(f"snulbug share setup console failed: {exc}\n")
            return 1
        sys.stderr.write(f"snulbug share console port {port} unavailable: {exc}; retrying with a dynamic port\n")
        server = ShareConsoleServer(
            directory=Path.cwd(),
            host=host,
            port=0,
            timeout=float(getattr(args, "console_timeout", 1.0)),
            live_checks=False,
            setup_only=True,
        )
        try:
            server.start()
        except OSError as retry_exc:
            sys.stderr.write(f"snulbug share setup console failed: {retry_exc}\n")
            return 1
    print(f"snulbug share setup wizard: {server.url}", flush=True)
    if getattr(server, "console_secret", None):
        print(f"snulbug share console secret: {server.console_secret}", flush=True)
    try:
        while not server.wait_for_gateway_start(timeout=0.25):
            continue
        from ..share import run_mcp_share

        run_mcp_share(server.directory)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        sys.stderr.write(f"snulbug share run failed: {exc}\n")
        return 1
    finally:
        server.stop()


def _run_proxy_from_share_args(args: argparse.Namespace) -> int:
    from ..config import (
        load_mcp_fabric_config,
        load_mcp_proxy_config,
        merge_mcp_proxy_config,
        normalize_mcp_fabric_config,
        normalize_mcp_proxy_config,
    )
    from ..proxy import run_mcp_proxy_config, run_proxy
    from ..share import load_share_contract

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
        share_contract = load_share_contract(args.require_contract) if args.require_contract is not None else None
        console_server = _start_share_run_console(None, args)
        try:
            run_mcp_proxy_config(
                proxy_config,
                fabric_config,
                runner=run_proxy,
                share_contract=share_contract,
                fabric_reload_config=args.config if args.reload_fabric else None,
                fabric_reload_interval=args.fabric_reload_interval or 2.0,
                fabric_reload_overrides=overrides if args.reload_fabric else None,
            )
        finally:
            _stop_share_run_console(console_server)
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

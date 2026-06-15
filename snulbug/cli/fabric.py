from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..cli_helpers import add_compact_arg, add_force_arg, add_token_arg, write_json_output
from ..config import load_mcp_fabric_config
from ..fabric_runtime import (
    DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    DEFAULT_FABRIC_RUNTIME_STATE,
    DEFAULT_FABRIC_RUNTIME_STATE_KEY,
)
from .common import read_required_env


def add_mcp_fabric_command(mcp_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_fabric = mcp_subparsers.add_parser("fabric", help="inspect and verify declarative MCP fabric config")
    mcp_fabric_subparsers = mcp_fabric.add_subparsers(dest="fabric_command", required=True)

    mcp_fabric_status = mcp_fabric_subparsers.add_parser("status", help="summarize declared MCP fabric topology")
    mcp_fabric_status.add_argument("--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file")
    add_compact_arg(mcp_fabric_status)

    mcp_fabric_discover = mcp_fabric_subparsers.add_parser(
        "discover",
        help="resolve configured MCP fabric discovery providers",
    )
    mcp_fabric_discover.add_argument(
        "--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file"
    )
    add_compact_arg(mcp_fabric_discover)

    mcp_fabric_doctor = mcp_fabric_subparsers.add_parser(
        "doctor",
        help="verify declared MCP fabric config, manifests, and reachable endpoints",
    )
    mcp_fabric_doctor.add_argument("--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file")
    mcp_fabric_doctor.add_argument(
        "--header",
        "--auth-header",
        action="append",
        default=[],
        help="authenticated probe header as 'Name: value'; repeat for multiple headers",
    )
    add_token_arg(mcp_fabric_doctor, help="bearer token for authenticated MCP probes")
    mcp_fabric_doctor.add_argument("--timeout", type=float, help="HTTP probe timeout in seconds")
    mcp_fabric_doctor.add_argument(
        "--probe-gateway",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="actively probe the client-facing snulbug gateway",
    )
    mcp_fabric_doctor.add_argument(
        "--probe-upstreams",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="actively probe declared HTTP/Holepunch upstream URLs",
    )
    add_compact_arg(mcp_fabric_doctor)

    mcp_fabric_learn = mcp_fabric_subparsers.add_parser(
        "learn",
        help="learn a declarative fabric profile from topology-aware logs",
    )
    mcp_fabric_learn.add_argument("log", type=Path, help="topology-aware replay or audit JSONL log")
    mcp_fabric_learn.add_argument("--out", "--output", type=Path, required=True, help="output fabric profile directory")
    mcp_fabric_learn.add_argument(
        "--kind",
        choices=("auto", "record", "audit"),
        default="auto",
        help="input log type",
    )
    add_force_arg(mcp_fabric_learn, help="overwrite the output directory")
    add_compact_arg(mcp_fabric_learn)

    _add_fabric_manifest_command(mcp_fabric_subparsers)
    _add_fabric_conformance_command(mcp_fabric_subparsers)
    _add_fabric_runtime_command(mcp_fabric_subparsers)
    _add_fabric_control_command(mcp_fabric_subparsers)
    _add_fabric_member_command(mcp_fabric_subparsers)
    _add_fabric_controller_command(mcp_fabric_subparsers)
    _add_fabric_run_command(mcp_fabric_subparsers)


def handle_mcp_fabric_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from ..controller import (
        FabricControllerStatusServer,
        format_fabric_controller_report,
        format_fabric_run_report,
        run_fabric_controller,
        run_fabric_data_plane,
    )
    from ..fabric import (
        discover_fabric_upstreams,
        doctor_fabric,
        fabric_status,
        format_fabric_discovery_report,
        format_fabric_learn_report,
        learn_fabric_profile,
    )
    from ..fabric_control import (
        clear_fabric_control_actions,
        format_fabric_control_report,
        issue_fabric_control_action,
        load_fabric_control_state,
    )
    from ..fabric_members import (
        format_fabric_member_report,
        heartbeat_fabric_member,
        load_fabric_member_registry,
        register_fabric_member,
        summarize_fabric_members,
        unregister_fabric_member,
    )
    from ..fabric_runtime import (
        clear_fabric_runtime_status,
        format_fabric_runtime_report,
        load_fabric_runtime_status,
    )
    from ..tunnel import parse_tunnel_headers

    try:
        if args.fabric_command == "status":
            result = fabric_status(args.config)
            status = 0 if result["ok"] else 1
            if not args.compact:
                from .rich_reports import write_fabric_status_rich

                write_fabric_status_rich(result)
                return status
        elif args.fabric_command == "discover":
            result = discover_fabric_upstreams(args.config)
            status = 0 if result["ok"] else 1
            if not args.compact:
                sys.stdout.write(format_fabric_discovery_report(result))
                sys.stdout.write("\n")
                return status
        elif args.fabric_command == "doctor":
            result = doctor_fabric(
                args.config,
                headers=parse_tunnel_headers(args.header, token=args.token),
                timeout=args.timeout,
                probe_gateway=args.probe_gateway,
                probe_upstreams=args.probe_upstreams,
            )
            status = 0 if result["ok"] else 1
            if not args.compact:
                from .rich_reports import write_fabric_doctor_rich

                write_fabric_doctor_rich(result)
                return status
        elif args.fabric_command == "learn":
            result = learn_fabric_profile(args.log, args.out, kind=args.kind, force=args.force)
            status = 0 if result["ok"] else 1
            if not args.compact:
                sys.stdout.write(format_fabric_learn_report(result))
                sys.stdout.write("\n")
                return status
        elif args.fabric_command == "manifest":
            return _handle_fabric_manifest_command(args, parser)
        elif args.fabric_command == "conformance":
            return _handle_fabric_conformance_command(args, parser, parse_tunnel_headers)
        elif args.fabric_command == "runtime":
            return _handle_fabric_runtime_command(
                args,
                parser,
                clear_fabric_runtime_status=clear_fabric_runtime_status,
                format_fabric_runtime_report=format_fabric_runtime_report,
                load_fabric_runtime_status=load_fabric_runtime_status,
            )
        elif args.fabric_command == "control":
            return _handle_fabric_control_command(
                args,
                parser,
                clear_fabric_control_actions=clear_fabric_control_actions,
                format_fabric_control_report=format_fabric_control_report,
                issue_fabric_control_action=issue_fabric_control_action,
                load_fabric_control_state=load_fabric_control_state,
            )
        elif args.fabric_command == "member":
            return _handle_fabric_member_command(
                args,
                parser,
                format_fabric_member_report=format_fabric_member_report,
                heartbeat_fabric_member=heartbeat_fabric_member,
                load_fabric_member_registry=load_fabric_member_registry,
                register_fabric_member=register_fabric_member,
                summarize_fabric_members=summarize_fabric_members,
                unregister_fabric_member=unregister_fabric_member,
            )
        elif args.fabric_command == "controller":
            event_log = None if args.no_event_log else args.event_log
            status_server = None
            if args.status_server:
                status_server = FabricControllerStatusServer(host=args.status_host, port=args.status_port)
                status_server.start()

            def emit_controller_result(payload: Mapping[str, Any]) -> None:
                if status_server is not None:
                    payload = {**dict(payload), "status_server": status_server_url(status_server)}
                if args.compact:
                    write_json_output(payload, compact=True)
                else:
                    sys.stdout.write(format_fabric_controller_report(payload))
                    if status_server is not None:
                        sys.stdout.write("\n\n## Status server\n")
                        sys.stdout.write(f"- health: `{status_server_url(status_server)}/healthz`\n")
                        sys.stdout.write(f"- status: `{status_server_url(status_server)}/status`\n")
                        sys.stdout.write(f"- metrics: `{status_server_url(status_server)}/metrics`\n")
                    sys.stdout.write("\n")
                sys.stdout.flush()

            try:
                fabric_config = load_mcp_fabric_config(args.config)
                result = run_fabric_controller(
                    args.config,
                    state_path=args.state,
                    event_log=event_log,
                    interval=args.interval,
                    once=args.once,
                    emit=emit_controller_result,
                    status_server=status_server,
                    event_sinks=fabric_config["event_sinks"],
                )
            finally:
                if status_server is not None and args.once:
                    status_server.stop()
            return 0 if result["ok"] else 1
        elif args.fabric_command == "run":
            event_log = None if args.no_event_log else args.event_log

            def emit_fabric_run_started(payload: Mapping[str, Any]) -> None:
                if args.compact:
                    write_json_output(payload, compact=True)
                else:
                    sys.stdout.write(format_fabric_run_report(payload))
                    sys.stdout.write("\n")
                sys.stdout.flush()

            result = run_fabric_data_plane(
                args.config,
                state_path=args.state,
                event_log=event_log,
                controller_interval=args.controller_interval,
                reload_interval=args.reload_interval,
                status_host=args.status_host,
                status_port=args.status_port,
                conformance_pack=args.conformance_pack,
                require_conformance=args.require_conformance,
                runtime_state=args.runtime_state,
                runtime_state_key=args.runtime_state_key,
                runtime_heartbeat_ttl=args.runtime_heartbeat_ttl,
                runtime_instance_id=args.runtime_instance_id,
                runtime_lease_ttl=args.runtime_lease_ttl,
                emit=emit_fabric_run_started,
            )
            return 0 if result["ok"] else 1
        else:
            parser.error(f"unknown mcp fabric command: {args.fabric_command}")
            return 2
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        if hasattr(args, "config"):
            result["config"] = str(args.config)
        if hasattr(args, "out"):
            result["output"] = str(args.out)
        status = 1

    write_json_output(result, compact=args.compact)
    return status


def _add_fabric_manifest_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_manifest = mcp_fabric_subparsers.add_parser(
        "manifest",
        help="sign and verify MCP upstream manifests",
    )
    manifest_subparsers = mcp_fabric_manifest.add_subparsers(dest="manifest_command", required=True)

    manifest_sign = manifest_subparsers.add_parser("sign", help="sign an upstream manifest JSON file")
    manifest_sign.add_argument("manifest", type=Path, help="unsigned upstream manifest JSON file")
    manifest_sign.add_argument("--out", "--output", type=Path, required=True, help="signed manifest output path")
    manifest_sign.add_argument("--key-id", required=True, help="manifest signing key id")
    manifest_sign.add_argument(
        "--secret-env",
        default="SNULBUG_MANIFEST_SECRET",
        help="environment variable containing the manifest signing secret",
    )
    add_compact_arg(manifest_sign)

    manifest_verify = manifest_subparsers.add_parser("verify", help="verify a signed upstream manifest")
    manifest_verify.add_argument("manifest", type=Path, help="signed upstream manifest JSON file")
    manifest_verify.add_argument("--key-id", help="manifest signing key id; defaults to the manifest key_id")
    manifest_verify.add_argument(
        "--secret-env",
        default="SNULBUG_MANIFEST_SECRET",
        help="environment variable containing the manifest signing secret",
    )
    manifest_verify.add_argument("--expect-identity", help="required manifest identity")
    add_compact_arg(manifest_verify)


def _handle_fabric_manifest_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from ..manifests import load_manifest, sign_upstream_manifest, verify_upstream_manifest, write_manifest

    try:
        secret = read_required_env(args.secret_env)
        if args.manifest_command == "sign":
            manifest = load_manifest(args.manifest)
            signed_manifest = sign_upstream_manifest(manifest, secret=secret, key_id=args.key_id)
            write_manifest(args.out, signed_manifest)
            result = {
                "ok": True,
                "manifest": str(args.manifest),
                "output": str(args.out),
                "signature": signed_manifest["snulbug_signature"],
            }
        elif args.manifest_command == "verify":
            manifest = load_manifest(args.manifest)
            signature = manifest.get("snulbug_signature")
            signature_key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
            key_id = args.key_id or signature_key_id
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("manifest key_id is required; pass --key-id or include snulbug_signature.key_id")
            result = {
                "ok": True,
                "manifest": str(args.manifest),
                "verified": verify_upstream_manifest(
                    manifest,
                    secrets={key_id: secret},
                    expected_identity=args.expect_identity,
                ),
            }
        else:
            parser.error(f"unknown mcp fabric manifest command: {args.manifest_command}")
            return 2
        status = 0
    except Exception as exc:
        result = {"ok": False, "manifest": str(args.manifest), "error": str(exc)}
        status = 1

    write_json_output(result, compact=args.compact)
    return status


def _add_fabric_conformance_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_conformance = mcp_fabric_subparsers.add_parser(
        "conformance",
        help="generate and run fabric conformance test packs",
    )
    mcp_fabric_conformance_subparsers = mcp_fabric_conformance.add_subparsers(
        dest="conformance_command",
        required=True,
    )
    mcp_fabric_conformance_generate = mcp_fabric_conformance_subparsers.add_parser(
        "generate",
        help="generate a fabric conformance test pack",
    )
    mcp_fabric_conformance_generate.add_argument(
        "--config",
        type=Path,
        default=Path("snulbug.toml"),
        help="snulbug.toml config file",
    )
    mcp_fabric_conformance_generate.add_argument(
        "--out",
        "--output",
        type=Path,
        required=True,
        help="output conformance pack directory",
    )
    mcp_fabric_conformance_generate.add_argument(
        "--log",
        action="append",
        type=Path,
        required=True,
        help="topology-aware replay or audit JSONL log; repeat for multiple logs",
    )
    mcp_fabric_conformance_generate.add_argument(
        "--kind",
        choices=("auto", "record", "audit"),
        default="auto",
        help="input log type",
    )
    add_force_arg(mcp_fabric_conformance_generate, help="overwrite generated files")
    add_compact_arg(mcp_fabric_conformance_generate)

    mcp_fabric_conformance_run = mcp_fabric_conformance_subparsers.add_parser(
        "run",
        help="run a generated fabric conformance test pack",
    )
    mcp_fabric_conformance_run.add_argument("pack", type=Path, help="fabric conformance pack directory")
    mcp_fabric_conformance_run.add_argument(
        "--header",
        "--auth-header",
        action="append",
        default=[],
        help="authenticated probe header as 'Name: value'; repeat for multiple headers",
    )
    add_token_arg(mcp_fabric_conformance_run, help="bearer token for authenticated MCP probes")
    mcp_fabric_conformance_run.add_argument("--timeout", type=float, help="HTTP probe timeout in seconds")
    mcp_fabric_conformance_run.add_argument(
        "--probe-gateway",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="actively probe the client-facing snulbug gateway",
    )
    mcp_fabric_conformance_run.add_argument(
        "--probe-upstreams",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="actively probe declared HTTP/Holepunch upstream URLs",
    )
    mcp_fabric_conformance_run.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_fabric_conformance_run.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(mcp_fabric_conformance_run)


def _handle_fabric_conformance_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    parse_tunnel_headers: Any,
) -> int:
    from ..fabric import (
        format_fabric_conformance_report,
        generate_fabric_conformance_pack,
        run_fabric_conformance_pack,
    )

    if args.conformance_command == "generate":
        result = generate_fabric_conformance_pack(
            args.config,
            args.out,
            logs=args.log,
            kind=args.kind,
            force=args.force,
        )
        status = 0 if result["ok"] else 1
        if not args.compact:
            sys.stdout.write("# snulbug fabric conformance generate\n\n")
            sys.stdout.write(f"Output: {result.get('output')}\n")
            sys.stdout.write(f"Manifest: {result.get('manifest')}\n")
            sys.stdout.write(f"Report: {result.get('report')}\n")
            sys.stdout.write("\n## Next steps\n")
            for check in result.get("checks", []):
                sys.stdout.write(f"- {check}\n")
            return status
    elif args.conformance_command == "run":
        result = run_fabric_conformance_pack(
            args.pack,
            headers=parse_tunnel_headers(args.header, token=args.token),
            timeout=args.timeout,
            probe_gateway=args.probe_gateway,
            probe_upstreams=args.probe_upstreams,
            instruction_limit=args.instruction_limit,
            memory_limit_bytes=args.memory_limit_bytes,
        )
        status = 0 if result["ok"] else 1
        if not args.compact:
            sys.stdout.write(format_fabric_conformance_report(result))
            sys.stdout.write("\n")
            return status
    else:
        parser.error(f"unknown mcp fabric conformance command: {args.conformance_command}")
        return 2

    write_json_output(result, compact=args.compact)
    return status


def _add_fabric_runtime_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_runtime = mcp_fabric_subparsers.add_parser(
        "runtime",
        help="inspect or clear persisted managed data-plane runtime state",
    )
    mcp_fabric_runtime_subparsers = mcp_fabric_runtime.add_subparsers(dest="runtime_command", required=True)
    mcp_fabric_runtime_status = mcp_fabric_runtime_subparsers.add_parser(
        "status",
        help="read the latest persisted managed data-plane runtime state",
    )
    mcp_fabric_runtime_status.add_argument(
        "--runtime-state",
        default=DEFAULT_FABRIC_RUNTIME_STATE,
        help="'memory', 'none', 'sqlite:/path/to/state.sqlite3', or 'redis://...'",
    )
    mcp_fabric_runtime_status.add_argument(
        "--runtime-state-key",
        default=DEFAULT_FABRIC_RUNTIME_STATE_KEY,
        help="runtime state key for shared stores",
    )
    add_compact_arg(mcp_fabric_runtime_status)

    mcp_fabric_runtime_clear = mcp_fabric_runtime_subparsers.add_parser(
        "clear",
        help="delete the persisted managed data-plane runtime state",
    )
    mcp_fabric_runtime_clear.add_argument(
        "--runtime-state",
        default=DEFAULT_FABRIC_RUNTIME_STATE,
        help="'memory', 'none', 'sqlite:/path/to/state.sqlite3', or 'redis://...'",
    )
    mcp_fabric_runtime_clear.add_argument(
        "--runtime-state-key",
        default=DEFAULT_FABRIC_RUNTIME_STATE_KEY,
        help="runtime state key for shared stores",
    )
    add_compact_arg(mcp_fabric_runtime_clear)


def _handle_fabric_runtime_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    clear_fabric_runtime_status: Any,
    format_fabric_runtime_report: Any,
    load_fabric_runtime_status: Any,
) -> int:
    if args.runtime_command == "status":
        result = load_fabric_runtime_status(
            args.runtime_state,
            key=args.runtime_state_key,
        )
        status = 0 if result["ok"] else 1
        if not args.compact:
            sys.stdout.write(format_fabric_runtime_report(result))
            sys.stdout.write("\n")
            return status
    elif args.runtime_command == "clear":
        result = clear_fabric_runtime_status(
            args.runtime_state,
            key=args.runtime_state_key,
        )
        status = 0 if result["ok"] else 1
        if not args.compact:
            verb = "cleared" if result.get("cleared") else "empty"
            sys.stdout.write("# snulbug fabric runtime clear\n\n")
            sys.stdout.write(f"Store: {result.get('runtime_state')}\n")
            sys.stdout.write(f"Key: {result.get('runtime_state_key')}\n")
            sys.stdout.write(f"Status: {verb}\n")
            return status
    else:
        parser.error(f"unknown mcp fabric runtime command: {args.runtime_command}")
        return 2

    write_json_output(result, compact=args.compact)
    return status


def _add_fabric_control_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_control = mcp_fabric_subparsers.add_parser(
        "control",
        help="issue or inspect live fabric operational controls",
    )
    mcp_fabric_control_subparsers = mcp_fabric_control.add_subparsers(dest="control_command", required=True)
    mcp_fabric_control_list = mcp_fabric_control_subparsers.add_parser(
        "list",
        help="list active fabric operational controls",
    )
    _add_fabric_control_store_args(mcp_fabric_control_list)
    mcp_fabric_control_pause = mcp_fabric_control_subparsers.add_parser(
        "pause-sharing",
        help="block the fabric share gate until cleared",
    )
    _add_fabric_control_store_args(mcp_fabric_control_pause)
    _add_fabric_control_issue_args(mcp_fabric_control_pause)
    mcp_fabric_control_drain = mcp_fabric_control_subparsers.add_parser(
        "drain-upstream",
        help="skip an upstream for new facade routing until cleared",
    )
    mcp_fabric_control_drain.add_argument("upstream", help="upstream name to drain")
    _add_fabric_control_store_args(mcp_fabric_control_drain)
    _add_fabric_control_issue_args(mcp_fabric_control_drain)
    mcp_fabric_control_quarantine = mcp_fabric_control_subparsers.add_parser(
        "quarantine-upstream",
        help="quarantine an upstream from facade routing until cleared",
    )
    mcp_fabric_control_quarantine.add_argument("upstream", help="upstream name to quarantine")
    _add_fabric_control_store_args(mcp_fabric_control_quarantine)
    _add_fabric_control_issue_args(mcp_fabric_control_quarantine)
    mcp_fabric_control_reload = mcp_fabric_control_subparsers.add_parser(
        "force-reload",
        help="force the managed data plane to rebuild facade routes on the next reload tick",
    )
    _add_fabric_control_store_args(mcp_fabric_control_reload)
    _add_fabric_control_issue_args(mcp_fabric_control_reload, default_ttl=60.0)
    mcp_fabric_control_rollback = mcp_fabric_control_subparsers.add_parser(
        "rollback-policy",
        help="record a policy rollback intent and block sharing until cleared",
    )
    mcp_fabric_control_rollback.add_argument("policy", type=Path, help="policy path to roll back to")
    _add_fabric_control_store_args(mcp_fabric_control_rollback)
    _add_fabric_control_issue_args(mcp_fabric_control_rollback)
    mcp_fabric_control_clear = mcp_fabric_control_subparsers.add_parser(
        "clear",
        help="clear active fabric operational controls",
    )
    mcp_fabric_control_clear.add_argument("--id", dest="action_id", help="clear one action id")
    mcp_fabric_control_clear.add_argument(
        "--action",
        choices=("pause_sharing", "drain_upstream", "quarantine_upstream", "force_reload", "rollback_policy"),
        help="clear active controls of this type",
    )
    mcp_fabric_control_clear.add_argument("--target", help="clear active controls for this upstream target")
    mcp_fabric_control_clear.add_argument("--actor", help="actor recorded on the clear event")
    _add_fabric_control_store_args(mcp_fabric_control_clear)


def _handle_fabric_control_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    clear_fabric_control_actions: Any,
    format_fabric_control_report: Any,
    issue_fabric_control_action: Any,
    load_fabric_control_state: Any,
) -> int:
    if args.control_command == "list":
        result = load_fabric_control_state(
            args.runtime_state,
            key=args.runtime_state_key,
        )
    elif args.control_command == "clear":
        result = clear_fabric_control_actions(
            args.runtime_state,
            key=args.runtime_state_key,
            action_id=args.action_id,
            action_type=args.action,
            target=args.target,
            actor=args.actor,
        )
    else:
        action_map = {
            "pause-sharing": "pause_sharing",
            "drain-upstream": "drain_upstream",
            "quarantine-upstream": "quarantine_upstream",
            "force-reload": "force_reload",
            "rollback-policy": "rollback_policy",
        }
        action_type = action_map.get(args.control_command)
        if action_type is None:
            parser.error(f"unknown mcp fabric control command: {args.control_command}")
            return 2
        result = issue_fabric_control_action(
            args.runtime_state,
            key=args.runtime_state_key,
            action_type=action_type,
            target=getattr(args, "upstream", None),
            policy=getattr(args, "policy", None),
            reason=args.reason,
            actor=args.actor,
            ttl_seconds=args.ttl_seconds,
        )
    status = 0 if result["ok"] else 1
    if not args.compact:
        sys.stdout.write(format_fabric_control_report(result))
        sys.stdout.write("\n")
        return status
    write_json_output(result, compact=True)
    return status


def _add_fabric_member_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_member = mcp_fabric_subparsers.add_parser(
        "member",
        help="register or inspect remote fabric members",
    )
    mcp_fabric_member_subparsers = mcp_fabric_member.add_subparsers(dest="member_command", required=True)
    mcp_fabric_member_list = mcp_fabric_member_subparsers.add_parser(
        "list",
        help="list registered remote fabric members",
    )
    _add_fabric_member_registry_args(mcp_fabric_member_list)
    mcp_fabric_member_register = mcp_fabric_member_subparsers.add_parser(
        "register",
        help="register or refresh a remote fabric member",
    )
    mcp_fabric_member_register.add_argument("member_id", help="stable member/node id")
    _add_fabric_member_metadata_args(mcp_fabric_member_register)
    _add_fabric_member_registry_args(mcp_fabric_member_register)

    mcp_fabric_member_agent = mcp_fabric_member_subparsers.add_parser(
        "agent",
        help="register a remote fabric member and keep its heartbeat fresh",
    )
    mcp_fabric_member_agent.add_argument("member_id", help="stable member/node id")
    _add_fabric_member_metadata_args(mcp_fabric_member_agent)
    mcp_fabric_member_agent.add_argument(
        "--interval",
        type=float,
        default=20.0,
        help="seconds between heartbeat refreshes",
    )
    mcp_fabric_member_agent.add_argument(
        "--once",
        action="store_true",
        help="register once and exit after emitting the agent result",
    )
    mcp_fabric_member_agent.add_argument(
        "--unregister-on-exit",
        action="store_true",
        help="mark the member left when the agent receives Ctrl-C",
    )
    _add_fabric_member_registry_args(mcp_fabric_member_agent)

    mcp_fabric_member_heartbeat = mcp_fabric_member_subparsers.add_parser(
        "heartbeat",
        help="refresh an existing member heartbeat",
    )
    mcp_fabric_member_heartbeat.add_argument("member_id", help="registered member id")
    mcp_fabric_member_heartbeat.add_argument(
        "--ttl-seconds",
        type=float,
        default=60.0,
        help="seconds until the member expires without another heartbeat",
    )
    mcp_fabric_member_heartbeat.add_argument(
        "--status",
        choices=("active", "draining", "left"),
        default="active",
        help="member status to record",
    )
    _add_fabric_member_registry_args(mcp_fabric_member_heartbeat)

    mcp_fabric_member_unregister = mcp_fabric_member_subparsers.add_parser(
        "unregister",
        help="mark a remote fabric member as left",
    )
    mcp_fabric_member_unregister.add_argument("member_id", help="registered member id")
    _add_fabric_member_registry_args(mcp_fabric_member_unregister)


def _add_fabric_member_metadata_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--role",
        choices=("data-plane", "data_plane", "control-plane", "control_plane", "observer"),
        default="data-plane",
        help="member role",
    )
    parser.add_argument(
        "--status",
        choices=("active", "draining"),
        default="active",
        help="member routing status",
    )
    parser.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="member MCP upstream as NAME=URL; repeat for multiple upstreams",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=float,
        default=60.0,
        help="seconds until the member expires without another heartbeat",
    )
    parser.add_argument("--label", action="append", default=[], help="member label as KEY=VALUE")
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        help="member metadata as KEY=VALUE",
    )


def _handle_fabric_member_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    format_fabric_member_report: Any,
    heartbeat_fabric_member: Any,
    load_fabric_member_registry: Any,
    register_fabric_member: Any,
    summarize_fabric_members: Any,
    unregister_fabric_member: Any,
) -> int:
    if args.member_command == "list":
        registry = load_fabric_member_registry(args.registry, key=args.registry_key)
        result = {
            "ok": True,
            "registry": str(args.registry),
            "registry_key": args.registry_key,
            "registry_state": registry,
            "summary": summarize_fabric_members(registry),
        }
    elif args.member_command == "register":
        result = register_fabric_member(
            args.registry,
            key=args.registry_key,
            member_id=args.member_id,
            role=args.role,
            status=args.status,
            upstreams=_parse_member_upstreams(args.upstream),
            ttl_seconds=args.ttl_seconds,
            labels=_parse_key_values(args.label),
            metadata=_parse_key_values(args.metadata),
        )
    elif args.member_command == "agent":
        if args.interval <= 0:
            raise ValueError("--interval must be positive")
        result = register_fabric_member(
            args.registry,
            key=args.registry_key,
            member_id=args.member_id,
            role=args.role,
            status=args.status,
            upstreams=_parse_member_upstreams(args.upstream),
            ttl_seconds=args.ttl_seconds,
            labels=_parse_key_values(args.label),
            metadata={
                **_parse_key_values(args.metadata),
                "agent": "snulbug mcp fabric member agent",
            },
        )
        result["agent"] = {
            "running": not args.once,
            "interval_seconds": args.interval,
            "ttl_seconds": args.ttl_seconds,
            "unregister_on_exit": bool(args.unregister_on_exit),
        }
        if not args.once and result["ok"]:
            if not args.compact:
                sys.stdout.write(format_fabric_member_report(result))
                sys.stdout.write("\n")
                sys.stdout.flush()
            try:
                while True:
                    time.sleep(args.interval)
                    result = heartbeat_fabric_member(
                        args.registry,
                        key=args.registry_key,
                        member_id=args.member_id,
                        ttl_seconds=args.ttl_seconds,
                        status=args.status,
                    )
                    result["agent"] = {
                        "running": True,
                        "interval_seconds": args.interval,
                        "ttl_seconds": args.ttl_seconds,
                        "unregister_on_exit": bool(args.unregister_on_exit),
                    }
                    if not result["ok"]:
                        break
            except KeyboardInterrupt:
                if args.unregister_on_exit:
                    result = unregister_fabric_member(
                        args.registry,
                        key=args.registry_key,
                        member_id=args.member_id,
                    )
                result["agent"] = {
                    "running": False,
                    "interrupted": True,
                    "interval_seconds": args.interval,
                    "ttl_seconds": args.ttl_seconds,
                    "unregister_on_exit": bool(args.unregister_on_exit),
                }
    elif args.member_command == "heartbeat":
        result = heartbeat_fabric_member(
            args.registry,
            key=args.registry_key,
            member_id=args.member_id,
            ttl_seconds=args.ttl_seconds,
            status=args.status,
        )
    elif args.member_command == "unregister":
        result = unregister_fabric_member(args.registry, key=args.registry_key, member_id=args.member_id)
    else:
        parser.error(f"unknown mcp fabric member command: {args.member_command}")
        return 2

    status = 0 if result["ok"] else 1
    if not args.compact:
        sys.stdout.write(format_fabric_member_report(result))
        sys.stdout.write("\n")
        return status
    write_json_output(result, compact=True)
    return status


def _add_fabric_controller_command(
    mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mcp_fabric_controller = mcp_fabric_subparsers.add_parser(
        "controller",
        help="reconcile declarative MCP fabric config into a controller state snapshot",
    )
    mcp_fabric_controller.add_argument(
        "--config",
        type=Path,
        default=Path("snulbug.toml"),
        help="snulbug.toml config file",
    )
    mcp_fabric_controller.add_argument(
        "--state",
        type=Path,
        default=Path(".snulbug/fabric-state.json"),
        help="controller state snapshot path",
    )
    mcp_fabric_controller.add_argument(
        "--event-log",
        type=Path,
        default=Path(".snulbug/fabric-events.jsonl"),
        help="controller change event JSONL path",
    )
    mcp_fabric_controller.add_argument(
        "--no-event-log",
        action="store_true",
        help="do not append reconcile change events",
    )
    mcp_fabric_controller.add_argument("--interval", type=float, default=2.0, help="reconcile interval in seconds")
    mcp_fabric_controller.add_argument("--once", action="store_true", help="run one reconcile and exit")
    mcp_fabric_controller.add_argument(
        "--status-server",
        action="store_true",
        help="serve local /healthz, /status, and /metrics endpoints while running",
    )
    mcp_fabric_controller.add_argument("--status-host", default="127.0.0.1", help="status server bind host")
    mcp_fabric_controller.add_argument("--status-port", type=int, default=0, help="status server bind port")
    add_compact_arg(mcp_fabric_controller)


def _add_fabric_run_command(mcp_fabric_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_fabric_run = mcp_fabric_subparsers.add_parser(
        "run",
        help="run the fabric controller and live-reloading MCP data plane together",
    )
    mcp_fabric_run.add_argument("--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file")
    mcp_fabric_run.add_argument(
        "--state",
        type=Path,
        default=Path(".snulbug/fabric-state.json"),
        help="controller state snapshot path",
    )
    mcp_fabric_run.add_argument(
        "--event-log",
        type=Path,
        default=Path(".snulbug/fabric-events.jsonl"),
        help="controller change event JSONL path",
    )
    mcp_fabric_run.add_argument("--no-event-log", action="store_true", help="do not append reconcile change events")
    mcp_fabric_run.add_argument(
        "--controller-interval",
        type=float,
        default=2.0,
        help="controller reconcile interval in seconds",
    )
    mcp_fabric_run.add_argument(
        "--reload-interval",
        type=float,
        default=2.0,
        help="data-plane fabric reload interval in seconds",
    )
    mcp_fabric_run.add_argument("--status-host", default="127.0.0.1", help="status server bind host")
    mcp_fabric_run.add_argument("--status-port", type=int, default=8765, help="status server bind port")
    mcp_fabric_run.add_argument(
        "--conformance-pack",
        type=Path,
        help="generated fabric conformance pack to check before starting the data plane",
    )
    mcp_fabric_run.add_argument(
        "--require-conformance",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="block data-plane startup unless the configured conformance pack passes",
    )
    mcp_fabric_run.add_argument(
        "--runtime-state",
        default=DEFAULT_FABRIC_RUNTIME_STATE,
        help="'memory', 'none', 'sqlite:/path/to/state.sqlite3', or 'redis://...'",
    )
    mcp_fabric_run.add_argument(
        "--runtime-state-key",
        default=DEFAULT_FABRIC_RUNTIME_STATE_KEY,
        help="runtime state key for shared stores",
    )
    mcp_fabric_run.add_argument(
        "--runtime-heartbeat-ttl",
        type=float,
        default=15.0,
        help="seconds before persisted running runtime state is considered stale",
    )
    mcp_fabric_run.add_argument(
        "--runtime-instance-id",
        help="explicit managed data-plane owner id; defaults to a generated host/pid/id value",
    )
    mcp_fabric_run.add_argument(
        "--runtime-lease-ttl",
        type=float,
        default=DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
        help="seconds before another instance may acquire the shared runtime lease",
    )
    add_compact_arg(mcp_fabric_run, help="emit compact JSON startup output")


def _add_fabric_control_store_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--runtime-state",
        default=DEFAULT_FABRIC_RUNTIME_STATE,
        help="'memory', 'none', 'sqlite:/path/to/state.sqlite3', or 'redis://...'",
    )
    parser.add_argument(
        "--runtime-state-key",
        default=DEFAULT_FABRIC_RUNTIME_STATE_KEY,
        help="runtime state key for shared stores",
    )
    add_compact_arg(parser)


def _add_fabric_control_issue_args(parser: argparse.ArgumentParser, *, default_ttl: float | None = None) -> None:
    parser.add_argument("--reason", help="operator reason recorded with the control action")
    parser.add_argument("--actor", help="operator identity recorded with the control action")
    parser.add_argument(
        "--ttl-seconds",
        type=float,
        default=default_ttl,
        help="seconds before the control expires; omit for persistent controls",
    )


def _add_fabric_member_registry_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--registry",
        default=".snulbug/fabric-members.json",
        help="fabric member registry path, sqlite:/path/to/state.sqlite3, or redis://...",
    )
    parser.add_argument(
        "--registry-key",
        default="snulbug:fabric:members",
        help="fabric member registry key when --registry uses SQLite or Redis state",
    )
    add_compact_arg(parser)


def _parse_member_upstreams(values: Sequence[str]) -> list[dict[str, Any]]:
    upstreams = []
    for value in values:
        name, separator, url = str(value).partition("=")
        if not separator or not name or not url:
            raise ValueError("--upstream must use NAME=URL")
        upstreams.append({"name": name, "url": url, "tool_prefix": f"{name}."})
    return upstreams


def _parse_key_values(values: Sequence[str]) -> dict[str, str]:
    parsed = {}
    for value in values:
        key, separator, item = str(value).partition("=")
        if not separator or not key:
            raise ValueError("key/value options must use KEY=VALUE")
        parsed[key] = item
    return parsed


def status_server_url(status_server: Any) -> str:
    return f"http://{status_server.host}:{status_server.port}"

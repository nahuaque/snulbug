from __future__ import annotations

import argparse
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
)
from .common import read_required_env


def add_mcp_policy_command(
    mcp_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    bundle_states: Sequence[str],
) -> None:
    mcp_policy = mcp_subparsers.add_parser("policy", help="create, amend, and manage MCP policy bundles")
    mcp_policy_subparsers = mcp_policy.add_subparsers(dest="policy_command", required=True)

    mcp_policy_preset = mcp_policy_subparsers.add_parser("preset", help="list or copy a bundled MCP policy preset")
    mcp_policy_preset.add_argument(
        "preset",
        nargs="?",
        help="preset name to copy; omit to list presets unless --output is supplied",
    )
    mcp_policy_preset.add_argument("--output", "--out", type=Path, help="output bundle directory")
    add_force_arg(mcp_policy_preset, help="overwrite the output directory when it exists")
    add_token_arg(mcp_policy_preset, help="bearer token to render into generated policy")
    add_token_env_arg(
        mcp_policy_preset,
        help="context key used by generated policy for env-derived token lookup",
    )
    mcp_policy_preset.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    add_allow_path_arg(mcp_policy_preset, help="allowed project path or prefix")
    mcp_policy_preset.add_argument("--rate-limit", type=int, help="fixed-window request limit")
    mcp_policy_preset.add_argument("--rate-window", type=int, help="fixed-window duration in seconds")
    mcp_policy_preset.add_argument("--list", action="store_true", help="list bundled presets")
    add_compact_arg(mcp_policy_preset)

    mcp_policy_learn = mcp_policy_subparsers.add_parser(
        "learn",
        help="compile MCP replay or audit logs into a policy bundle",
    )
    mcp_policy_learn.add_argument("log", type=Path, help="JSONL replay or audit log")
    mcp_policy_learn.add_argument("--out", "--output", type=Path, required=True, help="output policy bundle directory")
    mcp_policy_learn.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    add_force_arg(mcp_policy_learn, help="overwrite files in the output directory")
    add_validate_arg(mcp_policy_learn, help="validate the generated policy bundle")
    add_compact_arg(mcp_policy_learn)

    mcp_policy_amend = mcp_policy_subparsers.add_parser(
        "amend",
        help="propose a candidate amendment for a learned MCP policy",
    )
    mcp_policy_amend.add_argument("bundle", type=Path, help="source learned policy bundle")
    mcp_policy_amend.add_argument("log", type=Path, help="JSONL replay or audit log containing blocked decisions")
    mcp_policy_amend.add_argument(
        "--out",
        "--output",
        type=Path,
        required=True,
        help="candidate output policy bundle directory",
    )
    mcp_policy_amend.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    add_force_arg(mcp_policy_amend, help="overwrite files in the output directory")
    mcp_policy_amend.add_argument(
        "--allow-risky",
        action="store_true",
        help="allow risky shell/exec-style tool names into the candidate policy",
    )
    add_validate_arg(mcp_policy_amend, help="validate the generated policy bundle")
    add_compact_arg(mcp_policy_amend)

    mcp_policy_lifecycle = mcp_policy_subparsers.add_parser(
        "lifecycle",
        help="inspect, sign, verify, or promote policy bundle lifecycle state",
    )
    mcp_policy_lifecycle_subparsers = mcp_policy_lifecycle.add_subparsers(
        dest="policy_lifecycle_command",
        required=True,
    )
    mcp_policy_lifecycle_status = mcp_policy_lifecycle_subparsers.add_parser(
        "status",
        help="inspect policy bundle lifecycle metadata",
    )
    mcp_policy_lifecycle_status.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    add_compact_arg(mcp_policy_lifecycle_status)

    mcp_policy_lifecycle_sign = mcp_policy_lifecycle_subparsers.add_parser(
        "sign",
        help="sign current policy bundle lifecycle metadata",
    )
    mcp_policy_lifecycle_sign.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    mcp_policy_lifecycle_sign.add_argument("--state", choices=bundle_states, help="current lifecycle state to require")
    mcp_policy_lifecycle_sign.add_argument("--key-id", required=True, help="bundle signing key id")
    mcp_policy_lifecycle_sign.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    mcp_policy_lifecycle_sign.add_argument("--actor", help="actor to record in lifecycle history")
    mcp_policy_lifecycle_sign.add_argument("--note", help="note to record in lifecycle history")
    add_compact_arg(mcp_policy_lifecycle_sign)

    mcp_policy_lifecycle_verify = mcp_policy_lifecycle_subparsers.add_parser(
        "verify",
        help="verify signed policy bundle lifecycle metadata",
    )
    mcp_policy_lifecycle_verify.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    mcp_policy_lifecycle_verify.add_argument("--state", choices=bundle_states, help="required lifecycle state")
    mcp_policy_lifecycle_verify.add_argument(
        "--key-id",
        help="bundle signing key id; defaults to lifecycle signature key_id",
    )
    mcp_policy_lifecycle_verify.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    add_compact_arg(mcp_policy_lifecycle_verify)

    mcp_policy_lifecycle_promote = mcp_policy_lifecycle_subparsers.add_parser(
        "promote",
        help="advance a signed policy bundle through observed, proposed, approved, and active",
    )
    mcp_policy_lifecycle_promote.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    mcp_policy_lifecycle_promote.add_argument(
        "--to",
        choices=("next", *bundle_states),
        default="next",
        help="target lifecycle state; defaults to next",
    )
    mcp_policy_lifecycle_promote.add_argument("--key-id", required=True, help="bundle signing key id")
    mcp_policy_lifecycle_promote.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    mcp_policy_lifecycle_promote.add_argument("--actor", help="actor to record in lifecycle history")
    mcp_policy_lifecycle_promote.add_argument("--note", help="note to record in lifecycle history")
    mcp_policy_lifecycle_promote.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_policy_lifecycle_promote.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    add_compact_arg(mcp_policy_lifecycle_promote)


def handle_mcp_policy_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> tuple[dict[str, Any], int]:
    from ..presets import McpPolicyOptions, generate_mcp_preset, list_builtin_presets

    try:
        if args.policy_command == "preset":
            customized = any(
                (
                    args.token,
                    args.token_env,
                    args.allow_tool,
                    args.allow_path,
                    args.rate_limit,
                    args.rate_window,
                )
            )
            if args.list or (args.preset is None and args.output is None and not customized):
                return {"presets": list_builtin_presets()}, 0

            preset = args.preset or "local-dev-safe"
            output = args.output or Path(f"{preset}.snulbug")
            result = generate_mcp_preset(
                preset,
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
                f"uv run snulbug bundle validate {output}",
                f"uv run snulbug bundle test {output}",
            ]
            return result, 0

        if args.policy_command == "learn":
            from ..learn import learn_mcp_policy

            result = learn_mcp_policy(
                args.log,
                args.out,
                kind=args.kind,
                force=args.force,
                validate=args.validate,
            )
            return result, 0 if result["ok"] else 1

        if args.policy_command == "amend":
            from ..learn import amend_mcp_policy

            result = amend_mcp_policy(
                args.bundle,
                args.log,
                args.out,
                kind=args.kind,
                force=args.force,
                validate=args.validate,
                allow_risky=args.allow_risky,
            )
            return result, 0 if result["ok"] else 1

        if args.policy_command == "lifecycle":
            return _handle_mcp_policy_lifecycle_command(args, parser)

        parser.error(f"unknown mcp policy command: {args.policy_command}")
        raise AssertionError("argparse parser.error should exit")
    except Exception as exc:
        result: dict[str, Any] = {"ok": False, "error": str(exc)}
        if hasattr(args, "bundle") and args.bundle is not None:
            result["bundle"] = str(args.bundle)
        if hasattr(args, "log") and args.log is not None:
            result["log"] = str(args.log)
        if hasattr(args, "out") and args.out is not None:
            result["output"] = str(args.out)
        if hasattr(args, "catalog") and args.catalog is not None:
            result["catalog"] = str(args.catalog)
        return result, 1


def _handle_mcp_policy_lifecycle_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> tuple[dict[str, Any], int]:
    from ..bundle import (
        inspect_bundle_lifecycle,
        promote_bundle_lifecycle,
        sign_bundle_lifecycle,
        verify_bundle_lifecycle,
    )

    if args.policy_lifecycle_command == "status":
        return inspect_bundle_lifecycle(args.bundle), 0

    if args.policy_lifecycle_command == "sign":
        result = sign_bundle_lifecycle(
            args.bundle,
            secret=read_required_env(args.secret_env),
            key_id=args.key_id,
            state=args.state,
            actor=args.actor,
            note=args.note,
        )
        return result, 0

    if args.policy_lifecycle_command == "verify":
        lifecycle = inspect_bundle_lifecycle(args.bundle)
        signature = lifecycle.get("signature") if isinstance(lifecycle, Mapping) else None
        signature_key_id = signature.get("key_id") if isinstance(signature, Mapping) else None
        key_id = args.key_id or signature_key_id
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("bundle key_id is required; pass --key-id or include a lifecycle signature key_id")
        result = {
            "ok": True,
            "bundle": str(args.bundle),
            "verified": verify_bundle_lifecycle(
                args.bundle,
                secrets={key_id: read_required_env(args.secret_env)},
                required_state=args.state,
            ),
        }
        return result, 0

    if args.policy_lifecycle_command == "promote":
        memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
        result = promote_bundle_lifecycle(
            args.bundle,
            to_state=args.to,
            secret=read_required_env(args.secret_env),
            key_id=args.key_id,
            actor=args.actor,
            note=args.note,
            instruction_limit=args.instruction_limit,
            memory_limit_bytes=memory_limit,
        )
        return result, 0 if result["ok"] else 1

    parser.error(f"unknown mcp policy lifecycle command: {args.policy_lifecycle_command}")
    raise AssertionError("argparse parser.error should exit")

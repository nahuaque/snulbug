from __future__ import annotations

import argparse
from pathlib import Path

from ..cli_helpers import (
    add_allow_path_arg,
    add_compact_arg,
    add_force_arg,
    add_report_out_arg,
    add_sarif_out_arg,
    add_token_arg,
    add_token_env_arg,
    add_validate_arg,
    write_report_output,
    write_sarif_output,
)


def add_mcp_policy_schemas_command(policy_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    mcp_schemas = policy_subparsers.add_parser(
        "schemas",
        help="discover, diff, and generate policies from MCP capability schemas",
    )
    mcp_schemas_subparsers = mcp_schemas.add_subparsers(dest="schemas_command", required=True)
    mcp_schemas_discover = mcp_schemas_subparsers.add_parser(
        "discover",
        help="capture MCP initialize, tools, resources, resource templates, and prompts schemas",
    )
    mcp_schemas_discover_source = mcp_schemas_discover.add_mutually_exclusive_group(required=True)
    mcp_schemas_discover_source.add_argument(
        "--from",
        dest="source",
        type=Path,
        help="JSON file containing MCP method responses or an existing schema catalog",
    )
    mcp_schemas_discover_source.add_argument("--url", help="MCP HTTP URL to probe")
    mcp_schemas_discover.add_argument(
        "--method",
        action="append",
        choices=(
            "initialize",
            "tools",
            "tools/list",
            "resources",
            "resources/list",
            "resource-templates",
            "resource_templates",
            "resources/templates/list",
            "prompts",
            "prompts/list",
        ),
        help="MCP method or surface to discover; repeat to limit the catalog",
    )
    mcp_schemas_discover.add_argument("--header", action="append", default=[], help="HTTP header as 'Name: value'")
    add_token_arg(mcp_schemas_discover, help="bearer token for live MCP schema discovery")
    mcp_schemas_discover.add_argument("--timeout", type=float, default=10.0, help="live discovery timeout in seconds")
    mcp_schemas_discover.add_argument(
        "--protocol-version",
        default="2025-06-18",
        help="MCP protocol version sent in live discovery requests",
    )
    mcp_schemas_discover.add_argument("--label", help="human label stored in the catalog")
    mcp_schemas_discover.add_argument("--out", type=Path, help="write schema catalog JSON to this path")
    add_report_out_arg(mcp_schemas_discover, help="write a Markdown schema report")
    add_compact_arg(mcp_schemas_discover)

    mcp_schemas_diff = mcp_schemas_subparsers.add_parser("diff", help="compare two MCP schema catalogs")
    mcp_schemas_diff.add_argument("baseline", type=Path, help="baseline catalog or response collection JSON")
    mcp_schemas_diff.add_argument("current", type=Path, help="current catalog or response collection JSON")
    mcp_schemas_diff.add_argument(
        "--fail-on",
        action="append",
        default=[],
        choices=("added", "changed", "removed", "any"),
        help="return exit code 1 when this change type is present; repeat or use any",
    )
    add_report_out_arg(mcp_schemas_diff, help="write a Markdown schema diff report")
    add_sarif_out_arg(mcp_schemas_diff, help="write a SARIF schema gate report")
    add_compact_arg(mcp_schemas_diff)

    mcp_schemas_generate = mcp_schemas_subparsers.add_parser(
        "generate",
        help="generate a reviewable policy bundle from an MCP schema catalog",
    )
    mcp_schemas_generate.add_argument("catalog", type=Path, help="MCP schema catalog JSON")
    mcp_schemas_generate.add_argument(
        "--out",
        "--output",
        type=Path,
        required=True,
        help="output policy bundle directory",
    )
    add_force_arg(mcp_schemas_generate, help="overwrite the output directory")
    add_token_arg(mcp_schemas_generate, help="bearer token to render into the generated policy")
    add_token_env_arg(
        mcp_schemas_generate,
        help="context key used by generated policy for env-derived token lookup",
    )
    add_allow_path_arg(
        mcp_schemas_generate,
        help="allowed project path or prefix for path-like tool arguments; repeat to add multiple",
    )
    mcp_schemas_generate.add_argument(
        "--high-risk-action",
        choices=("allow", "confirm", "reject"),
        default="confirm",
        help="action for tools scored high risk from the discovered schema",
    )
    add_validate_arg(mcp_schemas_generate, help="validate and test the generated policy bundle")
    add_compact_arg(mcp_schemas_generate)


def handle_mcp_schemas_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> tuple[dict, int, object | None]:
    from ..mcp_schema_policy import (
        SchemaPolicyOptions,
        format_mcp_schema_policy_report,
        generate_mcp_schema_policy,
    )
    from ..mcp_schemas import (
        diff_mcp_schema_catalogs,
        discover_mcp_schemas,
        format_mcp_schema_catalog_report,
        format_mcp_schema_diff_report,
        parse_mcp_schema_headers,
    )

    try:
        if args.schemas_command == "discover":
            result = discover_mcp_schemas(
                source=args.source,
                url=args.url,
                headers=parse_mcp_schema_headers(args.header, token=args.token),
                token=args.token,
                timeout=args.timeout,
                label=args.label,
                out=args.out,
                report_out=args.report_out,
                methods=args.method,
                protocol_version=args.protocol_version,
            )
            return result, 0, format_mcp_schema_catalog_report
        elif args.schemas_command == "diff":
            result = diff_mcp_schema_catalogs(args.baseline, args.current, fail_on=args.fail_on)
            status = 0 if result["ok"] else 1
            if args.report_out is not None:
                write_report_output(
                    args.report_out,
                    format_mcp_schema_diff_report(result),
                    result,
                    trailing_newline=True,
                )
            if args.sarif_out is not None:
                from ..sarif import sarif_for_schema_diff

                write_sarif_output(args.sarif_out, sarif_for_schema_diff(result), result)
            return result, status, format_mcp_schema_diff_report
        elif args.schemas_command == "generate":
            result = generate_mcp_schema_policy(
                args.catalog,
                args.out,
                options=SchemaPolicyOptions(
                    token=args.token,
                    token_env=args.token_env,
                    allowed_paths=args.allow_path,
                    high_risk_action=args.high_risk_action,
                ),
                force=args.force,
                validate=args.validate,
            )
            status = 0 if result["ok"] else 1
            return result, status, format_mcp_schema_policy_report
        else:
            parser.error(f"unknown mcp policy schemas command: {args.schemas_command}")
            raise AssertionError("argparse parser.error should exit")
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}
        if hasattr(args, "source") and args.source is not None:
            result["source"] = str(args.source)
        if hasattr(args, "catalog") and args.catalog is not None:
            result["catalog"] = str(args.catalog)
        if hasattr(args, "url") and args.url is not None:
            result["url"] = args.url
        status = 1

    return result, status, None

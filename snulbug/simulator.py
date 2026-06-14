from __future__ import annotations

import argparse
import base64
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .cli.common import read_json, read_required_env
from .cli.evidence import add_mcp_evidence_command, handle_mcp_evidence_command
from .cli.fabric import add_mcp_fabric_command, handle_mcp_fabric_command
from .cli.policy import add_mcp_policy_command, handle_mcp_policy_command
from .cli.schemas import (
    add_mcp_schemas_command,
    add_mcp_tools_command,
    handle_mcp_schemas_command,
    handle_mcp_tools_command,
)
from .cli_helpers import (
    add_allow_path_arg,
    add_compact_arg,
    add_force_arg,
    add_report_out_arg,
    add_token_arg,
    add_token_env_arg,
    add_validate_arg,
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

    bundle_states = ("observed", "proposed", "approved", "active")

    tunnel = subparsers.add_parser("tunnel", help="work with public tunnel interop checks")
    tunnel_subparsers = tunnel.add_subparsers(dest="tunnel_command", required=True)

    tunnel_init = tunnel_subparsers.add_parser("init", help="generate provider-specific tunnel setup snippets")
    tunnel_init.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        required=True,
        help="tunnel provider profile",
    )
    tunnel_init.add_argument("--config", type=Path, help="snulbug.toml config file")
    tunnel_init.add_argument("--local-url", help="local snulbug MCP URL or origin")
    tunnel_init.add_argument("--url", "--public-url", dest="url", help="public tunnel MCP URL")
    tunnel_init.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    add_token_env_arg(tunnel_init, default="SNULBUG_TOKEN", help="environment variable holding bearer token")
    tunnel_init.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_init.add_argument("--output-dir", type=Path, help="optional directory for generated setup files")
    add_force_arg(tunnel_init, help="overwrite generated files")
    add_compact_arg(tunnel_init)

    tunnel_doctor = tunnel_subparsers.add_parser("doctor", help="verify tunnel-safe MCP proxy exposure")
    tunnel_doctor.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        default="generic",
        help="tunnel provider profile",
    )
    tunnel_doctor.add_argument("--url", "--public-url", dest="url", help="public tunnel URL to check")
    tunnel_doctor.add_argument("--local-url", help="local snulbug proxy URL to check")
    tunnel_doctor.add_argument("--config", type=Path, help="snulbug.toml config file")
    tunnel_doctor.add_argument(
        "--header",
        "--auth-header",
        action="append",
        default=[],
        help="authenticated probe header as 'Name: value'; repeat for multiple headers",
    )
    add_token_arg(tunnel_doctor, help="bearer token for authenticated MCP probes")
    tunnel_doctor.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    add_compact_arg(tunnel_doctor)

    expose = subparsers.add_parser("expose", help="plan a tunnel-safe MCP exposure session")
    expose.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        required=True,
        help="tunnel provider or peer bridge profile",
    )
    expose.add_argument("--config", type=Path, help="snulbug.toml config file")
    expose.add_argument("--local-url", help="local snulbug MCP URL or origin")
    expose.add_argument("--url", "--public-url", dest="url", help="public tunnel MCP URL")
    expose.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    add_token_env_arg(expose, default="SNULBUG_TOKEN", help="environment variable holding bearer token")
    expose.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    expose.add_argument("--output-dir", type=Path, help="optional directory for generated setup files")
    add_report_out_arg(expose, help="session report path for the generated inspect command")
    expose.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include decision-console mode in the proxy command",
    )
    add_force_arg(expose, help="overwrite generated files")
    expose.add_argument("--dry-run", action="store_true", help="print the exposure plan without writing files")
    add_compact_arg(expose)

    mcp = subparsers.add_parser("mcp", help="work with local-dev MCP policy helpers and presets")
    mcp_subparsers = mcp.add_subparsers(
        dest="mcp_command",
        required=True,
        metavar=("{guide,policy,quickstart,codespace,share,config,schemas,fabric,manifest,lease,evidence,lab,proxy}"),
    )

    mcp_guide = mcp_subparsers.add_parser("guide", help="print agent-oriented MCP workflow guidance")
    mcp_guide.add_argument(
        "--workflow",
        choices=("all", "share", "tunnel", "learn-amend-impact", "leases", "facade"),
        default="all",
        help="workflow to print",
    )
    add_compact_arg(mcp_guide)

    add_mcp_policy_command(mcp_subparsers, bundle_states=bundle_states)

    mcp_quickstart = mcp_subparsers.add_parser("quickstart", help="create a local MCP policy proxy starter")
    mcp_quickstart.add_argument("--directory", "--dir", type=Path, default=Path("."), help="starter output directory")
    mcp_quickstart.add_argument("--preset", default="local-dev-safe", help="MCP preset to generate")
    mcp_quickstart.add_argument("--policy-output", type=Path, default=Path("policy.snulbug"), help="policy bundle path")
    mcp_quickstart.add_argument("--config-output", type=Path, default=Path("snulbug.toml"), help="config file path")
    mcp_quickstart.add_argument("--traces-dir", type=Path, default=Path("traces"), help="trace directory path")
    mcp_quickstart.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server URL")
    add_token_arg(mcp_quickstart, help="bearer token to render into generated policy")
    add_token_env_arg(mcp_quickstart, help="context key used by generated policy for env-derived token lookup")
    mcp_quickstart.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    add_allow_path_arg(mcp_quickstart, help="allowed project path or prefix")
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
    mcp_quickstart.add_argument(
        "--confirm",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="prompt before executing Lua confirm decisions",
    )
    mcp_quickstart.add_argument("--max-body-bytes", type=int, default=65536)
    mcp_quickstart.add_argument("--response-max-bytes", type=int, default=262144)
    mcp_quickstart.add_argument(
        "--response-redact-secrets",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="redact likely secrets from MCP tool/resource/prompt responses",
    )
    mcp_quickstart.add_argument(
        "--response-block-instructions",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="block MCP responses containing instruction-like text",
    )
    mcp_quickstart.add_argument(
        "--tool-pinning",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="pin tools/list descriptions and schemas on first sight",
    )
    mcp_quickstart.add_argument(
        "--tool-pinning-action",
        choices=("warn", "block"),
        default="block",
        help="what to do when a pinned tool description or schema changes",
    )
    mcp_quickstart.add_argument(
        "--schema-validation",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate tools/call arguments against cached MCP inputSchema definitions",
    )
    mcp_quickstart.add_argument(
        "--schema-validation-action",
        choices=("warn", "block"),
        default="block",
        help="what to do when tools/call arguments violate the cached inputSchema",
    )
    mcp_quickstart.add_argument("--lease-file", type=Path, default=Path("leases.json"), help="task lease JSON file")
    mcp_quickstart.add_argument(
        "--lease-required",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require a valid task lease for MCP tools/call requests",
    )
    mcp_quickstart.add_argument(
        "--lease-header",
        default="x-snulbug-lease",
        help="HTTP header carrying the task lease token",
    )
    mcp_quickstart.add_argument(
        "--tunnel-provider",
        choices=("auto", "generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        default="auto",
        help="provider label for tunnel-aware audit fields",
    )
    mcp_quickstart.add_argument("--tunnel-public-url", help="public tunnel URL to include in audit fields")
    mcp_quickstart.add_argument(
        "--cloudflare-access",
        choices=("off", "audit", "enforce"),
        default="off",
        help="origin-side Cloudflare Access header mode",
    )
    mcp_quickstart.add_argument(
        "--cloudflare-access-require-jwt",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require CF-Access-Jwt-Assertion when Cloudflare Access enforcement is enabled",
    )
    mcp_quickstart.add_argument(
        "--cloudflare-access-require-email",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require CF-Access-Authenticated-User-Email when Cloudflare Access enforcement is enabled",
    )
    mcp_quickstart.add_argument(
        "--cloudflare-access-require-cf-ray",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require a CF-Ray header when Cloudflare Access enforcement is enabled",
    )
    mcp_quickstart.add_argument(
        "--cloudflare-access-allow-email",
        action="append",
        default=[],
        help="allowed Cloudflare Access authenticated user email; repeat for multiple emails",
    )
    mcp_quickstart.add_argument(
        "--cloudflare-access-allow-domain",
        action="append",
        default=[],
        help="allowed Cloudflare Access authenticated email domain; repeat for multiple domains",
    )
    mcp_quickstart.add_argument("--timeout", type=float, default=30.0, help="upstream timeout in seconds")
    add_force_arg(mcp_quickstart, help="overwrite generated policy and config")
    add_validate_arg(mcp_quickstart, help="validate and test the generated policy bundle")
    add_compact_arg(mcp_quickstart)

    mcp_codespace = mcp_subparsers.add_parser("codespace", help="attach GitHub Codespace MCP upstreams")
    mcp_codespace_subparsers = mcp_codespace.add_subparsers(dest="codespace_command", required=True)
    mcp_codespace_attach = mcp_codespace_subparsers.add_parser(
        "attach",
        help="start a local gateway for one Codespaces forwarded MCP URL",
    )
    mcp_codespace_attach.add_argument(
        "url",
        help="Codespaces forwarded MCP URL, such as https://NAME-9001.app.github.dev/mcp",
    )
    mcp_codespace_attach.add_argument("--name", default="codespace-files", help="facade upstream name")
    mcp_codespace_attach.add_argument(
        "--tool-prefix",
        default="codespace.files.",
        help="tool prefix exposed by the local facade",
    )
    mcp_codespace_attach.add_argument(
        "--directory",
        type=Path,
        default=Path(".snulbug/codespace-local"),
        help="generated local gateway artifact directory",
    )
    mcp_codespace_attach.add_argument("--host", default="127.0.0.1", help="local gateway bind host")
    mcp_codespace_attach.add_argument("--port", type=int, default=8080, help="local gateway bind port")
    mcp_codespace_attach.add_argument(
        "--state",
        default="memory",
        help="'memory', 'none', or sqlite:/path/to/state.sqlite3",
    )
    mcp_codespace_attach.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="print live redacted policy decisions while proxying",
    )
    mcp_codespace_attach.add_argument(
        "--smoke-check",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="preflight the remote upstream with tools/list before starting the gateway",
    )
    mcp_codespace_attach.add_argument("--smoke-timeout", type=float, default=5.0, help="smoke-check timeout in seconds")
    mcp_codespace_attach.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite generated local gateway files",
    )
    mcp_codespace_attach.add_argument(
        "--dry-run",
        action="store_true",
        help="write artifacts and print the plan without starting the gateway",
    )
    add_compact_arg(mcp_codespace_attach)
    mcp_codespace_serve_demo = mcp_codespace_subparsers.add_parser(
        "serve-demo",
        help="run the bundled mock MCP server inside a Codespace",
    )
    mcp_codespace_serve_demo.add_argument("--host", default="0.0.0.0", help="demo MCP server bind host")
    mcp_codespace_serve_demo.add_argument("--port", type=int, default=9001, help="demo MCP server bind port")
    mcp_codespace_serve_demo.add_argument("--name", default="codespace", help="demo MCP server name")
    mcp_codespace_serve_demo.add_argument("--path", default="/mcp", help="MCP HTTP path")
    mcp_codespace_serve_demo.add_argument(
        "--ready-check",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="verify local tools/list before printing the laptop attach command",
    )
    mcp_codespace_serve_demo.add_argument("--ready-timeout", type=float, default=5.0, help="ready-check timeout")
    mcp_codespace_serve_demo.add_argument(
        "--dry-run",
        action="store_true",
        help="print the inferred URLs and commands without starting the server",
    )
    add_compact_arg(mcp_codespace_serve_demo)

    mcp_share = mcp_subparsers.add_parser(
        "share",
        help="create an ephemeral MCP share session with bearer auth, lease, tunnel setup, and client config",
    )
    mcp_share.add_argument("--directory", type=Path, help="share session directory")
    mcp_share.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        default="holepunch",
        help="tunnel or peer bridge provider",
    )
    mcp_share.add_argument("--preset", default="tunnel-safe", help="MCP policy preset")
    mcp_share.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server")
    mcp_share.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    mcp_share.add_argument("--url", "--public-url", dest="url", help="public tunnel or client bridge MCP URL")
    add_token_arg(mcp_share, help="bearer token; defaults to a generated session token")
    mcp_share.add_argument("--ttl", default="30m", help="share lease TTL, such as 30m, 2h, or 1d")
    mcp_share.add_argument("--task", default="Ephemeral MCP share session", help="human-readable share task")
    mcp_share.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    add_allow_path_arg(mcp_share, help="allowed path or path prefix")
    mcp_share.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    mcp_share.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    mcp_share.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    mcp_share.add_argument("--host", default="127.0.0.1", help="proxy bind host")
    mcp_share.add_argument("--port", type=int, default=8080, help="proxy bind port")
    mcp_share.add_argument("--state", default="memory", help="'memory', 'none', or 'sqlite:/path/to/state.sqlite3'")
    mcp_share.add_argument(
        "--lease-required",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require a valid task lease for MCP tools/call requests",
    )
    mcp_share.add_argument(
        "--lease-header",
        default="x-snulbug-lease",
        help="HTTP header carrying the task lease token",
    )
    mcp_share.add_argument("--client-name", default="snulbug-share", help="MCP client config server name")
    add_force_arg(mcp_share, help="overwrite generated share files")
    add_validate_arg(mcp_share, help="validate and test the generated policy bundle")
    add_compact_arg(mcp_share)

    mcp_config = mcp_subparsers.add_parser("config", help="work with MCP TOML config files")
    mcp_config_subparsers = mcp_config.add_subparsers(dest="config_command", required=True)
    mcp_config_init = mcp_config_subparsers.add_parser("init", help="write a starter snulbug.toml config")
    mcp_config_init.add_argument("--output", type=Path, default=Path("snulbug.toml"), help="config file path")
    add_force_arg(mcp_config_init, help="overwrite the config file when it exists")
    add_compact_arg(mcp_config_init)

    add_mcp_tools_command(mcp_subparsers)
    add_mcp_schemas_command(mcp_subparsers)
    add_mcp_fabric_command(mcp_subparsers)

    mcp_manifest = mcp_subparsers.add_parser("manifest", help="sign and verify MCP upstream manifests")
    mcp_manifest_subparsers = mcp_manifest.add_subparsers(dest="manifest_command", required=True)
    mcp_manifest_sign = mcp_manifest_subparsers.add_parser("sign", help="sign an upstream manifest JSON file")
    mcp_manifest_sign.add_argument("manifest", type=Path, help="unsigned upstream manifest JSON file")
    mcp_manifest_sign.add_argument("--out", "--output", type=Path, required=True, help="signed manifest output path")
    mcp_manifest_sign.add_argument("--key-id", required=True, help="manifest signing key id")
    mcp_manifest_sign.add_argument(
        "--secret-env",
        default="SNULBUG_MANIFEST_SECRET",
        help="environment variable containing the manifest signing secret",
    )
    add_compact_arg(mcp_manifest_sign)
    mcp_manifest_verify = mcp_manifest_subparsers.add_parser("verify", help="verify a signed upstream manifest")
    mcp_manifest_verify.add_argument("manifest", type=Path, help="signed upstream manifest JSON file")
    mcp_manifest_verify.add_argument("--key-id", help="manifest signing key id; defaults to the manifest key_id")
    mcp_manifest_verify.add_argument(
        "--secret-env",
        default="SNULBUG_MANIFEST_SECRET",
        help="environment variable containing the manifest signing secret",
    )
    mcp_manifest_verify.add_argument("--expect-identity", help="required manifest identity")
    add_compact_arg(mcp_manifest_verify)

    mcp_lease = mcp_subparsers.add_parser("lease", help="create and manage task-scoped MCP capability leases")
    mcp_lease_subparsers = mcp_lease.add_subparsers(dest="lease_command", required=True)

    mcp_lease_create = mcp_lease_subparsers.add_parser("create", help="create a task-scoped MCP capability lease")
    mcp_lease_create.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    mcp_lease_create.add_argument("--task", required=True, help="human-readable task this lease grants")
    mcp_lease_create.add_argument("--allow-tool", action="append", required=True, help="allowed MCP tool name")
    add_allow_path_arg(mcp_lease_create, help="allowed path or path prefix")
    mcp_lease_create.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    mcp_lease_create.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    mcp_lease_create.add_argument("--ttl", default="1h", help="lease TTL, such as 30m, 2h, or 1d")
    mcp_lease_create.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    add_compact_arg(mcp_lease_create)

    mcp_lease_list = mcp_lease_subparsers.add_parser("list", help="list task-scoped MCP capability leases")
    mcp_lease_list.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    mcp_lease_list.add_argument("--active-only", action="store_true", help="show only active leases")
    add_compact_arg(mcp_lease_list)

    mcp_lease_revoke = mcp_lease_subparsers.add_parser("revoke", help="revoke a task-scoped MCP capability lease")
    mcp_lease_revoke.add_argument("lease_id", help="lease id to revoke")
    mcp_lease_revoke.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    add_compact_arg(mcp_lease_revoke)

    add_mcp_evidence_command(mcp_subparsers)

    mcp_lab = mcp_subparsers.add_parser("lab", help="run the one-command local MCP policy lab")
    mcp_lab.add_argument("--output-dir", type=Path, default=Path(".snulbug-lab"), help="lab artifact directory")
    mcp_lab.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite the lab artifact directory",
    )
    add_compact_arg(mcp_lab)

    mcp_proxy = mcp_subparsers.add_parser("proxy", help="run a local-dev MCP reverse proxy")
    mcp_proxy.add_argument("--config", type=Path, help="TOML config file")
    mcp_proxy.add_argument("--upstream", help="upstream MCP HTTP server URL")
    mcp_proxy.add_argument(
        "--facade-upstream",
        action="append",
        metavar="NAME=URL",
        help="add an MCP facade upstream; tools are exposed as NAME.tool_name",
    )
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
    mcp_proxy.add_argument(
        "--confirm",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="prompt before executing Lua confirm decisions",
    )
    mcp_proxy.add_argument("--max-body-bytes", type=int)
    mcp_proxy.add_argument("--response-max-bytes", type=int)
    mcp_proxy.add_argument(
        "--response-redact-secrets",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="redact likely secrets from MCP tool/resource/prompt responses",
    )
    mcp_proxy.add_argument(
        "--response-block-instructions",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="block MCP responses containing instruction-like text",
    )
    mcp_proxy.add_argument(
        "--tool-pinning",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="pin tools/list descriptions and schemas on first sight",
    )
    mcp_proxy.add_argument(
        "--tool-pinning-action",
        choices=("warn", "block"),
        help="what to do when a pinned tool description or schema changes",
    )
    mcp_proxy.add_argument(
        "--schema-validation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="validate tools/call arguments against cached MCP inputSchema definitions",
    )
    mcp_proxy.add_argument(
        "--schema-validation-action",
        choices=("warn", "block"),
        help="what to do when tools/call arguments violate the cached inputSchema",
    )
    mcp_proxy.add_argument(
        "--facade-health-routing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="track facade upstream health and skip unhealthy upstreams during routing",
    )
    mcp_proxy.add_argument(
        "--facade-health-failure-threshold",
        type=int,
        help="consecutive facade upstream failures before marking unhealthy",
    )
    mcp_proxy.add_argument(
        "--facade-health-cooldown-seconds",
        type=float,
        help="seconds before an unhealthy facade upstream is probed again",
    )
    mcp_proxy.add_argument(
        "--facade-health-exclude-unhealthy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="remove unhealthy facade upstreams from tools/list and tools/call routing",
    )
    mcp_proxy.add_argument("--lease-file", type=Path, help="task lease JSON file")
    mcp_proxy.add_argument(
        "--lease-required",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="require a valid task lease for MCP tools/call requests",
    )
    mcp_proxy.add_argument("--lease-header", help="HTTP header carrying the task lease token")
    mcp_proxy.add_argument(
        "--tunnel-provider",
        choices=("auto", "generic", "ngrok", "cloudflare", "tailscale", "localxpose", "pinggy", "holepunch"),
        help="provider label for tunnel-aware audit fields",
    )
    mcp_proxy.add_argument("--tunnel-public-url", help="public tunnel URL to include in audit fields")
    mcp_proxy.add_argument(
        "--cloudflare-access",
        choices=("off", "audit", "enforce"),
        help="origin-side Cloudflare Access header mode",
    )
    mcp_proxy.add_argument(
        "--cloudflare-access-require-jwt",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="require CF-Access-Jwt-Assertion when Cloudflare Access enforcement is enabled",
    )
    mcp_proxy.add_argument(
        "--cloudflare-access-require-email",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="require CF-Access-Authenticated-User-Email when Cloudflare Access enforcement is enabled",
    )
    mcp_proxy.add_argument(
        "--cloudflare-access-require-cf-ray",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="require a CF-Ray header when Cloudflare Access enforcement is enabled",
    )
    mcp_proxy.add_argument(
        "--cloudflare-access-allow-email",
        action="append",
        help="allowed Cloudflare Access authenticated user email; repeat for multiple emails",
    )
    mcp_proxy.add_argument(
        "--cloudflare-access-allow-domain",
        action="append",
        help="allowed Cloudflare Access authenticated email domain; repeat for multiple domains",
    )
    mcp_proxy.add_argument("--timeout", type=float, help="upstream timeout in seconds")
    mcp_proxy.add_argument(
        "--reload-fabric",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="hot-reload facade upstream routes from --config while the proxy runs",
    )
    mcp_proxy.add_argument(
        "--fabric-reload-interval",
        type=float,
        default=None,
        help="fabric hot-reload polling interval in seconds",
    )

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

    if args.command == "tunnel":
        from .tunnel import (
            doctor_tunnel,
            format_tunnel_doctor_report,
            format_tunnel_init_report,
            init_tunnel_provider,
            parse_tunnel_headers,
        )

        if args.tunnel_command == "init":
            try:
                result = init_tunnel_provider(
                    provider=args.provider,
                    config=args.config,
                    local_url=args.local_url,
                    public_url=args.url,
                    hostname=args.hostname,
                    token_env=args.token_env,
                    path=args.path,
                    output_dir=args.output_dir,
                    force=args.force,
                )
                status = 0
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}
                status = 1
        elif args.tunnel_command == "doctor":
            try:
                result = doctor_tunnel(
                    provider=args.provider,
                    url=args.url,
                    local_url=args.local_url,
                    config=args.config,
                    headers=parse_tunnel_headers(args.header, token=args.token),
                    path=args.path,
                    timeout=args.timeout,
                )
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}
                status = 1
        else:
            parser.error(f"unknown tunnel command: {args.tunnel_command}")
            return 2

        formatter = None
        if "checks" in result:
            formatter = format_tunnel_doctor_report
        elif "commands" in result:
            formatter = format_tunnel_init_report
        write_result_output(result, compact=args.compact, formatter=formatter)
        return status

    if args.command == "expose":
        from .expose import format_exposure_session_report, plan_exposure_session

        try:
            result = plan_exposure_session(
                provider=args.provider,
                config=args.config,
                local_url=args.local_url,
                public_url=args.url,
                hostname=args.hostname,
                token_env=args.token_env,
                path=args.path,
                output_dir=args.output_dir,
                report_out=args.report_out,
                decision_console=args.decision_console,
                force=args.force,
                dry_run=args.dry_run,
            )
            status = 0 if result["ok"] else 1
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
            status = 1

        write_result_output(result, compact=args.compact, formatter=format_exposure_session_report)
        return status

    if args.command == "mcp":
        from .config import (
            load_mcp_fabric_config,
            load_mcp_proxy_config,
            merge_mcp_proxy_config,
            normalize_mcp_fabric_config,
            normalize_mcp_proxy_config,
            write_sample_config,
        )
        from .leases import create_lease, list_leases, revoke_lease

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
            result, status = handle_mcp_policy_command(args, parser)
        elif args.mcp_command == "share":
            from .share import create_mcp_share

            try:
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
            except Exception as exc:
                result = {"ok": False, "directory": str(args.directory) if args.directory else None, "error": str(exc)}
                status = 1
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
            except Exception as exc:
                result = {"ok": False, "directory": str(args.directory), "error": str(exc)}
                status = 1
        elif args.mcp_command == "codespace":
            from .codespaces import (
                format_codespace_attach_report,
                format_codespace_demo_report,
                prepare_codespace_attach,
                prepare_codespace_demo,
                serve_codespace_demo,
                smoke_check_codespace_upstream,
            )

            if args.codespace_command == "attach":
                try:
                    result = prepare_codespace_attach(
                        args.url,
                        directory=args.directory,
                        name=args.name,
                        tool_prefix=args.tool_prefix,
                        host=args.host,
                        port=args.port,
                        state=args.state,
                        decision_console=args.decision_console,
                        force=args.force,
                    )
                    if args.smoke_check:
                        result["smoke_check"] = smoke_check_codespace_upstream(args.url, timeout=args.smoke_timeout)
                        if not result["smoke_check"]["ok"]:
                            status = 1
                            write_result_output(
                                result,
                                compact=args.compact,
                                formatter=format_codespace_attach_report,
                            )
                            return status
                    result["dry_run"] = bool(args.dry_run)
                    status = 0
                    if args.dry_run:
                        write_result_output(result, compact=args.compact, formatter=format_codespace_attach_report)
                        return status

                    import os

                    os.environ[result["env"]["name"]] = result["env"]["value"]
                    proxy_config = load_mcp_proxy_config(result["config"])
                    fabric_config = load_mcp_fabric_config(result["config"])
                    fabric_config["proxy"] = proxy_config
                    result["starting_proxy"] = True
                    write_result_output(result, compact=args.compact, formatter=format_codespace_attach_report)
                    sys.stdout.flush()

                    from .fabric import build_fabric_audit_metadata
                    from .proxy import run_proxy

                    _run_loaded_mcp_proxy(
                        proxy_config,
                        fabric_config,
                        build_fabric_audit_metadata=build_fabric_audit_metadata,
                        run_proxy=run_proxy,
                    )
                    return 0
                except Exception as exc:
                    result = {"ok": False, "url": args.url, "directory": str(args.directory), "error": str(exc)}
                    status = 1
                    write_json_output(result, compact=args.compact)
                    return status
            if args.codespace_command == "serve-demo":
                try:
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
                except Exception as exc:
                    result = {
                        "ok": False,
                        "host": args.host,
                        "port": args.port,
                        "path": args.path,
                        "error": str(exc),
                    }
                    write_json_output(result, compact=args.compact)
                    return 1
            parser.error(f"unknown mcp codespace command: {args.codespace_command}")
            return 2
        elif args.mcp_command == "config":
            if args.config_command == "init":
                try:
                    result = write_sample_config(args.output, force=args.force)
                    result["next_steps"] = [
                        "uv run snulbug mcp policy preset local-dev-safe --output policy.snulbug",
                        f"uv run snulbug mcp proxy --config {args.output}",
                    ]
                    status = 0
                except Exception as exc:
                    result = {"ok": False, "config": str(args.output), "error": str(exc)}
                    status = 1
            else:
                parser.error(f"unknown mcp config command: {args.config_command}")
                return 2
        elif args.mcp_command == "tools":
            return handle_mcp_tools_command(args, parser)
        elif args.mcp_command == "schemas":
            return handle_mcp_schemas_command(args, parser)
        elif args.mcp_command == "fabric":
            return handle_mcp_fabric_command(args, parser)
        elif args.mcp_command == "manifest":
            from .manifests import load_manifest, sign_upstream_manifest, verify_upstream_manifest, write_manifest

            try:
                secret = _read_required_env(args.secret_env)
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
                        raise ValueError(
                            "manifest key_id is required; pass --key-id or include snulbug_signature.key_id"
                        )
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
                    parser.error(f"unknown mcp manifest command: {args.manifest_command}")
                    return 2
                status = 0
            except Exception as exc:
                result = {"ok": False, "manifest": str(args.manifest), "error": str(exc)}
                status = 1
        elif args.mcp_command == "lease":
            try:
                if args.lease_command == "create":
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
                elif args.lease_command == "list":
                    result = list_leases(args.file, include_inactive=not args.active_only)
                elif args.lease_command == "revoke":
                    result = revoke_lease(args.file, args.lease_id)
                else:
                    parser.error(f"unknown mcp lease command: {args.lease_command}")
                    return 2
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "file": str(args.file), "error": str(exc)}
                status = 1
        elif args.mcp_command == "evidence":
            return handle_mcp_evidence_command(args, parser)
        elif args.mcp_command == "lab":
            from .lab import run_mcp_lab

            try:
                result = run_mcp_lab(args.output_dir, force=args.force, emit=not args.compact)
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "output_dir": str(args.output_dir), "error": str(exc)}
                status = 1
            if not args.compact:
                return status
        elif args.mcp_command == "proxy":
            from .fabric import build_fabric_audit_metadata
            from .proxy import run_proxy

            try:
                overrides = {
                    "upstream": args.upstream,
                    "upstreams": _parse_facade_upstreams(args.facade_upstream),
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
                    "confirm": args.confirm,
                    "max_body_bytes": args.max_body_bytes,
                    "response_max_bytes": args.response_max_bytes,
                    "response_redact_secrets": args.response_redact_secrets,
                    "response_block_instructions": args.response_block_instructions,
                    "tool_pinning": args.tool_pinning,
                    "tool_pinning_action": args.tool_pinning_action,
                    "schema_validation": args.schema_validation,
                    "schema_validation_action": args.schema_validation_action,
                    "facade_health_routing": args.facade_health_routing,
                    "facade_health_failure_threshold": args.facade_health_failure_threshold,
                    "facade_health_cooldown_seconds": args.facade_health_cooldown_seconds,
                    "facade_health_exclude_unhealthy": args.facade_health_exclude_unhealthy,
                    "lease_file": args.lease_file,
                    "lease_required": args.lease_required,
                    "lease_header": args.lease_header,
                    "tunnel_provider": args.tunnel_provider,
                    "tunnel_public_url": args.tunnel_public_url,
                    "cloudflare_access": args.cloudflare_access,
                    "cloudflare_access_require_jwt": args.cloudflare_access_require_jwt,
                    "cloudflare_access_require_email": args.cloudflare_access_require_email,
                    "cloudflare_access_require_cf_ray": args.cloudflare_access_require_cf_ray,
                    "cloudflare_access_allowed_emails": args.cloudflare_access_allow_email,
                    "cloudflare_access_allowed_domains": args.cloudflare_access_allow_domain,
                    "timeout": args.timeout,
                }
                if args.reload_fabric and args.config is None:
                    sys.stderr.write("snulbug proxy failed: --reload-fabric requires --config\n")
                    return 1
                if args.config is not None:
                    proxy_config = merge_mcp_proxy_config(load_mcp_proxy_config(args.config), overrides)
                    fabric_config = load_mcp_fabric_config(args.config)
                    fabric_config["proxy"] = proxy_config
                else:
                    if args.policy is None or (args.upstream is None and not args.facade_upstream):
                        sys.stderr.write(
                            "snulbug proxy failed: --policy and either --upstream or "
                            "--facade-upstream are required without --config\n"
                        )
                        return 1
                    proxy_config = normalize_mcp_proxy_config(overrides)
                    fabric_config = normalize_mcp_fabric_config({}, proxy_config=proxy_config)
                _run_loaded_mcp_proxy(
                    proxy_config,
                    fabric_config,
                    build_fabric_audit_metadata=build_fabric_audit_metadata,
                    run_proxy=run_proxy,
                    fabric_reload_config=args.config if args.reload_fabric else None,
                    fabric_reload_interval=args.fabric_reload_interval or 2.0,
                    fabric_reload_overrides=overrides if args.reload_fabric else None,
                )
            except Exception as exc:
                sys.stderr.write(f"snulbug proxy failed: {exc}\n")
                return 1
            return 0
        else:
            parser.error(f"unknown mcp command: {args.mcp_command}")
            return 2

        write_json_output(result, compact=args.compact)
        return status

    parser.error(f"unknown command: {args.command}")
    return 2


def _read_json(path: Path) -> Any:
    return read_json(path)


def _read_required_env(name: str) -> str:
    return read_required_env(name)


def _parse_facade_upstreams(values: Sequence[str] | None) -> list[dict[str, Any]] | None:
    if not values:
        return None
    upstreams = []
    for value in values:
        name, separator, url = value.partition("=")
        if not separator or not name or not url:
            raise ValueError("--facade-upstream must use NAME=URL")
        upstreams.append({"name": name, "url": url, "tool_prefix": f"{name}."})
    return upstreams


def _run_loaded_mcp_proxy(
    proxy_config: Mapping[str, Any],
    fabric_config: Mapping[str, Any],
    *,
    build_fabric_audit_metadata: Any,
    run_proxy: Any,
    fabric_reload_config: str | Path | None = None,
    fabric_reload_interval: float = 2.0,
    fabric_reload_overrides: Mapping[str, Any] | None = None,
) -> None:
    topology_audit = build_fabric_audit_metadata(fabric_config)
    run_proxy(
        upstream=proxy_config["upstream"],
        upstreams=proxy_config["upstreams"],
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
        confirm=proxy_config["confirm"],
        response_max_bytes=proxy_config["response_max_bytes"],
        response_redact_secrets=proxy_config["response_redact_secrets"],
        response_block_instructions=proxy_config["response_block_instructions"],
        tool_pinning=proxy_config["tool_pinning"],
        tool_pinning_action=proxy_config["tool_pinning_action"],
        schema_validation=proxy_config["schema_validation"],
        schema_validation_action=proxy_config["schema_validation_action"],
        facade_health_routing=proxy_config["facade_health_routing"],
        facade_health_failure_threshold=proxy_config["facade_health_failure_threshold"],
        facade_health_cooldown_seconds=proxy_config["facade_health_cooldown_seconds"],
        facade_health_exclude_unhealthy=proxy_config["facade_health_exclude_unhealthy"],
        lease_file=proxy_config["lease_file"],
        lease_required=proxy_config["lease_required"],
        lease_header=proxy_config["lease_header"],
        tunnel_provider=proxy_config["tunnel_provider"],
        tunnel_public_url=proxy_config["tunnel_public_url"],
        cloudflare_access=proxy_config["cloudflare_access"],
        cloudflare_access_require_jwt=proxy_config["cloudflare_access_require_jwt"],
        cloudflare_access_require_email=proxy_config["cloudflare_access_require_email"],
        cloudflare_access_require_cf_ray=proxy_config["cloudflare_access_require_cf_ray"],
        cloudflare_access_allowed_emails=proxy_config["cloudflare_access_allowed_emails"],
        cloudflare_access_allowed_domains=proxy_config["cloudflare_access_allowed_domains"],
        topology_audit=topology_audit,
        fabric_reload_config=fabric_reload_config,
        fabric_reload_interval=fabric_reload_interval,
        fabric_reload_overrides=fabric_reload_overrides,
    )


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

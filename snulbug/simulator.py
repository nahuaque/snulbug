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

    tunnel = subparsers.add_parser("tunnel", help="work with public tunnel interop checks")
    tunnel_subparsers = tunnel.add_subparsers(dest="tunnel_command", required=True)

    tunnel_init = tunnel_subparsers.add_parser("init", help="generate provider-specific tunnel setup snippets")
    tunnel_init.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "holepunch"),
        required=True,
        help="tunnel provider profile",
    )
    tunnel_init.add_argument("--config", type=Path, help="snulbug.toml config file")
    tunnel_init.add_argument("--local-url", help="local snulbug MCP URL or origin")
    tunnel_init.add_argument("--url", "--public-url", dest="url", help="public tunnel MCP URL")
    tunnel_init.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    tunnel_init.add_argument("--token-env", default="SNULBUG_TOKEN", help="environment variable holding bearer token")
    tunnel_init.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_init.add_argument("--output-dir", type=Path, help="optional directory for generated setup files")
    tunnel_init.add_argument("--force", action="store_true", help="overwrite generated files")
    tunnel_init.add_argument("--compact", action="store_true", help="emit compact JSON")

    tunnel_doctor = tunnel_subparsers.add_parser("doctor", help="verify tunnel-safe MCP proxy exposure")
    tunnel_doctor.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "holepunch"),
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
    tunnel_doctor.add_argument("--token", help="bearer token for authenticated MCP probes")
    tunnel_doctor.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    tunnel_doctor.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp = subparsers.add_parser("mcp", help="work with local-dev MCP policy helpers and presets")
    mcp_subparsers = mcp.add_subparsers(dest="mcp_command", required=True)

    mcp_guide = mcp_subparsers.add_parser("guide", help="print agent-oriented MCP workflow guidance")
    mcp_guide.add_argument(
        "--workflow",
        choices=("all", "share", "tunnel", "learn-amend-impact", "leases", "facade"),
        default="all",
        help="workflow to print",
    )
    mcp_guide.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_presets = mcp_subparsers.add_parser("presets", help="list bundled MCP policy presets")
    mcp_presets.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_quickstart = mcp_subparsers.add_parser("quickstart", help="create a local MCP policy proxy starter")
    mcp_quickstart.add_argument("--directory", "--dir", type=Path, default=Path("."), help="starter output directory")
    mcp_quickstart.add_argument("--preset", default="local-dev-safe", help="MCP preset to generate")
    mcp_quickstart.add_argument("--policy-output", type=Path, default=Path("policy.snulbug"), help="policy bundle path")
    mcp_quickstart.add_argument("--config-output", type=Path, default=Path("snulbug.toml"), help="config file path")
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
        choices=("auto", "generic", "ngrok", "cloudflare", "tailscale", "holepunch"),
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
    mcp_quickstart.add_argument("--force", action="store_true", help="overwrite generated policy and config")
    mcp_quickstart.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate and test the generated policy bundle",
    )
    mcp_quickstart.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_share = mcp_subparsers.add_parser(
        "share",
        help="create an ephemeral MCP share session with bearer auth, lease, tunnel setup, and client config",
    )
    mcp_share.add_argument("--directory", type=Path, help="share session directory")
    mcp_share.add_argument(
        "--provider",
        choices=("generic", "ngrok", "cloudflare", "tailscale", "holepunch"),
        default="holepunch",
        help="tunnel or peer bridge provider",
    )
    mcp_share.add_argument("--preset", default="tunnel-safe", help="MCP policy preset")
    mcp_share.add_argument("--upstream", default="http://127.0.0.1:9000", help="upstream MCP HTTP server")
    mcp_share.add_argument("--hostname", help="provider hostname to use when --url is omitted")
    mcp_share.add_argument("--url", "--public-url", dest="url", help="public tunnel or client bridge MCP URL")
    mcp_share.add_argument("--token", help="bearer token; defaults to a generated session token")
    mcp_share.add_argument("--ttl", default="30m", help="share lease TTL, such as 30m, 2h, or 1d")
    mcp_share.add_argument("--task", default="Ephemeral MCP share session", help="human-readable share task")
    mcp_share.add_argument("--allow-tool", action="append", default=[], help="allowed MCP tool name")
    mcp_share.add_argument("--allow-path", action="append", default=[], help="allowed path or path prefix")
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
    mcp_share.add_argument("--force", action="store_true", help="overwrite generated share files")
    mcp_share.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate and test the generated policy bundle",
    )
    mcp_share.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_config_init = mcp_config_subparsers.add_parser("init", help="write a starter snulbug.toml config")
    mcp_config_init.add_argument("--output", type=Path, default=Path("snulbug.toml"), help="config file path")
    mcp_config_init.add_argument("--force", action="store_true", help="overwrite the config file when it exists")
    mcp_config_init.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_fabric = mcp_subparsers.add_parser("fabric", help="inspect and verify declarative MCP fabric config")
    mcp_fabric_subparsers = mcp_fabric.add_subparsers(dest="fabric_command", required=True)
    mcp_fabric_status = mcp_fabric_subparsers.add_parser("status", help="summarize declared MCP fabric topology")
    mcp_fabric_status.add_argument("--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file")
    mcp_fabric_status.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_doctor.add_argument("--token", help="bearer token for authenticated MCP probes")
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
    mcp_fabric_doctor.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_manifest_sign.add_argument("--compact", action="store_true", help="emit compact JSON")
    mcp_manifest_verify = mcp_manifest_subparsers.add_parser("verify", help="verify a signed upstream manifest")
    mcp_manifest_verify.add_argument("manifest", type=Path, help="signed upstream manifest JSON file")
    mcp_manifest_verify.add_argument("--key-id", help="manifest signing key id; defaults to the manifest key_id")
    mcp_manifest_verify.add_argument(
        "--secret-env",
        default="SNULBUG_MANIFEST_SECRET",
        help="environment variable containing the manifest signing secret",
    )
    mcp_manifest_verify.add_argument("--expect-identity", help="required manifest identity")
    mcp_manifest_verify.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_lease = mcp_subparsers.add_parser("lease", help="create and manage task-scoped MCP capability leases")
    mcp_lease_subparsers = mcp_lease.add_subparsers(dest="lease_command", required=True)

    mcp_lease_create = mcp_lease_subparsers.add_parser("create", help="create a task-scoped MCP capability lease")
    mcp_lease_create.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    mcp_lease_create.add_argument("--task", required=True, help="human-readable task this lease grants")
    mcp_lease_create.add_argument("--allow-tool", action="append", required=True, help="allowed MCP tool name")
    mcp_lease_create.add_argument("--allow-path", action="append", default=[], help="allowed path or path prefix")
    mcp_lease_create.add_argument("--allow-host", action="append", default=[], help="allowed URL host")
    mcp_lease_create.add_argument("--allow-command", action="append", default=[], help="allowed command name")
    mcp_lease_create.add_argument("--ttl", default="1h", help="lease TTL, such as 30m, 2h, or 1d")
    mcp_lease_create.add_argument("--max-calls", type=int, help="maximum number of allowed tools/call uses")
    mcp_lease_create.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_lease_list = mcp_lease_subparsers.add_parser("list", help="list task-scoped MCP capability leases")
    mcp_lease_list.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    mcp_lease_list.add_argument("--active-only", action="store_true", help="show only active leases")
    mcp_lease_list.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_lease_revoke = mcp_lease_subparsers.add_parser("revoke", help="revoke a task-scoped MCP capability lease")
    mcp_lease_revoke.add_argument("lease_id", help="lease id to revoke")
    mcp_lease_revoke.add_argument("--file", type=Path, default=Path("leases.json"), help="lease JSON file")
    mcp_lease_revoke.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_inspect.add_argument("--report-out", type=Path, help="optional Markdown session report path")
    mcp_inspect.add_argument(
        "--report-format",
        choices=("markdown",),
        default="markdown",
        help="session report output format",
    )
    mcp_inspect.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_impact = mcp_subparsers.add_parser("impact", help="preview policy or lease impact against MCP replay logs")
    mcp_impact.add_argument("log", type=Path, help="JSONL replay log")
    mcp_impact.add_argument("--policy", type=Path, help="candidate policy to replay against the log")
    mcp_impact.add_argument("--lease", "--lease-file", dest="lease_file", type=Path, help="task lease JSON file")
    mcp_impact.add_argument("--instruction-limit", type=int, default=100_000)
    mcp_impact.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    mcp_impact.add_argument("--report-out", type=Path, help="optional Markdown impact report path")
    mcp_impact.add_argument(
        "--report-format",
        choices=("markdown",),
        default="markdown",
        help="impact report output format",
    )
    mcp_impact.add_argument("--no-fail", action="store_true", help="return exit code 0 even when impact has errors")
    mcp_impact.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_learn = mcp_subparsers.add_parser("learn", help="compile MCP replay or audit logs into a policy bundle")
    mcp_learn.add_argument("log", type=Path, help="JSONL replay or audit log")
    mcp_learn.add_argument("--out", "--output", type=Path, required=True, help="output policy bundle directory")
    mcp_learn.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    mcp_learn.add_argument("--force", action="store_true", help="overwrite files in the output directory")
    mcp_learn.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate the generated policy bundle",
    )
    mcp_learn.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_amend = mcp_subparsers.add_parser("amend", help="propose a candidate amendment for a learned MCP policy")
    mcp_amend.add_argument("bundle", type=Path, help="source learned policy bundle")
    mcp_amend.add_argument("log", type=Path, help="JSONL replay or audit log containing blocked decisions")
    mcp_amend.add_argument(
        "--out",
        "--output",
        type=Path,
        required=True,
        help="candidate output policy bundle directory",
    )
    mcp_amend.add_argument("--kind", choices=("auto", "record", "audit"), default="auto", help="input log type")
    mcp_amend.add_argument("--force", action="store_true", help="overwrite files in the output directory")
    mcp_amend.add_argument(
        "--allow-risky",
        action="store_true",
        help="allow risky shell/exec-style tool names into the candidate policy",
    )
    mcp_amend.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate the generated policy bundle",
    )
    mcp_amend.add_argument("--compact", action="store_true", help="emit compact JSON")

    mcp_lab = mcp_subparsers.add_parser("lab", help="run the one-command local MCP policy lab")
    mcp_lab.add_argument("--output-dir", type=Path, default=Path(".snulbug-lab"), help="lab artifact directory")
    mcp_lab.add_argument(
        "--force",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="overwrite the lab artifact directory",
    )
    mcp_lab.add_argument("--compact", action="store_true", help="emit compact JSON")

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
        choices=("auto", "generic", "ngrok", "cloudflare", "tailscale", "holepunch"),
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

        if args.compact:
            sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
        else:
            if "checks" in result:
                output = format_tunnel_doctor_report(result)
            elif "commands" in result:
                output = format_tunnel_init_report(result)
            else:
                output = json.dumps(result, indent=2)
            sys.stdout.write(output)
        sys.stdout.write("\n")
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
        from .inspection import format_mcp_inspection_report, inspect_mcp_log
        from .leases import create_lease, list_leases, revoke_lease
        from .presets import McpPolicyOptions, generate_mcp_preset, list_builtin_presets
        from .recorder import append_record, record_audit_event, record_policy_request, replay_record_log
        from .redaction import append_audit_event

        if args.mcp_command == "guide":
            from .guide import build_mcp_guide, format_mcp_guide

            try:
                result = build_mcp_guide(workflow=args.workflow)
            except Exception as exc:
                result = {"ok": False, "workflow": args.workflow, "error": str(exc)}
                status = 1
            else:
                status = 0
            if args.compact:
                output = json.dumps(result, separators=(",", ":"), sort_keys=True)
            else:
                output = format_mcp_guide(result) if status == 0 else json.dumps(result, indent=2, sort_keys=True)
            sys.stdout.write(output)
            sys.stdout.write("\n")
            return status
        elif args.mcp_command == "presets":
            result = {"presets": list_builtin_presets()}
            status = 0
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
        elif args.mcp_command == "init":
            output = args.output or Path(f"{args.preset}.snulbug")
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
                    f"uv run snulbug bundle validate {output}",
                    f"uv run snulbug bundle test {output}",
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
                        "uv run snulbug mcp init local-dev-safe --output policy.snulbug",
                        f"uv run snulbug mcp proxy --config {args.output}",
                    ]
                    status = 0
                except Exception as exc:
                    result = {"ok": False, "config": str(args.output), "error": str(exc)}
                    status = 1
            else:
                parser.error(f"unknown mcp config command: {args.config_command}")
                return 2
        elif args.mcp_command == "fabric":
            from .fabric import (
                doctor_fabric,
                fabric_status,
                format_fabric_doctor_report,
                format_fabric_status_report,
            )
            from .tunnel import parse_tunnel_headers

            try:
                if args.fabric_command == "status":
                    result = fabric_status(args.config)
                    status = 0 if result["ok"] else 1
                    if not args.compact:
                        sys.stdout.write(format_fabric_status_report(result))
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
                        sys.stdout.write(format_fabric_doctor_report(result))
                        sys.stdout.write("\n")
                        return status
                else:
                    parser.error(f"unknown mcp fabric command: {args.fabric_command}")
                    return 2
            except Exception as exc:
                result = {"ok": False, "config": str(args.config), "error": str(exc)}
                status = 1
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
                if args.report_out is not None:
                    report_text = format_mcp_inspection_report(result, output_format=args.report_format)
                    args.report_out.parent.mkdir(parents=True, exist_ok=True)
                    args.report_out.write_text(report_text, encoding="utf-8")
                    result["report_out"] = str(args.report_out)
                    result["report_format"] = args.report_format
                status = 0
            except Exception as exc:
                result = {"ok": False, "log": str(args.log), "error": str(exc)}
                status = 1
        elif args.mcp_command == "impact":
            from .impact import analyze_mcp_impact, format_mcp_impact_report

            memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
            try:
                result = analyze_mcp_impact(
                    args.log,
                    policy=args.policy,
                    lease_file=args.lease_file,
                    instruction_limit=args.instruction_limit,
                    memory_limit_bytes=memory_limit,
                )
                if args.report_out is not None:
                    report_text = format_mcp_impact_report(result, output_format=args.report_format)
                    args.report_out.parent.mkdir(parents=True, exist_ok=True)
                    args.report_out.write_text(report_text, encoding="utf-8")
                    result["report_out"] = str(args.report_out)
                    result["report_format"] = args.report_format
                status = 0 if args.no_fail or result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "log": str(args.log), "error": str(exc)}
                status = 1
        elif args.mcp_command == "learn":
            from .learn import learn_mcp_policy

            try:
                result = learn_mcp_policy(
                    args.log,
                    args.out,
                    kind=args.kind,
                    force=args.force,
                    validate=args.validate,
                )
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {"ok": False, "log": str(args.log), "output": str(args.out), "error": str(exc)}
                status = 1
        elif args.mcp_command == "amend":
            from .learn import amend_mcp_policy

            try:
                result = amend_mcp_policy(
                    args.bundle,
                    args.log,
                    args.out,
                    kind=args.kind,
                    force=args.force,
                    validate=args.validate,
                    allow_risky=args.allow_risky,
                )
                status = 0 if result["ok"] else 1
            except Exception as exc:
                result = {
                    "ok": False,
                    "bundle": str(args.bundle),
                    "log": str(args.log),
                    "output": str(args.out),
                    "error": str(exc),
                }
                status = 1
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
                )
            except Exception as exc:
                sys.stderr.write(f"snulbug proxy failed: {exc}\n")
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


def _read_required_env(name: str) -> str:
    import os

    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable is not set: {name}")
    return value


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

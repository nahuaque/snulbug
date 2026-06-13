from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .fabric_runtime import (
    DEFAULT_FABRIC_RUNTIME_LEASE_TTL_SECONDS,
    DEFAULT_FABRIC_RUNTIME_STATE,
    DEFAULT_FABRIC_RUNTIME_STATE_KEY,
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

    bundle_states = ("observed", "proposed", "approved", "active")
    bundle_lifecycle = bundle_subparsers.add_parser("lifecycle", help="inspect policy bundle lifecycle metadata")
    bundle_lifecycle.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_lifecycle.add_argument("--compact", action="store_true", help="emit compact JSON")

    bundle_sign = bundle_subparsers.add_parser("sign", help="sign current policy bundle lifecycle metadata")
    bundle_sign.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_sign.add_argument("--state", choices=bundle_states, help="current lifecycle state to require before signing")
    bundle_sign.add_argument("--key-id", required=True, help="bundle signing key id")
    bundle_sign.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    bundle_sign.add_argument("--actor", help="actor to record in lifecycle history")
    bundle_sign.add_argument("--note", help="note to record in lifecycle history")
    bundle_sign.add_argument("--compact", action="store_true", help="emit compact JSON")

    bundle_verify = bundle_subparsers.add_parser("verify", help="verify signed policy bundle lifecycle metadata")
    bundle_verify.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_verify.add_argument("--state", choices=bundle_states, help="required lifecycle state")
    bundle_verify.add_argument("--key-id", help="bundle signing key id; defaults to lifecycle signature key_id")
    bundle_verify.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    bundle_verify.add_argument("--compact", action="store_true", help="emit compact JSON")

    bundle_promote = bundle_subparsers.add_parser(
        "promote",
        help="advance a signed policy bundle through observed, proposed, approved, and active",
    )
    bundle_promote.add_argument("bundle", type=Path, help="path to a policy bundle directory")
    bundle_promote.add_argument(
        "--to",
        choices=("next", "proposed", "approved", "active"),
        default="next",
        help="target lifecycle state; defaults to the next valid state",
    )
    bundle_promote.add_argument("--key-id", required=True, help="bundle signing key id")
    bundle_promote.add_argument(
        "--secret-env",
        default="SNULBUG_BUNDLE_SECRET",
        help="environment variable containing the bundle signing secret",
    )
    bundle_promote.add_argument("--actor", help="actor to record in lifecycle history")
    bundle_promote.add_argument("--note", help="note to record in lifecycle history")
    bundle_promote.add_argument("--instruction-limit", type=int, default=100_000)
    bundle_promote.add_argument("--memory-limit-bytes", type=int, default=8 * 1024 * 1024)
    bundle_promote.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    tunnel_init.add_argument("--token-env", default="SNULBUG_TOKEN", help="environment variable holding bearer token")
    tunnel_init.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_init.add_argument("--output-dir", type=Path, help="optional directory for generated setup files")
    tunnel_init.add_argument("--force", action="store_true", help="overwrite generated files")
    tunnel_init.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    tunnel_doctor.add_argument("--token", help="bearer token for authenticated MCP probes")
    tunnel_doctor.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    tunnel_doctor.add_argument("--timeout", type=float, default=5.0, help="HTTP probe timeout in seconds")
    tunnel_doctor.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    expose.add_argument("--token-env", default="SNULBUG_TOKEN", help="environment variable holding bearer token")
    expose.add_argument("--path", default="/mcp", help="MCP path to append when URLs omit a path")
    expose.add_argument("--output-dir", type=Path, help="optional directory for generated setup files")
    expose.add_argument("--report-out", type=Path, help="session report path for the generated inspect command")
    expose.add_argument(
        "--decision-console",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include decision-console mode in the proxy command",
    )
    expose.add_argument("--force", action="store_true", help="overwrite generated files")
    expose.add_argument("--dry-run", action="store_true", help="print the exposure plan without writing files")
    expose.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_quickstart.add_argument("--force", action="store_true", help="overwrite generated policy and config")
    mcp_quickstart.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="validate and test the generated policy bundle",
    )
    mcp_quickstart.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_codespace_attach.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_codespace_serve_demo.add_argument("--compact", action="store_true", help="emit compact JSON")

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
    mcp_fabric_discover = mcp_fabric_subparsers.add_parser(
        "discover",
        help="resolve configured MCP fabric discovery providers",
    )
    mcp_fabric_discover.add_argument(
        "--config", type=Path, default=Path("snulbug.toml"), help="snulbug.toml config file"
    )
    mcp_fabric_discover.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_learn.add_argument("--force", action="store_true", help="overwrite the output directory")
    mcp_fabric_learn.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_conformance_generate.add_argument("--force", action="store_true", help="overwrite generated files")
    mcp_fabric_conformance_generate.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_conformance_run.add_argument("--token", help="bearer token for authenticated MCP probes")
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
    mcp_fabric_conformance_run.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_runtime_status.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_runtime_clear.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_member_register.add_argument(
        "--role",
        choices=("data-plane", "data_plane", "control-plane", "control_plane", "observer"),
        default="data-plane",
        help="member role",
    )
    mcp_fabric_member_register.add_argument(
        "--status",
        choices=("active", "draining"),
        default="active",
        help="member routing status",
    )
    mcp_fabric_member_register.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="member MCP upstream as NAME=URL; repeat for multiple upstreams",
    )
    mcp_fabric_member_register.add_argument(
        "--ttl-seconds",
        type=float,
        default=60.0,
        help="seconds until the member expires without another heartbeat",
    )
    mcp_fabric_member_register.add_argument("--label", action="append", default=[], help="member label as KEY=VALUE")
    mcp_fabric_member_register.add_argument(
        "--metadata",
        action="append",
        default=[],
        help="member metadata as KEY=VALUE",
    )
    _add_fabric_member_registry_args(mcp_fabric_member_register)
    mcp_fabric_member_agent = mcp_fabric_member_subparsers.add_parser(
        "agent",
        help="register a remote fabric member and keep its heartbeat fresh",
    )
    mcp_fabric_member_agent.add_argument("member_id", help="stable member/node id")
    mcp_fabric_member_agent.add_argument(
        "--role",
        choices=("data-plane", "data_plane", "control-plane", "control_plane", "observer"),
        default="data-plane",
        help="member role",
    )
    mcp_fabric_member_agent.add_argument(
        "--status",
        choices=("active", "draining"),
        default="active",
        help="member routing status",
    )
    mcp_fabric_member_agent.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="member MCP upstream as NAME=URL; repeat for multiple upstreams",
    )
    mcp_fabric_member_agent.add_argument(
        "--ttl-seconds",
        type=float,
        default=60.0,
        help="seconds until the member expires without another heartbeat",
    )
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
    mcp_fabric_member_agent.add_argument("--label", action="append", default=[], help="member label as KEY=VALUE")
    mcp_fabric_member_agent.add_argument(
        "--metadata",
        action="append",
        default=[],
        help="member metadata as KEY=VALUE",
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
    mcp_fabric_controller.add_argument("--compact", action="store_true", help="emit compact JSON")
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
    mcp_fabric_run.add_argument("--compact", action="store_true", help="emit compact JSON startup output")

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
        from .bundle import (
            inspect_bundle_lifecycle,
            pack_bundle,
            promote_bundle_lifecycle,
            sign_bundle_lifecycle,
            test_bundle,
            validate_bundle,
            verify_bundle_lifecycle,
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
            elif args.bundle_command == "lifecycle":
                result = inspect_bundle_lifecycle(args.bundle)
                status = 0
            elif args.bundle_command == "sign":
                result = sign_bundle_lifecycle(
                    args.bundle,
                    secret=_read_required_env(args.secret_env),
                    key_id=args.key_id,
                    state=args.state,
                    actor=args.actor,
                    note=args.note,
                )
                status = 0
            elif args.bundle_command == "verify":
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
                        secrets={key_id: _read_required_env(args.secret_env)},
                        required_state=args.state,
                    ),
                }
                status = 0
            elif args.bundle_command == "promote":
                memory_limit = None if args.memory_limit_bytes <= 0 else args.memory_limit_bytes
                result = promote_bundle_lifecycle(
                    args.bundle,
                    to_state=args.to,
                    secret=_read_required_env(args.secret_env),
                    key_id=args.key_id,
                    actor=args.actor,
                    note=args.note,
                    instruction_limit=args.instruction_limit,
                    memory_limit_bytes=memory_limit,
                )
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

        if args.compact:
            sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
        else:
            sys.stdout.write(format_exposure_session_report(result))
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
                            if args.compact:
                                sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                            else:
                                sys.stdout.write(format_codespace_attach_report(result))
                            sys.stdout.write("\n")
                            return status
                    result["dry_run"] = bool(args.dry_run)
                    status = 0
                    if args.dry_run:
                        if args.compact:
                            sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                        else:
                            sys.stdout.write(format_codespace_attach_report(result))
                        sys.stdout.write("\n")
                        return status

                    import os

                    os.environ[result["env"]["name"]] = result["env"]["value"]
                    proxy_config = load_mcp_proxy_config(result["config"])
                    fabric_config = load_mcp_fabric_config(result["config"])
                    fabric_config["proxy"] = proxy_config
                    result["starting_proxy"] = True
                    if args.compact:
                        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                    else:
                        sys.stdout.write(format_codespace_attach_report(result))
                    sys.stdout.write("\n")
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
                    if args.compact:
                        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                    else:
                        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True))
                    sys.stdout.write("\n")
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
                        if args.compact:
                            sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                        else:
                            sys.stdout.write(format_codespace_demo_report(result))
                        sys.stdout.write("\n")
                        return 0

                    def emit_codespace_demo(payload: Mapping[str, Any]) -> None:
                        if args.compact:
                            sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
                        else:
                            sys.stdout.write(format_codespace_demo_report(payload))
                        sys.stdout.write("\n")
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
                    if args.compact:
                        sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
                    else:
                        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True))
                    sys.stdout.write("\n")
                    return 1
            parser.error(f"unknown mcp codespace command: {args.codespace_command}")
            return 2
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
            from .controller import (
                FabricControllerStatusServer,
                format_fabric_controller_report,
                format_fabric_run_report,
                run_fabric_controller,
                run_fabric_data_plane,
            )
            from .fabric import (
                discover_fabric_upstreams,
                doctor_fabric,
                fabric_status,
                format_fabric_conformance_report,
                format_fabric_discovery_report,
                format_fabric_doctor_report,
                format_fabric_learn_report,
                format_fabric_status_report,
                generate_fabric_conformance_pack,
                learn_fabric_profile,
                run_fabric_conformance_pack,
            )
            from .fabric_control import (
                clear_fabric_control_actions,
                format_fabric_control_report,
                issue_fabric_control_action,
                load_fabric_control_state,
            )
            from .fabric_members import (
                format_fabric_member_report,
                heartbeat_fabric_member,
                load_fabric_member_registry,
                register_fabric_member,
                summarize_fabric_members,
                unregister_fabric_member,
            )
            from .fabric_runtime import (
                clear_fabric_runtime_status,
                format_fabric_runtime_report,
                load_fabric_runtime_status,
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
                        sys.stdout.write(format_fabric_doctor_report(result))
                        sys.stdout.write("\n")
                        return status
                elif args.fabric_command == "learn":
                    result = learn_fabric_profile(args.log, args.out, kind=args.kind, force=args.force)
                    status = 0 if result["ok"] else 1
                    if not args.compact:
                        sys.stdout.write(format_fabric_learn_report(result))
                        sys.stdout.write("\n")
                        return status
                elif args.fabric_command == "conformance":
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
                elif args.fabric_command == "runtime":
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
                elif args.fabric_command == "control":
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
                elif args.fabric_command == "member":
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
                        result = unregister_fabric_member(
                            args.registry, key=args.registry_key, member_id=args.member_id
                        )
                    else:
                        parser.error(f"unknown mcp fabric member command: {args.member_command}")
                        return 2
                    status = 0 if result["ok"] else 1
                    if not args.compact:
                        sys.stdout.write(format_fabric_member_report(result))
                        sys.stdout.write("\n")
                        return status
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
                            sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
                            sys.stdout.write("\n")
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
                        result = run_fabric_controller(
                            args.config,
                            state_path=args.state,
                            event_log=event_log,
                            interval=args.interval,
                            once=args.once,
                            emit=emit_controller_result,
                            status_server=status_server,
                        )
                    finally:
                        if status_server is not None and args.once:
                            status_server.stop()
                    status = 0 if result["ok"] else 1
                    return status
                elif args.fabric_command == "run":
                    event_log = None if args.no_event_log else args.event_log

                    def emit_fabric_run_started(payload: Mapping[str, Any]) -> None:
                        if args.compact:
                            sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
                            sys.stdout.write("\n")
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
                    status = 0 if result["ok"] else 1
                    return status
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

        indent = None if args.compact else 2
        sys.stdout.write(json.dumps(result, indent=indent, sort_keys=True))
        sys.stdout.write("\n")
        return status

    parser.error(f"unknown command: {args.command}")
    return 2


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
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")


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
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")


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


def status_server_url(status_server: Any) -> str:
    return f"http://{status_server.host}:{status_server.port}"


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

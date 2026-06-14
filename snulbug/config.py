from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .credentials import attach_upstream_credentials, normalize_fabric_credentials, normalize_upstream_credential
from .discovery import apply_fabric_discovery
from .events import normalize_event_sink_configs
from .gateway_templates import render_toml_array_table

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

DEFAULT_CONFIG_PATH = "snulbug.toml"
REMOVED_EVENT_OUTPUT_KEYS = {"audit_out", "decision_console", "decision_console_format", "webhooks"}

DEFAULT_MCP_AUTH_CONFIG = {
    "mode": "off",
    "resource": None,
    "issuer": None,
    "authorization_servers": [],
    "audience": None,
    "required_scopes": [],
    "scopes_supported": [],
    "jwks_path": None,
    "jwks_url": None,
    "jwks_cache_seconds": 300.0,
    "jwks_fetch_timeout": 5.0,
    "issuer_metadata_url": None,
    "issuer_discovery": True,
    "token_validation": "jwt",
    "introspection_endpoint": None,
    "introspection_client_id": None,
    "introspection_client_secret_env": None,
    "introspection_cache_seconds": 30.0,
    "introspection_fetch_timeout": 5.0,
    "resource_metadata_url": None,
    "realm": "mcp",
    "leeway_seconds": 60.0,
    "strip_authorization_upstream": True,
    "scope_map": {},
}

DEFAULT_MCP_PROXY_CONFIG = {
    "upstream": "http://127.0.0.1:9000",
    "upstream_credential": None,
    "upstreams": [],
    "policy": "policy.snulbug/policy.lua",
    "host": "127.0.0.1",
    "port": 8080,
    "state": "memory",
    "trace": True,
    "record_out": "traces/session.jsonl",
    "redact_records": True,
    "confirm": False,
    "max_body_bytes": 65536,
    "response_max_bytes": 262144,
    "response_redact_secrets": True,
    "response_block_instructions": False,
    "tool_pinning": True,
    "tool_pinning_action": "block",
    "schema_validation": True,
    "schema_validation_action": "block",
    "facade_health_routing": False,
    "facade_health_failure_threshold": 2,
    "facade_health_cooldown_seconds": 30.0,
    "facade_health_exclude_unhealthy": True,
    "lease_file": "leases.json",
    "lease_required": False,
    "lease_header": "x-snulbug-lease",
    "tunnel_provider": "auto",
    "tunnel_public_url": None,
    "cloudflare_access": "off",
    "cloudflare_access_require_jwt": True,
    "cloudflare_access_require_email": False,
    "cloudflare_access_require_cf_ray": True,
    "cloudflare_access_allowed_emails": [],
    "cloudflare_access_allowed_domains": [],
    "timeout": 30.0,
    "event_sinks": [],
}

DEFAULT_MCP_FABRIC_CONFIG = {
    "name": "local-dev",
    "description": "",
    "gateway_url": None,
    "require_manifests": False,
    "probe_gateway": True,
    "probe_upstreams": True,
    "timeout": 5.0,
    "credentials": {},
    "policy_activation": {
        "mode": "off",
        "key_id": None,
        "secret_env": "SNULBUG_BUNDLE_SECRET",
        "actor": "snulbug fabric controller",
        "note": "activated by fabric controller",
        "instruction_limit": 100_000,
        "memory_limit_bytes": 8 * 1024 * 1024,
    },
}


def default_event_sink_configs(
    *,
    audit_path: str | Path = "traces/audit.jsonl",
    console_format: str = "text",
) -> list[dict[str, Any]]:
    return [
        {"type": "audit_jsonl", "path": str(audit_path)},
        {"type": "console", "format": console_format},
    ]


def format_event_sinks_toml(event_sinks: Sequence[Mapping[str, Any]]) -> str:
    lines: list[str] = []
    for sink in event_sinks:
        lines.extend(["", *render_toml_array_table("mcp.events.sinks", sink)])
    return "\n".join(lines)


SAMPLE_CONFIG = """[mcp.proxy]
upstream = "http://127.0.0.1:9000"
# Optional single-upstream credential reference from [mcp.fabric.credentials].
# upstream_credential = "local_api"
policy = "policy.snulbug/policy.lua"
host = "127.0.0.1"
port = 8080
state = "memory"
trace = true
record_out = "traces/session.jsonl"
redact_records = true
confirm = false
max_body_bytes = 65536
response_max_bytes = 262144
response_redact_secrets = true
response_block_instructions = false
tool_pinning = true
tool_pinning_action = "block"
schema_validation = true
schema_validation_action = "block"
facade_health_routing = false
facade_health_failure_threshold = 2
facade_health_cooldown_seconds = 30.0
facade_health_exclude_unhealthy = true
lease_file = "leases.json"
lease_required = false
lease_header = "x-snulbug-lease"
tunnel_provider = "auto"
tunnel_public_url = ""
cloudflare_access = "off"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = false
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_emails = []
cloudflare_access_allowed_domains = []
timeout = 30.0

[mcp.auth]
# Optional OAuth 2.1 protected-resource mode for public MCP endpoints.
# mode = "oauth-resource"
# resource = "https://YOUR-TUNNEL.example/mcp"
# issuer = "https://issuer.example"
# authorization_servers = ["https://issuer.example"]
# audience = "https://YOUR-TUNNEL.example/mcp"
# required_scopes = ["mcp:connect"]
# scopes_supported = ["mcp:connect"]
# jwks_path = "auth/jwks.json"
# jwks_url = "https://issuer.example/.well-known/jwks.json"
# jwks_cache_seconds = 300
# jwks_fetch_timeout = 5
# issuer_discovery = true
# issuer_metadata_url = "https://issuer.example/.well-known/oauth-authorization-server"
# token_validation = "jwt" # jwt, introspection, jwt_or_introspection, or jwt_and_introspection
# introspection_endpoint = "https://issuer.example/oauth/introspect"
# introspection_client_id = "snulbug-share"
# introspection_client_secret_env = "SNULBUG_INTROSPECTION_CLIENT_SECRET"
# introspection_cache_seconds = 30
# introspection_fetch_timeout = 5
# resource_metadata_url = "https://YOUR-TUNNEL.example/.well-known/oauth-protected-resource"
# realm = "mcp"
# leeway_seconds = 60.0
# strip_authorization_upstream = true
#
# Optional MCP-aware scope-to-method/tool mapping:
# [mcp.auth.scope_map]
# "mcp:tools.read" = ["tools/list", "resources/list"]
# "mcp:tool.files.read" = ["tools/call:filesystem.read_file"]
# "mcp:tool.git.status" = ["tools/call:git.status"]

[mcp.fabric]
name = "local-dev"
description = ""
# Inferred from [mcp.proxy] host/port when empty.
gateway_url = ""
require_manifests = false
probe_gateway = true
probe_upstreams = true
timeout = 5.0

# Optional controller-enforced policy bundle lifecycle:
# [mcp.fabric.policy_activation]
# mode = "promote_approved" # off, require_active, or promote_approved
# key_id = "local-review"
# secret_env = "SNULBUG_BUNDLE_SECRET"

# Optional upstream credentials. Values are resolved only at request/probe time.
# [mcp.fabric.credentials.codespace]
# type = "env"
# env = "CODESPACE_MCP_TOKEN"
# scheme = "bearer" # bearer, basic, or raw
# header = "Authorization"

# Optional discovery providers append facade upstreams before validation:
# [mcp.fabric.discovery]
# enabled = true
#
# [[mcp.fabric.discovery.providers]]
# name = "local-registry"
# type = "file"
# path = "discovery/upstreams.json"
# required = false
#
# [[mcp.fabric.discovery.providers]]
# name = "compose"
# type = "docker_compose"
# path = "compose.yml"

# Optional MCP facade mode:
# [[mcp.proxy.upstreams]]
# name = "files"
# url = "http://127.0.0.1:9001/mcp"
#
# [[mcp.proxy.upstreams]]
# name = "git"
# url = "http://127.0.0.1:9002/mcp"
#
# [[mcp.proxy.upstreams]]
# name = "filesystem"
# transport = "stdio"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
#
# [[mcp.proxy.upstreams]]
# name = "remote-devbox"
# transport = "holepunch"
# peer = "SERVER_PEER_KEY"
# local_port = 19100
# auth = "codespace"

[[mcp.events.sinks]]
type = "audit_jsonl"
path = "traces/audit.jsonl"

[[mcp.events.sinks]]
type = "console"
format = "text"

# Optional webhook event sink.
# [[mcp.events.sinks]]
# type = "webhook"
# name = "security-alerts"
# url_env = "SNULBUG_SECURITY_WEBHOOK_URL"
# events = ["mcp.decision.blocked", "mcp.response.redacted", "snulbug.fabric.upstream.unhealthy"]
# body_mode = "metadata_only" # metadata_only or full_event
# redaction = "strict" # strict or none
# timeout_ms = 750
# retry_attempts = 3
# signing_secret_env = "SNULBUG_WEBHOOK_SECRET"
"""


def write_sample_config(path: str | Path = DEFAULT_CONFIG_PATH, *, force: bool = False) -> dict[str, Any]:
    output = Path(path)
    if output.exists() and not force:
        raise FileExistsError(f"config file already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(SAMPLE_CONFIG, encoding="utf-8")
    return {"ok": True, "config": str(output)}


def load_mcp_proxy_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    with config_path.open("rb") as file:
        raw_config = tomllib.load(file)
    if not isinstance(raw_config, Mapping):
        raise ValueError("config file must contain a TOML object")
    mcp = raw_config.get("mcp", {})
    if not isinstance(mcp, Mapping):
        raise ValueError("config section [mcp] must be a table")
    _reject_removed_event_output_config(mcp)
    proxy = mcp.get("proxy", {})
    if not isinstance(proxy, Mapping):
        raise ValueError("config section [mcp.proxy] must be a table")
    auth = mcp.get("auth", {})
    if not isinstance(auth, Mapping):
        raise ValueError("config section [mcp.auth] must be a table")
    fabric = mcp.get("fabric", {})
    if not isinstance(fabric, Mapping):
        raise ValueError("config section [mcp.fabric] must be a table")
    event_sinks = _load_event_sinks_table(mcp)
    return _normalize_proxy_config_with_discovery(
        proxy,
        fabric,
        auth=auth,
        event_sinks=event_sinks,
        base_dir=config_path.parent,
    )


def load_mcp_fabric_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    with config_path.open("rb") as file:
        raw_config = tomllib.load(file)
    if not isinstance(raw_config, Mapping):
        raise ValueError("config file must contain a TOML object")
    mcp = raw_config.get("mcp", {})
    if not isinstance(mcp, Mapping):
        raise ValueError("config section [mcp] must be a table")
    _reject_removed_event_output_config(mcp)
    fabric = mcp.get("fabric", {})
    if not isinstance(fabric, Mapping):
        raise ValueError("config section [mcp.fabric] must be a table")
    proxy = mcp.get("proxy", {})
    if not isinstance(proxy, Mapping):
        raise ValueError("config section [mcp.proxy] must be a table")
    auth = mcp.get("auth", {})
    if not isinstance(auth, Mapping):
        raise ValueError("config section [mcp.auth] must be a table")
    event_sinks = _load_event_sinks_table(mcp)
    proxy_config = _normalize_proxy_config_with_discovery(
        proxy,
        fabric,
        auth=auth,
        event_sinks=event_sinks,
        base_dir=config_path.parent,
    )
    return normalize_mcp_fabric_config(
        fabric,
        proxy_config=proxy_config,
        event_sinks=event_sinks,
        base_dir=config_path.parent,
    )


def _normalize_proxy_config_with_discovery(
    proxy: Mapping[str, Any],
    fabric: Mapping[str, Any],
    *,
    auth: Mapping[str, Any] | None = None,
    event_sinks: Any = None,
    base_dir: Path,
) -> dict[str, Any]:
    credentials = normalize_fabric_credentials(fabric.get("credentials", {}), base_dir=base_dir)
    discovered_proxy, discovery = apply_fabric_discovery(proxy, fabric, base_dir=base_dir)
    discovered_proxy = attach_upstream_credentials(discovered_proxy, credentials)
    proxy_config = normalize_mcp_proxy_config(discovered_proxy, base_dir=base_dir)
    proxy_config["auth"] = normalize_mcp_auth_config(auth, base_dir=base_dir)
    proxy_config["discovery"] = discovery
    proxy_config["event_sinks"] = [
        *proxy_config.get("event_sinks", []),
        *normalize_event_sink_configs(event_sinks, base_dir=base_dir),
    ]
    return proxy_config


def normalize_mcp_proxy_config(config: Mapping[str, Any], *, base_dir: str | Path = ".") -> dict[str, Any]:
    removed = REMOVED_EVENT_OUTPUT_KEYS.intersection(config)
    if removed:
        keys = ", ".join(f"mcp.proxy.{key}" for key in sorted(removed))
        raise ValueError(f"{keys} were removed; configure live outputs with [[mcp.events.sinks]]")
    normalized = dict(DEFAULT_MCP_PROXY_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})
    base = Path(base_dir)

    for field in (
        "upstream",
        "host",
        "state",
        "tool_pinning_action",
        "schema_validation_action",
        "lease_header",
        "tunnel_provider",
        "cloudflare_access",
    ):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"mcp.proxy.{field} must be a string")
    if normalized.get("tunnel_public_url") is not None and not isinstance(normalized.get("tunnel_public_url"), str):
        raise ValueError("mcp.proxy.tunnel_public_url must be a string")
    if normalized.get("tunnel_public_url") == "":
        normalized["tunnel_public_url"] = None
    for field in ("policy", "record_out", "lease_file"):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str | Path):
            raise ValueError(f"mcp.proxy.{field} must be a string path")
    for field in ("port", "max_body_bytes", "response_max_bytes"):
        value = normalized.get(field)
        if not isinstance(value, int) or value <= 0:
            raise ValueError(f"mcp.proxy.{field} must be a positive integer")
    if not isinstance(normalized.get("timeout"), int | float) or float(normalized["timeout"]) <= 0:
        raise ValueError("mcp.proxy.timeout must be a positive number")
    if (
        not isinstance(normalized.get("facade_health_failure_threshold"), int)
        or normalized["facade_health_failure_threshold"] <= 0
    ):
        raise ValueError("mcp.proxy.facade_health_failure_threshold must be a positive integer")
    if (
        not isinstance(normalized.get("facade_health_cooldown_seconds"), int | float)
        or float(normalized["facade_health_cooldown_seconds"]) <= 0
    ):
        raise ValueError("mcp.proxy.facade_health_cooldown_seconds must be a positive number")
    for field in (
        "trace",
        "redact_records",
        "confirm",
        "response_redact_secrets",
        "response_block_instructions",
        "tool_pinning",
        "schema_validation",
        "facade_health_routing",
        "facade_health_exclude_unhealthy",
        "lease_required",
        "cloudflare_access_require_jwt",
        "cloudflare_access_require_email",
        "cloudflare_access_require_cf_ray",
    ):
        if not isinstance(normalized.get(field), bool):
            raise ValueError(f"mcp.proxy.{field} must be a boolean")
    if normalized["tool_pinning_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.tool_pinning_action must be 'warn' or 'block'")
    if normalized["schema_validation_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.schema_validation_action must be 'warn' or 'block'")
    if normalized["tunnel_provider"] not in {
        "auto",
        "generic",
        "ngrok",
        "cloudflare",
        "tailscale",
        "localxpose",
        "pinggy",
        "holepunch",
    }:
        raise ValueError(
            "mcp.proxy.tunnel_provider must be 'auto', 'generic', 'ngrok', 'cloudflare', "
            "'tailscale', 'localxpose', 'pinggy', or 'holepunch'"
        )
    if normalized["cloudflare_access"] not in {"off", "audit", "enforce"}:
        raise ValueError("mcp.proxy.cloudflare_access must be 'off', 'audit', or 'enforce'")

    normalized["upstreams"] = _normalize_upstreams(normalized.get("upstreams", []), base_dir=base)
    upstream_credential = normalized.get("upstream_credential")
    if upstream_credential in (None, ""):
        normalized["upstream_credential"] = None
    elif isinstance(upstream_credential, Mapping):
        normalized["upstream_credential"] = normalize_upstream_credential(
            upstream_credential,
            field="mcp.proxy.upstream_credential",
            base_dir=base,
            resolve_relative_paths=True,
        )
    else:
        raise ValueError(
            "mcp.proxy.upstream_credential must be a credential table or a reference to mcp.fabric.credentials"
        )
    normalized["cloudflare_access_allowed_emails"] = _normalize_string_list(
        normalized.get("cloudflare_access_allowed_emails", []),
        field="cloudflare_access_allowed_emails",
    )
    normalized["cloudflare_access_allowed_domains"] = _normalize_string_list(
        normalized.get("cloudflare_access_allowed_domains", []),
        field="cloudflare_access_allowed_domains",
    )
    normalized["policy"] = _resolve_path(base, normalized["policy"])
    for field in ("record_out",):
        if normalized.get(field):
            normalized[field] = _resolve_path(base, normalized[field])
    if normalized.get("lease_file"):
        normalized["lease_file"] = _resolve_path(base, normalized["lease_file"])
    normalized["timeout"] = float(normalized["timeout"])
    normalized["facade_health_cooldown_seconds"] = float(normalized["facade_health_cooldown_seconds"])
    normalized["event_sinks"] = normalize_event_sink_configs(normalized.get("event_sinks", []), base_dir=base)
    normalized["auth"] = normalize_mcp_auth_config(normalized.get("auth", {}), base_dir=base)
    return normalized


def normalize_mcp_auth_config(config: Mapping[str, Any] | None, *, base_dir: str | Path = ".") -> dict[str, Any]:
    if config in (None, ""):
        config = {}
    if not isinstance(config, Mapping):
        raise ValueError("mcp.auth must be a table")
    normalized = dict(DEFAULT_MCP_AUTH_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})
    mode = normalized.get("mode")
    if not isinstance(mode, str):
        raise ValueError("mcp.auth.mode must be a string")
    if mode not in {"off", "oauth-resource"}:
        raise ValueError("mcp.auth.mode must be 'off' or 'oauth-resource'")
    for field in (
        "resource",
        "issuer",
        "audience",
        "jwks_url",
        "issuer_metadata_url",
        "token_validation",
        "introspection_endpoint",
        "introspection_client_id",
        "introspection_client_secret_env",
        "resource_metadata_url",
        "realm",
    ):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"mcp.auth.{field} must be a string")
        if value == "":
            normalized[field] = None if field != "realm" else "mcp"
    for field in ("authorization_servers", "required_scopes", "scopes_supported"):
        normalized[field] = _normalize_auth_string_list(normalized.get(field), field=field)
    jwks_path = normalized.get("jwks_path")
    if jwks_path in (None, ""):
        normalized["jwks_path"] = None
    elif isinstance(jwks_path, str | Path):
        normalized["jwks_path"] = _resolve_path(Path(base_dir), jwks_path)
    else:
        raise ValueError("mcp.auth.jwks_path must be a string path")
    if normalized["token_validation"] not in {"jwt", "introspection", "jwt_or_introspection", "jwt_and_introspection"}:
        raise ValueError(
            "mcp.auth.token_validation must be 'jwt', 'introspection', 'jwt_or_introspection', or "
            "'jwt_and_introspection'"
        )
    if not isinstance(normalized.get("issuer_discovery"), bool):
        raise ValueError("mcp.auth.issuer_discovery must be a boolean")
    for field in (
        "jwks_cache_seconds",
        "jwks_fetch_timeout",
        "introspection_cache_seconds",
        "introspection_fetch_timeout",
    ):
        if not isinstance(normalized.get(field), int | float) or float(normalized[field]) < 0:
            raise ValueError(f"mcp.auth.{field} must be a non-negative number")
        normalized[field] = float(normalized[field])
    if normalized["jwks_fetch_timeout"] <= 0:
        raise ValueError("mcp.auth.jwks_fetch_timeout must be positive")
    if normalized["introspection_fetch_timeout"] <= 0:
        raise ValueError("mcp.auth.introspection_fetch_timeout must be positive")
    if not isinstance(normalized.get("leeway_seconds"), int | float) or float(normalized["leeway_seconds"]) < 0:
        raise ValueError("mcp.auth.leeway_seconds must be a non-negative number")
    normalized["leeway_seconds"] = float(normalized["leeway_seconds"])
    if not isinstance(normalized.get("strip_authorization_upstream"), bool):
        raise ValueError("mcp.auth.strip_authorization_upstream must be a boolean")
    normalized["scope_map"] = _normalize_auth_scope_map(normalized.get("scope_map", {}))
    if normalized["mode"] == "oauth-resource":
        if not normalized.get("resource"):
            raise ValueError("mcp.auth.resource is required when mode is 'oauth-resource'")
        token_validation = normalized["token_validation"]
        uses_jwt = token_validation in {"jwt", "jwt_or_introspection", "jwt_and_introspection"}
        uses_introspection = token_validation in {"introspection", "jwt_or_introspection", "jwt_and_introspection"}
        has_issuer_discovery = bool(normalized.get("issuer_discovery") and normalized.get("issuer"))
        if uses_jwt and not normalized.get("jwks_path") and not normalized.get("jwks_url") and not has_issuer_discovery:
            raise ValueError(
                "mcp.auth.jwks_path, mcp.auth.jwks_url, or mcp.auth.issuer discovery is required "
                "when JWT validation is enabled"
            )
        if uses_introspection and not normalized.get("introspection_endpoint") and not has_issuer_discovery:
            raise ValueError(
                "mcp.auth.introspection_endpoint or mcp.auth.issuer discovery is required "
                "when token introspection is enabled"
            )
        if not normalized["scopes_supported"]:
            normalized["scopes_supported"] = sorted(
                {
                    *normalized["required_scopes"],
                    *normalized["scope_map"],
                }
            )
    return normalized


def normalize_mcp_fabric_config(
    config: Mapping[str, Any],
    *,
    proxy_config: Mapping[str, Any] | None = None,
    event_sinks: Any = None,
    base_dir: str | Path = ".",
) -> dict[str, Any]:
    normalized = dict(DEFAULT_MCP_FABRIC_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})

    for field in ("name", "description"):
        value = normalized.get(field)
        if not isinstance(value, str):
            raise ValueError(f"mcp.fabric.{field} must be a string")
    if not normalized["name"].strip():
        raise ValueError("mcp.fabric.name must be a non-empty string")
    if normalized.get("gateway_url") is not None and not isinstance(normalized.get("gateway_url"), str):
        raise ValueError("mcp.fabric.gateway_url must be a string")
    if normalized.get("gateway_url") == "":
        normalized["gateway_url"] = None
    for field in ("require_manifests", "probe_gateway", "probe_upstreams"):
        if not isinstance(normalized.get(field), bool):
            raise ValueError(f"mcp.fabric.{field} must be a boolean")
    if not isinstance(normalized.get("timeout"), int | float) or float(normalized["timeout"]) <= 0:
        raise ValueError("mcp.fabric.timeout must be a positive number")
    normalized["timeout"] = float(normalized["timeout"])
    normalized["credentials"] = normalize_fabric_credentials(normalized.get("credentials", {}), base_dir=base_dir)
    normalized["policy_activation"] = _normalize_policy_activation(normalized.get("policy_activation", {}))

    if normalized["gateway_url"] is None and proxy_config is not None:
        host = proxy_config.get("host")
        port = proxy_config.get("port")
        if isinstance(host, str) and isinstance(port, int):
            normalized["gateway_url"] = f"http://{host}:{port}/mcp"
    normalized["proxy"] = dict(proxy_config or {})
    if event_sinks is None and proxy_config is not None:
        normalized["event_sinks"] = list(proxy_config.get("event_sinks", []))
    else:
        normalized["event_sinks"] = normalize_event_sink_configs(event_sinks, base_dir=base_dir)
    return normalized


def _load_event_sinks_table(mcp: Mapping[str, Any]) -> Any:
    events = mcp.get("events", {})
    if events in (None, ""):
        return []
    if not isinstance(events, Mapping):
        raise ValueError("config section [mcp.events] must be a table")
    sinks = events.get("sinks", [])
    if sinks in (None, ""):
        return []
    if not isinstance(sinks, list):
        raise ValueError("config section [[mcp.events.sinks]] must be an array of tables")
    return sinks


def _reject_removed_event_output_config(mcp: Mapping[str, Any]) -> None:
    if "webhooks" in mcp:
        raise ValueError("[[mcp.webhooks]] was removed; configure webhook outputs with [[mcp.events.sinks]]")


def _normalize_policy_activation(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        value = {}
    if not isinstance(value, Mapping):
        raise ValueError("mcp.fabric.policy_activation must be a table")
    normalized = dict(DEFAULT_MCP_FABRIC_CONFIG["policy_activation"])
    normalized.update({key: item for key, item in value.items() if item is not None})
    mode = normalized.get("mode")
    if mode not in {"off", "require_active", "promote_approved"}:
        raise ValueError("mcp.fabric.policy_activation.mode must be 'off', 'require_active', or 'promote_approved'")
    for field in ("key_id", "secret_env", "actor", "note"):
        item = normalized.get(field)
        if item is not None and not isinstance(item, str):
            raise ValueError(f"mcp.fabric.policy_activation.{field} must be a string")
    if not isinstance(normalized.get("instruction_limit"), int) or normalized["instruction_limit"] <= 0:
        raise ValueError("mcp.fabric.policy_activation.instruction_limit must be a positive integer")
    memory_limit = normalized.get("memory_limit_bytes")
    if memory_limit is not None and (not isinstance(memory_limit, int) or memory_limit <= 0):
        raise ValueError("mcp.fabric.policy_activation.memory_limit_bytes must be a positive integer")
    return normalized


def merge_mcp_proxy_config(config: Mapping[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(config)
    for key, value in overrides.items():
        if value is not None:
            merged[key] = value
    return normalize_mcp_proxy_config(merged)


def _resolve_path(base_dir: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _normalize_string_list(value: Any, *, field: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"mcp.proxy.{field} must be a list of strings")
    return list(value)


def _normalize_auth_string_list(value: Any, *, field: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"mcp.auth.{field} must be a list of strings")
    return list(value)


def _normalize_auth_scope_map(value: Any) -> dict[str, list[str]]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("mcp.auth.scope_map must be a table")
    result: dict[str, list[str]] = {}
    for scope, selectors in value.items():
        if not isinstance(scope, str) or not scope:
            raise ValueError("mcp.auth.scope_map keys must be non-empty scope strings")
        if selectors in (None, ""):
            result[scope] = []
            continue
        if not isinstance(selectors, list) or not all(isinstance(selector, str) for selector in selectors):
            raise ValueError(f"mcp.auth.scope_map.{scope} must be a list of strings")
        if any(not selector for selector in selectors):
            raise ValueError(f"mcp.auth.scope_map.{scope} selectors must be non-empty strings")
        result[scope] = list(selectors)
    return result


def _normalize_upstreams(value: Any, *, base_dir: Path = Path(".")) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("mcp.proxy.upstreams must be a list of tables")

    upstreams = []
    names = set()
    prefixes = set()
    default_count = 0
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"mcp.proxy.upstreams[{index}] must be a table")
        name = item.get("name")
        transport = item.get("transport") or ("stdio" if item.get("command") else "http")
        url = item.get("url", item.get("upstream"))
        command = item.get("command")
        args = item.get("args", [])
        cwd = item.get("cwd")
        env = item.get("env")
        discovered = item.get("discovered", False)
        discovery_provider = item.get("discovery_provider")
        discovery_type = item.get("discovery_type")
        discovery_source = item.get("discovery_source")
        fabric_member_id = item.get("fabric_member_id")
        fabric_member_role = item.get("fabric_member_role")
        fabric_member_status = item.get("fabric_member_status")
        fabric_member_heartbeat_at = item.get("fabric_member_heartbeat_at")
        fabric_member_expires_at = item.get("fabric_member_expires_at")
        peer = item.get("peer")
        local_port = item.get("local_port")
        bridge_config = item.get("bridge_config")
        bridge_command = item.get("bridge_command", "hypertele")
        bridge_args = item.get("bridge_args")
        bridge_cwd = item.get("bridge_cwd")
        bridge_env = item.get("bridge_env")
        bridge_private = item.get("bridge_private", True)
        bridge_ready_timeout = item.get("bridge_ready_timeout", 10.0)
        auth = item.get("auth")
        credential = item.get("credential")
        manifest = item.get("manifest", item.get("manifest_path"))
        manifest_secret_env = item.get("manifest_secret_env")
        manifest_secret = item.get("manifest_secret")
        manifest_key_id = item.get("manifest_key_id")
        manifest_identity = item.get("manifest_identity")
        raw_manifest_required = item.get("manifest_required")
        if raw_manifest_required is None:
            manifest_required = manifest is not None
        elif isinstance(raw_manifest_required, bool):
            manifest_required = raw_manifest_required
        else:
            raise ValueError(f"mcp.proxy.upstreams[{index}].manifest_required must be a boolean")
        tool_prefix = item.get("tool_prefix", f"{name}.")
        default = bool(item.get("default", False))
        if not isinstance(name, str) or not name:
            raise ValueError(f"mcp.proxy.upstreams[{index}].name must be a non-empty string")
        if transport not in {"http", "stdio", "holepunch"}:
            raise ValueError(f"mcp.proxy.upstreams[{index}].transport must be 'http', 'stdio', or 'holepunch'")
        if transport == "http" and (not isinstance(url, str) or not url):
            raise ValueError(f"mcp.proxy.upstreams[{index}].url must be a non-empty string")
        if transport == "stdio" and (not isinstance(command, str) or not command):
            raise ValueError(f"mcp.proxy.upstreams[{index}].command must be a non-empty string")
        if transport == "holepunch":
            if local_port is not None and (not isinstance(local_port, int) or local_port <= 0):
                raise ValueError(f"mcp.proxy.upstreams[{index}].local_port must be a positive integer")
            if not isinstance(url, str) or not url:
                if local_port is None:
                    raise ValueError(f"mcp.proxy.upstreams[{index}].url or local_port is required")
                url = f"http://127.0.0.1:{local_port}/mcp"
            if peer is not None and not isinstance(peer, str):
                raise ValueError(f"mcp.proxy.upstreams[{index}].peer must be a string")
            if bridge_config is not None and not isinstance(bridge_config, str):
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_config must be a string")
            if not isinstance(bridge_command, str) or not bridge_command:
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_command must be a non-empty string")
            if bridge_args is not None and (
                not isinstance(bridge_args, list) or not all(isinstance(arg, str) for arg in bridge_args)
            ):
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_args must be a list of strings")
            if bridge_args is None and not peer and not bridge_config:
                raise ValueError(f"mcp.proxy.upstreams[{index}].peer, bridge_config, or bridge_args is required")
            if bridge_cwd is not None and not isinstance(bridge_cwd, str):
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_cwd must be a string")
            if bridge_env is not None:
                if not isinstance(bridge_env, Mapping):
                    raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_env must be a table of strings")
                if not all(
                    isinstance(key, str) and isinstance(item_value, str) for key, item_value in bridge_env.items()
                ):
                    raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_env must be a table of strings")
            if not isinstance(bridge_private, bool):
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_private must be a boolean")
            if not isinstance(bridge_ready_timeout, int | float) or float(bridge_ready_timeout) <= 0:
                raise ValueError(f"mcp.proxy.upstreams[{index}].bridge_ready_timeout must be a positive number")
        if not isinstance(tool_prefix, str) or not tool_prefix:
            raise ValueError(f"mcp.proxy.upstreams[{index}].tool_prefix must be a non-empty string")
        if auth is not None and (not isinstance(auth, str) or not auth):
            raise ValueError(f"mcp.proxy.upstreams[{index}].auth must be a non-empty credential id")
        if credential is not None:
            credential = normalize_upstream_credential(
                credential,
                field=f"mcp.proxy.upstreams[{index}].credential",
                base_dir=base_dir,
                resolve_relative_paths=True,
            )
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f"mcp.proxy.upstreams[{index}].args must be a list of strings")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError(f"mcp.proxy.upstreams[{index}].cwd must be a string")
        if manifest is not None and not isinstance(manifest, str | Path):
            raise ValueError(f"mcp.proxy.upstreams[{index}].manifest must be a string path")
        for manifest_field, manifest_value in (
            ("manifest_secret_env", manifest_secret_env),
            ("manifest_secret", manifest_secret),
            ("manifest_key_id", manifest_key_id),
            ("manifest_identity", manifest_identity),
        ):
            if manifest_value is not None and not isinstance(manifest_value, str):
                raise ValueError(f"mcp.proxy.upstreams[{index}].{manifest_field} must be a string")
        if env is not None:
            if not isinstance(env, Mapping):
                raise ValueError(f"mcp.proxy.upstreams[{index}].env must be a table of strings")
            if not all(isinstance(key, str) and isinstance(item_value, str) for key, item_value in env.items()):
                raise ValueError(f"mcp.proxy.upstreams[{index}].env must be a table of strings")
        if not isinstance(discovered, bool):
            raise ValueError(f"mcp.proxy.upstreams[{index}].discovered must be a boolean")
        for discovery_field, discovery_value in (
            ("discovery_provider", discovery_provider),
            ("discovery_type", discovery_type),
            ("discovery_source", discovery_source),
            ("fabric_member_id", fabric_member_id),
            ("fabric_member_role", fabric_member_role),
            ("fabric_member_status", fabric_member_status),
            ("fabric_member_heartbeat_at", fabric_member_heartbeat_at),
            ("fabric_member_expires_at", fabric_member_expires_at),
        ):
            if discovery_value is not None and not isinstance(discovery_value, str):
                raise ValueError(f"mcp.proxy.upstreams[{index}].{discovery_field} must be a string")
        if name in names:
            raise ValueError(f"duplicate mcp.proxy.upstreams name: {name!r}")
        if tool_prefix in prefixes:
            raise ValueError(f"duplicate mcp.proxy.upstreams tool_prefix: {tool_prefix!r}")
        names.add(name)
        prefixes.add(tool_prefix)
        default_count += int(default)
        if transport == "holepunch" and bridge_args is None:
            bridge_args = _holepunch_bridge_args(
                url=str(url),
                local_port=local_port,
                peer=peer,
                bridge_config=bridge_config,
                bridge_private=bridge_private,
            )
        upstreams.append(
            {
                "name": name,
                "transport": transport,
                "tool_prefix": tool_prefix,
                "default": default,
                **({"auth": auth} if auth is not None else {}),
                **({"credential": credential} if credential is not None else {}),
                **({"url": url} if transport in {"http", "holepunch"} else {}),
                **(
                    {
                        "command": command,
                        "args": list(args),
                        **({"cwd": cwd} if cwd is not None else {}),
                        **({"env": dict(env)} if isinstance(env, Mapping) else {}),
                    }
                    if transport == "stdio"
                    else {}
                ),
                **(
                    {
                        **({"peer": peer} if peer is not None else {}),
                        **({"local_port": local_port} if local_port is not None else {}),
                        **({"bridge_config": bridge_config} if bridge_config is not None else {}),
                        "bridge_command": bridge_command,
                        "bridge_args": list(bridge_args),
                        **({"bridge_cwd": bridge_cwd} if bridge_cwd is not None else {}),
                        **({"bridge_env": dict(bridge_env)} if isinstance(bridge_env, Mapping) else {}),
                        "bridge_private": bridge_private,
                        "bridge_ready_timeout": float(bridge_ready_timeout),
                    }
                    if transport == "holepunch"
                    else {}
                ),
                **(
                    {
                        "manifest": _resolve_path(base_dir, manifest),
                        "manifest_required": manifest_required,
                        **({"manifest_secret_env": manifest_secret_env} if manifest_secret_env is not None else {}),
                        **({"manifest_secret": manifest_secret} if manifest_secret is not None else {}),
                        **({"manifest_key_id": manifest_key_id} if manifest_key_id is not None else {}),
                        **({"manifest_identity": manifest_identity} if manifest_identity is not None else {}),
                    }
                    if manifest is not None
                    else {}
                ),
                **(
                    {
                        "discovered": True,
                        **({"discovery_provider": discovery_provider} if discovery_provider is not None else {}),
                        **({"discovery_type": discovery_type} if discovery_type is not None else {}),
                        **({"discovery_source": discovery_source} if discovery_source is not None else {}),
                        **({"fabric_member_id": fabric_member_id} if fabric_member_id is not None else {}),
                        **({"fabric_member_role": fabric_member_role} if fabric_member_role is not None else {}),
                        **({"fabric_member_status": fabric_member_status} if fabric_member_status is not None else {}),
                        **(
                            {"fabric_member_heartbeat_at": fabric_member_heartbeat_at}
                            if fabric_member_heartbeat_at is not None
                            else {}
                        ),
                        **(
                            {"fabric_member_expires_at": fabric_member_expires_at}
                            if fabric_member_expires_at is not None
                            else {}
                        ),
                    }
                    if discovered or fabric_member_id is not None
                    else {}
                ),
            }
        )
    if default_count > 1:
        raise ValueError("only one mcp.proxy.upstreams entry may set default = true")
    return upstreams


def _holepunch_bridge_args(
    *,
    url: str,
    local_port: int | None,
    peer: str | None,
    bridge_config: str | None,
    bridge_private: bool,
) -> list[str]:
    port = local_port
    if port is None:
        try:
            from urllib.parse import urlsplit

            port = urlsplit(url).port
        except Exception:
            port = None
    if port is None:
        raise ValueError("holepunch upstream url must include a port when local_port is omitted")
    args = ["-p", str(port)]
    if bridge_config:
        args.extend(["-c", bridge_config])
    elif peer:
        args.extend(["-s", peer])
    if bridge_private:
        args.append("--private")
    return args

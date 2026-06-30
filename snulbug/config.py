from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .credentials import attach_upstream_credentials, normalize_fabric_credentials, normalize_upstream_credential
from .discovery import apply_fabric_discovery
from .events import normalize_event_sink_configs
from .gateway_templates import render_toml_array_table
from .policy_backoff import (
    DEFAULT_POLICY_BACKOFF_EXCLUDE_REASON_CODES,
    DEFAULT_POLICY_BACKOFF_KEY_FIELDS,
    DEFAULT_POLICY_BACKOFF_REASON_CODES,
)
from .tool_catalog import CATALOG_PROJECTION_MODES
from .upstream_transports import get_upstream_transport

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10.
    import tomli as tomllib  # type: ignore[import-not-found]

DEFAULT_CONFIG_PATH = "snulbug.toml"
REMOVED_EVENT_OUTPUT_KEYS = {"audit_out", "decision_console", "decision_console_format", "webhooks"}
PROTECTED_RESOURCE_AUTH_MODES = {"oauth-resource", "enterprise-managed"}

DEFAULT_MCP_AUTH_CONFIG = {
    "mode": "off",
    "resource": None,
    "resource_aliases": [],
    "issuer": None,
    "authorization_servers": [],
    "audience": None,
    "audiences": [],
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
    "dpop_mode": "optional",
    "dpop_signing_alg_values_supported": [
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "RS256",
        "RS384",
        "RS512",
        "EdDSA",
    ],
    "dpop_proof_max_age_seconds": 300.0,
    "dpop_replay_cache_max_entries": 10000,
    "scope_map": {},
    "claim_policy": {
        "enabled": False,
        "default_action": "deny",
        "rules": [],
    },
    "required_claims": {},
    "issuers": [],
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
    "lease_required": True,
    "lease_header": "x-snulbug-lease",
    "tunnel_provider": "auto",
    "tunnel_public_url": None,
    "cloudflare_access_profile": None,
    "tailscale_profile": None,
    "cloudflare_access": "off",
    "cloudflare_access_require_jwt": True,
    "cloudflare_access_require_email": False,
    "cloudflare_access_require_cf_ray": True,
    "cloudflare_access_allowed_emails": [],
    "cloudflare_access_allowed_domains": [],
    "cloudflare_access_validate_jwt": False,
    "cloudflare_access_team_domain": None,
    "cloudflare_access_issuer": None,
    "cloudflare_access_audience": None,
    "cloudflare_access_certs_url": None,
    "cloudflare_access_jwks_cache_seconds": 300.0,
    "cloudflare_access_jwks_fetch_timeout": 5.0,
    "cloudflare_access_leeway_seconds": 60.0,
    "timeout": 30.0,
    "event_sinks": [],
    "catalog_projection": "off",
}

DEFAULT_MCP_CATALOG_CONFIG = {
    "projection": "off",
}

DEFAULT_MCP_POLICY_BACKOFF_CONFIG = {
    "enabled": False,
    "base_seconds": 2.0,
    "factor": 2.0,
    "max_seconds": 60.0,
    "window_seconds": 300.0,
    "jitter": True,
    "status": 429,
    "reason_codes": list(DEFAULT_POLICY_BACKOFF_REASON_CODES),
    "exclude_reason_codes": list(DEFAULT_POLICY_BACKOFF_EXCLUDE_REASON_CODES),
    "key_fields": list(DEFAULT_POLICY_BACKOFF_KEY_FIELDS),
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
lease_required = true
lease_header = "x-snulbug-lease"
tunnel_provider = "auto"
tunnel_public_url = ""
cloudflare_access_profile = ""
tailscale_profile = ""
cloudflare_access = "off"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = false
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_emails = []
cloudflare_access_allowed_domains = []
cloudflare_access_validate_jwt = false
cloudflare_access_team_domain = ""
cloudflare_access_audience = ""
cloudflare_access_certs_url = ""
cloudflare_access_jwks_cache_seconds = 300.0
cloudflare_access_jwks_fetch_timeout = 5.0
cloudflare_access_leeway_seconds = 60.0
timeout = 30.0

[mcp.catalog]
# Optional tools/list projection. "policy-aware" hides tools the caller cannot
# invoke under OAuth scope maps, claim policies, and task leases.
projection = "off"

[mcp.policy_backoff]
# Optional exponential backoff for repeated equivalent Lua policy denies.
enabled = false
base_seconds = 2
factor = 2.0
max_seconds = 60
window_seconds = 300
jitter = true
status = 429
reason_codes = ["mcp.*", "oauth.scope_map_denied", "lease.tool_not_allowed"]
exclude_reason_codes = ["oauth.invalid_token", "cloudflare_access.*"]
key_fields = [
  "auth.subject",
  "auth.client_id",
  "auth.tenant",
  "lease.id",
  "mcp.method",
  "mcp.tool",
  "mcp.target",
  "upstream.name",
  "decision.reason_code",
]

[mcp.auth]
# Optional OAuth 2.1 protected-resource mode for public MCP endpoints.
# Use "enterprise-managed" when an enterprise IdP/client owns the MCP
# authorization flow and snulbug validates the resulting access token.
# mode = "oauth-resource"
# resource = "https://YOUR-TUNNEL.example/mcp"
# resource_aliases = [] # additional public MCP URLs that intentionally reach this gateway
# issuer = "https://issuer.example"
# authorization_servers = ["https://issuer.example"]
# audience = "https://YOUR-TUNNEL.example/mcp"
# audiences = [] # additional accepted aud/resource indicator values
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
# dpop_mode = "optional" # off, optional, or required
# dpop_signing_alg_values_supported = ["ES256", "RS256", "PS256", "EdDSA"]
# dpop_proof_max_age_seconds = 300
# dpop_replay_cache_max_entries = 10000
#
# Optional MCP-aware scope-to-method/tool mapping:
# [mcp.auth.scope_map]
# "mcp:tools.read" = ["tools/list", "resources/list"]
# "mcp:tool.files.read" = ["tools/call:filesystem.read_file"]
# "mcp:tool.git.status" = ["tools/call:git.status"]
#
# Optional declarative claim-to-tool mapping before Lua:
# [mcp.auth.claim_policy]
# enabled = true
# default_action = "deny"
#
# [[mcp.auth.claim_policy.rules]]
# id = "tenant-a-tools"
# claim = "tenant" # aliases include tenant/tid, subject/sub, client_id/azp, scope
# values = ["tenant-a"]
# allow_tool_prefixes = ["tenant_a.", "shared."]
# allow_tools = ["filesystem.read_file"]
# allow_selectors = ["tools/call:git.status"]
#
# Optional multi-issuer / multi-tenant profiles. Each profile inherits unset
# fields from [mcp.auth] and can override issuer, audience, JWKS, scope_map,
# required_claims, and claim_policy.
# [[mcp.auth.issuers]]
# id = "tenant-a"
# issuer = "https://tenant-a-idp.example"
# audience = "https://YOUR-TUNNEL.example/mcp"
# jwks_url = "https://tenant-a-idp.example/.well-known/jwks.json"
# required_scopes = ["mcp:connect"]
# required_claims = { tenant = ["tenant-a"] }
#
# [mcp.auth.issuers.scope_map]
# "mcp:tenant-a.files" = ["tools/call:tenant_a.*"]

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
    catalog = mcp.get("catalog", {})
    if not isinstance(catalog, Mapping):
        raise ValueError("config section [mcp.catalog] must be a table")
    policy_backoff = mcp.get("policy_backoff", {})
    if not isinstance(policy_backoff, Mapping):
        raise ValueError("config section [mcp.policy_backoff] must be a table")
    fabric = mcp.get("fabric", {})
    if not isinstance(fabric, Mapping):
        raise ValueError("config section [mcp.fabric] must be a table")
    event_sinks = _load_event_sinks_table(mcp)
    return _normalize_proxy_config_with_discovery(
        proxy,
        fabric,
        auth=auth,
        catalog=catalog,
        policy_backoff=policy_backoff,
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
    catalog = mcp.get("catalog", {})
    if not isinstance(catalog, Mapping):
        raise ValueError("config section [mcp.catalog] must be a table")
    policy_backoff = mcp.get("policy_backoff", {})
    if not isinstance(policy_backoff, Mapping):
        raise ValueError("config section [mcp.policy_backoff] must be a table")
    event_sinks = _load_event_sinks_table(mcp)
    proxy_config = _normalize_proxy_config_with_discovery(
        proxy,
        fabric,
        auth=auth,
        catalog=catalog,
        policy_backoff=policy_backoff,
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
    catalog: Mapping[str, Any] | None = None,
    policy_backoff: Mapping[str, Any] | None = None,
    event_sinks: Any = None,
    base_dir: Path,
) -> dict[str, Any]:
    credentials = normalize_fabric_credentials(fabric.get("credentials", {}), base_dir=base_dir)
    discovered_proxy, discovery = apply_fabric_discovery(proxy, fabric, base_dir=base_dir)
    discovered_proxy = attach_upstream_credentials(discovered_proxy, credentials)
    proxy_config = normalize_mcp_proxy_config(discovered_proxy, base_dir=base_dir)
    proxy_config["auth"] = normalize_mcp_auth_config(auth, base_dir=base_dir)
    proxy_config["catalog"] = normalize_mcp_catalog_config(catalog)
    proxy_config["catalog_projection"] = proxy_config["catalog"]["projection"]
    proxy_config["policy_backoff"] = normalize_mcp_policy_backoff_config(policy_backoff)
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
        "catalog_projection",
        "cloudflare_access_profile",
        "tailscale_profile",
        "cloudflare_access",
        "cloudflare_access_team_domain",
        "cloudflare_access_issuer",
        "cloudflare_access_audience",
        "cloudflare_access_certs_url",
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
        "cloudflare_access_validate_jwt",
    ):
        if not isinstance(normalized.get(field), bool):
            raise ValueError(f"mcp.proxy.{field} must be a boolean")
    for field in (
        "cloudflare_access_jwks_cache_seconds",
        "cloudflare_access_jwks_fetch_timeout",
        "cloudflare_access_leeway_seconds",
    ):
        value = normalized.get(field)
        if not isinstance(value, int | float) or float(value) < 0:
            raise ValueError(f"mcp.proxy.{field} must be a non-negative number")
    if normalized["tool_pinning_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.tool_pinning_action must be 'warn' or 'block'")
    if normalized["schema_validation_action"] not in {"warn", "block"}:
        raise ValueError("mcp.proxy.schema_validation_action must be 'warn' or 'block'")
    if normalized["catalog_projection"] not in CATALOG_PROJECTION_MODES:
        raise ValueError("mcp.proxy.catalog_projection must be 'off' or 'policy-aware'")
    if normalized["tunnel_provider"] not in {
        "auto",
        "generic",
        "ngrok",
        "cloudflare",
        "tailscale",
        "pinggy",
        "ssh",
        "holepunch",
    }:
        raise ValueError(
            "mcp.proxy.tunnel_provider must be 'auto', 'generic', 'ngrok', 'cloudflare', "
            "'tailscale', 'pinggy', 'ssh', or 'holepunch'"
        )
    if normalized["cloudflare_access"] not in {"off", "audit", "enforce"}:
        raise ValueError("mcp.proxy.cloudflare_access must be 'off', 'audit', or 'enforce'")
    if normalized.get("cloudflare_access_profile") == "":
        normalized["cloudflare_access_profile"] = None
    if normalized.get("cloudflare_access_profile") is not None and normalized["cloudflare_access_profile"] not in {
        "access-gate",
        "service-token",
        "oauth-resource",
        "audit",
    }:
        raise ValueError(
            "mcp.proxy.cloudflare_access_profile must be 'access-gate', 'service-token', 'oauth-resource', or 'audit'"
        )
    if normalized.get("tailscale_profile") == "":
        normalized["tailscale_profile"] = None
    if normalized.get("tailscale_profile") is not None and normalized["tailscale_profile"] not in {
        "funnel-public",
        "serve-tailnet",
        "oauth-resource",
    }:
        raise ValueError("mcp.proxy.tailscale_profile must be 'funnel-public', 'serve-tailnet', or 'oauth-resource'")

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
    for field in (
        "cloudflare_access_team_domain",
        "cloudflare_access_issuer",
        "cloudflare_access_audience",
        "cloudflare_access_certs_url",
    ):
        if normalized.get(field) == "":
            normalized[field] = None
    normalized["policy"] = _resolve_path(base, normalized["policy"])
    for field in ("record_out",):
        if normalized.get(field):
            normalized[field] = _resolve_path(base, normalized[field])
    if normalized.get("lease_file"):
        normalized["lease_file"] = _resolve_path(base, normalized["lease_file"])
    normalized["timeout"] = float(normalized["timeout"])
    normalized["cloudflare_access_jwks_cache_seconds"] = float(normalized["cloudflare_access_jwks_cache_seconds"])
    normalized["cloudflare_access_jwks_fetch_timeout"] = float(normalized["cloudflare_access_jwks_fetch_timeout"])
    normalized["cloudflare_access_leeway_seconds"] = float(normalized["cloudflare_access_leeway_seconds"])
    normalized["facade_health_cooldown_seconds"] = float(normalized["facade_health_cooldown_seconds"])
    normalized["event_sinks"] = normalize_event_sink_configs(normalized.get("event_sinks", []), base_dir=base)
    normalized["auth"] = normalize_mcp_auth_config(normalized.get("auth", {}), base_dir=base)
    normalized["catalog"] = normalize_mcp_catalog_config({"projection": normalized["catalog_projection"]})
    normalized["policy_backoff"] = normalize_mcp_policy_backoff_config(normalized.get("policy_backoff"))
    return normalized


def normalize_mcp_catalog_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    if config in (None, ""):
        config = {}
    if not isinstance(config, Mapping):
        raise ValueError("mcp.catalog must be a table")
    normalized = dict(DEFAULT_MCP_CATALOG_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})
    projection = normalized.get("projection")
    if not isinstance(projection, str):
        raise ValueError("mcp.catalog.projection must be a string")
    if projection not in CATALOG_PROJECTION_MODES:
        raise ValueError("mcp.catalog.projection must be 'off' or 'policy-aware'")
    return normalized


def normalize_mcp_policy_backoff_config(config: Mapping[str, Any] | None) -> dict[str, Any]:
    if config in (None, ""):
        config = {}
    if not isinstance(config, Mapping):
        raise ValueError("mcp.policy_backoff must be a table")
    normalized = dict(DEFAULT_MCP_POLICY_BACKOFF_CONFIG)
    normalized.update({key: value for key, value in config.items() if value is not None})
    if not isinstance(normalized.get("enabled"), bool):
        raise ValueError("mcp.policy_backoff.enabled must be a boolean")
    if not isinstance(normalized.get("jitter"), bool):
        raise ValueError("mcp.policy_backoff.jitter must be a boolean")
    for field in ("base_seconds", "factor", "max_seconds", "window_seconds"):
        value = normalized.get(field)
        if not isinstance(value, int | float) or float(value) <= 0:
            raise ValueError(f"mcp.policy_backoff.{field} must be a positive number")
        normalized[field] = float(value)
    if normalized["factor"] < 1:
        raise ValueError("mcp.policy_backoff.factor must be at least 1")
    status = normalized.get("status")
    if not isinstance(status, int) or status < 400 or status > 599:
        raise ValueError("mcp.policy_backoff.status must be an HTTP error status")
    normalized["reason_codes"] = _normalize_string_list(
        normalized.get("reason_codes"),
        field="policy_backoff.reason_codes",
    )
    normalized["exclude_reason_codes"] = _normalize_string_list(
        normalized.get("exclude_reason_codes"),
        field="policy_backoff.exclude_reason_codes",
    )
    normalized["key_fields"] = _normalize_string_list(
        normalized.get("key_fields"),
        field="policy_backoff.key_fields",
    )
    if not normalized["reason_codes"]:
        raise ValueError("mcp.policy_backoff.reason_codes must not be empty")
    if not normalized["key_fields"]:
        raise ValueError("mcp.policy_backoff.key_fields must not be empty")
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
    if mode not in {"off", *PROTECTED_RESOURCE_AUTH_MODES}:
        raise ValueError("mcp.auth.mode must be 'off', 'oauth-resource', or 'enterprise-managed'")
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
        "dpop_mode",
    ):
        value = normalized.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"mcp.auth.{field} must be a string")
        if value == "":
            normalized[field] = None if field != "realm" else "mcp"
    for field in ("authorization_servers", "resource_aliases", "audiences", "required_scopes", "scopes_supported"):
        normalized[field] = _normalize_auth_string_list(normalized.get(field), field=field)
    if normalized["dpop_mode"] not in {"off", "optional", "required"}:
        raise ValueError("mcp.auth.dpop_mode must be 'off', 'optional', or 'required'")
    normalized["dpop_signing_alg_values_supported"] = _normalize_auth_string_list(
        normalized.get("dpop_signing_alg_values_supported"),
        field="dpop_signing_alg_values_supported",
    )
    if not normalized["dpop_signing_alg_values_supported"]:
        raise ValueError("mcp.auth.dpop_signing_alg_values_supported must not be empty")
    _validate_dpop_signing_algorithms(
        normalized["dpop_signing_alg_values_supported"],
        field="mcp.auth.dpop_signing_alg_values_supported",
    )
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
        "dpop_proof_max_age_seconds",
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
    if (
        not isinstance(normalized.get("dpop_replay_cache_max_entries"), int)
        or normalized["dpop_replay_cache_max_entries"] <= 0
    ):
        raise ValueError("mcp.auth.dpop_replay_cache_max_entries must be a positive integer")
    if not isinstance(normalized.get("strip_authorization_upstream"), bool):
        raise ValueError("mcp.auth.strip_authorization_upstream must be a boolean")
    normalized["scope_map"] = _normalize_auth_scope_map(normalized.get("scope_map", {}))
    normalized["claim_policy"] = _normalize_auth_claim_policy(normalized.get("claim_policy", {}))
    normalized["required_claims"] = _normalize_auth_required_claims(normalized.get("required_claims", {}))
    if normalized["mode"] in PROTECTED_RESOURCE_AUTH_MODES:
        if not normalized.get("resource"):
            raise ValueError("mcp.auth.resource is required when protected-resource auth is enabled")
        normalized["issuers"] = _normalize_auth_issuer_profiles(
            normalized.get("issuers", []),
            parent=normalized,
            base_dir=Path(base_dir),
        )
        if not normalized["issuers"]:
            _validate_oauth_token_config(normalized, field="mcp.auth")
        if not normalized["scopes_supported"]:
            normalized["scopes_supported"] = _auth_scopes_supported(normalized)
    else:
        normalized["issuers"] = _normalize_auth_issuer_profiles(
            normalized.get("issuers", []),
            parent=normalized,
            base_dir=Path(base_dir),
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


def _normalize_auth_required_claims(value: Any, *, field: str = "required_claims") -> dict[str, list[str]]:
    if value in (None, ""):
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"mcp.auth.{field} must be a table")
    result: dict[str, list[str]] = {}
    for claim, expected in value.items():
        if not isinstance(claim, str) or not claim:
            raise ValueError(f"mcp.auth.{field} keys must be non-empty claim strings")
        expected_values = _normalize_auth_string_list(expected, field=f"{field}.{claim}")
        if not expected_values or any(not item for item in expected_values):
            raise ValueError(f"mcp.auth.{field}.{claim} must contain non-empty strings")
        result[claim] = expected_values
    return result


def _normalize_auth_issuer_profiles(
    value: Any,
    *,
    parent: Mapping[str, Any],
    base_dir: Path,
) -> list[dict[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("mcp.auth.issuers must be a list of tables")
    profiles = []
    ids = set()
    for index, item in enumerate(value):
        profile = _normalize_auth_issuer_profile(item, parent=parent, base_dir=base_dir, index=index)
        if profile["id"] in ids:
            raise ValueError(f"mcp.auth.issuers[{index}].id must be unique")
        ids.add(profile["id"])
        profiles.append(profile)
    return profiles


def _normalize_auth_issuer_profile(
    value: Any,
    *,
    parent: Mapping[str, Any],
    base_dir: Path,
    index: int,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"mcp.auth.issuers[{index}] must be a table")
    profile_id = value.get("id")
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError(f"mcp.auth.issuers[{index}].id must be a non-empty string")

    inherited_fields = (
        "mode",
        "resource",
        "resource_aliases",
        "issuer",
        "authorization_servers",
        "audience",
        "audiences",
        "required_scopes",
        "scopes_supported",
        "jwks_path",
        "jwks_url",
        "jwks_cache_seconds",
        "jwks_fetch_timeout",
        "issuer_metadata_url",
        "issuer_discovery",
        "token_validation",
        "introspection_endpoint",
        "introspection_client_id",
        "introspection_client_secret_env",
        "introspection_cache_seconds",
        "introspection_fetch_timeout",
        "resource_metadata_url",
        "realm",
        "leeway_seconds",
        "strip_authorization_upstream",
        "dpop_mode",
        "dpop_signing_alg_values_supported",
        "dpop_proof_max_age_seconds",
        "dpop_replay_cache_max_entries",
        "scope_map",
        "claim_policy",
        "required_claims",
    )
    profile = {field: parent.get(field) for field in inherited_fields}
    profile.update({key: item for key, item in value.items() if item is not None})
    profile["id"] = profile_id

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
        "dpop_mode",
    ):
        item = profile.get(field)
        if item is not None and not isinstance(item, str):
            raise ValueError(f"mcp.auth.issuers[{index}].{field} must be a string")
        if item == "":
            profile[field] = None if field != "realm" else "mcp"
    for field in ("authorization_servers", "resource_aliases", "audiences", "required_scopes", "scopes_supported"):
        profile[field] = _normalize_auth_string_list(profile.get(field), field=f"issuers[{index}].{field}")
    if profile["dpop_mode"] not in {"off", "optional", "required"}:
        raise ValueError(f"mcp.auth.issuers[{index}].dpop_mode must be 'off', 'optional', or 'required'")
    profile["dpop_signing_alg_values_supported"] = _normalize_auth_string_list(
        profile.get("dpop_signing_alg_values_supported"),
        field=f"issuers[{index}].dpop_signing_alg_values_supported",
    )
    if not profile["dpop_signing_alg_values_supported"]:
        raise ValueError(f"mcp.auth.issuers[{index}].dpop_signing_alg_values_supported must not be empty")
    _validate_dpop_signing_algorithms(
        profile["dpop_signing_alg_values_supported"],
        field=f"mcp.auth.issuers[{index}].dpop_signing_alg_values_supported",
    )

    jwks_path = profile.get("jwks_path")
    if jwks_path in (None, ""):
        profile["jwks_path"] = None
    elif isinstance(jwks_path, str | Path):
        profile["jwks_path"] = _resolve_path(base_dir, jwks_path)
    else:
        raise ValueError(f"mcp.auth.issuers[{index}].jwks_path must be a string path")

    if profile["token_validation"] not in {"jwt", "introspection", "jwt_or_introspection", "jwt_and_introspection"}:
        raise ValueError(
            f"mcp.auth.issuers[{index}].token_validation must be 'jwt', 'introspection', "
            "'jwt_or_introspection', or 'jwt_and_introspection'"
        )
    if not isinstance(profile.get("issuer_discovery"), bool):
        raise ValueError(f"mcp.auth.issuers[{index}].issuer_discovery must be a boolean")
    for field in (
        "jwks_cache_seconds",
        "jwks_fetch_timeout",
        "introspection_cache_seconds",
        "introspection_fetch_timeout",
        "dpop_proof_max_age_seconds",
    ):
        if not isinstance(profile.get(field), int | float) or float(profile[field]) < 0:
            raise ValueError(f"mcp.auth.issuers[{index}].{field} must be a non-negative number")
        profile[field] = float(profile[field])
    if profile["jwks_fetch_timeout"] <= 0:
        raise ValueError(f"mcp.auth.issuers[{index}].jwks_fetch_timeout must be positive")
    if profile["introspection_fetch_timeout"] <= 0:
        raise ValueError(f"mcp.auth.issuers[{index}].introspection_fetch_timeout must be positive")
    if not isinstance(profile.get("leeway_seconds"), int | float) or float(profile["leeway_seconds"]) < 0:
        raise ValueError(f"mcp.auth.issuers[{index}].leeway_seconds must be a non-negative number")
    profile["leeway_seconds"] = float(profile["leeway_seconds"])
    if (
        not isinstance(profile.get("dpop_replay_cache_max_entries"), int)
        or profile["dpop_replay_cache_max_entries"] <= 0
    ):
        raise ValueError(f"mcp.auth.issuers[{index}].dpop_replay_cache_max_entries must be a positive integer")
    if not isinstance(profile.get("strip_authorization_upstream"), bool):
        raise ValueError(f"mcp.auth.issuers[{index}].strip_authorization_upstream must be a boolean")
    profile["scope_map"] = _normalize_auth_scope_map(profile.get("scope_map", {}))
    profile["claim_policy"] = _normalize_auth_claim_policy(profile.get("claim_policy", {}))
    profile["required_claims"] = _normalize_auth_required_claims(
        profile.get("required_claims", {}),
        field=f"issuers[{index}].required_claims",
    )
    _validate_oauth_token_config(profile, field=f"mcp.auth.issuers[{index}]")
    if not profile["scopes_supported"]:
        profile["scopes_supported"] = _auth_scopes_supported(profile)
    return profile


def _validate_oauth_token_config(config: Mapping[str, Any], *, field: str) -> None:
    if not config.get("audience") and not config.get("audiences"):
        raise ValueError(f"{field}.audience or {field}.audiences is required when protected-resource auth is enabled")
    token_validation = config["token_validation"]
    uses_jwt = token_validation in {"jwt", "jwt_or_introspection", "jwt_and_introspection"}
    uses_introspection = token_validation in {"introspection", "jwt_or_introspection", "jwt_and_introspection"}
    has_issuer_discovery = bool(config.get("issuer_discovery") and config.get("issuer"))
    if uses_jwt and not config.get("jwks_path") and not config.get("jwks_url") and not has_issuer_discovery:
        raise ValueError(
            f"{field}.jwks_path, {field}.jwks_url, or {field}.issuer discovery is required "
            "when JWT validation is enabled"
        )
    if uses_introspection and not config.get("introspection_endpoint") and not has_issuer_discovery:
        raise ValueError(
            f"{field}.introspection_endpoint or {field}.issuer discovery is required "
            "when token introspection is enabled"
        )


def _validate_dpop_signing_algorithms(values: Sequence[str], *, field: str) -> None:
    for value in values:
        if value == "none" or value.startswith("HS"):
            raise ValueError(f"{field} must contain only asymmetric signing algorithms")


def _auth_scopes_supported(config: Mapping[str, Any]) -> list[str]:
    scopes = {
        *config.get("required_scopes", []),
        *_normalize_auth_scope_map(config.get("scope_map", {})),
    }
    for profile in config.get("issuers", []):
        if isinstance(profile, Mapping):
            scopes.update(profile.get("required_scopes", []))
            scopes.update(_normalize_auth_scope_map(profile.get("scope_map", {})))
    return sorted(str(scope) for scope in scopes)


def _normalize_auth_claim_policy(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        value = {}
    if not isinstance(value, Mapping):
        raise ValueError("mcp.auth.claim_policy must be a table")
    normalized = {
        "enabled": False,
        "default_action": "deny",
        "rules": [],
    }
    normalized.update({key: item for key, item in value.items() if item is not None})
    if not isinstance(normalized.get("enabled"), bool):
        raise ValueError("mcp.auth.claim_policy.enabled must be a boolean")
    if normalized.get("default_action") not in {"deny", "allow"}:
        raise ValueError("mcp.auth.claim_policy.default_action must be 'deny' or 'allow'")
    rules = normalized.get("rules", [])
    if rules in (None, ""):
        rules = []
    if not isinstance(rules, list):
        raise ValueError("mcp.auth.claim_policy.rules must be a list of tables")
    normalized_rules = [_normalize_auth_claim_policy_rule(rule, index=index) for index, rule in enumerate(rules)]
    if normalized["enabled"] and not normalized_rules:
        raise ValueError("mcp.auth.claim_policy.rules must contain at least one rule when enabled")
    normalized["rules"] = normalized_rules
    return normalized


def _normalize_auth_claim_policy_rule(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"mcp.auth.claim_policy.rules[{index}] must be a table")
    rule = dict(value)
    rule_id = rule.get("id", f"rule-{index + 1}")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"mcp.auth.claim_policy.rules[{index}].id must be a non-empty string")
    claim = rule.get("claim")
    if not isinstance(claim, str) or not claim:
        raise ValueError(f"mcp.auth.claim_policy.rules[{index}].claim must be a non-empty string")
    values = _normalize_auth_string_list(
        rule.get("values"),
        field=f"claim_policy.rules[{index}].values",
    )
    if not values or any(not value for value in values):
        raise ValueError(f"mcp.auth.claim_policy.rules[{index}].values must contain non-empty strings")
    allow_tools = _normalize_auth_string_list(
        rule.get("allow_tools"),
        field=f"claim_policy.rules[{index}].allow_tools",
    )
    allow_tool_prefixes = _normalize_auth_string_list(
        rule.get("allow_tool_prefixes"),
        field=f"claim_policy.rules[{index}].allow_tool_prefixes",
    )
    allow_selectors = _normalize_auth_string_list(
        rule.get("allow_selectors"),
        field=f"claim_policy.rules[{index}].allow_selectors",
    )
    if any(not item for item in [*allow_tools, *allow_tool_prefixes, *allow_selectors]):
        raise ValueError(f"mcp.auth.claim_policy.rules[{index}] allow entries must be non-empty strings")
    if not allow_tools and not allow_tool_prefixes and not allow_selectors:
        raise ValueError(
            f"mcp.auth.claim_policy.rules[{index}] must configure allow_tools, allow_tool_prefixes, or allow_selectors"
        )
    return {
        "id": rule_id,
        "claim": claim,
        "values": values,
        "allow_tools": allow_tools,
        "allow_tool_prefixes": allow_tool_prefixes,
        "allow_selectors": allow_selectors,
    }


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
        transport_plugin = get_upstream_transport(item.get("transport") or ("stdio" if item.get("command") else "http"))
        transport = transport_plugin.normalized_type
        transport_fields = transport_plugin.normalize_config(
            item,
            field=f"mcp.proxy.upstreams[{index}]",
            base_dir=base_dir,
        )
        discovered = item.get("discovered", False)
        discovery_provider = item.get("discovery_provider")
        discovery_type = item.get("discovery_type")
        discovery_source = item.get("discovery_source")
        fabric_member_id = item.get("fabric_member_id")
        fabric_member_role = item.get("fabric_member_role")
        fabric_member_status = item.get("fabric_member_status")
        fabric_member_heartbeat_at = item.get("fabric_member_heartbeat_at")
        fabric_member_expires_at = item.get("fabric_member_expires_at")
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
        upstreams.append(
            {
                "name": name,
                "transport": transport,
                "tool_prefix": tool_prefix,
                "default": default,
                **({"auth": auth} if auth is not None else {}),
                **({"credential": credential} if credential is not None else {}),
                **dict(transport_fields),
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

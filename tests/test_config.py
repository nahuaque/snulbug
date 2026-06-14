from __future__ import annotations

import json

import pytest

from snulbug import (
    GatewayTemplate,
    default_event_sink_configs,
    format_event_sinks_toml,
    load_mcp_fabric_config,
    load_mcp_proxy_config,
    render_gateway_toml,
    write_sample_config,
)
from snulbug.config import merge_mcp_proxy_config
from snulbug.simulator import main as simulator_main


def test_load_mcp_proxy_config_resolves_relative_paths(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        upstream = "http://127.0.0.1:9000"
        policy = "policy.snulbug/policy.lua"
        host = "127.0.0.1"
        port = 9090
        state = "sqlite:policy-state.sqlite3"
        trace = false
        record_out = "traces/session.jsonl"
        redact_records = true
        confirm = true
        max_body_bytes = 32768
        response_max_bytes = 131072
        response_redact_secrets = false
        response_block_instructions = true
        tool_pinning = true
        tool_pinning_action = "warn"
        schema_validation = true
        schema_validation_action = "warn"
        facade_health_routing = true
        facade_health_failure_threshold = 3
        facade_health_cooldown_seconds = 1.5
        facade_health_exclude_unhealthy = false
        lease_file = "leases.json"
        lease_required = true
        lease_header = "x-task-lease"
        tunnel_provider = "cloudflare"
        tunnel_public_url = "https://mcp.example.com/mcp"
        cloudflare_access = "enforce"
        cloudflare_access_require_jwt = true
        cloudflare_access_require_email = true
        cloudflare_access_require_cf_ray = true
        cloudflare_access_allowed_emails = ["dev@example.com"]
        cloudflare_access_allowed_domains = ["example.com"]
        timeout = 5.5

        [mcp.auth]
        mode = "oauth-resource"
        resource = "https://mcp.example.com/mcp"
        issuer = "https://issuer.example.com"
        authorization_servers = ["https://issuer.example.com"]
        audience = "https://mcp.example.com/mcp"
        required_scopes = ["mcp:connect"]
        scopes_supported = ["mcp:connect", "mcp:tools"]
        jwks_path = "auth/jwks.json"
        jwks_url = "https://issuer.example.com/jwks"
        jwks_cache_seconds = 120
        jwks_fetch_timeout = 2.5
        resource_metadata_url = "https://mcp.example.com/.well-known/oauth-protected-resource"
        realm = "mcp"
        leeway_seconds = 30
        strip_authorization_upstream = true

        [mcp.auth.scope_map]
        "mcp:tools.read" = ["tools/list", "resources/list"]
        "mcp:tool.files.read" = ["tools/call:filesystem.read_file"]
        "mcp:tool.git.status" = ["tools/call:git.status"]

        [[mcp.events.sinks]]
        type = "audit_jsonl"
        path = "events/audit.jsonl"
        events = ["snulbug.audit"]

        [[mcp.events.sinks]]
        type = "webhook"
        name = "security-alerts"
        url_env = "SNULBUG_SECURITY_WEBHOOK_URL"
        events = ["mcp.decision.blocked", "mcp.response.redacted"]
        body_mode = "metadata_only"
        redaction = "strict"
        timeout_ms = 500
        retry_attempts = 1
        signing_secret_env = "SNULBUG_WEBHOOK_SECRET"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstream"] == "http://127.0.0.1:9000"
    assert result["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert result["record_out"] == tmp_path / "traces/session.jsonl"
    assert result["port"] == 9090
    assert result["trace"] is False
    assert result["redact_records"] is True
    assert result["confirm"] is True
    assert result["response_max_bytes"] == 131072
    assert result["response_redact_secrets"] is False
    assert result["response_block_instructions"] is True
    assert result["tool_pinning"] is True
    assert result["tool_pinning_action"] == "warn"
    assert result["schema_validation"] is True
    assert result["schema_validation_action"] == "warn"
    assert result["facade_health_routing"] is True
    assert result["facade_health_failure_threshold"] == 3
    assert result["facade_health_cooldown_seconds"] == 1.5
    assert result["facade_health_exclude_unhealthy"] is False
    assert result["lease_file"] == tmp_path / "leases.json"
    assert result["lease_required"] is True
    assert result["lease_header"] == "x-task-lease"
    assert result["tunnel_provider"] == "cloudflare"
    assert result["tunnel_public_url"] == "https://mcp.example.com/mcp"
    assert result["cloudflare_access"] == "enforce"
    assert result["cloudflare_access_require_jwt"] is True
    assert result["cloudflare_access_require_email"] is True
    assert result["cloudflare_access_require_cf_ray"] is True
    assert result["cloudflare_access_allowed_emails"] == ["dev@example.com"]
    assert result["cloudflare_access_allowed_domains"] == ["example.com"]
    assert result["auth"] == {
        "mode": "oauth-resource",
        "resource": "https://mcp.example.com/mcp",
        "issuer": "https://issuer.example.com",
        "authorization_servers": ["https://issuer.example.com"],
        "audience": "https://mcp.example.com/mcp",
        "required_scopes": ["mcp:connect"],
        "scopes_supported": ["mcp:connect", "mcp:tools"],
        "jwks_path": tmp_path / "auth/jwks.json",
        "jwks_url": "https://issuer.example.com/jwks",
        "jwks_cache_seconds": 120.0,
        "jwks_fetch_timeout": 2.5,
        "resource_metadata_url": "https://mcp.example.com/.well-known/oauth-protected-resource",
        "realm": "mcp",
        "leeway_seconds": 30.0,
        "strip_authorization_upstream": True,
        "scope_map": {
            "mcp:tools.read": ["tools/list", "resources/list"],
            "mcp:tool.files.read": ["tools/call:filesystem.read_file"],
            "mcp:tool.git.status": ["tools/call:git.status"],
        },
    }
    assert result["event_sinks"] == [
        {
            "type": "audit_jsonl",
            "path": tmp_path / "events/audit.jsonl",
            "events": ("snulbug.audit",),
            "enabled": True,
        },
        {
            "type": "webhook",
            "webhook": result["event_sinks"][1]["webhook"],
        },
    ]
    webhook = result["event_sinks"][1]["webhook"]
    assert webhook.name == "security-alerts"
    assert webhook.url_env == "SNULBUG_SECURITY_WEBHOOK_URL"
    assert webhook.events == ("mcp.decision.blocked", "mcp.response.redacted")
    assert webhook.timeout_ms == 500
    assert webhook.retry_attempts == 1
    assert webhook.signing_secret_env == "SNULBUG_WEBHOOK_SECRET"


def test_load_mcp_proxy_config_accepts_holepunch_provider(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        tunnel_provider = "holepunch"
        tunnel_public_url = "http://127.0.0.1:18080/mcp"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["tunnel_provider"] == "holepunch"
    assert result["tunnel_public_url"] == "http://127.0.0.1:18080/mcp"


def test_load_mcp_proxy_config_accepts_remote_jwks_without_local_file(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [mcp.auth]
        mode = "oauth-resource"
        resource = "https://mcp.example.com/mcp"
        issuer = "https://issuer.example.com"
        audience = "https://mcp.example.com/mcp"
        required_scopes = ["mcp:connect"]
        jwks_url = "https://issuer.example.com/.well-known/jwks.json"
        jwks_cache_seconds = 60
        jwks_fetch_timeout = 1.5
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["auth"]["jwks_path"] is None
    assert result["auth"]["jwks_url"] == "https://issuer.example.com/.well-known/jwks.json"
    assert result["auth"]["jwks_cache_seconds"] == 60.0
    assert result["auth"]["jwks_fetch_timeout"] == 1.5


def test_event_sink_toml_helper_writes_loadable_sink_blocks(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        "\n".join(
            [
                "[mcp.proxy]",
                'policy = "policy.snulbug/policy.lua"',
                'record_out = "traces/session.jsonl"',
                format_event_sinks_toml(default_event_sink_configs(audit_path="logs/audit.jsonl")),
            ]
        ),
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["event_sinks"][0]["type"] == "audit_jsonl"
    assert result["event_sinks"][0]["path"] == tmp_path / "logs/audit.jsonl"
    assert result["event_sinks"][1]["type"] == "console"


def test_gateway_template_renders_loadable_proxy_and_fabric_config(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        render_gateway_toml(
            GatewayTemplate(
                fabric={
                    "name": "dev-fabric",
                    "description": "Generated fabric config",
                    "gateway_url": "http://127.0.0.1:8080/mcp",
                    "require_manifests": False,
                    "probe_gateway": False,
                    "probe_upstreams": False,
                    "timeout": 5.0,
                },
                fabric_credentials={
                    "codespace": {
                        "type": "env",
                        "env": "CODESPACE_MCP_TOKEN",
                        "scheme": "bearer",
                        "header": "Authorization",
                    }
                },
                proxy={
                    "policy": "policy.snulbug/policy.lua",
                    "host": "127.0.0.1",
                    "port": 8080,
                    "record_out": "traces/session.jsonl",
                },
                upstreams=[
                    {
                        "name": "files",
                        "transport": "http",
                        "url": "http://127.0.0.1:9001/mcp",
                        "tool_prefix": "files.",
                        "auth": "codespace",
                    }
                ],
                event_sinks=default_event_sink_configs(audit_path="traces/audit.jsonl"),
            )
        ),
        encoding="utf-8",
    )

    proxy = load_mcp_proxy_config(config)
    fabric = load_mcp_fabric_config(config)

    assert proxy["upstreams"][0]["name"] == "files"
    assert proxy["upstreams"][0]["credential"]["id"] == "codespace"
    assert proxy["event_sinks"][0]["path"] == tmp_path / "traces/audit.jsonl"
    assert fabric["name"] == "dev-fabric"
    assert fabric["proxy"]["upstreams"][0]["tool_prefix"] == "files."


def test_load_mcp_proxy_config_accepts_localxpose_provider(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        tunnel_provider = "localxpose"
        tunnel_public_url = "https://dev.loclx.io/mcp"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["tunnel_provider"] == "localxpose"
    assert result["tunnel_public_url"] == "https://dev.loclx.io/mcp"


def test_load_mcp_proxy_config_accepts_pinggy_provider(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        tunnel_provider = "pinggy"
        tunnel_public_url = "https://demo.run.pinggy-free.link/mcp"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["tunnel_provider"] == "pinggy"
    assert result["tunnel_public_url"] == "https://demo.run.pinggy-free.link/mcp"


def test_load_mcp_proxy_config_supports_facade_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        default = true
        manifest = "manifests/files.json"
        manifest_secret_env = "SNULBUG_MANIFEST_SECRET"
        manifest_key_id = "dev"
        manifest_identity = "files@local"

        [[mcp.proxy.upstreams]]
        name = "git"
        url = "http://127.0.0.1:9002/mcp"
        tool_prefix = "repo."
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"] == [
        {
            "name": "files",
            "transport": "http",
            "url": "http://127.0.0.1:9001/mcp",
            "tool_prefix": "files.",
            "default": True,
            "manifest": tmp_path / "manifests/files.json",
            "manifest_required": True,
            "manifest_secret_env": "SNULBUG_MANIFEST_SECRET",
            "manifest_key_id": "dev",
            "manifest_identity": "files@local",
        },
        {
            "name": "git",
            "transport": "http",
            "url": "http://127.0.0.1:9002/mcp",
            "tool_prefix": "repo.",
            "default": False,
        },
    ]


def test_load_mcp_proxy_config_attaches_fabric_credentials_to_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.credentials.codespace]
        type = "env"
        env = "CODESPACE_MCP_TOKEN"
        scheme = "bearer"

        [mcp.fabric.credentials.file_token]
        type = "file"
        path = "secrets/upstream-token"
        scheme = "raw"
        header = "x-api-key"

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        auth = "codespace"

        [[mcp.proxy.upstreams]]
        name = "git"
        url = "http://127.0.0.1:9002/mcp"
        auth = "file_token"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["auth"] == "codespace"
    assert result["upstreams"][0]["credential"] == {
        "id": "codespace",
        "type": "env",
        "env": "CODESPACE_MCP_TOKEN",
        "scheme": "bearer",
        "header": "Authorization",
    }
    assert result["upstreams"][1]["credential"] == {
        "id": "file_token",
        "type": "file",
        "path": str(tmp_path / "secrets/upstream-token"),
        "scheme": "raw",
        "header": "x-api-key",
    }


def test_load_mcp_proxy_config_attaches_single_upstream_credential(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.credentials.local_api]
        type = "env"
        env = "LOCAL_MCP_TOKEN"
        scheme = "bearer"

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        upstream = "http://127.0.0.1:9001/mcp"
        upstream_credential = "local_api"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstream_credential"] == {
        "id": "local_api",
        "type": "env",
        "env": "LOCAL_MCP_TOKEN",
        "scheme": "bearer",
        "header": "Authorization",
    }


def test_load_mcp_proxy_config_rejects_unknown_upstream_credential_ref(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        auth = "missing"
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown mcp.fabric.credentials"):
        load_mcp_proxy_config(config)


def test_load_mcp_proxy_config_rejects_unknown_single_upstream_credential_ref(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        upstream_credential = "missing"
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown mcp.fabric.credentials"):
        load_mcp_proxy_config(config)


def test_load_mcp_proxy_config_supports_stdio_facade_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        transport = "stdio"
        command = "npx"
        args = ["-y", "@modelcontextprotocol/server-filesystem", "."]
        cwd = "."
        env = { MCP_LOG_LEVEL = "error" }
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"] == [
        {
            "name": "files",
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
            "cwd": ".",
            "env": {"MCP_LOG_LEVEL": "error"},
            "tool_prefix": "files.",
            "default": False,
        }
    ]


def test_load_mcp_proxy_config_supports_holepunch_facade_upstreams(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "remote"
        transport = "holepunch"
        peer = "SERVER_PEER_KEY"
        local_port = 19100
        bridge_config = "hypertele-client.json"
        bridge_command = "hypertele"
        bridge_private = true
        bridge_ready_timeout = 3.5
        tool_prefix = "remote."
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"] == [
        {
            "name": "remote",
            "transport": "holepunch",
            "url": "http://127.0.0.1:19100/mcp",
            "peer": "SERVER_PEER_KEY",
            "local_port": 19100,
            "bridge_config": "hypertele-client.json",
            "bridge_command": "hypertele",
            "bridge_args": ["-p", "19100", "-c", "hypertele-client.json", "--private"],
            "bridge_private": True,
            "bridge_ready_timeout": 3.5,
            "tool_prefix": "remote.",
            "default": False,
        }
    ]


def test_load_mcp_proxy_config_applies_file_discovery_provider(tmp_path):
    registry = tmp_path / "discovery/upstreams.json"
    registry.parent.mkdir()
    registry.write_text(
        json.dumps(
            {
                "upstreams": [
                    {
                        "name": "remote",
                        "transport": "holepunch",
                        "peer": "SERVER_PEER_KEY",
                        "local_port": 19100,
                        "tool_prefix": "remote.",
                        "manifest": "manifests/remote.json",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.discovery]
        enabled = true

        [[mcp.fabric.discovery.providers]]
        name = "local-registry"
        type = "file"
        path = "discovery/upstreams.json"
        required = true

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["discovery"]["summary"]["upstream_count"] == 1
    assert result["discovery"]["providers"][0]["status"] == "loaded"
    assert result["upstreams"] == [
        {
            "name": "remote",
            "transport": "holepunch",
            "url": "http://127.0.0.1:19100/mcp",
            "peer": "SERVER_PEER_KEY",
            "local_port": 19100,
            "bridge_command": "hypertele",
            "bridge_args": ["-p", "19100", "-s", "SERVER_PEER_KEY", "--private"],
            "bridge_private": True,
            "bridge_ready_timeout": 10.0,
            "tool_prefix": "remote.",
            "default": False,
            "manifest": tmp_path / "manifests/remote.json",
            "manifest_required": True,
            "discovered": True,
            "discovery_provider": "local-registry",
            "discovery_type": "file",
            "discovery_source": str(registry),
        }
    ]


def test_load_mcp_proxy_config_applies_env_discovery_provider(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SNULBUG_DISCOVERY_UPSTREAMS",
        json.dumps([{"name": "files", "url": "http://127.0.0.1:9001/mcp"}]),
    )
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "container-env"
        type = "env"
        env = "SNULBUG_DISCOVERY_UPSTREAMS"

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "files"
    assert result["upstreams"][0]["discovered"] is True
    assert result["upstreams"][0]["discovery_provider"] == "container-env"
    assert result["upstreams"][0]["discovery_type"] == "env"


def test_load_mcp_proxy_config_fails_on_duplicate_discovered_upstream_name(tmp_path):
    registry = tmp_path / "discovery/upstreams.json"
    registry.parent.mkdir()
    registry.write_text(json.dumps([{"name": "files", "url": "http://127.0.0.1:9002/mcp"}]), encoding="utf-8")
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.fabric.discovery]

        [[mcp.fabric.discovery.providers]]
        name = "local-registry"
        type = "file"
        path = "discovery/upstreams.json"

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"

        [[mcp.proxy.upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        """,
        encoding="utf-8",
    )

    try:
        load_mcp_proxy_config(config)
    except ValueError as exc:
        assert "duplicate mcp.proxy.upstreams name" in str(exc)
    else:
        raise AssertionError("expected duplicate upstream validation error")


def test_merge_mcp_proxy_config_ignores_none_and_applies_overrides(tmp_path):
    config = load_mcp_proxy_config(write_config(tmp_path))

    merged = merge_mcp_proxy_config(config, {"port": 8181, "host": None, "record_out": tmp_path / "override.jsonl"})

    assert merged["host"] == "127.0.0.1"
    assert merged["port"] == 8181
    assert merged["record_out"] == tmp_path / "override.jsonl"
    assert merged["redact_records"] is True


def test_write_sample_config_refuses_to_overwrite(tmp_path):
    config = tmp_path / "snulbug.toml"
    write_sample_config(config)

    try:
        write_sample_config(config)
    except FileExistsError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected FileExistsError")


def test_mcp_share_config_init_cli_writes_config(tmp_path, capsys):
    config = tmp_path / "snulbug.toml"

    status = simulator_main(["mcp", "share", "config", "init", "--output", str(config), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert config.is_file()
    assert load_mcp_proxy_config(config)["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert load_mcp_proxy_config(config)["redact_records"] is True


def test_mcp_share_run_cli_requires_policy_and_upstream_without_config(capsys):
    status = simulator_main(["mcp", "share", "run", "--port", "9001"])

    captured = capsys.readouterr()
    assert status == 1
    assert "--policy and either --upstream or --facade-upstream are required" in captured.err


def test_mcp_share_run_cli_loads_config_before_running(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "share", "run", "--config", str(config), "--port", "8181"])

    assert status == 0
    assert calls[0]["upstream"] == "http://127.0.0.1:9000"
    assert calls[0]["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert calls[0]["port"] == 8181
    assert calls[0]["trace"] is True
    assert calls[0]["record_out"] == tmp_path / "traces/session.jsonl"
    assert calls[0]["redact_records"] is True
    assert calls[0]["confirm"] is False
    assert calls[0]["response_max_bytes"] == 262144
    assert calls[0]["response_redact_secrets"] is True
    assert calls[0]["response_block_instructions"] is False
    assert calls[0]["tool_pinning"] is True
    assert calls[0]["tool_pinning_action"] == "block"
    assert calls[0]["schema_validation"] is True
    assert calls[0]["schema_validation_action"] == "block"
    assert calls[0]["facade_health_routing"] is False
    assert calls[0]["facade_health_failure_threshold"] == 2
    assert calls[0]["facade_health_cooldown_seconds"] == 30.0
    assert calls[0]["facade_health_exclude_unhealthy"] is True
    assert calls[0]["lease_file"] == tmp_path / "leases.json"
    assert calls[0]["lease_required"] is False
    assert calls[0]["lease_header"] == "x-snulbug-lease"
    assert calls[0]["tunnel_provider"] == "auto"
    assert calls[0]["tunnel_public_url"] is None
    assert calls[0]["cloudflare_access"] == "off"
    assert calls[0]["cloudflare_access_require_jwt"] is True
    assert calls[0]["cloudflare_access_require_email"] is False
    assert calls[0]["fabric_reload_config"] is None
    assert calls[0]["cloudflare_access_require_cf_ray"] is True
    assert calls[0]["cloudflare_access_allowed_emails"] == []
    assert calls[0]["cloudflare_access_allowed_domains"] == []
    assert calls[0]["event_sinks"] == [
        {
            "type": "audit_jsonl",
            "path": tmp_path / "traces/audit.jsonl",
            "events": ("snulbug.audit",),
            "enabled": True,
        },
        {
            "type": "console",
            "format": "json",
            "events": ("snulbug.audit",),
            "enabled": True,
        },
    ]


def test_mcp_share_run_cli_passes_facade_upstreams_without_config(monkeypatch, tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return { action = "continue" } end', encoding="utf-8")
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "share",
            "run",
            "--policy",
            str(policy),
            "--facade-upstream",
            "files=http://127.0.0.1:9001/mcp",
            "--facade-upstream",
            "git=http://127.0.0.1:9002/mcp",
        ]
    )

    assert status == 0
    assert calls[0]["upstreams"] == [
        {
            "name": "files",
            "transport": "http",
            "url": "http://127.0.0.1:9001/mcp",
            "tool_prefix": "files.",
            "default": False,
        },
        {
            "name": "git",
            "transport": "http",
            "url": "http://127.0.0.1:9002/mcp",
            "tool_prefix": "git.",
            "default": False,
        },
    ]
    assert calls[0]["facade_health_routing"] is False
    assert calls[0]["facade_health_failure_threshold"] == 2
    assert calls[0]["facade_health_cooldown_seconds"] == 30.0
    assert calls[0]["facade_health_exclude_unhealthy"] is True


def test_mcp_share_run_cli_can_enable_fabric_reload(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "share",
            "run",
            "--config",
            str(config),
            "--reload-fabric",
            "--fabric-reload-interval",
            "0.5",
        ]
    )

    assert status == 0
    assert calls[0]["fabric_reload_config"] == config
    assert calls[0]["fabric_reload_interval"] == 0.5
    assert calls[0]["fabric_reload_overrides"] == {}


def test_mcp_share_run_cli_rejects_fabric_reload_without_config(tmp_path, capsys):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return { action = "continue" } end', encoding="utf-8")

    status = simulator_main(
        [
            "mcp",
            "share",
            "run",
            "--policy",
            str(policy),
            "--facade-upstream",
            "files=http://127.0.0.1:9001/mcp",
            "--reload-fabric",
        ]
    )

    captured = capsys.readouterr()
    assert status == 1
    assert "--reload-fabric requires --config" in captured.err


def write_config(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        upstream = "http://127.0.0.1:9000"
        policy = "policy.snulbug/policy.lua"
        record_out = "traces/session.jsonl"

        [[mcp.events.sinks]]
        type = "audit_jsonl"
        path = "traces/audit.jsonl"

        [[mcp.events.sinks]]
        type = "console"
        format = "json"
        """,
        encoding="utf-8",
    )
    return config

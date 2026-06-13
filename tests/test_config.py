from __future__ import annotations

import json

from snulbug import load_mcp_proxy_config, write_sample_config
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
        audit_out = "traces/audit.jsonl"
        redact_records = true
        decision_console = true
        decision_console_format = "json"
        confirm = true
        max_body_bytes = 32768
        response_max_bytes = 131072
        response_redact_secrets = false
        response_block_instructions = true
        tool_pinning = true
        tool_pinning_action = "warn"
        schema_validation = true
        schema_validation_action = "warn"
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
        """,
        encoding="utf-8",
    )

    result = load_mcp_proxy_config(config)

    assert result["upstream"] == "http://127.0.0.1:9000"
    assert result["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert result["record_out"] == tmp_path / "traces/session.jsonl"
    assert result["audit_out"] == tmp_path / "traces/audit.jsonl"
    assert result["port"] == 9090
    assert result["trace"] is False
    assert result["redact_records"] is True
    assert result["decision_console"] is True
    assert result["decision_console_format"] == "json"
    assert result["confirm"] is True
    assert result["response_max_bytes"] == 131072
    assert result["response_redact_secrets"] is False
    assert result["response_block_instructions"] is True
    assert result["tool_pinning"] is True
    assert result["tool_pinning_action"] == "warn"
    assert result["schema_validation"] is True
    assert result["schema_validation_action"] == "warn"
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


def test_mcp_config_init_cli_writes_config(tmp_path, capsys):
    config = tmp_path / "snulbug.toml"

    status = simulator_main(["mcp", "config", "init", "--output", str(config), "--compact"])

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["ok"] is True
    assert config.is_file()
    assert load_mcp_proxy_config(config)["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert load_mcp_proxy_config(config)["redact_records"] is True


def test_mcp_proxy_cli_requires_policy_and_upstream_without_config(capsys):
    status = simulator_main(["mcp", "proxy", "--port", "9001"])

    captured = capsys.readouterr()
    assert status == 1
    assert "--policy and either --upstream or --facade-upstream are required" in captured.err


def test_mcp_proxy_cli_loads_config_before_running(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "proxy", "--config", str(config), "--port", "8181", "--no-trace"])

    assert status == 0
    assert calls[0]["upstream"] == "http://127.0.0.1:9000"
    assert calls[0]["policy"] == tmp_path / "policy.snulbug/policy.lua"
    assert calls[0]["port"] == 8181
    assert calls[0]["trace"] is False
    assert calls[0]["record_out"] == tmp_path / "traces/session.jsonl"
    assert calls[0]["redact_records"] is True
    assert calls[0]["decision_console"] is True
    assert calls[0]["decision_console_format"] == "json"
    assert calls[0]["confirm"] is False
    assert calls[0]["response_max_bytes"] == 262144
    assert calls[0]["response_redact_secrets"] is True
    assert calls[0]["response_block_instructions"] is False
    assert calls[0]["tool_pinning"] is True
    assert calls[0]["tool_pinning_action"] == "block"
    assert calls[0]["schema_validation"] is True
    assert calls[0]["schema_validation_action"] == "block"
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


def test_mcp_proxy_cli_passes_facade_upstreams_without_config(monkeypatch, tmp_path):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return { action = "continue" } end', encoding="utf-8")
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
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


def test_mcp_proxy_cli_can_enable_fabric_reload(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
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
    assert calls[0]["fabric_reload_overrides"]["upstream"] is None


def test_mcp_proxy_cli_rejects_fabric_reload_without_config(tmp_path, capsys):
    policy = tmp_path / "policy.lua"
    policy.write_text('return function() return { action = "continue" } end', encoding="utf-8")

    status = simulator_main(
        [
            "mcp",
            "proxy",
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


def test_mcp_proxy_cli_can_disable_record_redaction(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "proxy", "--config", str(config), "--no-redact-records"])

    assert status == 0
    assert calls[0]["redact_records"] is False


def test_mcp_proxy_cli_can_enable_confirmation(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(["mcp", "proxy", "--config", str(config), "--confirm"])

    assert status == 0
    assert calls[0]["confirm"] is True


def test_mcp_proxy_cli_applies_response_policy_overrides(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--config",
            str(config),
            "--response-max-bytes",
            "4096",
            "--no-response-redact-secrets",
            "--response-block-instructions",
            "--no-tool-pinning",
            "--tool-pinning-action",
            "warn",
        ]
    )

    assert status == 0
    assert calls[0]["response_max_bytes"] == 4096
    assert calls[0]["response_redact_secrets"] is False
    assert calls[0]["response_block_instructions"] is True
    assert calls[0]["tool_pinning"] is False
    assert calls[0]["tool_pinning_action"] == "warn"


def test_mcp_proxy_cli_applies_schema_validation_overrides(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--config",
            str(config),
            "--no-schema-validation",
            "--schema-validation-action",
            "warn",
        ]
    )

    assert status == 0
    assert calls[0]["schema_validation"] is False
    assert calls[0]["schema_validation_action"] == "warn"


def test_mcp_proxy_cli_applies_lease_overrides(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--config",
            str(config),
            "--lease-file",
            str(tmp_path / "task-leases.json"),
            "--lease-required",
            "--lease-header",
            "x-task-lease",
        ]
    )

    assert status == 0
    assert calls[0]["lease_file"] == tmp_path / "task-leases.json"
    assert calls[0]["lease_required"] is True
    assert calls[0]["lease_header"] == "x-task-lease"


def test_mcp_proxy_cli_applies_tunnel_audit_overrides(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--config",
            str(config),
            "--tunnel-provider",
            "ngrok",
            "--tunnel-public-url",
            "https://mcp-dev.ngrok.app/mcp",
        ]
    )

    assert status == 0
    assert calls[0]["tunnel_provider"] == "ngrok"
    assert calls[0]["tunnel_public_url"] == "https://mcp-dev.ngrok.app/mcp"


def test_mcp_proxy_cli_applies_cloudflare_access_overrides(monkeypatch, tmp_path):
    config = write_config(tmp_path)
    calls = []

    def fake_run_proxy(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("snulbug.proxy.run_proxy", fake_run_proxy)

    status = simulator_main(
        [
            "mcp",
            "proxy",
            "--config",
            str(config),
            "--cloudflare-access",
            "enforce",
            "--cloudflare-access-require-email",
            "--no-cloudflare-access-require-cf-ray",
            "--cloudflare-access-allow-email",
            "dev@example.com",
            "--cloudflare-access-allow-domain",
            "example.com",
        ]
    )

    assert status == 0
    assert calls[0]["cloudflare_access"] == "enforce"
    assert calls[0]["cloudflare_access_require_jwt"] is True
    assert calls[0]["cloudflare_access_require_email"] is True
    assert calls[0]["cloudflare_access_require_cf_ray"] is False
    assert calls[0]["cloudflare_access_allowed_emails"] == ["dev@example.com"]
    assert calls[0]["cloudflare_access_allowed_domains"] == ["example.com"]


def write_config(tmp_path):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        """
        [mcp.proxy]
        upstream = "http://127.0.0.1:9000"
        policy = "policy.snulbug/policy.lua"
        record_out = "traces/session.jsonl"
        audit_out = "traces/audit.jsonl"
        decision_console = true
        decision_console_format = "json"
        """,
        encoding="utf-8",
    )
    return config

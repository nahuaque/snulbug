from __future__ import annotations

import json

import pytest

from snulbug import format_tunnel_init_report, init_tunnel_provider
from snulbug.simulator import main as simulator_main


def test_tunnel_init_ngrok_generates_command_doctor_and_policy_snippet(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(
        provider="ngrok",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="mcp-dev.ngrok.app",
    )

    assert result["ok"] is True
    assert result["config_generated"] is True
    assert result["output_dir"] == ".snulbug/configs"
    assert (tmp_path / ".snulbug/configs/snulbug.toml").is_file()
    assert (tmp_path / ".snulbug/configs/policy.snulbug/policy.lua").is_file()
    assert (tmp_path / ".snulbug/configs/ngrok-traffic-policy.yml").is_file()
    assert (tmp_path / ".snulbug/configs/ngrok-agent.yml").is_file()
    assert result["local_origin"] == "http://127.0.0.1:8080"
    assert result["public_url"] == "https://mcp-dev.ngrok.app/mcp"
    assert result["commands"][0]["command"] == "ngrok start --config .snulbug/configs/ngrok-agent.yml --all"
    assert "Attach .snulbug/configs/ngrok-traffic-policy.yml" in result["commands"][1]["command"]
    assert result["traffic_policy"]["path"] == ".snulbug/configs/ngrok-traffic-policy.yml"
    assert result["traffic_policy"]["mode"] == "cloud-endpoint"
    assert result["traffic_policy"]["internal_endpoint"] == "https://snulbug-mcp.internal"
    assert "require Authorization header" in result["traffic_policy"]["checks"]
    assert result["doctor"]["command"] == "snulbug mcp share doctor <share-directory>"
    policy_file = next(file for file in result["files"] if file["path"] == "ngrok-traffic-policy.yml")
    agent_file = next(file for file in result["files"] if file["path"] == "ngrok-agent.yml")
    assert 'x-snulbug-traffic-policy: "ngrok-mcp-v1"' in policy_file["contents"]
    assert 'req.url.path != \\"/mcp\\"' in policy_file["contents"]
    assert "!hasReqHeader('Authorization')" in policy_file["contents"]
    assert "!getReqHeader('Authorization').exists(v, v.matches('^Bearer .+'))" in policy_file["contents"]
    assert "!(req.method in ['GET', 'POST', 'OPTIONS', 'DELETE'])" in policy_file["contents"]
    assert "req.method == 'POST'" in policy_file["contents"]
    assert "type: forward-internal" in policy_file["contents"]
    assert 'url: "https://snulbug-mcp.internal"' in policy_file["contents"]
    assert 'body: "Authorization required"' not in policy_file["contents"]
    assert "version: 3" in agent_file["contents"]
    assert 'url: "https://snulbug-mcp.internal"' in agent_file["contents"]
    assert 'url: "http://127.0.0.1:8080"' in agent_file["contents"]


def test_tunnel_init_ngrok_without_config_writes_default_config_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(provider="ngrok")
    report = format_tunnel_init_report(result)

    assert result["initial_config_missing"] is True
    assert result["config_generated"] is True
    assert result["config"] == ".snulbug/configs/snulbug.toml"
    assert result["output_dir"] == ".snulbug/configs"
    assert result["public_url"] == "https://YOUR-NGROK-FORWARDING-DOMAIN/mcp"
    assert result["commands"][0]["command"] == ("ngrok start --config .snulbug/configs/ngrok-agent.yml --all")
    assert result["doctor"]["command"] == "snulbug mcp share doctor <share-directory>"
    assert result["written_files"] == [
        ".snulbug/configs/snulbug.toml",
        ".snulbug/configs/policy.snulbug",
        ".snulbug/configs/traces",
        ".snulbug/configs/README.md",
        ".snulbug/configs/ngrok-traffic-policy.yml",
        ".snulbug/configs/ngrok-agent.yml",
    ]
    assert (tmp_path / ".snulbug/configs/snulbug.toml").is_file()
    assert (tmp_path / ".snulbug/configs/policy.snulbug/policy.lua").is_file()
    assert (tmp_path / ".snulbug/configs/ngrok-traffic-policy.yml").is_file()
    assert (tmp_path / ".snulbug/configs/ngrok-agent.yml").is_file()
    assert "Generated snulbug config" in report
    assert "Config: `.snulbug/configs/snulbug.toml`" in report
    assert "export SNULBUG_TOKEN=local-dev-secret" in report
    assert "export NGROK_URL=https://YOUR-NGROK-FORWARDING-DOMAIN" in report
    assert "ngrok-free.dev" in report
    assert "ngrok start --config .snulbug/configs/ngrok-agent.yml --all" in report
    assert "internal Agent Endpoint" in report
    assert "snulbug mcp share run --config .snulbug/configs/snulbug.toml" in result["next_steps"][1]


def test_tunnel_init_ngrok_writes_readme_and_traffic_policy(tmp_path):
    output_dir = tmp_path / "ngrok"

    result = init_tunnel_provider(
        provider="ngrok",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="mcp-dev.ngrok.app",
        output_dir=output_dir,
    )

    readme = output_dir / "README.md"
    policy = output_dir / "ngrok-traffic-policy.yml"
    agent = output_dir / "ngrok-agent.yml"
    assert result["written_files"] == [
        str(output_dir / "snulbug.toml"),
        str(output_dir / "policy.snulbug"),
        str(output_dir / "traces"),
        str(readme),
        str(policy),
        str(agent),
    ]
    assert f"ngrok start --config {agent} --all" in readme.read_text(encoding="utf-8")
    assert "Ngrok MCP gateway" in readme.read_text(encoding="utf-8")
    assert 'x-snulbug-public-url: "https://mcp-dev.ngrok.app/mcp"' in policy.read_text(encoding="utf-8")
    assert "type: forward-internal" in policy.read_text(encoding="utf-8")
    assert 'url: "https://snulbug-mcp.internal"' in agent.read_text(encoding="utf-8")


def test_tunnel_init_ngrok_can_customize_internal_agent_endpoint(tmp_path):
    output_dir = tmp_path / "ngrok"

    result = init_tunnel_provider(
        provider="ngrok",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="mcp-dev.ngrok.app",
        ngrok_internal_url="https://team-snulbug.internal",
        ngrok_endpoint_name="team-snulbug-agent",
        output_dir=output_dir,
    )

    policy = (output_dir / "ngrok-traffic-policy.yml").read_text(encoding="utf-8")
    agent = (output_dir / "ngrok-agent.yml").read_text(encoding="utf-8")
    assert result["bridge"] == {
        "transport": "ngrok-internal",
        "mode": "cloud-endpoint",
        "internal_url": "https://team-snulbug.internal",
        "endpoint_name": "team-snulbug-agent",
        "agent_config": "ngrok-agent.yml",
    }
    assert 'url: "https://team-snulbug.internal"' in policy
    assert 'name: "team-snulbug-agent"' in agent
    assert 'url: "https://team-snulbug.internal"' in agent


def test_tunnel_init_ngrok_rejects_non_internal_agent_endpoint(tmp_path):
    with pytest.raises(ValueError, match="must end with .internal"):
        init_tunnel_provider(
            provider="ngrok",
            local_url="http://127.0.0.1:8080/mcp",
            ngrok_internal_url="https://mcp.example.com",
            output_dir=tmp_path,
        )


def test_tunnel_init_cloudflare_writes_generated_files(tmp_path):
    output_dir = tmp_path / "cloudflare"

    result = init_tunnel_provider(
        provider="cloudflare",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="mcp.example.com",
        output_dir=output_dir,
    )

    config = output_dir / "cloudflared.yml"
    readme = output_dir / "README.md"
    assert result["written_files"] == [
        str(output_dir / "snulbug.toml"),
        str(output_dir / "policy.snulbug"),
        str(output_dir / "traces"),
        str(readme),
        str(config),
    ]
    assert "hostname: mcp.example.com" in config.read_text(encoding="utf-8")
    assert "service: http://127.0.0.1:8080" in config.read_text(encoding="utf-8")
    readme_text = readme.read_text(encoding="utf-8")
    assert "cloudflared tunnel route dns snulbug-mcp mcp.example.com" in readme_text
    assert f"cloudflared tunnel --config {config} run snulbug-mcp" in readme_text


def test_tunnel_init_cloudflare_without_hostname_uses_url_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(provider="cloudflare")
    report = format_tunnel_init_report(result)

    assert result["public_url"] == "https://YOUR-CLOUDFLARE-TUNNEL-HOSTNAME/mcp"
    assert result["doctor"]["command"] == "snulbug mcp share doctor <share-directory>"
    assert "Public MCP URL: ${CLOUDFLARE_TUNNEL_URL}/mcp" in report
    assert "export CLOUDFLARE_TUNNEL_URL=https://YOUR-CLOUDFLARE-TUNNEL-HOSTNAME" in report
    assert "URL: `${CLOUDFLARE_TUNNEL_URL}/mcp`" in report
    assert "hostname: your-cloudflare-tunnel-hostname" in (tmp_path / ".snulbug/configs/cloudflared.yml").read_text(
        encoding="utf-8"
    )


def test_tunnel_init_refuses_to_overwrite_without_force(tmp_path):
    output_dir = tmp_path / "tunnel"
    init_tunnel_provider(provider="generic", local_url="http://127.0.0.1:8080/mcp", output_dir=output_dir)

    with pytest.raises(FileExistsError):
        init_tunnel_provider(provider="generic", local_url="http://127.0.0.1:8080/mcp", output_dir=output_dir)

    result = init_tunnel_provider(
        provider="generic",
        local_url="http://127.0.0.1:8080/mcp",
        output_dir=output_dir,
        force=True,
    )
    assert result["written_files"] == [
        str(output_dir / "snulbug.toml"),
        str(output_dir / "policy.snulbug"),
        str(output_dir / "traces"),
        str(output_dir / "README.md"),
    ]


def test_tunnel_init_cli_surface_is_removed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as exc:
        simulator_main(["tunnel", "init", "--provider", "tailscale"])

    assert exc.value.code == 2


def test_tunnel_init_tailscale_readme_includes_bearer_and_lease_defaults(tmp_path):
    output_dir = tmp_path / "tailscale"

    result = init_tunnel_provider(
        provider="tailscale",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="dev.tailnet.ts.net",
        output_dir=output_dir,
    )

    readme = output_dir / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert result["written_files"] == [
        str(output_dir / "snulbug.toml"),
        str(output_dir / "policy.snulbug"),
        str(output_dir / "traces"),
        str(readme),
    ]
    assert "Tailscale Funnel bearer + lease recipe" in text
    assert "Authorization: Bearer ${SNULBUG_TOKEN}" in text
    assert 'lease_file = "leases.json"' in text
    assert "lease_required = false" in text
    assert 'lease_header = "x-snulbug-lease"' in text
    assert "snulbug mcp share lease create" in text
    assert "x-snulbug-lease: <lease token>" in text
    assert "lease_required = true" in text


def test_tunnel_init_tailscale_without_hostname_uses_url_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(provider="tailscale")
    report = format_tunnel_init_report(result)

    assert result["public_url"] == "https://YOUR-HOST.YOUR-TAILNET.ts.net/mcp"
    assert result["commands"][0]["command"] == "sudo tailscale funnel 8080"
    assert result["doctor"]["command"] == "snulbug mcp share doctor <share-directory>"
    assert "Public MCP URL: ${TAILSCALE_FUNNEL_URL}/mcp" in report
    assert "export TAILSCALE_FUNNEL_URL=https://YOUR-HOST.YOUR-TAILNET.ts.net" in report
    assert "URL: `${TAILSCALE_FUNNEL_URL}/mcp`" in report


def test_tunnel_init_pinggy_generates_ssh_command_and_url_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(provider="pinggy")
    report = format_tunnel_init_report(result)

    assert result["public_url"] == "https://YOUR-PINGGY-FORWARDING-DOMAIN/mcp"
    assert result["commands"][0]["command"] == "ssh -p 443 -R0:localhost:8080 free.pinggy.io"
    assert result["commands"][0]["title"] == "Expose snulbug with Pinggy"
    assert result["doctor"]["command"] == "snulbug mcp share doctor <share-directory>"
    assert "Public MCP URL: ${PINGGY_URL}/mcp" in report
    assert "export PINGGY_URL=https://YOUR-PINGGY-FORWARDING-DOMAIN" in report
    assert "URL: `${PINGGY_URL}/mcp`" in report


def test_tunnel_init_pinggy_uses_local_port_from_url(tmp_path):
    output_dir = tmp_path / "pinggy"

    result = init_tunnel_provider(
        provider="pinggy",
        local_url="http://127.0.0.1:8181/mcp",
        output_dir=output_dir,
    )

    readme = output_dir / "README.md"
    assert result["commands"][0]["command"] == "ssh -p 443 -R0:localhost:8181 free.pinggy.io"
    assert str(readme) in result["written_files"]
    assert "ssh -p 443 -R0:localhost:8181 free.pinggy.io" in readme.read_text(encoding="utf-8")


def test_tunnel_init_holepunch_generates_hypertele_bridge_files(tmp_path):
    output_dir = tmp_path / "holepunch"

    result = init_tunnel_provider(
        provider="holepunch",
        local_url="http://127.0.0.1:8080/mcp",
        output_dir=output_dir,
    )

    readme = output_dir / "README.md"
    server_config = output_dir / "hypertele-server.json"
    client_config = output_dir / "hypertele-client.json"
    assert result["provider"] == "holepunch"
    assert result["public_url"] == "http://127.0.0.1:18080/mcp"
    assert result["bridge"] == {
        "transport": "hypertele",
        "mode": "private",
        "server_config": "hypertele-server.json",
        "client_config": "hypertele-client.json",
        "server_address": "127.0.0.1",
        "server_port": 8080,
        "client_url": "http://127.0.0.1:18080/mcp",
        "client_host": "127.0.0.1",
        "client_port": 18080,
    }
    assert result["commands"][0]["command"] == (
        f"hypertele-server -l 8080 --address 127.0.0.1 -c {server_config} --private"
    )
    assert result["commands"][1]["command"] == f"hypertele -p 18080 -c {client_config} --private"
    assert result["written_files"] == [
        str(output_dir / "snulbug.toml"),
        str(output_dir / "policy.snulbug"),
        str(output_dir / "traces"),
        str(readme),
        str(server_config),
        str(client_config),
    ]
    assert json.loads(server_config.read_text(encoding="utf-8")) == {
        "seed": "REPLACE_WITH_32_BYTE_SERVER_SEED",
        "allow": ["REPLACE_WITH_CLIENT_PEER_KEY"],
    }
    assert json.loads(client_config.read_text(encoding="utf-8")) == {
        "peer": "REPLACE_WITH_SERVER_PEER_KEY_OR_PRIVATE_SEED"
    }
    readme_text = readme.read_text(encoding="utf-8")
    assert "Holepunch peer bridge" in readme_text
    assert "Authorization: Bearer ${SNULBUG_TOKEN}" in readme_text
    assert 'tunnel_provider = "holepunch"' in readme_text
    assert "snulbug mcp share lease create" in readme_text


def test_format_tunnel_init_report_includes_commands_and_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = init_tunnel_provider(provider="generic", local_url="http://127.0.0.1:8080/mcp")

    report = format_tunnel_init_report(result)

    assert "# snulbug MCP share provider setup" in report
    assert "Configure your tunnel provider" in report
    assert "Public MCP URL: ${TUNNEL_URL}/mcp" in report
    assert "export TUNNEL_URL=https://YOUR-TUNNEL-FORWARDING-DOMAIN" in report
    assert "URL: `${TUNNEL_URL}/mcp`" in report
    assert "`Authorization: Bearer ${SNULBUG_TOKEN}`" in report

from __future__ import annotations

import json

import pytest

from snulbug import format_tunnel_init_report, init_tunnel_provider
from snulbug.simulator import main as simulator_main


def test_tunnel_init_ngrok_generates_command_doctor_and_policy_snippet():
    result = init_tunnel_provider(
        provider="ngrok",
        local_url="http://127.0.0.1:8080/mcp",
        hostname="mcp-dev.ngrok.app",
    )

    assert result["ok"] is True
    assert result["local_origin"] == "http://127.0.0.1:8080"
    assert result["public_url"] == "https://mcp-dev.ngrok.app/mcp"
    assert result["commands"][0]["command"] == (
        "ngrok http 8080 --url https://mcp-dev.ngrok.app --traffic-policy-file ngrok-traffic-policy.yml"
    )
    assert result["traffic_policy"]["path"] == "ngrok-traffic-policy.yml"
    assert "require Authorization header" in result["traffic_policy"]["checks"]
    assert result["doctor"]["command"].startswith("snulbug tunnel doctor")
    assert "--provider ngrok" in result["doctor"]["command"]
    policy_file = next(file for file in result["files"] if file["path"] == "ngrok-traffic-policy.yml")
    assert 'x-snulbug-traffic-policy: "ngrok-mcp-v1"' in policy_file["contents"]
    assert 'req.url.path != \\"/mcp\\"' in policy_file["contents"]
    assert "!hasReqHeader('Authorization')" in policy_file["contents"]
    assert "!getReqHeader('Authorization').exists(v, v.matches('^Bearer .+'))" in policy_file["contents"]
    assert "!(req.method in ['GET', 'POST', 'OPTIONS', 'DELETE'])" in policy_file["contents"]
    assert "req.method == 'POST'" in policy_file["contents"]
    assert 'body: "Authorization required"' not in policy_file["contents"]


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
    assert result["written_files"] == [str(readme), str(policy)]
    assert "--traffic-policy-file ngrok-traffic-policy.yml" in readme.read_text(encoding="utf-8")
    assert "Ngrok Traffic Policy" in readme.read_text(encoding="utf-8")
    assert 'x-snulbug-public-url: "https://mcp-dev.ngrok.app/mcp"' in policy.read_text(encoding="utf-8")


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
    assert result["written_files"] == [str(readme), str(config)]
    assert "hostname: mcp.example.com" in config.read_text(encoding="utf-8")
    assert "service: http://127.0.0.1:8080" in config.read_text(encoding="utf-8")
    assert "cloudflared tunnel route dns snulbug-mcp mcp.example.com" in readme.read_text(encoding="utf-8")


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
    assert result["written_files"] == [str(output_dir / "README.md")]


def test_tunnel_init_cli_emits_compact_tailscale_plan(capsys):
    status = simulator_main(
        [
            "tunnel",
            "init",
            "--provider",
            "tailscale",
            "--local-url",
            "http://127.0.0.1:8080/mcp",
            "--hostname",
            "dev.tailnet.ts.net",
            "--compact",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert status == 0
    assert output["provider"] == "tailscale"
    assert output["public_url"] == "https://dev.tailnet.ts.net/mcp"
    assert output["commands"][0]["command"] == "sudo tailscale funnel 8080"
    assert output["client"]["headers"]["Authorization"] == "Bearer ${SNULBUG_TOKEN}"


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
    assert result["written_files"] == [str(readme)]
    assert "Tailscale Funnel bearer + lease recipe" in text
    assert "Authorization: Bearer ${SNULBUG_TOKEN}" in text
    assert 'lease_file = "leases.json"' in text
    assert "lease_required = false" in text
    assert 'lease_header = "x-snulbug-lease"' in text
    assert "snulbug mcp lease create" in text
    assert "x-snulbug-lease: <lease token>" in text
    assert "lease_required = true" in text


def test_format_tunnel_init_report_includes_commands_and_client():
    result = init_tunnel_provider(provider="generic", local_url="http://127.0.0.1:8080/mcp")

    report = format_tunnel_init_report(result)

    assert "# snulbug tunnel init" in report
    assert "Configure your tunnel provider" in report
    assert "URL: `https://YOUR-TUNNEL.example/mcp`" in report
    assert "`Authorization: Bearer ${SNULBUG_TOKEN}`" in report

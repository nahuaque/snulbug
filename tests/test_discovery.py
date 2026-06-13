from __future__ import annotations

import json

from snulbug import load_mcp_proxy_config, register_fabric_member
from snulbug.discovery import discovery_provider_types, register_discovery_provider


def test_static_toml_discovery_provider_reads_upstream_registry(tmp_path):
    registry = tmp_path / "static.toml"
    registry.write_text(
        """
        [[upstreams]]
        name = "files"
        url = "http://127.0.0.1:9001/mcp"
        tool_prefix = "files."
        """,
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "static-registry"
        type = "static_toml"
        path = "static.toml"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "files"
    assert result["upstreams"][0]["discovery_type"] == "static_toml"


def test_docker_compose_discovery_provider_extracts_service_labels(tmp_path):
    compose = tmp_path / "compose.json"
    compose.write_text(
        json.dumps(
            {
                "services": {
                    "files-mcp": {
                        "ports": ["9001:9000"],
                        "labels": {
                            "snulbug.mcp.enabled": "true",
                            "snulbug.mcp.name": "files",
                            "snulbug.mcp.tool_prefix": "files.",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "compose"
        type = "docker_compose"
        path = "compose.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "files"
    assert result["upstreams"][0]["url"] == "http://files-mcp:9000/mcp"
    assert result["upstreams"][0]["discovery_type"] == "docker_compose"


def test_kubernetes_discovery_provider_extracts_annotated_services(tmp_path):
    services = tmp_path / "services.json"
    services.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "kind": "Service",
                        "metadata": {
                            "name": "git-mcp",
                            "namespace": "dev",
                            "annotations": {
                                "snulbug.dev/mcp-enabled": "true",
                                "snulbug.dev/mcp-name": "git",
                                "snulbug.dev/mcp-tool_prefix": "git.",
                            },
                        },
                        "spec": {"ports": [{"port": 9002}]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "k8s"
        type = "kubernetes"
        path = "services.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "git"
    assert result["upstreams"][0]["url"] == "http://git-mcp.dev.svc:9002/mcp"
    assert result["upstreams"][0]["discovery_type"] == "kubernetes"


def test_tailscale_discovery_provider_filters_devices_by_tag(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SNULBUG_TAILSCALE_DEVICES",
        json.dumps(
            {
                "devices": [
                    {
                        "name": "devbox.tailnet.ts.net",
                        "hostname": "devbox",
                        "dnsName": "devbox.tailnet.ts.net.",
                        "tags": ["tag:mcp"],
                    },
                    {"hostname": "laptop", "dnsName": "laptop.tailnet.ts.net.", "tags": ["tag:workstation"]},
                ]
            }
        ),
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "tailnet"
        type = "tailscale"
        env = "SNULBUG_TAILSCALE_DEVICES"
        tag = "tag:mcp"
        port = 9003
        """,
    )

    result = load_mcp_proxy_config(config)

    assert [upstream["name"] for upstream in result["upstreams"]] == ["devbox"]
    assert result["upstreams"][0]["url"] == "http://devbox.tailnet.ts.net:9003/mcp"
    assert result["upstreams"][0]["discovery_type"] == "tailscale"


def test_mdns_discovery_provider_uses_dns_sd_record_snapshot(tmp_path):
    records = tmp_path / "mdns.json"
    records.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "name": "files",
                        "host": "files.local",
                        "port": 9004,
                        "properties": {
                            "snulbug.mcp.enabled": "true",
                            "snulbug.mcp.tool_prefix": "files.",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "lan"
        type = "mdns"
        path = "mdns.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "files"
    assert result["upstreams"][0]["url"] == "http://files.local:9004/mcp"
    assert result["upstreams"][0]["discovery_type"] == "mdns"


def test_codespaces_discovery_provider_builds_forwarded_port_urls(tmp_path, monkeypatch):
    monkeypatch.setenv("CODESPACE_NAME", "ideal-space")
    monkeypatch.setenv("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "codespace"
        type = "codespaces"
        ports = [{ name = "files", port = 9005, tool_prefix = "files." }]
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["url"] == "https://ideal-space-9005.app.github.dev/mcp"
    assert result["upstreams"][0]["discovery_type"] == "codespaces"


def test_devcontainer_discovery_provider_reads_customization_metadata(tmp_path):
    devcontainer = tmp_path / ".devcontainer/devcontainer.json"
    devcontainer.parent.mkdir()
    devcontainer.write_text(
        """
        {
          // snulbug consumes this local metadata only.
          "customizations": {
            "snulbug": {
              "upstreams": [
                { "name": "workspace", "url": "http://127.0.0.1:9006/mcp" }
              ]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "devcontainer"
        type = "devcontainer"
        path = ".devcontainer/devcontainer.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "workspace"
    assert result["upstreams"][0]["discovery_type"] == "devcontainer"


def test_supervisor_discovery_provider_reads_ready_process_registry(tmp_path):
    registry = tmp_path / "supervisor.json"
    registry.write_text(
        json.dumps(
            {
                "processes": [
                    {"name": "ready-mcp", "port": 9007, "status": "ready"},
                    {"name": "starting-mcp", "port": 9008, "status": "starting"},
                ]
            }
        ),
        encoding="utf-8",
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "supervisor"
        type = "supervisor"
        path = "supervisor.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert [upstream["name"] for upstream in result["upstreams"]] == ["ready-mcp"]
    assert result["upstreams"][0]["url"] == "http://127.0.0.1:9007/mcp"
    assert result["upstreams"][0]["discovery_type"] == "supervisor"


def test_members_discovery_provider_reads_active_member_registry(tmp_path):
    registry = tmp_path / "fabric-members.json"
    register_fabric_member(
        registry,
        member_id="remote-a",
        upstreams=[{"name": "files", "url": "http://127.0.0.1:9009/mcp"}],
        ttl_seconds=120,
    )
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "remote-members"
        type = "members"
        path = "fabric-members.json"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "remote-a-files"
    assert result["upstreams"][0]["url"] == "http://127.0.0.1:9009/mcp"
    assert result["upstreams"][0]["tool_prefix"] == "remote-a.files."
    assert result["upstreams"][0]["discovery_type"] == "members"
    assert result["upstreams"][0]["fabric_member_id"] == "remote-a"


def test_members_discovery_provider_can_read_shared_sqlite_registry(tmp_path):
    registry = f"sqlite:{tmp_path / 'fabric-members.sqlite3'}"
    register_fabric_member(
        registry,
        key="snulbug:test:members",
        member_id="container-a",
        upstreams=[{"name": "git", "url": "http://127.0.0.1:9011/mcp"}],
        ttl_seconds=120,
    )
    config = discovery_config(
        tmp_path,
        f"""
        [[mcp.fabric.discovery.providers]]
        name = "remote-members"
        type = "members"
        state = "{registry}"
        state_key = "snulbug:test:members"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert result["upstreams"][0]["name"] == "container-a-git"
    assert result["upstreams"][0]["fabric_member_id"] == "container-a"


def test_custom_discovery_provider_can_be_registered(tmp_path):
    def custom_provider(_provider):
        return [{"name": "custom", "url": "http://127.0.0.1:9010/mcp"}]

    register_discovery_provider("unit_custom", custom_provider)
    config = discovery_config(
        tmp_path,
        """
        [[mcp.fabric.discovery.providers]]
        name = "custom"
        type = "unit_custom"
        """,
    )

    result = load_mcp_proxy_config(config)

    assert "unit_custom" in discovery_provider_types()
    assert result["upstreams"][0]["name"] == "custom"
    assert result["upstreams"][0]["discovery_type"] == "unit_custom"


def discovery_config(tmp_path, providers: str):
    config = tmp_path / "snulbug.toml"
    config.write_text(
        f"""
        [mcp.fabric.discovery]
        enabled = true

        {providers}

        [mcp.proxy]
        policy = "policy.snulbug/policy.lua"
        """,
        encoding="utf-8",
    )
    return config

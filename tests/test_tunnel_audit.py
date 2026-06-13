from __future__ import annotations

from snulbug import TunnelAuditConfig, build_tunnel_audit_metadata


def test_tunnel_audit_metadata_infers_ngrok_from_forwarded_host():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [
                (b"host", b"127.0.0.1:8080"),
                (b"x-forwarded-host", b"dev.ngrok.app"),
                (b"x-forwarded-proto", b"https"),
                (b"x-ngrok-request-id", b"req_123"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )

    assert metadata["provider"] == "ngrok"
    assert metadata["inferred"] is True
    assert metadata["public_url"] == "https://dev.ngrok.app/mcp"
    assert metadata["public_host"] == "dev.ngrok.app"
    assert metadata["edge_request_id"] == "req_123"
    assert metadata["ngrok"] == {"request_id": "req_123"}


def test_tunnel_audit_metadata_uses_explicit_provider_and_public_url():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [(b"host", b"local")],
            "client": ("100.100.100.100", 443),
        },
        config=TunnelAuditConfig(provider="tailscale", public_url="https://dev.tailnet.ts.net/mcp"),
    )

    assert metadata["provider"] == "tailscale"
    assert metadata["inferred"] is False
    assert metadata["public_url"] == "https://dev.tailnet.ts.net/mcp"
    assert metadata["public_host"] == "dev.tailnet.ts.net"
    assert metadata["source_ip"] == "100.100.100.100"
    assert metadata["tailscale"] == {"tsnet_host": True}


def test_tunnel_audit_metadata_infers_localxpose_from_forwarded_host():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [
                (b"host", b"127.0.0.1:8080"),
                (b"x-forwarded-host", b"dev.loclx.io"),
                (b"x-forwarded-proto", b"https"),
                (b"x-real-ip", b"198.51.100.10"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )

    assert metadata["provider"] == "localxpose"
    assert metadata["inferred"] is True
    assert metadata["public_url"] == "https://dev.loclx.io/mcp"
    assert metadata["public_host"] == "dev.loclx.io"
    assert metadata["source_ip"] == "198.51.100.10"
    assert metadata["localxpose"] == {"real_ip": "198.51.100.10"}


def test_tunnel_audit_metadata_infers_pinggy_from_forwarded_host():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [
                (b"host", b"127.0.0.1:8080"),
                (b"x-forwarded-host", b"demo.run.pinggy-free.link"),
                (b"x-forwarded-proto", b"https"),
                (b"x-forwarded-for", b"198.51.100.11"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )

    assert metadata["provider"] == "pinggy"
    assert metadata["inferred"] is True
    assert metadata["public_url"] == "https://demo.run.pinggy-free.link/mcp"
    assert metadata["public_host"] == "demo.run.pinggy-free.link"
    assert metadata["source_ip"] == "198.51.100.11"


def test_tunnel_audit_metadata_tracks_holepunch_bridge_headers():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [
                (b"host", b"127.0.0.1:18080"),
                (b"x-snulbug-tunnel-provider", b"holepunch"),
                (b"x-snulbug-holepunch-transport", b"hypertele"),
                (b"x-snulbug-holepunch-peer", b"peer_123"),
                (b"x-snulbug-bridge-id", b"bridge_abc"),
            ],
            "client": ("127.0.0.1", 54321),
        }
    )

    assert metadata["provider"] == "holepunch"
    assert metadata["inferred"] is True
    assert metadata["public_url"] == "http://127.0.0.1:18080/mcp"
    assert metadata["edge_request_id"] == "bridge_abc"
    assert metadata["holepunch"] == {
        "transport": "hypertele",
        "peer": "peer_123",
        "bridge": "bridge_abc",
        "client_bridge": True,
    }


def test_tunnel_audit_metadata_keeps_generic_forwarded_fields():
    metadata = build_tunnel_audit_metadata(
        {
            "type": "http",
            "scheme": "http",
            "path": "/mcp",
            "headers": [
                (b"host", b"mcp.example.com"),
                (b"x-forwarded-for", b"198.51.100.9, 127.0.0.1"),
                (b"x-forwarded-proto", b"https"),
            ],
            "client": ("127.0.0.1", 1234),
        }
    )

    assert metadata["provider"] == "generic"
    assert metadata["public_url"] == "https://mcp.example.com/mcp"
    assert metadata["forwarded_for"] == ["198.51.100.9", "127.0.0.1"]
    assert metadata["source_ip"] == "198.51.100.9"

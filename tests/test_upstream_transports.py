from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from snulbug import (
    McpFacadeProxyApp,
    ResponsePolicyConfig,
    SchemaPolicyConfig,
    UpstreamForwardContext,
    UpstreamHttpTarget,
    UpstreamTransport,
    get_upstream_transport,
    list_upstream_transports,
    load_mcp_proxy_config,
    register_upstream_transport,
)


def test_builtin_upstream_transports_are_registered():
    assert list_upstream_transports() == ("http", "stdio", "holepunch")
    assert get_upstream_transport("http").normalized_type == "http"
    assert get_upstream_transport("stdio").normalized_type == "stdio"
    assert get_upstream_transport("holepunch").normalized_type == "holepunch"


def test_custom_upstream_transport_normalizes_config_and_runtime_metadata(tmp_path):
    class FixtureHttpTransport(UpstreamTransport):
        type = "fixture-http"
        aliases = ("fixture",)

        def normalize_config(
            self,
            upstream: Mapping[str, Any],
            *,
            field: str,
            base_dir: Path,
        ) -> Mapping[str, Any]:
            del field, base_dir
            endpoint = upstream.get("endpoint", upstream.get("url"))
            return {
                "url": endpoint,
                "transport_config": {"endpoint": endpoint, "mode": "fixture"},
            }

        def http_target(self, upstream: Any) -> UpstreamHttpTarget | None:
            return UpstreamHttpTarget(str(upstream.url))

        async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
            return await context.forward_http()

        def metadata(self, upstream: Any) -> Mapping[str, Any]:
            return {"url": upstream.url, "fixture": upstream.transport_config}

        def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
            return {"url": upstream.url, "fixture": upstream.transport_config}

    register_upstream_transport(FixtureHttpTransport(), replace=True)
    config_path = tmp_path / "snulbug.toml"
    config_path.write_text(
        """
[mcp.proxy]
upstream = "http://127.0.0.1:9000"
probe_upstreams = false

[[mcp.proxy.upstreams]]
name = "fixture"
transport = "fixture"
endpoint = "http://127.0.0.1:9010/mcp"
tool_prefix = "fixture."
""",
        encoding="utf-8",
    )

    proxy_config = load_mcp_proxy_config(config_path)
    facade = McpFacadeProxyApp(
        proxy_config["upstreams"],
        response_policy=ResponsePolicyConfig(tool_pinning=False),
        schema_policy=SchemaPolicyConfig(enabled=False),
    )

    assert proxy_config["upstreams"][0]["transport"] == "fixture-http"
    assert proxy_config["upstreams"][0]["url"] == "http://127.0.0.1:9010/mcp"
    assert proxy_config["upstreams"][0]["transport_config"] == {
        "endpoint": "http://127.0.0.1:9010/mcp",
        "mode": "fixture",
    }
    route_state = facade.route_state()
    assert route_state["upstreams"][0]["transport"] == "fixture-http"
    assert route_state["upstreams"][0]["fixture"] == {
        "endpoint": "http://127.0.0.1:9010/mcp",
        "mode": "fixture",
    }


def test_custom_upstream_transport_can_forward_facade_requests():
    class FixtureStaticTransport(UpstreamTransport):
        type = "fixture-static"

        def normalize_config(
            self,
            upstream: Mapping[str, Any],
            *,
            field: str,
            base_dir: Path,
        ) -> Mapping[str, Any]:
            del field, base_dir
            return {"transport_config": {"tool": upstream.get("tool", "echo")}}

        async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
            tool = context.upstream.transport_config["tool"]
            request = context.request
            if request.get("method") == "tools/list":
                payload = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": tool,
                                "description": "Fixture static tool",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"value": {"type": "string"}},
                                    "additionalProperties": False,
                                },
                            }
                        ]
                    },
                }
            else:
                payload = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "content": [{"type": "text", "text": request["params"]["arguments"]["value"]}],
                    },
                }
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            return {
                "status": 200,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                "body": body,
            }

    register_upstream_transport(FixtureStaticTransport(), replace=True)
    app = McpFacadeProxyApp(
        [{"name": "fixture", "transport": "fixture-static", "tool": "echo", "tool_prefix": "fixture."}],
        response_policy=ResponsePolicyConfig(tool_pinning=False),
        schema_policy=SchemaPolicyConfig(enabled=False),
    )

    tools_response = _run_asgi(
        app,
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list", "params": {}},
    )
    call_response = _run_asgi(
        app,
        {
            "jsonrpc": "2.0",
            "id": "call",
            "method": "tools/call",
            "params": {"name": "fixture.echo", "arguments": {"value": "hello"}},
        },
    )

    tools = json.loads(tools_response[1]["body"])
    call = json.loads(call_response[1]["body"])
    assert tools_response[0]["status"] == 200
    assert tools["result"]["tools"][0]["name"] == "fixture.echo"
    assert call_response[0]["status"] == 200
    assert call["result"]["content"][0]["text"] == "hello"


def _run_asgi(app: Any, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    return asyncio.run(_run_asgi_once(app, payload))


async def _run_asgi_once(app: Any, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "scheme": "http",
            "server": ("127.0.0.1", 8080),
            "client": ("127.0.0.1", 50000),
        },
        receive,
        send,
    )
    return sent

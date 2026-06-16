# Upstream transport plugins

Upstream transports teach the snulbug facade how to reach an MCP upstream. The
built-ins are:

- `http`: forward JSON-RPC over HTTP or HTTPS
- `stdio`: manage a local stdio MCP subprocess
- `holepunch`: start a local Hypertele bridge, then forward over HTTP

External transports can add other local-dev data planes without changing the
facade router.

```python
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from snulbug import (
    UpstreamForwardContext,
    UpstreamHttpTarget,
    UpstreamTransport,
    register_upstream_transport,
)


class AcmePeerTransport(UpstreamTransport):
    type = "acme-peer"
    aliases = ("acme",)

    def normalize_config(
        self,
        upstream: Mapping[str, Any],
        *,
        field: str,
        base_dir: Path,
    ) -> Mapping[str, Any]:
        del field, base_dir
        url = upstream.get("url") or resolve_peer_url(upstream["peer"])
        return {
            "url": url,
            "transport_config": {"peer": upstream["peer"]},
        }

    def http_target(self, upstream: Any) -> UpstreamHttpTarget | None:
        return UpstreamHttpTarget(upstream.url)

    async def forward(self, context: UpstreamForwardContext) -> dict[str, Any]:
        return await context.forward_http()

    def metadata(self, upstream: Any) -> Mapping[str, Any]:
        return {"url": upstream.url, "peer": upstream.transport_config.get("peer")}

    def fingerprint(self, upstream: Any) -> Mapping[str, Any]:
        return {"url": upstream.url, "peer": upstream.transport_config.get("peer")}


register_upstream_transport(AcmePeerTransport(), replace=True)
```

Config can then use either the canonical type or an alias:

```toml
[[mcp.proxy.upstreams]]
name = "remote-files"
transport = "acme"
peer = "devbox-123"
tool_prefix = "remote.files."
```

A transport can contribute:

- config normalization and validation with `normalize_config()`
- runtime normalization with `normalize_runtime()`
- an HTTP target with `http_target()`
- a managed stdio client spec with `stdio_client()`
- a managed bridge spec with `bridge()`
- request forwarding behavior with `forward()`
- secret-safe metadata, Lua route context, and route fingerprints

`transport_config` is the reserved place for plugin-owned normalized fields.
Keep it JSON-like and secret-safe because route status, audit records, share
reports, and fabric events may include plugin metadata.

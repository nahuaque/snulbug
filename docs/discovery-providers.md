# Discovery provider plugins

Discovery providers let snulbug discover MCP facade upstreams from registries
outside `snulbug.toml`. Built-ins cover files, directories, environment JSON,
static TOML, Docker Compose labels, Kubernetes services, Tailscale snapshots,
mDNS snapshots, Codespaces/devcontainers, supervisor registries, and remote
fabric members.

External providers can register the same surface from Python:

```python
from collections.abc import Mapping
from typing import Any

from snulbug import DiscoveryProvider, register_discovery_provider


class AcmeDiscoveryProvider(DiscoveryProvider):
    type = "acme"
    aliases = ("acme-registry",)

    def resolve(self, provider: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        registry_url = str(provider["registry_url"])
        return [
            {
                "name": item["name"],
                "url": item["mcp_url"],
                "tool_prefix": f"{item['name']}.",
            }
            for item in fetch_acme_registry(registry_url)
        ]


register_discovery_provider(AcmeDiscoveryProvider(), replace=True)
```

Config then uses the registered type or alias:

```toml
[mcp.fabric.discovery]
enabled = true

[[mcp.fabric.discovery.providers]]
name = "acme-dev"
type = "acme-registry"
registry_url = "https://registry.example.test/mcp-upstreams.json"
required = true
```

Providers receive a normalized provider table and return raw
`[[mcp.proxy.upstreams]]`-style mappings. snulbug still performs the normal
upstream validation after discovery, including duplicate names, transport
fields, credentials, and signed manifests.

Existing function resolvers remain supported:

```python
from snulbug import register_discovery_provider


def resolve_acme(provider):
    return [{"name": "files", "url": "http://127.0.0.1:9001/mcp"}]


register_discovery_provider("acme", resolve_acme)
```

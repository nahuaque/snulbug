# Tunnel Provider Plugins

`snulbug mcp share create --provider ...` is backed by a tunnel provider
registry. Built-in providers are `generic`, `ngrok`, `cloudflare`, `tailscale`,
`pinggy`, `ssh`, and `holepunch`.

Use a provider plugin when a tunnel or peer bridge needs custom setup commands,
generated config files, default public URL handling, request attribution, or
doctor/report metadata.

## Contract

A provider subclasses `TunnelProvider` and registers itself:

```python
from snulbug import TunnelProvider, TunnelProviderContext, register_tunnel_provider


class AcmeTunnelProvider(TunnelProvider):
    name = "acme"
    public_url_env = "ACME_TUNNEL_URL"
    default_public_host = "YOUR-ACME-TUNNEL-HOST"

    def build_plan(self, context: TunnelProviderContext) -> dict[str, object]:
        return {
            "commands": [
                {
                    "id": "run-acme",
                    "title": "Expose snulbug with Acme Tunnel",
                    "description": "Point Acme Tunnel at the local snulbug origin.",
                    "command": f"acme tunnel http --to {context.origin}",
                }
            ],
            "traffic_policy": None,
            "bridge": None,
            "client": self.client(context),
            "doctor": self.doctor(context),
        }

    def init_files(self, context: TunnelProviderContext, plan: dict[str, object]) -> list[dict[str, str]]:
        return [
            {
                "path": "acme-tunnel.txt",
                "kind": "acme-config",
                "contents": f"origin={context.origin}\npublic={context.public_endpoint}\n",
            }
        ]

    def matches_request(self, headers: dict[str, str], public_url: str | None) -> bool:
        host = public_url or headers.get("host", "")
        return "acme" in host

    def audit_metadata(self, headers: dict[str, str], metadata: dict[str, object]) -> dict[str, object]:
        return {"request_id": headers.get("x-acme-request-id")}


register_tunnel_provider(AcmeTunnelProvider())
```

After registration:

```bash
snulbug mcp share create --provider acme --upstream http://127.0.0.1:9000
```

## Provider Responsibilities

`public_endpoint()` defines the default client-facing MCP URL when the user does
not pass `--url`.

`build_plan()` returns setup commands plus the MCP client URL/header shape. Most
providers can reuse `self.client(context)` and `self.doctor(context)`.

`init_files()` returns generated files written under the share provider
directory. Paths must be relative.

`default_public_url_report_lines()` controls placeholder URL guidance when the
provider uses a generated/default hostname.

`matches_request()` lets `tunnel_provider = "auto"` infer the provider from
request headers or public URL.

`audit_metadata()` adds provider-specific fields under `audit.tunnel.<provider>`
without logging raw credentials.

## Notes

The registry is in-process. A package can register providers from its import
side effects, or an application can call `register_tunnel_provider()` before it
builds the CLI/parser or creates a share. Built-in providers use the same
surface as external providers.

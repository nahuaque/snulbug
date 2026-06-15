# snulbug docs

## Start Here: Golden Path

Start with the share session lifecycle:

```text
share create -> share run -> share status -> policy amend -> share activate -> share report
```

- [Quickstart: local MCP policy gateway](quickstart.md)
- [MCP share sessions](mcp-share.md)
- [MCP CLI guide for agents and harnesses](mcp-guide.md)

## Deeper MCP Workflows

- [Policy workflow: preset, learn, amend, lifecycle](mcp-policy.md)
- [Policy bundles](bundles.md)
- [Schema workflow: discover, diff, generate policy](mcp-schemas.md)
- [Evidence workflow: record, replay, inspect, impact, diff](mcp-evidence.md)
- [Reverse proxy and live recording](mcp-proxy.md)
- [Fabric control plane and facade routing](mcp-fabric.md)

## Sharing, Tunnels, And Remote Dev

- [MCP client setup recipes](mcp-client-recipes.md)
- [MCP auth interop recipes](mcp-auth-recipes.md)
- [OAuth claim-policy examples](../examples/auth_claim_patterns/README.md)
- [Provider-aware Lua policy templates](../examples/provider_policy_templates/README.md)
- [Codespaces and devcontainers](devcontainers.md)

## Demos

- [One-command MCP policy lab](quickstart.md#2-run-the-policy-lab)
- [End-to-end MCP policy proxy demo](../examples/mcp_proxy_demo/README.md)
- [Keycloak OAuth compose demo](../examples/keycloak_oauth_demo/README.md)

## Detailed References

- [MCP presets](mcp-presets.md)
- [MCP learn and amend mode](mcp-learn.md)
- [MCP evidence record, replay, and inspect](mcp-recorder.md)
- [MCP evidence impact preview](mcp-impact.md)
- [State adapters](state.md)
- [Security model](security-model.md)
- [Positioning and comparisons](comparison.md)
- [Roadmap](roadmap.md)

## Generic ASGI Middleware

- [ASGI middleware getting started](getting-started.md)
- [Lua request API](lua-request-api.md)
- [Action reference](actions.md)
- [Lower-level MCP gateway example](mcp-gateway.md)

## Project

- [Release process](release.md)

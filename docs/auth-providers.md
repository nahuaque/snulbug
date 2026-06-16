# Auth provider plugins

snulbug has a small auth provider extension point for two related jobs:

- generate `snulbug mcp share auth init --provider ...` setup recipes
- map provider-specific token claims into `context.auth.provider.*` for Lua policy helpers

Built-ins cover Keycloak, Auth0, Okta, Entra, Cloudflare Access, and GitHub
Actions OIDC. External providers can register the same surface from Python.

```python
from collections.abc import Mapping
from typing import Any

from snulbug import AuthProvider, AuthProviderRecipeContext, register_auth_provider


class AcmeAuthProvider(AuthProvider):
    name = "acme-auth"
    title = "Acme Auth"
    docs = ("https://auth.example.test/docs",)
    context_key = "acme"

    def recipe(self, context: AuthProviderRecipeContext) -> dict[str, Any]:
        return {
            "ok": True,
            "kind": "snulbug.auth.recipe",
            "provider": self.name,
            "title": self.title,
            "public_url": context.public_url,
            "issuer": context.issuer or "https://auth.example.test",
            "audience": context.audience or context.public_url,
            "scopes": list(context.scopes),
            "summary": "Register snulbug as an Acme Auth protected MCP resource.",
            "provider_steps": [
                "Create an API/resource for the public MCP URL.",
                "Issue access tokens with the MCP scopes used by the share.",
            ],
            "client_request": {"audience": context.audience or context.public_url},
            "snulbug_config": '[mcp.auth]\nmode = "oauth-resource"\n',
            "commands": {
                "doctor": f"snulbug mcp share auth doctor --url {context.public_url}",
            },
            "docs": list(self.docs),
        }

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "tenant": claims.get("acme_tenant"),
            "risk": claims.get("acme_risk"),
        }


register_auth_provider(AcmeAuthProvider(), replace=True)
```

After registration, `snulbug mcp share auth recipe --provider acme-auth ...`
uses the provider recipe. OAuth runtime also exposes non-empty claim mapper
results under:

```lua
context.auth.provider.acme
```

Use provider claim mappers for normalized identity facts that Lua policies can
reason over without each policy re-parsing raw JWT claim shapes.

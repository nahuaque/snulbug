# Credential broker plugins

snulbug uses credential brokers to inject upstream credentials without
forwarding caller tokens. Built-ins support:

- `type = "env"`: read the secret from an environment variable
- `type = "file"`: read the secret from a local file

External brokers can add other sources such as a local keychain, a vault, a
container metadata service, or a short-lived token minting service.

```python
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from snulbug import CredentialBroker, register_credential_broker


class AcmeVaultBroker(CredentialBroker):
    type = "acme-vault"

    def normalize_source(
        self,
        entry: Mapping[str, Any],
        *,
        base_dir: Path,
        field: str,
        resolve_relative_paths: bool,
    ) -> Mapping[str, Any]:
        del base_dir, resolve_relative_paths
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{field}.name must be a non-empty credential name")
        return {"name": name}

    def resolve(self, credential: Mapping[str, Any]) -> str:
        # Fetch or mint the secret here. Return the raw token value; snulbug
        # applies the configured scheme before forwarding.
        return fetch_from_acme_vault(str(credential["name"]))

    def metadata(self, credential: Mapping[str, Any]) -> Mapping[str, Any]:
        # Return only audit-safe fields. Never return the resolved secret.
        return {"name": credential.get("name")}


register_credential_broker(AcmeVaultBroker(), replace=True)
```

Config uses the same `[mcp.fabric.credentials]` table as built-ins:

```toml
[mcp.fabric.credentials.codespace]
type = "acme-vault"
name = "codespace-mcp-token"
scheme = "bearer"
header = "Authorization"

[[mcp.proxy.upstreams]]
name = "codespace-files"
url = "https://example-codespace.github.dev/mcp"
auth = "codespace"
```

The broker is called only when snulbug forwards a request or probes an upstream.
Audit logs, share contracts, fabric status, and replay logs receive only
`credential_metadata()` output.

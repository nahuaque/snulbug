# Credential broker plugins

snulbug uses credential brokers to inject upstream credentials without
forwarding caller tokens. Built-ins support:

- `type = "env"`: read the secret from an environment variable
- `type = "file"`: read the secret from a local file

External brokers can add other sources such as a local keychain, a vault, a
container metadata service, or a short-lived token minting service.

## Always-on upstream credentials

Keep caller authentication and upstream credentials separate. A client's OAuth
token or share bearer authenticates to snulbug; an upstream credential reference
authenticates snulbug to that upstream. Missing upstream credentials fail closed,
without retrying a tool call, forwarding the caller's token as a fallback, or
reusing a previously resolved value.

Use the existing registry in the share's `snulbug.toml`. File paths are relative
to that config file, not the launcher's working directory:

```toml
[mcp.fabric.credentials.service]
type = "file"
path = "/run/secrets/mcp-service-token"
scheme = "bearer"
header = "Authorization"

[mcp.proxy]
upstream = "https://mcp.example.com/mcp"
upstream_credential = "service"
```

Merge the setting into the existing `[mcp.proxy]` table rather than adding a
duplicate. For a facade, attach `auth = "service"` to the relevant
`[[mcp.proxy.upstreams]]` entry instead. Do not store secret values in TOML,
command arguments, images, or the policy source.

### Check and inspect

```bash
snulbug mcp share doctor /var/lib/snulbug/share
snulbug mcp share status /var/lib/snulbug/share
snulbug mcp share report /var/lib/snulbug/share
```

Doctor's `credentials` check resolves each used source once and adds
`upstream_credentials` to its JSON result. It reports missing/unreadable,
empty, malformed, or oversized values as failures. It warns about POSIX
group/other file permissions, credentials sent over non-loopback plain HTTP,
client Authorization passthrough, and HTTP credential references on stdio
transports. Hygiene warnings require review, not an automatic chmod or config
rewrite. Intentional private Docker networks may explain an HTTP warning;
snulbug cannot prove that such a network is private.

The console's **Auth** section has an **Upstream credentials** drawer with
source references, attached upstreams, last-check state, rotation guidance,
and the existing **Run doctor** action. Readiness fails for a recorded source
failure and requests review for unchecked, changed, or warning states. No
additional credential-management endpoint or secret-reveal control is added.

Offline doctor skips source resolution. Status, reports, and normal console
refreshes reuse saved diagnostics, never invoke brokers, and never record
secret values or hashes of them. A reference, route, or file stat change
invalidates saved availability and requires another doctor run. The input
digest covers references and file metadata only; it is not a secret fingerprint.
Doctor results are historical diagnostics, not an authorization decision or a
guarantee about the next request. The request path always resolves again.

Availability means **resolved in the checking process**, not accepted by the
upstream. Run doctor with the same service account and environment as the
gateway, or use the running console's action. A CLI process may have different
environment values or permissions. Opaque token expiry, revocation, audience,
and upstream privileges cannot be inferred from a successful local read; use
the existing health checks and request failure explanations to see upstream
401/403 responses.

### Rotation

- **File:** stage the new value in a protected file on the same filesystem,
  set its service ownership and mode (`0600` or a deliberate read-only mode),
  then atomically rename it over the referenced path. New requests read the
  replacement without a gateway restart. Do not truncate/rewrite the live file.
  Symlinks to regular files are supported, including projected container
  secrets. A missing or invalid replacement fails new requests immediately.
- **Environment:** update the supervisor's protected environment file and
  restart the gateway. Exporting a variable in another shell cannot modify a
  running process's environment. There is no last-known-good cache to flush.
- **Plugin:** the broker owns its source-specific refresh and rotation policy.
  Keep network resolution bounded; plugins run trusted Python code and snulbug
  does not supply a universal vault timeout or refresh scheduler.

File sources must resolve to regular UTF-8 files, at most 16 KiB, with an
optional trailing newline. Nonregular sources (including FIFOs/devices) are
rejected before reading. Every broker's result must be a nonempty, bounded
single HTTP header value without control characters. Resolver exception text
is replaced with fixed diagnostics, including for plugin errors.
POSIX mode checks inspect the target file, not directory permissions, ACLs,
ownership, or Windows access controls; restrict those separately as part of
service provisioning.

Rotation applies at request/probe boundaries. An established SSE stream or
managed upstream session is not reauthenticated mid-flight. Arrange upstream
old/new-token overlap when needed; snulbug does not retry rejected calls or
guess whether side effects occurred. After replacement, run doctor again and
verify a safe client operation before revoking the old token upstream.

This check covers credentials attached to MCP HTTP/Holepunch upstreams. It does
not rotate client share bearers, invite renewal secrets, OAuth signing keys,
ngrok agent authtokens, SSH keys, or mounted applications' sessions. Keep using
their existing controls. HTTP mounts remain outside the MCP credential broker.

## Custom brokers

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

The broker is called when snulbug forwards a request, probes an upstream, or
explicitly checks its availability through live doctor/fabric diagnostics.
Audit logs, share contracts, fabric status, and replay logs receive only
`credential_metadata()` output.

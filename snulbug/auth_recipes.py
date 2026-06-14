from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

AUTH_RECIPE_PROVIDERS = (
    "keycloak",
    "auth0",
    "okta",
    "entra",
    "cloudflare-access",
    "github-oidc",
)

DEFAULT_AUTH_SCOPES = (
    "mcp:connect",
    "mcp:tools.read",
    "mcp:tool.files.read",
    "mcp:tool.git.status",
)

DEFAULT_AUTH_INIT_ROOT = Path(".snulbug/auth")

PROVIDER_DOCS = {
    "keycloak": "https://www.keycloak.org/docs/latest/server_admin/#_clients",
    "auth0": "https://auth0.com/docs/get-started/auth0-overview/create-applications",
    "okta": "https://developer.okta.com/docs/guides/customize-authz-server/main/",
    "entra": "https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",
    "cloudflare-access": (
        "https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/"
        "self-hosted-public-app/"
    ),
    "github-oidc": "https://docs.github.com/en/actions/concepts/security/openid-connect",
}


def generate_mcp_auth_recipe(
    provider: str,
    *,
    public_url: str,
    issuer: str | None = None,
    audience: str | None = None,
    client_id: str | None = None,
    tenant: str | None = None,
    domain: str | None = None,
    realm: str | None = None,
    auth_server_id: str | None = None,
    scopes: Sequence[str] | None = None,
    output: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Generate provider-specific registration/setup guidance for an MCP share."""

    normalized_provider = provider.strip().lower()
    if normalized_provider not in AUTH_RECIPE_PROVIDERS:
        raise ValueError(f"provider must be one of: {', '.join(AUTH_RECIPE_PROVIDERS)}")
    url = _require_public_url(public_url)
    scope_values = _unique_strings(scopes or DEFAULT_AUTH_SCOPES)

    if normalized_provider == "cloudflare-access":
        recipe = _cloudflare_access_recipe(url, scopes=scope_values)
    elif normalized_provider == "github-oidc":
        recipe = _github_oidc_recipe(url, issuer=issuer, audience=audience, scopes=scope_values)
    else:
        recipe_issuer = _provider_issuer(
            normalized_provider,
            issuer=issuer,
            domain=domain,
            tenant=tenant,
            realm=realm,
            auth_server_id=auth_server_id,
        )
        recipe_audience = audience or url
        recipe = _oauth_provider_recipe(
            normalized_provider,
            public_url=url,
            issuer=recipe_issuer,
            audience=recipe_audience,
            client_id=client_id,
            tenant=tenant,
            domain=domain,
            realm=realm,
            auth_server_id=auth_server_id,
            scopes=scope_values,
        )

    report = format_mcp_auth_recipe_report(recipe)
    recipe["report"] = report
    if output is not None:
        output_path = Path(output)
        if output_path.exists() and not force:
            raise FileExistsError(f"auth recipe output already exists: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
        recipe["output"] = str(output_path)
    return recipe


def generate_mcp_auth_init(
    provider: str,
    *,
    public_url: str,
    issuer: str | None = None,
    audience: str | None = None,
    client_id: str | None = None,
    tenant: str | None = None,
    domain: str | None = None,
    realm: str | None = None,
    auth_server_id: str | None = None,
    scopes: Sequence[str] | None = None,
    output_dir: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Generate a provider auth setup directory for an MCP share."""

    recipe = generate_mcp_auth_recipe(
        provider,
        public_url=public_url,
        issuer=issuer,
        audience=audience,
        client_id=client_id,
        tenant=tenant,
        domain=domain,
        realm=realm,
        auth_server_id=auth_server_id,
        scopes=scopes,
    )
    normalized_provider = str(recipe["provider"])
    directory = Path(output_dir) if output_dir is not None else DEFAULT_AUTH_INIT_ROOT / normalized_provider
    files = {
        "readme": directory / "README.md",
        "config": directory / "snulbug.auth.toml",
        "client_request": directory / "client-token-request.json",
        "metadata": directory / "auth-init.json",
        "commands": directory / "commands.json",
    }
    existing = [path for path in files.values() if path.exists()]
    if existing and not force:
        raise FileExistsError(f"auth init output already exists: {existing[0]}")

    directory.mkdir(parents=True, exist_ok=True)
    commands = _auth_init_commands(recipe, directory=directory)
    metadata = {
        "ok": True,
        "kind": "snulbug.auth.init",
        "provider": normalized_provider,
        "public_url": recipe["public_url"],
        "directory": str(directory),
        "files": {key: str(path) for key, path in files.items()},
        "commands": commands,
        "next_steps": _auth_init_next_steps(recipe, directory=directory),
        "recipe": _auth_init_recipe_summary(recipe),
    }
    metadata["written_files"] = [str(path) for path in files.values()]

    _write_auth_init_file(files["readme"], _format_auth_init_readme(recipe, metadata), force=force)
    _write_auth_init_file(files["config"], str(recipe.get("snulbug_config") or ""), force=force)
    _write_auth_init_file(
        files["client_request"],
        json.dumps(recipe.get("client_request") or {}, indent=2, sort_keys=True) + "\n",
        force=force,
    )
    _write_auth_init_file(files["commands"], json.dumps(commands, indent=2, sort_keys=True) + "\n", force=force)
    _write_auth_init_file(files["metadata"], json.dumps(metadata, indent=2, sort_keys=True) + "\n", force=force)

    return metadata


def format_mcp_auth_recipe_report(recipe: Mapping[str, Any]) -> str:
    """Render an auth interop recipe as Markdown."""

    provider = str(recipe.get("provider", "unknown"))
    title = str(recipe.get("title") or provider)
    lines = [
        f"# snulbug auth recipe: {title}",
        "",
        f"Provider: `{provider}`",
        f"Public MCP URL: `{recipe.get('public_url')}`",
        "",
    ]
    summary = recipe.get("summary")
    if isinstance(summary, str) and summary:
        lines.extend([summary, ""])

    assumptions = _sequence(recipe.get("assumptions"))
    if assumptions:
        lines.extend(["## Assumptions", ""])
        lines.extend(f"- {item}" for item in assumptions)
        lines.append("")

    setup_steps = _sequence(recipe.get("provider_steps"))
    if setup_steps:
        lines.extend(["## Provider Setup", ""])
        for index, step in enumerate(setup_steps, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")

    client_request = _mapping(recipe.get("client_request"))
    if client_request:
        lines.extend(["## Client Token Request", ""])
        for key, value in client_request.items():
            if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
                lines.append(f"- `{key}`: `{', '.join(str(item) for item in value)}`")
            else:
                lines.append(f"- `{key}`: `{value}`")
        lines.append("")

    config = recipe.get("snulbug_config")
    if isinstance(config, str) and config:
        lines.extend(["## snulbug Config", "", "```toml", config.rstrip(), "```", ""])

    commands = _mapping(recipe.get("commands"))
    if commands:
        lines.extend(["## Commands", ""])
        for name, command in commands.items():
            lines.append(f"- `{name}`: `{command}`")
        lines.append("")

    notes = _sequence(recipe.get("notes"))
    if notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {item}" for item in notes)
        lines.append("")

    docs = _sequence(recipe.get("docs"))
    if docs:
        lines.extend(["## Provider Docs", ""])
        lines.extend(f"- {item}" for item in docs)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_mcp_auth_init_report(result: Mapping[str, Any]) -> str:
    """Render a generated auth init flow as Markdown."""

    recipe = _mapping(result.get("recipe"))
    files = _mapping(result.get("files"))
    commands = _mapping(result.get("commands"))
    lines = [
        "# snulbug mcp share auth init",
        "",
        f"Provider: `{result.get('provider')}`",
        f"Public MCP URL: `{result.get('public_url')}`",
        f"Directory: `{result.get('directory')}`",
        "",
    ]
    if recipe.get("title"):
        lines.extend([str(recipe["title"]), ""])
    if files:
        lines.extend(["## Files", ""])
        for name, path in files.items():
            lines.append(f"- `{name}`: `{path}`")
        lines.append("")
    next_steps = _sequence(result.get("next_steps"))
    if next_steps:
        lines.extend(["## Next Steps", ""])
        for index, step in enumerate(next_steps, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")
    if commands:
        lines.extend(["## Commands", ""])
        for name, command in commands.items():
            lines.append(f"- `{name}`: `{command}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _oauth_provider_recipe(
    provider: str,
    *,
    public_url: str,
    issuer: str,
    audience: str,
    client_id: str | None,
    tenant: str | None,
    domain: str | None,
    realm: str | None,
    auth_server_id: str | None,
    scopes: Sequence[str],
) -> dict[str, Any]:
    provider_steps = _oauth_provider_steps(
        provider,
        public_url=public_url,
        audience=audience,
        client_id=client_id,
        tenant=tenant,
        domain=domain,
        realm=realm,
        auth_server_id=auth_server_id,
        scopes=scopes,
    )
    return {
        "ok": True,
        "kind": "snulbug.auth.recipe",
        "provider": provider,
        "title": _provider_title(provider),
        "public_url": public_url,
        "issuer": issuer,
        "audience": audience,
        "client_id": client_id,
        "scopes": list(scopes),
        "summary": (
            "Use your identity provider as the authorization server. snulbug remains the protected MCP "
            "resource: it verifies issuer, audience/resource, scopes, and then applies leases/Lua policy."
        ),
        "assumptions": [
            "You already have a public MCP URL that routes to snulbug.",
            "The provider issues JWT access tokens for the MCP resource.",
            "Dynamic client registration is handled outside snulbug.",
        ],
        "provider_steps": provider_steps,
        "client_request": {
            "issuer": issuer,
            "audience": audience,
            "client_id": client_id or "<provider-client-id>",
            "scopes": list(scopes),
        },
        "snulbug_config": _oauth_snulbug_config(
            public_url=public_url,
            issuer=issuer,
            audience=audience,
            scopes=scopes,
        ),
        "commands": _auth_recipe_commands(public_url),
        "notes": _oauth_provider_notes(provider, public_url=public_url, audience=audience),
        "docs": [PROVIDER_DOCS[provider]],
    }


def _cloudflare_access_recipe(public_url: str, *, scopes: Sequence[str]) -> dict[str, Any]:
    return {
        "ok": True,
        "kind": "snulbug.auth.recipe",
        "provider": "cloudflare-access",
        "title": "Cloudflare Access",
        "public_url": public_url,
        "scopes": list(scopes),
        "summary": (
            "Use Cloudflare Access as the outer user/device gate and snulbug as the origin-side MCP policy "
            "gateway. This recipe uses Cloudflare Access headers, not OAuth protected-resource mode."
        ),
        "assumptions": [
            "The public MCP URL is a Cloudflare Access self-hosted application.",
            "cloudflared routes the public hostname to the snulbug origin.",
            "snulbug is configured to verify Access-origin headers before Lua/upstream forwarding.",
        ],
        "provider_steps": [
            f"Create a Cloudflare Access self-hosted application for `{public_url}`.",
            "Add Access policies for the users, groups, service tokens, or device posture allowed to use the share.",
            "Route the hostname to the snulbug gateway with Cloudflare Tunnel.",
            "Do not require Access service-token headers on OAuth discovery endpoints if you also enable OAuth mode.",
        ],
        "client_request": {
            "mcp_url": public_url,
            "authentication": "Cloudflare Access browser/session or service-token policy",
        },
        "snulbug_config": _cloudflare_snulbug_config(public_url),
        "commands": {
            "run": "uv run snulbug mcp share run --config snulbug.toml",
            "doctor": f"uv run snulbug mcp share auth doctor --config snulbug.toml --url {public_url}",
        },
        "notes": [
            "This is an origin-side verification layer for Cloudflare Access headers.",
            'Use `cloudflare_access = "audit"` first if you want to observe headers before enforcing.',
            "Use snulbug leases and Lua policy for task-specific capability bounds after Access succeeds.",
        ],
        "docs": [PROVIDER_DOCS["cloudflare-access"]],
    }


def _github_oidc_recipe(
    public_url: str,
    *,
    issuer: str | None,
    audience: str | None,
    scopes: Sequence[str],
) -> dict[str, Any]:
    recipe_issuer = issuer or "https://token.actions.githubusercontent.com"
    recipe_audience = audience or public_url
    return {
        "ok": True,
        "kind": "snulbug.auth.recipe",
        "provider": "github-oidc",
        "title": "GitHub Actions OIDC",
        "public_url": public_url,
        "issuer": recipe_issuer,
        "audience": recipe_audience,
        "scopes": [],
        "summary": (
            "Use GitHub Actions OIDC when a workflow needs temporary access to a snulbug MCP share. "
            "GitHub OIDC tokens do not carry MCP scopes, so combine issuer/audience validation with leases "
            "and Lua identity policy."
        ),
        "assumptions": [
            "A GitHub Actions workflow has `id-token: write` permission.",
            "The workflow requests an ID token with the MCP public URL as the audience.",
            "Lua policy or leases constrain the repository/ref/job that can use the share.",
        ],
        "provider_steps": [
            "In the workflow, grant `permissions: id-token: write` for the job that needs MCP access.",
            f"Request an OIDC token with audience `{recipe_audience}`.",
            "Pass the token to the MCP client as `Authorization: Bearer <token>`.",
            "Add a snulbug lease for the workflow task and require the lease header for tool calls.",
        ],
        "client_request": {
            "issuer": recipe_issuer,
            "audience": recipe_audience,
            "scopes": [],
        },
        "snulbug_config": _github_oidc_snulbug_config(
            public_url=public_url,
            issuer=recipe_issuer,
            audience=recipe_audience,
        ),
        "commands": _auth_recipe_commands(public_url),
        "notes": [
            "This is not an OAuth access-token flow with MCP scopes.",
            "Use `context.auth.subject` or `auth.require_subject(...)` for exact workflow subject fences.",
            "Keep `lease_required = true` so a valid GitHub OIDC token is not enough by itself.",
        ],
        "docs": [PROVIDER_DOCS["github-oidc"]],
    }


def _oauth_snulbug_config(
    *,
    public_url: str,
    issuer: str,
    audience: str,
    scopes: Sequence[str],
) -> str:
    scope_list = _toml_string_list(scopes)
    return f"""[mcp.proxy]
tunnel_public_url = {json.dumps(public_url)}
lease_required = true

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(public_url)}
issuer = {json.dumps(issuer)}
authorization_servers = [{json.dumps(issuer)}]
audience = {json.dumps(audience)}
required_scopes = ["mcp:connect"]
scopes_supported = {scope_list}
issuer_discovery = true
token_validation = "jwt"
strip_authorization_upstream = true

[mcp.auth.scope_map]
"mcp:tools.read" = ["tools/list", "resources/list"]
"mcp:tool.files.read" = ["tools/call:filesystem.read_file"]
"mcp:tool.git.status" = ["tools/call:git.status"]
"""


def _cloudflare_snulbug_config(public_url: str) -> str:
    return f"""[mcp.proxy]
tunnel_public_url = {json.dumps(public_url)}
lease_required = true
cloudflare_access = "enforce"
cloudflare_access_require_jwt = true
cloudflare_access_require_email = true
cloudflare_access_require_cf_ray = true
cloudflare_access_allowed_domains = ["example.com"]

[mcp.auth]
mode = "off"
"""


def _github_oidc_snulbug_config(*, public_url: str, issuer: str, audience: str) -> str:
    return f"""[mcp.proxy]
tunnel_public_url = {json.dumps(public_url)}
lease_required = true

[mcp.auth]
mode = "oauth-resource"
resource = {json.dumps(public_url)}
issuer = {json.dumps(issuer)}
authorization_servers = [{json.dumps(issuer)}]
audience = {json.dumps(audience)}
required_scopes = []
scopes_supported = []
issuer_discovery = true
token_validation = "jwt"
strip_authorization_upstream = true
"""


def _oauth_provider_steps(
    provider: str,
    *,
    public_url: str,
    audience: str,
    client_id: str | None,
    tenant: str | None,
    domain: str | None,
    realm: str | None,
    auth_server_id: str | None,
    scopes: Sequence[str],
) -> list[str]:
    scope_text = ", ".join(f"`{scope}`" for scope in scopes)
    if provider == "keycloak":
        return [
            f"In realm `{realm or '<realm>'}`, create or choose an OpenID Connect client for the MCP client.",
            "Create client scopes for the MCP scopes you want to issue.",
            f"Add scopes: {scope_text}.",
            f"Configure an audience mapper so access tokens include `{audience}`.",
            "Use the realm issuer URL as `mcp.auth.issuer`.",
        ]
    if provider == "auth0":
        return [
            f"Create an Auth0 API with Identifier `{audience}`.",
            f"Add API permissions/scopes: {scope_text}.",
            f"Create or choose an application for the MCP client{_client_suffix(client_id)}.",
            "Authorize the application for the API and request the API audience when minting tokens.",
            f"Use the tenant issuer URL from `{domain or '<tenant>.auth0.com'}` as `mcp.auth.issuer`.",
        ]
    if provider == "okta":
        return [
            f"Create or choose a custom authorization server `{auth_server_id or 'default'}`.",
            f"Set the authorization server audience to `{audience}`.",
            f"Add scopes: {scope_text}.",
            "Create access policies/rules for the MCP client and allowed users/groups.",
            f"Create or choose an OIDC application for the MCP client{_client_suffix(client_id)}.",
        ]
    if provider == "entra":
        return [
            f"Register an app for the MCP resource in tenant `{tenant or '<tenant-id>'}`.",
            f"Expose an API and set the Application ID URI / audience to `{audience}`.",
            f"Add delegated or application scopes: {scope_text}.",
            f"Register or choose the MCP client application{_client_suffix(client_id)} and grant API permissions.",
            "Use the tenant v2.0 issuer URL in snulbug and validate with `share auth doctor`.",
        ]
    raise ValueError(f"unsupported OAuth provider: {provider}")


def _oauth_provider_notes(provider: str, *, public_url: str, audience: str) -> list[str]:
    notes = [
        "Run `share auth doctor` after the provider starts issuing tokens.",
        "Do not forward caller OAuth tokens upstream; snulbug strips Authorization by default.",
    ]
    if audience != public_url:
        notes.append(
            "The configured audience differs from the public URL. Keep this intentional and validate the setup with "
            "`share auth doctor`; prefer the public MCP URL as the audience when the provider supports it."
        )
    if provider == "entra":
        notes.append(
            "For temporary tunnel domains, Entra may require an `api://...` Application ID URI unless the domain is "
            "verified. Prefer stable verified domains for public MCP shares."
        )
    if provider == "keycloak":
        notes.append("Keycloak often needs an explicit audience mapper for access-token `aud` values.")
    return notes


def _provider_issuer(
    provider: str,
    *,
    issuer: str | None,
    domain: str | None,
    tenant: str | None,
    realm: str | None,
    auth_server_id: str | None,
) -> str:
    if issuer:
        return issuer.rstrip("/")
    if provider == "keycloak":
        base = _https_domain(domain or "KEYCLOAK.example")
        return f"{base}/realms/{realm or 'YOUR_REALM'}"
    if provider == "auth0":
        return f"{_https_domain(domain or 'YOUR_TENANT.auth0.com')}/"
    if provider == "okta":
        return f"{_https_domain(domain or 'YOUR_OKTA_DOMAIN')}/oauth2/{auth_server_id or 'default'}"
    if provider == "entra":
        return f"https://login.microsoftonline.com/{tenant or 'TENANT_ID'}/v2.0"
    raise ValueError(f"unsupported provider: {provider}")


def _auth_recipe_commands(public_url: str) -> dict[str, str]:
    return {
        "run": "uv run snulbug mcp share run --config snulbug.toml",
        "doctor": (
            f"uv run snulbug mcp share auth doctor --config snulbug.toml --url {public_url} --token $ACCESS_TOKEN"
        ),
    }


def _auth_init_commands(recipe: Mapping[str, Any], *, directory: Path) -> dict[str, str]:
    public_url = str(recipe.get("public_url") or "")
    config = directory / "snulbug.auth.toml"
    return {
        "review": f"less {directory / 'README.md'}",
        "show_config": f"cat {config}",
        "run": "uv run snulbug mcp share run --config snulbug.toml",
        "doctor": (
            f"uv run snulbug mcp share auth doctor --config snulbug.toml --url {public_url} --token $ACCESS_TOKEN"
        ),
    }


def _auth_init_next_steps(recipe: Mapping[str, Any], *, directory: Path) -> list[str]:
    commands = _auth_init_commands(recipe, directory=directory)
    return [
        f"Review `{directory / 'README.md'}` and complete the provider setup.",
        f"Merge `{directory / 'snulbug.auth.toml'}` into the share's `snulbug.toml`.",
        commands["run"],
        commands["doctor"],
    ]


def _auth_init_recipe_summary(recipe: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": recipe.get("kind"),
        "provider": recipe.get("provider"),
        "title": recipe.get("title"),
        "issuer": recipe.get("issuer"),
        "audience": recipe.get("audience"),
        "client_id": recipe.get("client_id"),
        "scopes": list(_sequence(recipe.get("scopes"))),
        "docs": list(_sequence(recipe.get("docs"))),
    }


def _format_auth_init_readme(recipe: Mapping[str, Any], result: Mapping[str, Any]) -> str:
    lines = [
        f"# snulbug auth init: {recipe.get('title') or recipe.get('provider')}",
        "",
        "This directory is generated by `snulbug mcp share auth init`.",
        "Use it to configure your identity provider and merge the generated auth snippet into a share config.",
        "",
        "## Generated Files",
        "",
    ]
    files = _mapping(result.get("files"))
    for name, path in files.items():
        lines.append(f"- `{name}`: `{Path(path).name}`")
    lines.extend(["", "## Provider Recipe", "", format_mcp_auth_recipe_report(recipe).rstrip(), ""])
    lines.extend(["## Next Steps", ""])
    for index, step in enumerate(_sequence(result.get("next_steps")), start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    return "\n".join(lines)


def _write_auth_init_file(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"auth init output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if content and not content.endswith("\n"):
        content += "\n"
    path.write_text(content, encoding="utf-8")


def _provider_title(provider: str) -> str:
    return {
        "keycloak": "Keycloak",
        "auth0": "Auth0",
        "okta": "Okta",
        "entra": "Microsoft Entra ID",
        "cloudflare-access": "Cloudflare Access",
        "github-oidc": "GitHub Actions OIDC",
    }[provider]


def _client_suffix(client_id: str | None) -> str:
    return f" `{client_id}`" if client_id else ""


def _https_domain(value: str) -> str:
    stripped = value.rstrip("/")
    if stripped.startswith(("http://", "https://")):
        return stripped
    return f"https://{stripped}"


def _require_public_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("public_url is required")
    return value.strip().rstrip("/")


def _toml_string_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(json.dumps(value) for value in values) + "]"


def _sequence(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return list(value)
    return [value]


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _unique_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        item = str(value)
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result

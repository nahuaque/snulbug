from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthProviderRecipeContext:
    """Inputs available to auth provider recipe generators."""

    public_url: str
    issuer: str | None = None
    audience: str | None = None
    client_id: str | None = None
    tenant: str | None = None
    domain: str | None = None
    realm: str | None = None
    auth_server_id: str | None = None
    scopes: tuple[str, ...] = ()


class AuthProvider:
    """Extension point for auth setup recipes and provider-specific claim context."""

    name = ""
    title = ""
    docs: tuple[str, ...] = ()
    context_key: str | None = None

    def recipe(self, context: AuthProviderRecipeContext) -> dict[str, Any]:
        raise NotImplementedError(f"auth provider {self.name!r} does not support recipe generation")

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        return {}

    @property
    def normalized_name(self) -> str:
        return _normalize_provider_name(self.name)

    @property
    def normalized_context_key(self) -> str:
        return self.context_key or self.normalized_name.replace("-", "_")


class KeycloakAuthProvider(AuthProvider):
    name = "keycloak"
    title = "Keycloak"
    docs = ("https://www.keycloak.org/docs/latest/server_admin/#_clients",)

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        realm_access = claims.get("realm_access")
        realm_access = realm_access if isinstance(realm_access, Mapping) else {}
        resource_access = claims.get("resource_access")
        resource_access = resource_access if isinstance(resource_access, Mapping) else {}
        client_roles: dict[str, list[str]] = {}
        for client_id, access in resource_access.items():
            if not isinstance(access, Mapping):
                continue
            roles = _sequence_strings(access.get("roles"))
            if roles:
                client_roles[str(client_id)] = roles
        return _drop_empty(
            {
                "realm_roles": _sequence_strings(realm_access.get("roles")),
                "client_roles": client_roles,
            }
        )


class Auth0AuthProvider(AuthProvider):
    name = "auth0"
    title = "Auth0"
    docs = ("https://auth0.com/docs/get-started/auth0-overview/create-applications",)


class OktaAuthProvider(AuthProvider):
    name = "okta"
    title = "Okta"
    docs = ("https://developer.okta.com/docs/guides/customize-authz-server/main/",)


class EntraAuthProvider(AuthProvider):
    name = "entra"
    title = "Microsoft Entra ID"
    docs = ("https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app",)

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        return _drop_empty(
            {
                "tenant_id": _first_claim_value(claims.get("tid")),
                "object_id": _first_claim_value(claims.get("oid")),
                "app_id": _first_claim_value(claims.get("appid") or claims.get("azp") or claims.get("client_id")),
                "groups": _sequence_strings(claims.get("groups")),
                "app_roles": _sequence_strings(claims.get("roles")),
            }
        )


class CloudflareAccessAuthProvider(AuthProvider):
    name = "cloudflare-access"
    title = "Cloudflare Access"
    docs = (
        "https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/"
        "self-hosted-public-app/",
    )
    context_key = "cloudflare_access"

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        return _drop_empty(
            {
                "jwt_subject": _first_claim_value(claims.get("sub")),
                "email": _first_claim_value(claims.get("email")),
                "groups": _sequence_strings(claims.get("groups")),
            }
        )


class GitHubActionsOidcAuthProvider(AuthProvider):
    name = "github-oidc"
    title = "GitHub Actions OIDC"
    docs = ("https://docs.github.com/en/actions/concepts/security/openid-connect",)
    context_key = "github_actions"

    def claim_context(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        fields = (
            "repository",
            "repository_owner",
            "repository_id",
            "workflow",
            "workflow_ref",
            "job_workflow_ref",
            "ref",
            "ref_type",
            "event_name",
            "actor",
            "environment",
            "run_id",
            "run_attempt",
        )
        return _drop_empty({field: _first_claim_value(claims.get(field)) for field in fields})


_AUTH_PROVIDER_REGISTRY: dict[str, AuthProvider] = {}


def register_auth_provider(provider: AuthProvider, *, replace: bool = False) -> AuthProvider:
    """Register an auth provider plugin for recipes and provider claim mapping."""

    name = provider.normalized_name
    if not name:
        raise ValueError("auth provider name is required")
    if name in _AUTH_PROVIDER_REGISTRY and not replace:
        raise ValueError(f"auth provider already registered: {name}")
    _AUTH_PROVIDER_REGISTRY[name] = provider
    return provider


def get_auth_provider(provider: str) -> AuthProvider:
    """Return a registered auth provider plugin."""

    name = _normalize_provider_name(provider)
    try:
        return _AUTH_PROVIDER_REGISTRY[name]
    except KeyError as exc:
        known = ", ".join(list_auth_providers()) or "<none>"
        raise ValueError(f"unknown auth provider {provider!r}; known providers: {known}") from exc


def list_auth_providers() -> tuple[str, ...]:
    """Return registered auth provider names in registration order."""

    return tuple(_AUTH_PROVIDER_REGISTRY)


def auth_provider_claim_context(claims: Mapping[str, Any]) -> dict[str, Any]:
    """Build `context.auth.provider` by applying registered provider claim mappers."""

    provider_context: dict[str, Any] = {}
    for provider in _AUTH_PROVIDER_REGISTRY.values():
        context = provider.claim_context(claims)
        if context:
            provider_context[provider.normalized_context_key] = _drop_empty(dict(context))
    return _drop_empty(provider_context)


def _register_builtin_auth_providers() -> None:
    for provider in (
        KeycloakAuthProvider(),
        Auth0AuthProvider(),
        OktaAuthProvider(),
        EntraAuthProvider(),
        CloudflareAccessAuthProvider(),
        GitHubActionsOidcAuthProvider(),
    ):
        register_auth_provider(provider, replace=True)


def _normalize_provider_name(value: str) -> str:
    return str(value).strip().lower()


def _sequence_strings(value: Any) -> list[str]:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _first_claim_value(value: Any) -> str | None:
    values = _sequence_strings(value)
    return values[0] if values else None


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items() if item not in (None, {}, [], ())}


_register_builtin_auth_providers()

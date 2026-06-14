from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt


@dataclass(frozen=True)
class OAuthResourceConfig:
    mode: str = "off"
    resource: str | None = None
    issuer: str | None = None
    authorization_servers: tuple[str, ...] = ()
    audience: str | None = None
    required_scopes: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    jwks_path: Path | None = None
    resource_metadata_url: str | None = None
    realm: str = "mcp"
    leeway_seconds: float = 60.0
    strip_authorization_upstream: bool = True

    @property
    def enabled(self) -> bool:
        return self.mode == "oauth-resource"


@dataclass(frozen=True)
class OAuthDecision:
    allowed: bool
    status: int
    body: bytes
    headers: list[tuple[bytes, bytes]]
    metadata: dict[str, Any]
    context: dict[str, Any]


def protected_resource_metadata(config: OAuthResourceConfig) -> dict[str, Any]:
    if not config.enabled:
        raise ValueError("OAuth protected resource metadata requires oauth-resource mode")
    if not config.resource:
        raise ValueError("OAuth resource metadata requires resource")
    authorization_servers = list(config.authorization_servers)
    if not authorization_servers and config.issuer:
        authorization_servers = [config.issuer]
    metadata: dict[str, Any] = {
        "resource": config.resource,
        "authorization_servers": authorization_servers,
    }
    if config.scopes_supported:
        metadata["scopes_supported"] = list(config.scopes_supported)
    return _drop_empty(metadata)


def oauth_resource_metadata_url(config: OAuthResourceConfig) -> str:
    if config.resource_metadata_url:
        return config.resource_metadata_url
    if not config.resource:
        return "/.well-known/oauth-protected-resource"
    parsed = urlsplit(config.resource)
    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", ""))
    return "/.well-known/oauth-protected-resource"


def oauth_bearer_challenge(config: OAuthResourceConfig, *, error: str | None = None) -> str:
    parts = [
        f'Bearer realm="{_quote_header(config.realm)}"',
        f'resource_metadata="{_quote_header(oauth_resource_metadata_url(config))}"',
    ]
    if error:
        parts.append(f'error="{_quote_header(error)}"')
    return ", ".join(parts)


def evaluate_oauth_request(scope: Mapping[str, Any], *, config: OAuthResourceConfig) -> OAuthDecision:
    if not config.enabled:
        return OAuthDecision(
            allowed=True,
            status=200,
            body=b"",
            headers=[],
            metadata={"enabled": False},
            context={},
        )
    token = _bearer_token(scope.get("headers", []))
    if not token:
        return _reject(config, reason_code="oauth.missing_token", error="invalid_token")
    try:
        claims = verify_jwt(token, config=config)
    except Exception as exc:
        return _reject(
            config,
            reason_code="oauth.invalid_token",
            error="invalid_token",
            details={"error_kind": type(exc).__name__},
        )
    scopes = _claim_scopes(claims)
    missing = [scope_name for scope_name in config.required_scopes if scope_name not in scopes]
    if missing:
        return _reject(
            config,
            reason_code="oauth.insufficient_scope",
            error="insufficient_scope",
            details={"missing_scopes": missing},
        )
    context = oauth_context(claims, scopes=scopes, config=config)
    return OAuthDecision(
        allowed=True,
        status=200,
        body=b"",
        headers=[],
        metadata={
            **context,
            "allowed": True,
            "reason_code": "oauth.allowed",
        },
        context=context,
    )


def verify_jwt(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm == "none":
        raise ValueError("JWT alg is missing or unsupported")
    jwks = _load_jwks(config.jwks_path)
    key = _select_jwks_key(jwks, kid=header.get("kid"), algorithm=algorithm)
    try:
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=[algorithm],
            audience=config.audience,
            issuer=config.issuer,
            leeway=config.leeway_seconds,
            options={
                "verify_aud": bool(config.audience),
                "verify_iss": bool(config.issuer),
            },
        )
    except jwt.PyJWTError as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(decoded, Mapping):
        raise ValueError("JWT payload must be a JSON object")
    return dict(decoded)


def oauth_context(
    claims: Mapping[str, Any],
    *,
    scopes: Sequence[str],
    config: OAuthResourceConfig,
) -> dict[str, Any]:
    audience = claims.get("aud")
    if isinstance(audience, str):
        audiences = [audience]
    elif isinstance(audience, Sequence) and not isinstance(audience, str | bytes | bytearray):
        audiences = [str(item) for item in audience]
    else:
        audiences = []
    groups = claims.get("groups")
    if isinstance(groups, Sequence) and not isinstance(groups, str | bytes | bytearray):
        group_values = [str(item) for item in groups]
    else:
        group_values = []
    return _drop_empty(
        {
            "enabled": True,
            "mode": config.mode,
            "subject": claims.get("sub"),
            "issuer": claims.get("iss"),
            "audience": audiences,
            "client_id": claims.get("azp") or claims.get("client_id"),
            "scopes": sorted(set(scopes)),
            "email": claims.get("email"),
            "tenant": claims.get("tid") or claims.get("tenant"),
            "groups": group_values,
        }
    )


def _reject(
    config: OAuthResourceConfig,
    *,
    reason_code: str,
    error: str,
    details: Mapping[str, Any] | None = None,
) -> OAuthDecision:
    metadata = {
        "enabled": True,
        "allowed": False,
        "reason_code": reason_code,
        **dict(details or {}),
    }
    body = b"authentication required"
    return OAuthDecision(
        allowed=False,
        status=401,
        body=body,
        headers=[
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"www-authenticate", oauth_bearer_challenge(config, error=error).encode("latin-1")),
        ],
        metadata=metadata,
        context={"auth": metadata},
    )


def _load_jwks(path: Path | None) -> dict[str, Any]:
    if path is None:
        raise ValueError("JWT verification requires auth.jwks_path")
    with path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    if not isinstance(loaded, Mapping):
        raise ValueError("JWKS must be a JSON object")
    keys = loaded.get("keys")
    if not isinstance(keys, Sequence) or isinstance(keys, str | bytes | bytearray):
        raise ValueError("JWKS keys must be a list")
    return {"keys": [dict(key) for key in keys if isinstance(key, Mapping)]}


def _select_jwks_key(jwks: Mapping[str, Any], *, kid: Any, algorithm: str) -> Any:
    keys = [key for key in jwks.get("keys", []) if isinstance(key, Mapping)]
    if kid is not None:
        keys = [key for key in keys if key.get("kid") == kid]
    if not keys:
        raise ValueError("JWKS does not contain a matching key")
    if len(keys) > 1 and kid is None:
        raise ValueError("JWT kid is required when JWKS contains multiple keys")
    key = keys[0]
    if key.get("alg") not in (None, algorithm):
        raise ValueError("JWKS key alg does not match JWT alg")
    try:
        return jwt.PyJWK.from_dict(dict(key), algorithm=algorithm).key
    except jwt.PyJWTError as exc:
        raise ValueError(f"JWKS key is invalid: {exc}") from exc


def _claim_scopes(claims: Mapping[str, Any]) -> list[str]:
    scopes: list[str] = []
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        scopes.extend(item for item in raw_scope.split() if item)
    raw_scp = claims.get("scp", claims.get("scopes"))
    if isinstance(raw_scp, str):
        scopes.extend(item for item in raw_scp.split() if item)
    elif isinstance(raw_scp, Sequence) and not isinstance(raw_scp, str | bytes | bytearray):
        scopes.extend(str(item) for item in raw_scp if item)
    return sorted(set(scopes))


def _bearer_token(raw_headers: Any) -> str | None:
    for name, value in raw_headers or []:
        raw_name = name if isinstance(name, bytes) else str(name).encode("latin-1")
        if raw_name.lower() != b"authorization":
            continue
        raw_value = value.decode("latin-1") if isinstance(value, bytes) else str(value)
        scheme, _, token = raw_value.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
    return None


def _quote_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}

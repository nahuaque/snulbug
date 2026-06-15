from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt

from .mcp_auth import OAuthResourceConfig, RemoteJwksCache, verify_jwt
from .middleware import Scope

CLOUDFLARE_ACCESS_MODES = {"off", "audit", "enforce"}
_GLOBAL_CLOUDFLARE_ACCESS_JWKS_CACHE = RemoteJwksCache()


@dataclass(frozen=True)
class CloudflareAccessConfig:
    """Origin-side Cloudflare Access header checks for tunnel-exposed proxies."""

    mode: str = "off"
    require_jwt: bool = True
    require_email: bool = False
    require_cf_ray: bool = True
    allowed_emails: Sequence[str] = ()
    allowed_domains: Sequence[str] = ()
    validate_jwt: bool = False
    team_domain: str | None = None
    issuer: str | None = None
    audience: str | None = None
    certs_url: str | None = None
    jwks_cache_seconds: float = 300.0
    jwks_fetch_timeout: float = 5.0
    leeway_seconds: float = 60.0
    jwks_cache: Any = None

    def __post_init__(self) -> None:
        mode = self.mode.lower()
        if mode not in CLOUDFLARE_ACCESS_MODES:
            raise ValueError("cloudflare_access mode must be 'off', 'audit', or 'enforce'")
        team_domain = _normalize_team_domain(self.team_domain)
        issuer = _normalize_access_url(self.issuer) or team_domain
        certs_url = _normalize_access_url(self.certs_url) or _cloudflare_access_certs_url(issuer)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "allowed_emails", _normalize_email_list(self.allowed_emails))
        object.__setattr__(self, "allowed_domains", _normalize_domain_list(self.allowed_domains))
        object.__setattr__(self, "team_domain", team_domain)
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "audience", _blank_to_none(self.audience))
        object.__setattr__(self, "certs_url", certs_url)
        object.__setattr__(self, "jwks_cache_seconds", float(self.jwks_cache_seconds))
        object.__setattr__(self, "jwks_fetch_timeout", float(self.jwks_fetch_timeout))
        object.__setattr__(self, "leeway_seconds", float(self.leeway_seconds))


@dataclass(frozen=True)
class CloudflareAccessDecision:
    allowed: bool
    status: int
    body: bytes
    metadata: dict[str, Any]


def evaluate_cloudflare_access(
    scope: Scope,
    *,
    config: CloudflareAccessConfig | None = None,
) -> CloudflareAccessDecision:
    """Evaluate Cloudflare Access origin headers without storing raw credentials."""

    access_config = config or CloudflareAccessConfig()
    headers = _scope_headers(scope)
    assertion = headers.get("cf-access-jwt-assertion")
    header_email = _normalize_email(headers.get("cf-access-authenticated-user-email"))
    jwt_validation = _validate_access_jwt(assertion, access_config)
    jwt_email = _normalize_email(jwt_validation.get("email") if isinstance(jwt_validation, Mapping) else None)
    email = jwt_email if access_config.validate_jwt else header_email
    email_domain = _email_domain(email)
    cf_ray = headers.get("cf-ray")
    groups = _normalize_group_list(
        headers.get("cf-access-authenticated-user-groups")
        or headers.get("cf-access-groups")
        or headers.get("cf-access-group")
    )
    service_token_present = bool(headers.get("cf-access-client-id") or headers.get("cf-access-client-secret"))

    checks = {
        "cf_ray_present": bool(cf_ray),
        "jwt_present": bool(assertion),
        "jwt_validation_configured": _jwt_validation_configured(access_config),
        "jwt_valid": jwt_validation.get("valid") is True,
        "email_present": bool(email),
        "email_allowed": _email_allowed(email, access_config.allowed_emails),
        "domain_allowed": _domain_allowed(email_domain, access_config.allowed_domains),
    }
    reason_code = _first_block_reason(access_config, checks)
    if access_config.validate_jwt and reason_code == "cloudflare_access.jwt_invalid":
        reason_code = str(jwt_validation.get("reason_code") or reason_code)
    would_block = reason_code != "cloudflare_access.allowed"
    blocked = access_config.mode == "enforce" and would_block
    allowed = not blocked
    metadata = {
        "enabled": access_config.mode != "off",
        "provider": "cloudflare",
        "mode": access_config.mode,
        "allowed": allowed,
        "blocked": blocked,
        "would_block": would_block,
        "reason_code": reason_code,
        "jwt_present": bool(assertion),
        "jwt_validated": jwt_validation.get("valid") is True,
        "jwt_validation": jwt_validation,
        "email": email,
        "email_source": "jwt" if access_config.validate_jwt and jwt_email else "header" if header_email else None,
        "header_email": header_email,
        "email_domain": email_domain,
        "groups": groups,
        "cf_ray": cf_ray,
        "connecting_ip": headers.get("cf-connecting-ip"),
        "ip_country": headers.get("cf-ipcountry"),
        "service_token_present": service_token_present,
        "checks": checks,
    }
    if access_config.mode == "off":
        metadata.update({"allowed": True, "blocked": False, "would_block": False})
        reason_code = "cloudflare_access.off"
        metadata["reason_code"] = reason_code
        return CloudflareAccessDecision(
            allowed=True,
            status=200,
            body=b"",
            metadata=_drop_none(metadata),
        )
    if blocked:
        body = f"Cloudflare Access rejected request: {reason_code}\n".encode("utf-8")
        return CloudflareAccessDecision(
            allowed=False,
            status=403,
            body=body,
            metadata=_drop_none(metadata),
        )
    return CloudflareAccessDecision(
        allowed=True,
        status=200,
        body=b"",
        metadata=_drop_none(metadata),
    )


def _first_block_reason(config: CloudflareAccessConfig, checks: Mapping[str, bool]) -> str:
    if config.mode == "off":
        return "cloudflare_access.off"
    if config.require_cf_ray and not checks["cf_ray_present"]:
        return "cloudflare_access.cf_ray_missing"
    if config.require_jwt and not checks["jwt_present"]:
        return "cloudflare_access.jwt_missing"
    if config.validate_jwt and not checks["jwt_validation_configured"]:
        return "cloudflare_access.jwt_config_missing"
    if config.validate_jwt and not checks["jwt_valid"]:
        return "cloudflare_access.jwt_invalid"
    needs_email = config.require_email or bool(config.allowed_emails) or bool(config.allowed_domains)
    if needs_email and not checks["email_present"]:
        return "cloudflare_access.email_missing"
    if config.allowed_emails and not checks["email_allowed"]:
        return "cloudflare_access.email_not_allowed"
    if config.allowed_domains and not checks["domain_allowed"]:
        return "cloudflare_access.domain_not_allowed"
    return "cloudflare_access.allowed"


def _validate_access_jwt(token: str | None, config: CloudflareAccessConfig) -> dict[str, Any]:
    validation = {
        "enabled": config.validate_jwt,
        "valid": False,
        "issuer": config.issuer,
        "audience": config.audience,
        "certs_url": config.certs_url,
    }
    if not config.validate_jwt:
        return validation
    if not token:
        return {**validation, "reason_code": "cloudflare_access.jwt_missing"}
    if not _jwt_validation_configured(config):
        return {**validation, "reason_code": "cloudflare_access.jwt_config_missing"}
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        return {
            **validation,
            "reason_code": "cloudflare_access.jwt_malformed",
            "error": _safe_error(exc),
        }
    algorithm = header.get("alg")
    key_id = header.get("kid")
    validation.update(
        {
            "algorithm": algorithm if isinstance(algorithm, str) else None,
            "key_id": key_id if isinstance(key_id, str) else None,
        }
    )
    if algorithm != "RS256":
        return {**validation, "reason_code": "cloudflare_access.jwt_algorithm_unsupported"}

    try:
        claims = verify_jwt(token, config=_access_oauth_config(config))
    except Exception as exc:
        return {
            **validation,
            "reason_code": "cloudflare_access.jwt_invalid",
            "error": _safe_error(exc),
        }
    return _drop_none(
        {
            **validation,
            "valid": True,
            "reason_code": "cloudflare_access.jwt_valid",
            "subject": _first_claim_value(claims.get("sub")),
            "email": _first_claim_value(claims.get("email")),
            "type": _first_claim_value(claims.get("type")),
            "identity_nonce": _first_claim_value(claims.get("identity_nonce")),
            "common_name": _first_claim_value(claims.get("common_name")),
            "claim_issuer": _first_claim_value(claims.get("iss")),
            "claim_audience": _claim_audience(claims.get("aud")),
        }
    )


def _access_oauth_config(config: CloudflareAccessConfig) -> OAuthResourceConfig:
    return OAuthResourceConfig(
        mode="oauth-resource",
        issuer=config.issuer,
        audience=config.audience,
        jwks_url=config.certs_url,
        jwks_cache_seconds=config.jwks_cache_seconds,
        jwks_fetch_timeout=config.jwks_fetch_timeout,
        jwks_cache=config.jwks_cache
        if isinstance(config.jwks_cache, RemoteJwksCache)
        else _GLOBAL_CLOUDFLARE_ACCESS_JWKS_CACHE,
        leeway_seconds=config.leeway_seconds,
        issuer_discovery=False,
    )


def _jwt_validation_configured(config: CloudflareAccessConfig) -> bool:
    return bool(config.issuer and config.audience and config.certs_url)


def _cloudflare_access_certs_url(issuer: str | None) -> str | None:
    if not issuer:
        return None
    return f"{issuer.rstrip('/')}/cdn-cgi/access/certs"


def _normalize_team_domain(value: str | None) -> str | None:
    raw = _blank_to_none(value)
    if raw is None:
        return None
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    hostname = parsed.hostname or ""
    if "." not in hostname:
        hostname = f"{hostname}.cloudflareaccess.com"
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme or "https", netloc, "", "", "")).rstrip("/")


def _normalize_access_url(value: str | None) -> str | None:
    raw = _blank_to_none(value)
    if raw is None:
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    return raw.rstrip("/")


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _safe_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def _first_claim_value(value: Any) -> str | None:
    values = _claim_values(value)
    return values[0] if values else None


def _claim_audience(value: Any) -> list[str]:
    return _claim_values(value)


def _claim_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [str(item) for item in value if str(item)]
    return [str(value)] if value != "" else []


def _scope_headers(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = _decode_header(raw_name).lower()
        value = _decode_header(raw_value)
        if name not in headers:
            headers[name] = value
    return headers


def _decode_header(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return str(value)


def _normalize_email(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def _email_domain(email: str | None) -> str | None:
    if email is None or "@" not in email:
        return None
    return email.rsplit("@", 1)[1] or None


def _normalize_email_list(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(value for item in _iter_values(values) if (value := _normalize_email(str(item))) is not None)


def _normalize_domain_list(values: Sequence[str]) -> tuple[str, ...]:
    domains = []
    for item in _iter_values(values):
        domain = str(item).strip().lower().removeprefix("@")
        if domain:
            domains.append(domain)
    return tuple(domains)


def _normalize_group_list(value: str | None) -> list[str]:
    if not value:
        return []
    groups = []
    for item in value.replace(";", ",").split(","):
        group = item.strip()
        if group:
            groups.append(group)
    return sorted(set(groups))


def _iter_values(values: Sequence[str]) -> Sequence[str]:
    if isinstance(values, str):
        return (values,)
    return values


def _email_allowed(email: str | None, allowed_emails: Sequence[str]) -> bool:
    return not allowed_emails or (email is not None and email in allowed_emails)


def _domain_allowed(email_domain: str | None, allowed_domains: Sequence[str]) -> bool:
    return not allowed_domains or (email_domain is not None and email_domain in allowed_domains)


def _drop_none(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}

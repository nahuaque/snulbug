from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .middleware import Scope

CLOUDFLARE_ACCESS_MODES = {"off", "audit", "enforce"}


@dataclass(frozen=True)
class CloudflareAccessConfig:
    """Origin-side Cloudflare Access header checks for tunnel-exposed proxies."""

    mode: str = "off"
    require_jwt: bool = True
    require_email: bool = False
    require_cf_ray: bool = True
    allowed_emails: Sequence[str] = ()
    allowed_domains: Sequence[str] = ()

    def __post_init__(self) -> None:
        mode = self.mode.lower()
        if mode not in CLOUDFLARE_ACCESS_MODES:
            raise ValueError("cloudflare_access mode must be 'off', 'audit', or 'enforce'")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "allowed_emails", _normalize_email_list(self.allowed_emails))
        object.__setattr__(self, "allowed_domains", _normalize_domain_list(self.allowed_domains))


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
    jwt = headers.get("cf-access-jwt-assertion")
    email = _normalize_email(headers.get("cf-access-authenticated-user-email"))
    email_domain = _email_domain(email)
    cf_ray = headers.get("cf-ray")
    service_token_present = bool(headers.get("cf-access-client-id") or headers.get("cf-access-client-secret"))

    checks = {
        "cf_ray_present": bool(cf_ray),
        "jwt_present": bool(jwt),
        "email_present": bool(email),
        "email_allowed": _email_allowed(email, access_config.allowed_emails),
        "domain_allowed": _domain_allowed(email_domain, access_config.allowed_domains),
    }
    reason_code = _first_block_reason(access_config, checks)
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
        "jwt_present": bool(jwt),
        "jwt_validated": False,
        "email": email,
        "email_domain": email_domain,
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
    needs_email = config.require_email or bool(config.allowed_emails) or bool(config.allowed_domains)
    if needs_email and not checks["email_present"]:
        return "cloudflare_access.email_missing"
    if config.allowed_emails and not checks["email_allowed"]:
        return "cloudflare_access.email_not_allowed"
    if config.allowed_domains and not checks["domain_allowed"]:
        return "cloudflare_access.domain_not_allowed"
    return "cloudflare_access.allowed"


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

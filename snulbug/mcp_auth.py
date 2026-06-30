from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlencode, urlsplit, urlunsplit

import jwt

from .auth_providers import auth_provider_claim_context

PROTECTED_RESOURCE_AUTH_MODES = {"oauth-resource", "enterprise-managed"}
ENTERPRISE_MANAGED_AUTH_EXTENSION = "io.modelcontextprotocol/enterprise-managed-authorization"
DEFAULT_DPOP_SIGNING_ALGORITHMS = (
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512",
    "EdDSA",
)
_DPOP_PRIVATE_JWK_FIELDS = {"d", "p", "q", "dp", "dq", "qi", "oth"}


@dataclass(frozen=True)
class OAuthResourceConfig:
    mode: str = "off"
    resource: str | None = None
    resource_aliases: tuple[str, ...] = ()
    issuer: str | None = None
    authorization_servers: tuple[str, ...] = ()
    audience: str | None = None
    audiences: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    jwks_path: Path | None = None
    jwks_url: str | None = None
    jwks_cache_seconds: float = 300.0
    jwks_fetch_timeout: float = 5.0
    jwks_cache: Any = None
    issuer_metadata_url: str | None = None
    issuer_discovery: bool = True
    issuer_metadata_cache: Any = None
    token_validation: str = "jwt"
    introspection_endpoint: str | None = None
    introspection_client_id: str | None = None
    introspection_client_secret_env: str | None = None
    introspection_cache_seconds: float = 30.0
    introspection_fetch_timeout: float = 5.0
    introspection_cache: Any = None
    resource_metadata_url: str | None = None
    realm: str = "mcp"
    leeway_seconds: float = 60.0
    strip_authorization_upstream: bool = True
    dpop_mode: str = "optional"
    dpop_signing_alg_values_supported: tuple[str, ...] = DEFAULT_DPOP_SIGNING_ALGORITHMS
    dpop_proof_max_age_seconds: float = 300.0
    dpop_replay_cache_max_entries: int = 10000
    dpop_replay_cache: Any = None
    scope_map: Mapping[str, tuple[str, ...]] | None = None
    claim_policy: Mapping[str, Any] | None = None
    required_claims: Mapping[str, tuple[str, ...]] | None = None
    profile_id: str | None = None
    profiles: tuple["OAuthResourceConfig", ...] = ()

    @property
    def enabled(self) -> bool:
        return self.mode in PROTECTED_RESOURCE_AUTH_MODES

    @property
    def mapped_scopes(self) -> dict[str, tuple[str, ...]]:
        return {str(scope): tuple(selectors) for scope, selectors in (self.scope_map or {}).items()}

    @property
    def has_claim_policy(self) -> bool:
        policy = self.claim_policy if isinstance(self.claim_policy, Mapping) else {}
        return policy.get("enabled") is True and bool(policy.get("rules"))

    @property
    def requires_body(self) -> bool:
        return bool(
            self.mapped_scopes or self.has_claim_policy or any(profile.requires_body for profile in self.profiles)
        )


@dataclass(frozen=True)
class OAuthDecision:
    allowed: bool
    status: int
    body: bytes
    headers: list[tuple[bytes, bytes]]
    metadata: dict[str, Any]
    context: dict[str, Any]


@dataclass(frozen=True)
class _TokenPresentation:
    token: str
    scheme: str


@dataclass(frozen=True)
class _DpopDecision:
    allowed: bool
    enabled: bool
    status: int = 200
    reason_code: str = "oauth.dpop_not_required"
    error: str = "invalid_dpop_proof"
    metadata: dict[str, Any] | None = None
    context: dict[str, Any] | None = None


@dataclass(frozen=True)
class _DpopProof:
    claims: dict[str, Any]
    header: dict[str, Any]
    jwk: dict[str, Any]
    thumbprint: str


class RemoteJwksCache:
    """Small in-process JWKS cache keyed by URL."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._metrics: dict[str, dict[str, Any]] = {}

    def get(self, url: str, *, ttl_seconds: float, timeout: float, force_refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            metrics = self._metrics.setdefault(url, _new_cache_metrics())
            entry = self._entries.get(url)
            if (
                not force_refresh
                and entry is not None
                and float(entry.get("expires_at", 0.0)) > now
                and isinstance(entry.get("jwks"), Mapping)
            ):
                metrics["hits"] += 1
                return dict(entry["jwks"])
            metrics["misses"] += 1

        try:
            jwks = _fetch_remote_jwks(url, timeout=timeout)
        except Exception as exc:
            with self._lock:
                _record_cache_failure(self._metrics.setdefault(url, _new_cache_metrics()), exc)
            raise
        expires_at = now + max(0.0, float(ttl_seconds))
        with self._lock:
            self._entries[url] = {"jwks": dict(jwks), "expires_at": expires_at, "fetched_at": now}
            metrics = self._metrics.setdefault(url, _new_cache_metrics())
            _record_cache_fetch(metrics, force_refresh=force_refresh)
        return jwks

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            urls: dict[str, Any] = {}
            for url in sorted({*self._entries, *self._metrics}):
                entry = self._entries.get(url, {})
                jwks = entry.get("jwks")
                keys = jwks.get("keys") if isinstance(jwks, Mapping) else []
                key_count = len(keys) if isinstance(keys, Sequence) and not isinstance(keys, str | bytes) else 0
                urls[url] = _cache_entry_snapshot(
                    self._metrics.get(url, _new_cache_metrics()),
                    entry=entry,
                    now=now,
                    extra={"key_count": key_count},
                )
            return {
                "entries": len(self._entries),
                "totals": _cache_totals(self._metrics.values()),
                "urls": urls,
            }


class RemoteIssuerMetadataCache:
    """Small in-process OAuth issuer metadata cache keyed by URL."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._metrics: dict[str, dict[str, Any]] = {}

    def get(self, url: str, *, ttl_seconds: float, timeout: float, force_refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            metrics = self._metrics.setdefault(url, _new_cache_metrics())
            entry = self._entries.get(url)
            if (
                not force_refresh
                and entry is not None
                and float(entry.get("expires_at", 0.0)) > now
                and isinstance(entry.get("metadata"), Mapping)
            ):
                metrics["hits"] += 1
                return dict(entry["metadata"])
            metrics["misses"] += 1

        try:
            metadata = _fetch_remote_issuer_metadata(url, timeout=timeout)
        except Exception as exc:
            with self._lock:
                _record_cache_failure(self._metrics.setdefault(url, _new_cache_metrics()), exc)
            raise
        expires_at = now + max(0.0, float(ttl_seconds))
        with self._lock:
            self._entries[url] = {"metadata": dict(metadata), "expires_at": expires_at, "fetched_at": now}
            metrics = self._metrics.setdefault(url, _new_cache_metrics())
            _record_cache_fetch(metrics, force_refresh=force_refresh)
        return metadata

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            urls = {
                url: _cache_entry_snapshot(self._metrics.get(url, _new_cache_metrics()), entry=entry, now=now)
                for url, entry in sorted(self._entries.items())
            }
            for url in sorted(set(self._metrics) - set(urls)):
                urls[url] = _cache_entry_snapshot(self._metrics[url], entry={}, now=now)
            return {
                "entries": len(self._entries),
                "totals": _cache_totals(self._metrics.values()),
                "urls": urls,
            }


class TokenIntrospectionCache:
    """Small in-process token introspection cache keyed by a token digest."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._metrics = _new_cache_metrics()

    def get(self, token: str, *, config: OAuthResourceConfig, force_refresh: bool = False) -> dict[str, Any]:
        key = _token_cache_key(token)
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if (
                not force_refresh
                and entry is not None
                and float(entry.get("expires_at", 0.0)) > now
                and isinstance(entry.get("response"), Mapping)
            ):
                self._metrics["hits"] += 1
                return dict(entry["response"])
            self._metrics["misses"] += 1

        try:
            response = _fetch_token_introspection(token, config=config)
        except Exception as exc:
            with self._lock:
                _record_cache_failure(self._metrics, exc)
            raise
        expires_at = _introspection_cache_expiry(response, now=now, ttl_seconds=config.introspection_cache_seconds)
        with self._lock:
            self._entries[key] = {"response": dict(response), "expires_at": expires_at, "fetched_at": now}
            _record_cache_fetch(self._metrics, force_refresh=force_refresh)
        return response

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            expires_in = [
                max(0.0, float(entry.get("expires_at", 0.0)) - now)
                for entry in self._entries.values()
                if isinstance(entry, Mapping)
            ]
            result = {
                "entries": len(self._entries),
                "totals": _cache_metrics_snapshot(self._metrics),
            }
            if expires_in:
                result["min_expires_in_seconds"] = round(min(expires_in), 3)
                result["max_expires_in_seconds"] = round(max(expires_in), 3)
            return result


class DpopReplayCache:
    """Bounded in-process DPoP proof replay cache keyed by proof key + jti."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, float] = {}
        self._metrics = _new_cache_metrics()

    def add_once(self, key: str, *, ttl_seconds: float, max_entries: int) -> bool:
        now = time.monotonic()
        expires_at = now + max(0.0, ttl_seconds)
        with self._lock:
            self._prune(now=now, max_entries=max_entries)
            if float(self._entries.get(key, 0.0)) > now:
                self._metrics["hits"] += 1
                return False
            self._metrics["misses"] += 1
            self._metrics["fetches"] += 1
            self._metrics["last_fetch_at"] = time.time()
            self._entries[key] = expires_at
            self._prune(now=now, max_entries=max_entries)
            return True

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            self._prune(now=now, max_entries=0)
            expires_in = [max(0.0, expires_at - now) for expires_at in self._entries.values()]
            result = {
                "entries": len(self._entries),
                "totals": _cache_metrics_snapshot(self._metrics),
            }
            if expires_in:
                result["min_expires_in_seconds"] = round(min(expires_in), 3)
                result["max_expires_in_seconds"] = round(max(expires_in), 3)
            return result

    def _prune(self, *, now: float, max_entries: int) -> None:
        expired = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)
        if max_entries <= 0:
            return
        while len(self._entries) > max_entries:
            oldest_key = min(self._entries, key=self._entries.__getitem__)
            self._entries.pop(oldest_key, None)


class StateDpopReplayCache(DpopReplayCache):
    """DPoP proof replay cache backed by the policy state-store CAS primitive."""

    def __init__(self, store: Any, *, key_prefix: str = "auth:dpop:jti:") -> None:
        self.store = store
        self.key_prefix = key_prefix
        self._lock = threading.RLock()
        self._metrics = _new_cache_metrics()

    def add_once(self, key: str, *, ttl_seconds: float, max_entries: int) -> bool:
        del max_entries
        ttl = max(1.0, float(ttl_seconds))
        stored = self.store.cas(f"{self.key_prefix}{key}", None, "seen", ttl=ttl)
        with self._lock:
            if stored:
                self._metrics["misses"] += 1
                self._metrics["fetches"] += 1
                self._metrics["last_fetch_at"] = time.time()
            else:
                self._metrics["hits"] += 1
        return bool(stored)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "backend": "state_store",
                "entries": None,
                "entries_unknown": True,
                "totals": _cache_metrics_snapshot(self._metrics),
            }


class AuthRuntimeDecisionStats:
    """Per-process OAuth decision counters for live diagnostics."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._totals = Counter()
        self._reason_codes = Counter()
        self._scope_denials = Counter()

    def record(self, metadata: Mapping[str, Any]) -> None:
        reason_code = str(metadata.get("reason_code") or "unknown")
        allowed = metadata.get("allowed") is True
        scope_denial_key = _scope_denial_key(metadata)
        with self._lock:
            self._totals["total"] += 1
            self._totals["allowed" if allowed else "denied"] += 1
            self._reason_codes[reason_code] += 1
            if scope_denial_key:
                self._scope_denials[scope_denial_key] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                **dict(self._totals),
                "reason_codes": dict(sorted(self._reason_codes.items())),
                "scope_denials": dict(sorted(self._scope_denials.items())),
            }


class _RemoteJwksRetry(ValueError):
    pass


def _new_cache_metrics() -> dict[str, Any]:
    return {
        "hits": 0,
        "misses": 0,
        "fetches": 0,
        "refreshes": 0,
        "failures": 0,
        "last_fetch_at": None,
        "last_refresh_at": None,
        "last_failure_at": None,
        "last_error": None,
    }


def _record_cache_fetch(metrics: dict[str, Any], *, force_refresh: bool) -> None:
    now = time.time()
    metrics["fetches"] = int(metrics.get("fetches") or 0) + 1
    metrics["last_fetch_at"] = now
    metrics["last_error"] = None
    if force_refresh:
        metrics["refreshes"] = int(metrics.get("refreshes") or 0) + 1
        metrics["last_refresh_at"] = now


def _record_cache_failure(metrics: dict[str, Any], exc: Exception) -> None:
    metrics["failures"] = int(metrics.get("failures") or 0) + 1
    metrics["last_failure_at"] = time.time()
    metrics["last_error"] = f"{type(exc).__name__}: {exc}"[:500]


def _cache_entry_snapshot(
    metrics: Mapping[str, Any],
    *,
    entry: Mapping[str, Any],
    now: float,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot = _cache_metrics_snapshot(metrics)
    if entry:
        snapshot["cached"] = True
        snapshot["expires_in_seconds"] = round(max(0.0, float(entry.get("expires_at", 0.0)) - now), 3)
        if entry.get("fetched_at") is not None:
            snapshot["age_seconds"] = round(max(0.0, now - float(entry.get("fetched_at", 0.0))), 3)
    else:
        snapshot["cached"] = False
    if extra:
        snapshot.update(dict(extra))
    return snapshot


def _cache_metrics_snapshot(metrics: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = {key: int(metrics.get(key) or 0) for key in ("hits", "misses", "fetches", "refreshes", "failures")}
    for key in ("last_fetch_at", "last_refresh_at", "last_failure_at", "last_error"):
        value = metrics.get(key)
        if value not in (None, ""):
            snapshot[key] = value
    return snapshot


def _cache_totals(metrics_values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    totals = {key: 0 for key in ("hits", "misses", "fetches", "refreshes", "failures")}
    latest: dict[str, Any] = {}
    for metrics in metrics_values:
        for key in totals:
            totals[key] += int(metrics.get(key) or 0)
        for key in ("last_fetch_at", "last_refresh_at", "last_failure_at"):
            value = metrics.get(key)
            if isinstance(value, int | float) and value > float(latest.get(key, 0.0) or 0.0):
                latest[key] = value
                if key == "last_failure_at" and metrics.get("last_error"):
                    latest["last_error"] = metrics["last_error"]
    return {**totals, **latest}


def _scope_denial_key(metadata: Mapping[str, Any]) -> str | None:
    scope_map = metadata.get("scope_map")
    if not isinstance(scope_map, Mapping) or scope_map.get("allowed") is not False:
        return None
    target = scope_map.get("target")
    if isinstance(target, Mapping):
        if target.get("tool"):
            return f"tools/call:{target['tool']}"
        selectors = target.get("selectors")
        if isinstance(selectors, Sequence) and not isinstance(selectors, str | bytes | bytearray) and selectors:
            return str(selectors[0])
        if target.get("method"):
            return str(target["method"])
        if target.get("reason"):
            return str(target["reason"])
    return str(scope_map.get("reason_code") or metadata.get("reason_code") or "unknown")


_GLOBAL_REMOTE_JWKS_CACHE = RemoteJwksCache()
_GLOBAL_ISSUER_METADATA_CACHE = RemoteIssuerMetadataCache()
_GLOBAL_TOKEN_INTROSPECTION_CACHE = TokenIntrospectionCache()
_GLOBAL_DPOP_REPLAY_CACHE = DpopReplayCache()
_GLOBAL_AUTH_DECISION_STATS = AuthRuntimeDecisionStats()


def auth_runtime_snapshot(config: OAuthResourceConfig | None = None) -> dict[str, Any]:
    """Return detailed per-process OAuth cache and decision counters."""

    return {
        "caches": {
            "jwks": _auth_jwks_cache(config).snapshot(),
            "issuer_metadata": _auth_issuer_metadata_cache(config).snapshot(),
            "introspection": _auth_introspection_cache(config).snapshot(),
            "dpop_replay": _auth_dpop_replay_cache(config).snapshot(),
        },
        "decisions": _GLOBAL_AUTH_DECISION_STATS.snapshot(),
    }


def auth_runtime_summary(config: OAuthResourceConfig | None = None) -> dict[str, Any]:
    """Return a compact OAuth runtime summary safe to attach to audit metadata."""

    snapshot = auth_runtime_snapshot(config)
    caches = snapshot["caches"]
    return {
        "caches": {
            name: _drop_empty(
                {
                    "backend": cache.get("backend"),
                    "entries_unknown": cache.get("entries_unknown"),
                    "min_expires_in_seconds": cache.get("min_expires_in_seconds"),
                    "max_expires_in_seconds": cache.get("max_expires_in_seconds"),
                    "entries": cache.get("entries", 0),
                    **dict(cache.get("totals") if isinstance(cache.get("totals"), Mapping) else {}),
                }
            )
            for name, cache in caches.items()
            if isinstance(cache, Mapping)
        },
        "decisions": snapshot["decisions"],
    }


def _recorded_auth_decision(decision: OAuthDecision) -> OAuthDecision:
    _GLOBAL_AUTH_DECISION_STATS.record(decision.metadata)
    return decision


def _auth_jwks_cache(config: OAuthResourceConfig | None) -> RemoteJwksCache:
    if config is not None and isinstance(config.jwks_cache, RemoteJwksCache):
        return config.jwks_cache
    return _GLOBAL_REMOTE_JWKS_CACHE


def _auth_issuer_metadata_cache(config: OAuthResourceConfig | None) -> RemoteIssuerMetadataCache:
    if config is not None and isinstance(config.issuer_metadata_cache, RemoteIssuerMetadataCache):
        return config.issuer_metadata_cache
    return _GLOBAL_ISSUER_METADATA_CACHE


def _auth_introspection_cache(config: OAuthResourceConfig | None) -> TokenIntrospectionCache:
    if config is not None and isinstance(config.introspection_cache, TokenIntrospectionCache):
        return config.introspection_cache
    return _GLOBAL_TOKEN_INTROSPECTION_CACHE


def _auth_dpop_replay_cache(config: OAuthResourceConfig | None) -> DpopReplayCache:
    if config is not None and isinstance(config.dpop_replay_cache, DpopReplayCache):
        return config.dpop_replay_cache
    return _GLOBAL_DPOP_REPLAY_CACHE


def protected_resource_metadata(config: OAuthResourceConfig) -> dict[str, Any]:
    if not config.enabled:
        raise ValueError("OAuth protected resource metadata requires protected-resource auth mode")
    if not config.resource:
        raise ValueError("OAuth resource metadata requires resource")
    authorization_servers = list(config.authorization_servers)
    if not authorization_servers and config.issuer:
        authorization_servers = [config.issuer]
    for profile in config.profiles:
        profile_servers = list(profile.authorization_servers)
        if not profile_servers and profile.issuer:
            profile_servers = [profile.issuer]
        authorization_servers.extend(profile_servers)
    metadata: dict[str, Any] = {
        "resource": config.resource,
        "authorization_servers": _ordered_unique(authorization_servers),
    }
    scopes = {*config.scopes_supported, *config.required_scopes, *config.mapped_scopes}
    for profile in config.profiles:
        scopes.update(profile.scopes_supported)
        scopes.update(profile.required_scopes)
        scopes.update(profile.mapped_scopes)
    scopes_supported = sorted(scopes)
    if scopes_supported:
        metadata["scopes_supported"] = scopes_supported
    if config.dpop_mode != "off":
        metadata["dpop_signing_alg_values_supported"] = list(config.dpop_signing_alg_values_supported)
    if config.mode == "enterprise-managed":
        metadata["extensions"] = {ENTERPRISE_MANAGED_AUTH_EXTENSION: {}}
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


def oauth_dpop_challenge(config: OAuthResourceConfig, *, error: str | None = None) -> str:
    parts = [
        f'DPoP realm="{_quote_header(config.realm)}"',
        f'algs="{_quote_header(" ".join(config.dpop_signing_alg_values_supported))}"',
    ]
    if error:
        parts.append(f'error="{_quote_header(error)}"')
    return ", ".join(parts)


def evaluate_oauth_request(
    scope: Mapping[str, Any],
    *,
    config: OAuthResourceConfig,
    body: bytes | None = None,
) -> OAuthDecision:
    if not config.enabled:
        return OAuthDecision(
            allowed=True,
            status=200,
            body=b"",
            headers=[],
            metadata={"enabled": False},
            context={},
        )
    try:
        presentation = _authorization_presentation(scope.get("headers", []))
    except ValueError as exc:
        return _recorded_auth_decision(
            _reject(
                config,
                status=400,
                reason_code="oauth.invalid_authorization",
                error="invalid_request",
                details={"error": str(exc)},
            )
        )
    if presentation is None:
        return _recorded_auth_decision(
            _reject(
                config,
                reason_code="oauth.missing_token",
                error="invalid_token",
                challenge_scheme="dpop" if config.dpop_mode == "required" else "bearer",
            )
        )
    if config.profiles:
        return _recorded_auth_decision(
            _evaluate_oauth_profiles(presentation, parent_config=config, scope=scope, body=body)
        )
    return _recorded_auth_decision(
        _evaluate_oauth_token(presentation, config=config, challenge_config=config, scope=scope, body=body)
    )


def _evaluate_oauth_profiles(
    presentation: _TokenPresentation,
    *,
    parent_config: OAuthResourceConfig,
    scope: Mapping[str, Any],
    body: bytes | None,
) -> OAuthDecision:
    decisions = [
        _evaluate_oauth_token(presentation, config=profile, challenge_config=parent_config, scope=scope, body=body)
        for profile in parent_config.profiles
    ]
    for decision in decisions:
        if decision.allowed:
            return decision

    profile_errors = [_profile_error_metadata(decision) for decision in decisions]
    non_invalid = [
        decision
        for decision in decisions
        if decision.metadata.get("reason_code") not in {"oauth.invalid_token", "oauth.no_matching_profile"}
    ]
    if not decisions or not non_invalid:
        return _reject(
            parent_config,
            status=401,
            reason_code="oauth.no_matching_profile",
            error="invalid_token",
            details={"profile_errors": profile_errors},
        )

    selected = sorted(non_invalid, key=_profile_failure_rank)[0]
    reason_code = str(selected.metadata.get("reason_code") or "oauth.rejected")
    status = int(selected.status or 403)
    error = "invalid_token" if status == 401 else "insufficient_scope"
    return _reject(
        parent_config,
        status=status,
        reason_code=reason_code,
        error=error,
        details={**dict(selected.metadata), "profile_errors": profile_errors},
    )


def _evaluate_oauth_token(
    presentation: _TokenPresentation,
    *,
    config: OAuthResourceConfig,
    challenge_config: OAuthResourceConfig,
    scope: Mapping[str, Any],
    body: bytes | None,
) -> OAuthDecision:
    try:
        claims, validation_method = _verify_token_with_method(presentation.token, config=config)
    except Exception as exc:
        return _reject(
            challenge_config,
            reason_code="oauth.invalid_token",
            error="invalid_token",
            details={**_auth_profile_metadata(config), "error_kind": type(exc).__name__},
        )
    dpop_decision = evaluate_dpop_proof(
        scope,
        token=presentation.token,
        token_scheme=presentation.scheme,
        claims=claims,
        config=config,
    )
    if not dpop_decision.allowed:
        return _reject(
            challenge_config,
            status=dpop_decision.status,
            reason_code=dpop_decision.reason_code,
            error=dpop_decision.error,
            challenge_scheme="dpop",
            details={**_auth_profile_metadata(config), "proof_of_possession": dpop_decision.metadata or {}},
        )
    scopes = _claim_scopes(claims)
    missing = [scope_name for scope_name in config.required_scopes if scope_name not in scopes]
    if missing:
        return _reject(
            challenge_config,
            reason_code="oauth.insufficient_scope",
            error="insufficient_scope",
            details={**_auth_profile_metadata(config), "missing_scopes": missing},
        )
    required_claims_decision = evaluate_required_claims(claims=claims, config=config)
    if not required_claims_decision["allowed"]:
        return _reject(
            challenge_config,
            status=403,
            reason_code=str(required_claims_decision["reason_code"]),
            error="insufficient_scope",
            details={**_auth_profile_metadata(config), "required_claims": required_claims_decision},
        )
    context = oauth_context(claims, scopes=scopes, config=config)
    if dpop_decision.enabled:
        context["proof_of_possession"] = dpop_decision.context or {}
    if required_claims_decision["enabled"]:
        context["required_claims"] = required_claims_decision
    scope_map_decision = evaluate_scope_map(body=body, scopes=scopes, config=config)
    scope_match = scope_match_metadata(scope_map_decision)
    if not scope_map_decision["allowed"]:
        return _reject(
            challenge_config,
            status=403,
            reason_code=str(scope_map_decision["reason_code"]),
            error="insufficient_scope",
            details={**_auth_profile_metadata(config), "scope_map": scope_map_decision, "scope_match": scope_match},
        )
    if scope_map_decision["enabled"]:
        context["scope_decision"] = scope_map_decision
    claim_policy_decision = evaluate_claim_policy(body=body, claims=claims, config=config)
    if not claim_policy_decision["allowed"]:
        return _reject(
            challenge_config,
            status=403,
            reason_code=str(claim_policy_decision["reason_code"]),
            error="insufficient_scope",
            details={**_auth_profile_metadata(config), "claim_policy": claim_policy_decision},
        )
    if claim_policy_decision["enabled"]:
        context["claim_policy"] = claim_policy_decision
    context["validation_method"] = validation_method
    return OAuthDecision(
        allowed=True,
        status=200,
        body=b"",
        headers=[],
        metadata=_drop_empty(
            {
                **context,
                "allowed": True,
                "reason_code": "oauth.allowed",
                "validation_method": validation_method,
                "token_scheme": presentation.scheme,
                "proof_of_possession": dpop_decision.metadata if dpop_decision.enabled else None,
                "required_claims": required_claims_decision if required_claims_decision["enabled"] else None,
                "scope_map": scope_map_decision if scope_map_decision["enabled"] else None,
                "scope_match": scope_match,
                "claim_policy": claim_policy_decision if claim_policy_decision["enabled"] else None,
            }
        ),
        context=context,
    )


def verify_token(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    claims, _validation_method = _verify_token_with_method(token, config=config)
    return claims


def evaluate_dpop_proof(
    scope: Mapping[str, Any],
    *,
    token: str,
    token_scheme: str,
    claims: Mapping[str, Any],
    config: OAuthResourceConfig,
) -> _DpopDecision:
    try:
        header_value = _single_header_value(scope.get("headers", []), "dpop")
    except ValueError as exc:
        return _dpop_reject(
            "oauth.dpop_invalid_header",
            "DPoP proof header is invalid",
            metadata={"error": str(exc)},
        )
    cnf_jkt = _token_confirmation_jkt(claims)
    supports_dpop = config.dpop_mode != "off"
    attempted_dpop = token_scheme == "dpop" or bool(header_value)
    token_bound = bool(cnf_jkt)

    if not supports_dpop:
        if attempted_dpop:
            return _dpop_reject("oauth.dpop_not_enabled", "DPoP proof was presented but DPoP is disabled")
        return _DpopDecision(allowed=True, enabled=False)
    if token_bound and token_scheme == "bearer":
        return _dpop_reject(
            "oauth.dpop_bearer_downgrade",
            "DPoP-bound access token was presented with the Bearer scheme",
            metadata={"token_bound": True, "token_scheme": token_scheme},
            error="invalid_token",
        )
    required = config.dpop_mode == "required" or attempted_dpop or token_bound
    if not required:
        return _DpopDecision(allowed=True, enabled=False)
    if not header_value:
        return _dpop_reject(
            "oauth.dpop_missing_proof",
            "DPoP proof header is required",
            metadata={"token_bound": token_bound, "token_scheme": token_scheme},
        )
    if not token_bound:
        return _dpop_reject(
            "oauth.dpop_unbound_token",
            "DPoP access token is missing cnf.jkt confirmation",
            metadata={"token_scheme": token_scheme},
            error="invalid_token",
        )
    try:
        proof = _decode_dpop_proof(header_value, config=config)
    except Exception as exc:
        return _dpop_reject(
            "oauth.dpop_invalid_proof",
            "DPoP proof is invalid",
            metadata={"error_kind": type(exc).__name__},
        )

    metadata = _dpop_proof_metadata(proof, token_scheme=token_scheme, token_bound=True)
    if proof.thumbprint != cnf_jkt:
        return _dpop_reject(
            "oauth.dpop_key_mismatch",
            "DPoP proof key does not match access-token cnf.jkt",
            metadata={**metadata, "token_jkt": cnf_jkt},
            error="invalid_token",
        )
    expected_method = str(scope.get("method", "GET")).upper()
    if str(proof.claims.get("htm") or "").upper() != expected_method:
        return _dpop_reject(
            "oauth.dpop_method_mismatch",
            "DPoP proof htm does not match request method",
            metadata={**metadata, "expected_method": expected_method},
        )
    try:
        expected_htu = _dpop_accepted_htu(scope, config=config)
    except ValueError as exc:
        return _dpop_reject(
            "oauth.dpop_invalid_request_uri",
            "request URI could not be normalized for DPoP validation",
            metadata={**metadata, "error": str(exc)},
        )
    proof_htu = proof.claims.get("htu")
    normalized_proof_htu = _normalize_dpop_htu(proof_htu) if isinstance(proof_htu, str) else None
    if normalized_proof_htu not in expected_htu:
        return _dpop_reject(
            "oauth.dpop_uri_mismatch",
            "DPoP proof htu does not match the protected resource URI",
            metadata={
                **metadata,
                "expected_htu": sorted(expected_htu),
                "proof_htu": normalized_proof_htu or proof_htu,
            },
        )
    expected_ath = _dpop_access_token_hash(token)
    if proof.claims.get("ath") != expected_ath:
        return _dpop_reject(
            "oauth.dpop_ath_mismatch",
            "DPoP proof ath does not match the access token",
            metadata=metadata,
        )
    iat = _numeric_claim(proof.claims.get("iat"))
    now = time.time()
    if iat is None:
        return _dpop_reject("oauth.dpop_missing_iat", "DPoP proof iat is required", metadata=metadata)
    if iat < now - config.dpop_proof_max_age_seconds - config.leeway_seconds:
        return _dpop_reject("oauth.dpop_expired_proof", "DPoP proof iat is too old", metadata=metadata)
    if iat > now + config.leeway_seconds:
        return _dpop_reject("oauth.dpop_future_proof", "DPoP proof iat is in the future", metadata=metadata)
    jti = proof.claims.get("jti")
    if not isinstance(jti, str) or not jti:
        return _dpop_reject("oauth.dpop_missing_jti", "DPoP proof jti is required", metadata=metadata)
    if len(jti) > 512:
        return _dpop_reject("oauth.dpop_invalid_jti", "DPoP proof jti is too large", metadata=metadata)
    replay_key = _dpop_replay_key(proof.thumbprint, jti=jti, htm=expected_method, htu=str(normalized_proof_htu))
    cache = _auth_dpop_replay_cache(config)
    if not cache.add_once(
        replay_key,
        ttl_seconds=config.dpop_proof_max_age_seconds + config.leeway_seconds,
        max_entries=config.dpop_replay_cache_max_entries,
    ):
        return _dpop_reject("oauth.dpop_replayed_proof", "DPoP proof jti has already been used", metadata=metadata)

    allowed_metadata = {
        **metadata,
        "allowed": True,
        "reason_code": "oauth.dpop_allowed",
        "proof_age_seconds": round(max(0.0, now - iat), 3),
    }
    context = {
        "enabled": True,
        "bound": True,
        "jkt": proof.thumbprint,
        "jti": jti,
        "htu": normalized_proof_htu,
        "htm": expected_method,
        "alg": proof.header.get("alg"),
    }
    return _DpopDecision(
        allowed=True,
        enabled=True,
        reason_code="oauth.dpop_allowed",
        metadata=allowed_metadata,
        context=context,
    )


def verify_jwt(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm == "none":
        raise ValueError("JWT alg is missing or unsupported")
    try:
        return _decode_jwt(token, header=header, algorithm=algorithm, config=config, force_refresh=False)
    except _RemoteJwksRetry:
        return _decode_jwt(token, header=header, algorithm=algorithm, config=config, force_refresh=True)


def _verify_token_with_method(token: str, *, config: OAuthResourceConfig) -> tuple[dict[str, Any], str]:
    mode = config.token_validation or "jwt"
    if mode == "jwt":
        return verify_jwt(token, config=config), "jwt"
    if mode == "introspection":
        return verify_introspection(token, config=config), "introspection"
    if mode == "jwt_or_introspection":
        try:
            return verify_jwt(token, config=config), "jwt"
        except Exception:
            return verify_introspection(token, config=config), "introspection"
    if mode == "jwt_and_introspection":
        jwt_claims = verify_jwt(token, config=config)
        introspection_claims = verify_introspection(token, config=config)
        return _merge_token_claims(jwt_claims, introspection_claims), "jwt_and_introspection"
    raise ValueError(f"unsupported token validation mode: {mode}")


def verify_introspection(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    cache = (
        config.introspection_cache
        if isinstance(config.introspection_cache, TokenIntrospectionCache)
        else _GLOBAL_TOKEN_INTROSPECTION_CACHE
    )
    response = cache.get(token, config=config)
    return _validate_introspection_response(response, config=config)


def _decode_jwt(
    token: str,
    *,
    header: Mapping[str, Any],
    algorithm: str,
    config: OAuthResourceConfig,
    force_refresh: bool,
) -> dict[str, Any]:
    jwks = _load_jwks(config, force_refresh=force_refresh)
    accepted_audiences = _accepted_audiences(config)
    key = _select_jwks_key(
        jwks,
        kid=header.get("kid"),
        algorithm=algorithm,
        retryable=_uses_remote_jwks(config) and not force_refresh,
    )
    try:
        decoded = jwt.decode(
            token,
            key=key,
            algorithms=[algorithm],
            audience=accepted_audiences or None,
            issuer=config.issuer,
            leeway=config.leeway_seconds,
            options={
                "verify_aud": bool(accepted_audiences),
                "verify_iss": bool(config.issuer),
            },
        )
    except jwt.InvalidSignatureError as exc:
        if _uses_remote_jwks(config) and not force_refresh:
            raise _RemoteJwksRetry(str(exc)) from exc
        raise ValueError(str(exc)) from exc
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
            "profile_id": config.profile_id,
            "scopes": sorted(set(scopes)),
            "email": claims.get("email"),
            "tenant": claims.get("tid") or claims.get("tenant"),
            "groups": group_values,
            "provider": auth_provider_claim_context(claims),
            "scope_map": {scope: list(selectors) for scope, selectors in sorted(config.mapped_scopes.items())},
        }
    )


def evaluate_required_claims(
    *,
    claims: Mapping[str, Any],
    config: OAuthResourceConfig,
) -> dict[str, Any]:
    required_claims = {str(claim): tuple(values) for claim, values in (config.required_claims or {}).items() if values}
    if not required_claims:
        return {"enabled": False, "allowed": True}

    matched: dict[str, list[str]] = {}
    missing: dict[str, list[str]] = {}
    for claim, expected in required_claims.items():
        actual = _claim_values(claims, claim)
        matched_values = _matching_claim_values(actual, expected)
        if matched_values:
            matched[claim] = matched_values
        else:
            missing[claim] = sorted(set(str(value) for value in expected))

    return {
        "enabled": True,
        "allowed": not missing,
        "reason_code": "oauth.required_claims_allowed" if not missing else "oauth.required_claims_denied",
        "matched": matched,
        "missing": missing,
    }


def evaluate_scope_map(
    *,
    body: bytes | None,
    scopes: Sequence[str],
    config: OAuthResourceConfig,
) -> dict[str, Any]:
    scope_map = config.mapped_scopes
    if not scope_map:
        return {"enabled": False, "allowed": True}

    target = mcp_scope_target(body)
    if target.get("allow_without_scope_map"):
        return {
            "enabled": True,
            "allowed": True,
            "reason_code": "oauth.scope_map_protocol_allowed",
            "target": target,
            "candidate_selectors": target.get("selectors", []),
        }
    selectors = target.get("selectors")
    selectors = selectors if isinstance(selectors, Sequence) and not isinstance(selectors, str | bytes) else []
    if not selectors:
        return {
            "enabled": True,
            "allowed": False,
            "reason_code": "oauth.scope_map_unmapped_request",
            "target": target,
            "candidate_selectors": [],
            "accepted_scopes": [],
        }

    matched = _scope_map_match(scopes=scopes, selectors=[str(selector) for selector in selectors], scope_map=scope_map)
    return {
        "enabled": True,
        "allowed": bool(matched),
        "reason_code": "oauth.scope_map_allowed" if matched else "oauth.scope_map_denied",
        "target": target,
        "candidate_selectors": [str(selector) for selector in selectors],
        "accepted_scopes": _accepted_scopes_for_selectors(
            selectors=[str(selector) for selector in selectors],
            scope_map=scope_map,
        ),
        **(matched or {}),
    }


def scope_match_metadata(scope_map_decision: Mapping[str, Any]) -> dict[str, Any]:
    if not scope_map_decision.get("enabled"):
        return {}
    return _drop_empty(
        {
            "allowed": scope_map_decision.get("allowed"),
            "reason_code": scope_map_decision.get("reason_code"),
            "matched_scope": scope_map_decision.get("matched_scope"),
            "matched_selector": scope_map_decision.get("matched_selector"),
            "matched_request_selector": scope_map_decision.get("matched_request_selector"),
            "accepted_scopes": scope_map_decision.get("accepted_scopes"),
            "candidate_selectors": scope_map_decision.get("candidate_selectors"),
            "target": scope_map_decision.get("target"),
        }
    )


def evaluate_claim_policy(
    *,
    body: bytes | None,
    claims: Mapping[str, Any],
    config: OAuthResourceConfig,
) -> dict[str, Any]:
    policy = config.claim_policy if isinstance(config.claim_policy, Mapping) else {}
    if policy.get("enabled") is not True:
        return {"enabled": False, "allowed": True}
    target = mcp_scope_target(body)
    if target.get("allow_without_scope_map"):
        return {
            "enabled": True,
            "allowed": True,
            "reason_code": "oauth.claim_policy_protocol_allowed",
            "target": target,
        }
    if target.get("method") != "tools/call":
        return {
            "enabled": True,
            "allowed": True,
            "reason_code": "oauth.claim_policy_non_tool_allowed",
            "target": target,
        }
    tool_name = target.get("tool")
    if not isinstance(tool_name, str) or not tool_name:
        return {
            "enabled": True,
            "allowed": False,
            "reason_code": "oauth.claim_policy_missing_tool",
            "target": target,
        }

    matching_claim_rules = []
    for rule in _claim_policy_rules(policy):
        claim_values = _claim_values(claims, str(rule.get("claim")))
        matched_values = _matching_claim_values(claim_values, _sequence_strings(rule.get("values")))
        if not matched_values:
            continue
        matching_claim_rules.append(_claim_rule_metadata(rule, matched_values=matched_values))
        tool_match = _claim_rule_tool_match(
            rule, tool_name=tool_name, selectors=_sequence_strings(target.get("selectors"))
        )
        if tool_match:
            return {
                "enabled": True,
                "allowed": True,
                "reason_code": "oauth.claim_policy_allowed",
                "target": target,
                "matched_rule": _claim_rule_metadata(rule, matched_values=matched_values),
                "matched_tool": tool_match,
            }

    default_action = str(policy.get("default_action") or "deny")
    if default_action == "allow":
        return {
            "enabled": True,
            "allowed": True,
            "reason_code": "oauth.claim_policy_default_allowed",
            "target": target,
            "matching_claim_rules": matching_claim_rules,
        }
    return {
        "enabled": True,
        "allowed": False,
        "reason_code": "oauth.claim_policy_denied",
        "target": target,
        "matching_claim_rules": matching_claim_rules,
        "accepted": _claim_policy_accepted_tools(policy),
    }


def mcp_scope_target(body: bytes | None) -> dict[str, Any]:
    if body is None:
        return {"kind": "unknown", "reason": "body_not_available", "selectors": []}
    if not body:
        return {"kind": "unknown", "reason": "empty_body", "selectors": []}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"kind": "unknown", "reason": "invalid_json", "selectors": []}
    if isinstance(payload, Sequence) and not isinstance(payload, str | bytes | bytearray):
        return {"kind": "batch", "reason": "batch_not_supported", "selectors": []}
    if not isinstance(payload, Mapping):
        return {"kind": "unknown", "reason": "non_object_body", "selectors": []}
    method = payload.get("method")
    if not isinstance(method, str) or not method:
        return {"kind": "unknown", "reason": "missing_method", "selectors": []}

    params = payload.get("params")
    params = params if isinstance(params, Mapping) else {}
    selectors = [method]
    target: dict[str, Any] = {
        "kind": "mcp",
        "method": method,
        "selectors": selectors,
    }
    if method in {"initialize", "initialized", "notifications/initialized", "ping"}:
        target["allow_without_scope_map"] = True
        return target
    if method.startswith("notifications/"):
        target["allow_without_scope_map"] = True
        return target
    if method == "tools/call" and isinstance(params.get("name"), str):
        tool_name = params["name"]
        target["tool"] = tool_name
        selectors.insert(0, f"tools/call:{tool_name}")
    elif method == "prompts/get" and isinstance(params.get("name"), str):
        prompt_name = params["name"]
        target["prompt"] = prompt_name
        selectors.insert(0, f"prompts/get:{prompt_name}")
    elif method == "resources/read" and isinstance(params.get("uri"), str):
        uri = params["uri"]
        target["uri"] = uri
        selectors.insert(0, f"resources/read:{uri}")
    return target


def _reject(
    config: OAuthResourceConfig,
    *,
    status: int = 401,
    reason_code: str,
    error: str,
    challenge_scheme: str = "bearer",
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
        status=status,
        body=body,
        headers=[
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (
                b"www-authenticate",
                (
                    oauth_dpop_challenge(config, error=error)
                    if challenge_scheme == "dpop"
                    else oauth_bearer_challenge(config, error=error)
                ).encode("latin-1"),
            ),
        ],
        metadata=metadata,
        context={"auth": metadata},
    )


def _dpop_reject(
    reason_code: str,
    reason: str,
    *,
    metadata: Mapping[str, Any] | None = None,
    status: int = 401,
    error: str = "invalid_dpop_proof",
) -> _DpopDecision:
    return _DpopDecision(
        allowed=False,
        enabled=True,
        status=status,
        reason_code=reason_code,
        error=error,
        metadata=_drop_empty(
            {
                "enabled": True,
                "allowed": False,
                "reason_code": reason_code,
                "reason": reason,
                **dict(metadata or {}),
            }
        ),
    )


def _load_jwks(config: OAuthResourceConfig, *, force_refresh: bool = False) -> dict[str, Any]:
    if config.jwks_path is not None:
        return _load_local_jwks(config.jwks_path)
    jwks_url = config.jwks_url or _discover_jwks_url(config, force_refresh=force_refresh)
    if jwks_url:
        cache = config.jwks_cache if isinstance(config.jwks_cache, RemoteJwksCache) else _GLOBAL_REMOTE_JWKS_CACHE
        return cache.get(
            jwks_url,
            ttl_seconds=config.jwks_cache_seconds,
            timeout=config.jwks_fetch_timeout,
            force_refresh=force_refresh,
        )
    raise ValueError("JWT verification requires auth.jwks_path, auth.jwks_url, or issuer discovery")


def _load_local_jwks(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    return _normalize_jwks(loaded)


def _fetch_remote_jwks(url: str, *, timeout: float) -> dict[str, Any]:
    loaded = _fetch_remote_json(url, timeout=timeout, user_agent="snulbug-jwks-cache/0.1")
    return _normalize_jwks(loaded)


def _fetch_remote_issuer_metadata(url: str, *, timeout: float) -> dict[str, Any]:
    loaded = _fetch_remote_json(url, timeout=timeout, user_agent="snulbug-issuer-cache/0.1")
    if not isinstance(loaded, Mapping):
        raise ValueError("issuer metadata must be a JSON object")
    return dict(loaded)


def _fetch_remote_json(url: str, *, timeout: float, user_agent: str) -> Any:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"unsupported remote auth URL: {url}")
    if parsed.scheme == "http" and not _is_localhost(parsed.hostname):
        raise ValueError("remote auth URL must use HTTPS except for localhost")
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request(
            "GET",
            _request_target(parsed),
            headers={
                "accept": "application/json",
                "user-agent": user_agent,
            },
        )
        response = connection.getresponse()
        body = response.read(1_048_577)
        if len(body) > 1_048_576:
            raise ValueError("remote auth response exceeds 1 MiB")
        if response.status < 200 or response.status >= 300:
            raise ValueError(f"remote auth fetch failed with HTTP {response.status}")
        try:
            loaded = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"remote auth response is not JSON: {exc}") from exc
    finally:
        connection.close()
    return loaded


def _discover_jwks_url(config: OAuthResourceConfig, *, force_refresh: bool = False) -> str | None:
    metadata = _discover_issuer_metadata(config, force_refresh=force_refresh)
    jwks_uri = metadata.get("jwks_uri")
    if isinstance(jwks_uri, str) and jwks_uri:
        return jwks_uri
    return None


def _discover_introspection_endpoint(config: OAuthResourceConfig) -> str | None:
    metadata = _discover_issuer_metadata(config, force_refresh=False)
    endpoint = metadata.get("introspection_endpoint")
    if isinstance(endpoint, str) and endpoint:
        return endpoint
    return None


def _discover_issuer_metadata(config: OAuthResourceConfig, *, force_refresh: bool = False) -> dict[str, Any]:
    if not config.issuer_discovery:
        return {}
    urls = _issuer_metadata_urls(config)
    cache = (
        config.issuer_metadata_cache
        if isinstance(config.issuer_metadata_cache, RemoteIssuerMetadataCache)
        else _GLOBAL_ISSUER_METADATA_CACHE
    )
    errors: list[str] = []
    for url in urls:
        try:
            metadata = cache.get(
                url,
                ttl_seconds=config.jwks_cache_seconds,
                timeout=config.jwks_fetch_timeout,
                force_refresh=force_refresh,
            )
        except Exception as exc:
            errors.append(str(exc))
            continue
        metadata_issuer = metadata.get("issuer")
        if (
            config.issuer
            and isinstance(metadata_issuer, str)
            and metadata_issuer.rstrip("/") != config.issuer.rstrip("/")
        ):
            errors.append("issuer metadata issuer does not match configured issuer")
            continue
        return metadata
    if errors:
        raise ValueError(f"issuer metadata discovery failed: {'; '.join(errors)}")
    return {}


def _issuer_metadata_urls(config: OAuthResourceConfig) -> list[str]:
    if config.issuer_metadata_url:
        return [config.issuer_metadata_url]
    if not config.issuer:
        return []
    base = config.issuer.rstrip("/")
    if not base.startswith(("http://", "https://")):
        return []
    return [
        f"{base}/.well-known/oauth-authorization-server",
        f"{base}/.well-known/openid-configuration",
    ]


def _uses_remote_jwks(config: OAuthResourceConfig) -> bool:
    return config.jwks_path is None and (bool(config.jwks_url) or bool(config.issuer_discovery and config.issuer))


def _fetch_token_introspection(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    endpoint = config.introspection_endpoint or _discover_introspection_endpoint(config)
    if not endpoint:
        raise ValueError("token introspection requires auth.introspection_endpoint or issuer metadata discovery")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"unsupported token introspection URL: {endpoint}")
    if parsed.scheme == "http" and not _is_localhost(parsed.hostname):
        raise ValueError("token introspection URL must use HTTPS except for localhost")

    fields = {"token": token}
    client_id = config.introspection_client_id
    client_secret = _introspection_client_secret(config)
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "snulbug-token-introspection/0.1",
    }
    if client_id and client_secret:
        import base64

        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        headers["authorization"] = f"Basic {credentials}"
    elif client_id:
        fields["client_id"] = client_id

    body = urlencode(fields).encode("utf-8")
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=config.introspection_fetch_timeout)
    try:
        connection.request("POST", _request_target(parsed), body=body, headers=headers)
        response = connection.getresponse()
        raw_body = response.read(1_048_577)
        if len(raw_body) > 1_048_576:
            raise ValueError("token introspection response exceeds 1 MiB")
        if response.status < 200 or response.status >= 300:
            raise ValueError(f"token introspection failed with HTTP {response.status}")
        try:
            loaded = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"token introspection response is not JSON: {exc}") from exc
    finally:
        connection.close()
    if not isinstance(loaded, Mapping):
        raise ValueError("token introspection response must be a JSON object")
    return dict(loaded)


def _introspection_client_secret(config: OAuthResourceConfig) -> str | None:
    if not config.introspection_client_secret_env:
        return None
    secret = os.environ.get(config.introspection_client_secret_env)
    return secret if secret else None


def _validate_introspection_response(response: Mapping[str, Any], *, config: OAuthResourceConfig) -> dict[str, Any]:
    if response.get("active") is not True:
        raise ValueError("token introspection response is inactive")
    claims = dict(response)
    if config.issuer:
        issuer = claims.get("iss")
        if isinstance(issuer, str) and issuer.rstrip("/") != config.issuer.rstrip("/"):
            raise ValueError("token introspection issuer mismatch")
    accepted_audiences = _accepted_audiences(config)
    if accepted_audiences:
        audiences = _audiences(claims.get("aud"))
        if not any(accepted in audiences for accepted in accepted_audiences):
            raise ValueError("token introspection audience mismatch")
    now = time.time()
    exp = _numeric_claim(claims.get("exp"))
    if exp is not None and exp < now - config.leeway_seconds:
        raise ValueError("token introspection response is expired")
    nbf = _numeric_claim(claims.get("nbf"))
    if nbf is not None and nbf > now + config.leeway_seconds:
        raise ValueError("token introspection response is not yet valid")
    return claims


def _merge_token_claims(jwt_claims: Mapping[str, Any], introspection_claims: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(introspection_claims)
    merged.update(jwt_claims)
    for field in ("scope", "scp", "scopes", "groups"):
        if field not in merged and field in introspection_claims:
            merged[field] = introspection_claims[field]
    return merged


def _token_cache_key(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _introspection_cache_expiry(response: Mapping[str, Any], *, now: float, ttl_seconds: float) -> float:
    expires_at = now + max(0.0, float(ttl_seconds))
    exp = _numeric_claim(response.get("exp"))
    if exp is not None:
        exp_monotonic = now + max(0.0, exp - time.time())
        expires_at = min(expires_at, exp_monotonic)
    return expires_at


def _numeric_claim(value: Any) -> float | None:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _audiences(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [str(item) for item in value]
    return []


def _accepted_audiences(config: OAuthResourceConfig) -> list[str]:
    return _unique_strings([*([config.audience] if config.audience else []), *(config.audiences or ())])


def _unique_strings(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalize_jwks(loaded: Any) -> dict[str, Any]:
    if not isinstance(loaded, Mapping):
        raise ValueError("JWKS must be a JSON object")
    keys = loaded.get("keys")
    if not isinstance(keys, Sequence) or isinstance(keys, str | bytes | bytearray):
        raise ValueError("JWKS keys must be a list")
    return {"keys": [dict(key) for key in keys if isinstance(key, Mapping)]}


def _select_jwks_key(jwks: Mapping[str, Any], *, kid: Any, algorithm: str, retryable: bool = False) -> Any:
    keys = [key for key in jwks.get("keys", []) if isinstance(key, Mapping)]
    if kid is not None:
        keys = [key for key in keys if key.get("kid") == kid]
    if not keys:
        if retryable:
            raise _RemoteJwksRetry("JWKS does not contain a matching key")
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


def _request_target(parsed: SplitResult) -> str:
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return target


def _is_localhost(hostname: str) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost")


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


def _scope_map_match(
    *,
    scopes: Sequence[str],
    selectors: Sequence[str],
    scope_map: Mapping[str, Sequence[str]],
) -> dict[str, Any] | None:
    for scope in scopes:
        for configured in scope_map.get(scope, ()):
            for selector in selectors:
                if _selector_matches(configured, selector):
                    return {
                        "matched_scope": scope,
                        "matched_selector": configured,
                        "matched_request_selector": selector,
                    }
    return None


def _accepted_scopes_for_selectors(
    *,
    selectors: Sequence[str],
    scope_map: Mapping[str, Sequence[str]],
) -> list[str]:
    accepted = []
    for scope, configured_selectors in scope_map.items():
        if any(
            _selector_matches(configured, selector) for configured in configured_selectors for selector in selectors
        ):
            accepted.append(scope)
    return sorted(set(accepted))


def _auth_profile_metadata(config: OAuthResourceConfig) -> dict[str, Any]:
    return _drop_empty(
        {
            "profile_id": config.profile_id,
            "profile": _drop_empty(
                {
                    "id": config.profile_id,
                    "issuer": config.issuer,
                    "audience": config.audience,
                    "audiences": list(config.audiences),
                }
            ),
        }
    )


def _profile_error_metadata(decision: OAuthDecision) -> dict[str, Any]:
    metadata = decision.metadata
    return _drop_empty(
        {
            "profile_id": metadata.get("profile_id"),
            "profile": metadata.get("profile"),
            "status": decision.status,
            "reason_code": metadata.get("reason_code"),
            "missing_scopes": metadata.get("missing_scopes"),
            "required_claims": metadata.get("required_claims"),
            "scope_match": metadata.get("scope_match"),
            "claim_policy": metadata.get("claim_policy"),
            "proof_of_possession": metadata.get("proof_of_possession"),
            "error_kind": metadata.get("error_kind"),
        }
    )


def _profile_failure_rank(decision: OAuthDecision) -> int:
    reason_code = str(decision.metadata.get("reason_code") or "")
    if reason_code == "oauth.required_claims_denied":
        return 30
    if reason_code.startswith("oauth.dpop_"):
        return 35
    if reason_code == "oauth.invalid_token":
        return 40
    return 10


def _claim_policy_rules(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rules = policy.get("rules")
    if isinstance(rules, Sequence) and not isinstance(rules, str | bytes | bytearray):
        return [rule for rule in rules if isinstance(rule, Mapping)]
    return []


def _claim_values(claims: Mapping[str, Any], claim: str) -> list[str]:
    if claim == "tenant":
        return _claim_value_list(claims.get("tenant", claims.get("tid")))
    if claim == "subject":
        return _claim_value_list(claims.get("sub"))
    if claim == "client_id":
        return _claim_value_list(claims.get("client_id", claims.get("azp")))
    if claim == "scope":
        return _claim_scopes(claims)
    if claim in claims:
        return _claim_value_list(claims.get(claim))
    value: Any = claims
    for part in claim.split("."):
        if not isinstance(value, Mapping):
            return []
        value = value.get(part)
    return _claim_value_list(value)


def _claim_value_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _matching_claim_values(actual: Sequence[str], expected: Sequence[str]) -> list[str]:
    if "*" in expected:
        return sorted(set(actual))
    expected_set = set(expected)
    return sorted({value for value in actual if value in expected_set})


def _claim_rule_tool_match(
    rule: Mapping[str, Any],
    *,
    tool_name: str,
    selectors: Sequence[str],
) -> dict[str, Any] | None:
    for allowed_tool in _sequence_strings(rule.get("allow_tools")):
        if allowed_tool == tool_name or allowed_tool == "*":
            return {"kind": "tool", "value": allowed_tool}
    for prefix in _sequence_strings(rule.get("allow_tool_prefixes")):
        if tool_name.startswith(prefix):
            return {"kind": "tool_prefix", "value": prefix}
    for allowed_selector in _sequence_strings(rule.get("allow_selectors")):
        for selector in selectors:
            if _selector_matches(allowed_selector, selector):
                return {"kind": "selector", "value": allowed_selector, "selector": selector}
    return None


def _claim_rule_metadata(rule: Mapping[str, Any], *, matched_values: Sequence[str]) -> dict[str, Any]:
    return _drop_empty(
        {
            "id": rule.get("id"),
            "claim": rule.get("claim"),
            "matched_values": list(matched_values),
            "allow_tools": _sequence_strings(rule.get("allow_tools")),
            "allow_tool_prefixes": _sequence_strings(rule.get("allow_tool_prefixes")),
            "allow_selectors": _sequence_strings(rule.get("allow_selectors")),
        }
    )


def _claim_policy_accepted_tools(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    accepted = []
    for rule in _claim_policy_rules(policy):
        accepted.append(
            _drop_empty(
                {
                    "id": rule.get("id"),
                    "claim": rule.get("claim"),
                    "values": _sequence_strings(rule.get("values")),
                    "allow_tools": _sequence_strings(rule.get("allow_tools")),
                    "allow_tool_prefixes": _sequence_strings(rule.get("allow_tool_prefixes")),
                    "allow_selectors": _sequence_strings(rule.get("allow_selectors")),
                }
            )
        )
    return accepted


def _sequence_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)] if value != "" else []


def _first_claim_value(value: Any) -> str | None:
    values = _sequence_strings(value)
    return values[0] if values else None


def _selector_matches(configured: str, requested: str) -> bool:
    if configured == requested or configured == "*":
        return True
    if configured.endswith("*"):
        return requested.startswith(configured[:-1])
    return False


def _authorization_presentation(raw_headers: Any) -> _TokenPresentation | None:
    presentations: list[_TokenPresentation] = []
    for name, value in raw_headers or []:
        raw_name = name if isinstance(name, bytes) else str(name).encode("latin-1")
        if raw_name.lower() != b"authorization":
            continue
        raw_value = value.decode("latin-1") if isinstance(value, bytes) else str(value)
        scheme, _, token = raw_value.partition(" ")
        normalized_scheme = scheme.lower()
        if normalized_scheme not in {"bearer", "dpop"} or not token:
            continue
        presentations.append(_TokenPresentation(token=token.strip(), scheme=normalized_scheme))
    if len(presentations) > 1:
        raise ValueError("multiple Authorization headers are not supported")
    return presentations[0] if presentations else None


def _single_header_value(raw_headers: Any, header_name: str) -> str | None:
    matches: list[str] = []
    wanted = header_name.lower().encode("latin-1")
    for name, value in raw_headers or []:
        raw_name = name if isinstance(name, bytes) else str(name).encode("latin-1")
        if raw_name.lower() != wanted:
            continue
        matches.append(value.decode("latin-1") if isinstance(value, bytes) else str(value))
    if len(matches) > 1:
        raise ValueError(f"multiple {header_name} headers are not supported")
    return matches[0].strip() if matches and matches[0].strip() else None


def _decode_dpop_proof(proof_jwt: str, *, config: OAuthResourceConfig) -> _DpopProof:
    header = jwt.get_unverified_header(proof_jwt)
    if str(header.get("typ") or "").lower() != "dpop+jwt":
        raise ValueError("DPoP proof typ must be dpop+jwt")
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm == "none" or algorithm.startswith("HS"):
        raise ValueError("DPoP proof alg must be an asymmetric signing algorithm")
    if algorithm not in set(config.dpop_signing_alg_values_supported):
        raise ValueError("DPoP proof alg is not configured as supported")
    jwk = header.get("jwk")
    if not isinstance(jwk, Mapping):
        raise ValueError("DPoP proof header must include a public jwk")
    normalized_jwk = _public_dpop_jwk(jwk)
    key = jwt.PyJWK.from_dict(normalized_jwk, algorithm=algorithm).key
    try:
        decoded = jwt.decode(
            proof_jwt,
            key=key,
            algorithms=[algorithm],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_iss": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(decoded, Mapping):
        raise ValueError("DPoP proof payload must be a JSON object")
    return _DpopProof(
        claims=dict(decoded),
        header=dict(header),
        jwk=normalized_jwk,
        thumbprint=_jwk_thumbprint(normalized_jwk),
    )


def _public_dpop_jwk(jwk: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {str(key): value for key, value in jwk.items() if value not in (None, "")}
    kty = normalized.get("kty")
    if kty not in {"EC", "RSA", "OKP"}:
        raise ValueError("DPoP proof jwk must be an asymmetric public key")
    if any(field in normalized for field in _DPOP_PRIVATE_JWK_FIELDS):
        raise ValueError("DPoP proof jwk must not include private key material")
    return normalized


def _jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        required = ("crv", "kty", "x", "y")
    elif kty == "RSA":
        required = ("e", "kty", "n")
    elif kty == "OKP":
        required = ("crv", "kty", "x")
    else:
        raise ValueError("unsupported JWK kty for thumbprint")
    thumbprint_input = {key: jwk.get(key) for key in required}
    if any(not isinstance(value, str) or not value for value in thumbprint_input.values()):
        raise ValueError("JWK is missing thumbprint fields")
    raw = json.dumps(thumbprint_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _base64url(hashlib.sha256(raw).digest())


def _token_confirmation_jkt(claims: Mapping[str, Any]) -> str | None:
    cnf = claims.get("cnf")
    if not isinstance(cnf, Mapping):
        return None
    jkt = cnf.get("jkt")
    return jkt if isinstance(jkt, str) and jkt else None


def _dpop_access_token_hash(token: str) -> str:
    return _base64url(hashlib.sha256(token.encode("ascii")).digest())


def _dpop_replay_key(jkt: str, *, jti: str, htm: str, htu: str) -> str:
    return hashlib.sha256(f"{jkt}\x00{jti}\x00{htm}\x00{htu}".encode("utf-8")).hexdigest()


def _dpop_proof_metadata(proof: _DpopProof, *, token_scheme: str, token_bound: bool) -> dict[str, Any]:
    return _drop_empty(
        {
            "enabled": True,
            "token_scheme": token_scheme,
            "token_bound": token_bound,
            "jkt": proof.thumbprint,
            "jti": proof.claims.get("jti"),
            "htm": proof.claims.get("htm"),
            "htu": proof.claims.get("htu"),
            "alg": proof.header.get("alg"),
        }
    )


def _dpop_accepted_htu(scope: Mapping[str, Any], *, config: OAuthResourceConfig) -> set[str]:
    accepted = {
        normalized
        for value in (config.resource, *config.resource_aliases, _request_uri_from_scope(scope))
        if isinstance(value, str) and (normalized := _normalize_dpop_htu(value))
    }
    return accepted


def _request_uri_from_scope(scope: Mapping[str, Any]) -> str:
    scheme = str(scope.get("scheme") or "http")
    host = _single_header_value(scope.get("headers", []), "host")
    if not host:
        server = scope.get("server")
        if isinstance(server, Sequence) and not isinstance(server, str | bytes | bytearray) and len(server) >= 2:
            host = f"{server[0]}:{server[1]}"
    if not host:
        return ""
    path = str(scope.get("path") or "/")
    query = scope.get("query_string") or b""
    query_string = query.decode("ascii", errors="ignore") if isinstance(query, bytes) else str(query)
    return f"{scheme}://{host}{path}{'?' + query_string if query_string else ''}"


def _normalize_dpop_htu(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = hostname
    if port is not None and not (
        (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    ):
        netloc = f"{hostname}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _quote_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _drop_empty(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _ordered_unique(values: Sequence[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result

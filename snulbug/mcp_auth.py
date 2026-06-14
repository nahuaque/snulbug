from __future__ import annotations

import http.client
import json
import os
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlencode, urlsplit, urlunsplit

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
    scope_map: Mapping[str, tuple[str, ...]] | None = None

    @property
    def enabled(self) -> bool:
        return self.mode == "oauth-resource"

    @property
    def mapped_scopes(self) -> dict[str, tuple[str, ...]]:
        return {str(scope): tuple(selectors) for scope, selectors in (self.scope_map or {}).items()}


@dataclass(frozen=True)
class OAuthDecision:
    allowed: bool
    status: int
    body: bytes
    headers: list[tuple[bytes, bytes]]
    metadata: dict[str, Any]
    context: dict[str, Any]


class RemoteJwksCache:
    """Small in-process JWKS cache keyed by URL."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}

    def get(self, url: str, *, ttl_seconds: float, timeout: float, force_refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(url)
            if (
                not force_refresh
                and entry is not None
                and float(entry.get("expires_at", 0.0)) > now
                and isinstance(entry.get("jwks"), Mapping)
            ):
                return dict(entry["jwks"])

        jwks = _fetch_remote_jwks(url, timeout=timeout)
        expires_at = now + max(0.0, float(ttl_seconds))
        with self._lock:
            self._entries[url] = {"jwks": dict(jwks), "expires_at": expires_at, "fetched_at": now}
        return jwks


class RemoteIssuerMetadataCache:
    """Small in-process OAuth issuer metadata cache keyed by URL."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}

    def get(self, url: str, *, ttl_seconds: float, timeout: float, force_refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(url)
            if (
                not force_refresh
                and entry is not None
                and float(entry.get("expires_at", 0.0)) > now
                and isinstance(entry.get("metadata"), Mapping)
            ):
                return dict(entry["metadata"])

        metadata = _fetch_remote_issuer_metadata(url, timeout=timeout)
        expires_at = now + max(0.0, float(ttl_seconds))
        with self._lock:
            self._entries[url] = {"metadata": dict(metadata), "expires_at": expires_at, "fetched_at": now}
        return metadata


class TokenIntrospectionCache:
    """Small in-process token introspection cache keyed by a token digest."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}

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
                return dict(entry["response"])

        response = _fetch_token_introspection(token, config=config)
        expires_at = _introspection_cache_expiry(response, now=now, ttl_seconds=config.introspection_cache_seconds)
        with self._lock:
            self._entries[key] = {"response": dict(response), "expires_at": expires_at, "fetched_at": now}
        return response


class _RemoteJwksRetry(ValueError):
    pass


_GLOBAL_REMOTE_JWKS_CACHE = RemoteJwksCache()
_GLOBAL_ISSUER_METADATA_CACHE = RemoteIssuerMetadataCache()
_GLOBAL_TOKEN_INTROSPECTION_CACHE = TokenIntrospectionCache()


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
    scopes_supported = sorted(
        {
            *config.scopes_supported,
            *config.required_scopes,
            *config.mapped_scopes,
        }
    )
    if scopes_supported:
        metadata["scopes_supported"] = scopes_supported
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
    token = _bearer_token(scope.get("headers", []))
    if not token:
        return _reject(config, reason_code="oauth.missing_token", error="invalid_token")
    try:
        claims, validation_method = _verify_token_with_method(token, config=config)
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
    scope_map_decision = evaluate_scope_map(body=body, scopes=scopes, config=config)
    scope_match = scope_match_metadata(scope_map_decision)
    if not scope_map_decision["allowed"]:
        return _reject(
            config,
            status=403,
            reason_code=str(scope_map_decision["reason_code"]),
            error="insufficient_scope",
            details={"scope_map": scope_map_decision, "scope_match": scope_match},
        )
    if scope_map_decision["enabled"]:
        context["scope_decision"] = scope_map_decision
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
                "scope_map": scope_map_decision if scope_map_decision["enabled"] else None,
                "scope_match": scope_match,
            }
        ),
        context=context,
    )


def verify_token(token: str, *, config: OAuthResourceConfig) -> dict[str, Any]:
    claims, _validation_method = _verify_token_with_method(token, config=config)
    return claims


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
            audience=config.audience,
            issuer=config.issuer,
            leeway=config.leeway_seconds,
            options={
                "verify_aud": bool(config.audience),
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
            "scopes": sorted(set(scopes)),
            "email": claims.get("email"),
            "tenant": claims.get("tid") or claims.get("tenant"),
            "groups": group_values,
            "scope_map": {scope: list(selectors) for scope, selectors in sorted(config.mapped_scopes.items())},
        }
    )


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
            (b"www-authenticate", oauth_bearer_challenge(config, error=error).encode("latin-1")),
        ],
        metadata=metadata,
        context={"auth": metadata},
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
    if config.audience:
        audiences = _audiences(claims.get("aud"))
        if config.audience not in audiences:
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


def _selector_matches(configured: str, requested: str) -> bool:
    if configured == requested or configured == "*":
        return True
    if configured.endswith("*"):
        return requested.startswith(configured[:-1])
    return False


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

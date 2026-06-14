from __future__ import annotations

import http.client
import json
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

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


class _RemoteJwksRetry(ValueError):
    pass


_GLOBAL_REMOTE_JWKS_CACHE = RemoteJwksCache()


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
                "scope_map": scope_map_decision if scope_map_decision["enabled"] else None,
                "scope_match": scope_match,
            }
        ),
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
        retryable=bool(config.jwks_url) and not force_refresh,
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
        if config.jwks_url and not force_refresh:
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
    if config.jwks_url:
        cache = config.jwks_cache if isinstance(config.jwks_cache, RemoteJwksCache) else _GLOBAL_REMOTE_JWKS_CACHE
        return cache.get(
            config.jwks_url,
            ttl_seconds=config.jwks_cache_seconds,
            timeout=config.jwks_fetch_timeout,
            force_refresh=force_refresh,
        )
    raise ValueError("JWT verification requires auth.jwks_path or auth.jwks_url")


def _load_local_jwks(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        loaded = json.load(file)
    return _normalize_jwks(loaded)


def _fetch_remote_jwks(url: str, *, timeout: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"unsupported JWKS URL: {url}")
    if parsed.scheme == "http" and not _is_localhost(parsed.hostname):
        raise ValueError("remote JWKS URL must use HTTPS except for localhost")
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    try:
        connection.request(
            "GET",
            _request_target(parsed),
            headers={
                "accept": "application/json",
                "user-agent": "snulbug-jwks-cache/0.1",
            },
        )
        response = connection.getresponse()
        body = response.read(1_048_577)
        if len(body) > 1_048_576:
            raise ValueError("remote JWKS response exceeds 1 MiB")
        if response.status < 200 or response.status >= 300:
            raise ValueError(f"remote JWKS fetch failed with HTTP {response.status}")
        try:
            loaded = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"remote JWKS response is not JSON: {exc}") from exc
    finally:
        connection.close()
    return _normalize_jwks(loaded)


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

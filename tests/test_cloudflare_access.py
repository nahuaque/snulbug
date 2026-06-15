from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from snulbug import CloudflareAccessConfig, evaluate_cloudflare_access


def test_cloudflare_access_enforce_blocks_missing_cf_ray_first():
    decision = evaluate_cloudflare_access(
        scope_with_headers([]),
        config=CloudflareAccessConfig(mode="enforce"),
    )

    assert decision.allowed is False
    assert decision.status == 403
    assert decision.metadata["blocked"] is True
    assert decision.metadata["reason_code"] == "cloudflare_access.cf_ray_missing"
    assert decision.metadata["jwt_present"] is False


def test_cloudflare_access_audit_allows_but_marks_would_block():
    decision = evaluate_cloudflare_access(
        scope_with_headers([(b"cf-ray", b"abc123-LHR")]),
        config=CloudflareAccessConfig(mode="audit"),
    )

    assert decision.allowed is True
    assert decision.metadata["blocked"] is False
    assert decision.metadata["would_block"] is True
    assert decision.metadata["reason_code"] == "cloudflare_access.jwt_missing"


def test_cloudflare_access_enforce_allows_matching_email_domain_without_exposing_jwt():
    decision = evaluate_cloudflare_access(
        scope_with_headers(
            [
                (b"cf-ray", b"abc123-LHR"),
                (b"cf-access-jwt-assertion", b"raw.jwt.value"),
                (b"cf-access-authenticated-user-email", b"Dev@Example.com"),
                (b"cf-connecting-ip", b"203.0.113.10"),
                (b"cf-ipcountry", b"GB"),
            ]
        ),
        config=CloudflareAccessConfig(
            mode="enforce",
            allowed_domains=("example.com",),
        ),
    )

    assert decision.allowed is True
    assert decision.metadata["reason_code"] == "cloudflare_access.allowed"
    assert decision.metadata["email"] == "dev@example.com"
    assert decision.metadata["email_domain"] == "example.com"
    assert decision.metadata["connecting_ip"] == "203.0.113.10"
    assert "raw.jwt.value" not in str(decision.metadata)


def test_cloudflare_access_enforce_rejects_unlisted_email():
    decision = evaluate_cloudflare_access(
        scope_with_headers(
            [
                (b"cf-ray", b"abc123-LHR"),
                (b"cf-access-jwt-assertion", b"raw.jwt.value"),
                (b"cf-access-authenticated-user-email", b"other@example.com"),
            ]
        ),
        config=CloudflareAccessConfig(
            mode="enforce",
            allowed_emails=("dev@example.com",),
        ),
    )

    assert decision.allowed is False
    assert decision.metadata["reason_code"] == "cloudflare_access.email_not_allowed"


def test_cloudflare_access_validate_jwt_uses_signed_email_claim_for_allowlists():
    server, private_key = start_access_jwks_server()
    issuer = f"http://127.0.0.1:{server.server_port}"
    token = make_access_token(
        private_key,
        issuer=issuer,
        audience="app-aud-tag",
        email="dev@example.com",
    )

    try:
        decision = evaluate_cloudflare_access(
            scope_with_headers(
                [
                    (b"cf-ray", b"abc123-LHR"),
                    (b"cf-access-jwt-assertion", token.encode("ascii")),
                    (b"cf-access-authenticated-user-email", b"attacker@evil.example"),
                ]
            ),
            config=CloudflareAccessConfig(
                mode="enforce",
                validate_jwt=True,
                issuer=issuer,
                audience="app-aud-tag",
                certs_url=f"{issuer}/cdn-cgi/access/certs",
                allowed_domains=("example.com",),
            ),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert decision.allowed is True
    assert decision.metadata["reason_code"] == "cloudflare_access.allowed"
    assert decision.metadata["jwt_validated"] is True
    assert decision.metadata["jwt_validation"]["reason_code"] == "cloudflare_access.jwt_valid"
    assert decision.metadata["email"] == "dev@example.com"
    assert decision.metadata["email_source"] == "jwt"
    assert decision.metadata["header_email"] == "attacker@evil.example"
    assert token not in json.dumps(decision.metadata)


def test_cloudflare_access_validate_jwt_rejects_wrong_audience_even_with_allowed_header_email():
    server, private_key = start_access_jwks_server()
    issuer = f"http://127.0.0.1:{server.server_port}"
    token = make_access_token(
        private_key,
        issuer=issuer,
        audience="wrong-audience",
        email="dev@example.com",
    )

    try:
        decision = evaluate_cloudflare_access(
            scope_with_headers(
                [
                    (b"cf-ray", b"abc123-LHR"),
                    (b"cf-access-jwt-assertion", token.encode("ascii")),
                    (b"cf-access-authenticated-user-email", b"dev@example.com"),
                ]
            ),
            config=CloudflareAccessConfig(
                mode="enforce",
                validate_jwt=True,
                issuer=issuer,
                audience="app-aud-tag",
                certs_url=f"{issuer}/cdn-cgi/access/certs",
                allowed_domains=("example.com",),
            ),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert decision.allowed is False
    assert decision.status == 403
    assert decision.metadata["reason_code"] == "cloudflare_access.jwt_invalid"
    assert decision.metadata["jwt_validated"] is False
    assert "email" not in decision.metadata
    assert token not in json.dumps(decision.metadata)


def test_cloudflare_access_validate_jwt_rejects_missing_validation_config():
    decision = evaluate_cloudflare_access(
        scope_with_headers(
            [
                (b"cf-ray", b"abc123-LHR"),
                (b"cf-access-jwt-assertion", b"not-a-real-token"),
                (b"cf-access-authenticated-user-email", b"dev@example.com"),
            ]
        ),
        config=CloudflareAccessConfig(
            mode="enforce",
            validate_jwt=True,
            allowed_domains=("example.com",),
        ),
    )

    assert decision.allowed is False
    assert decision.metadata["reason_code"] == "cloudflare_access.jwt_config_missing"
    assert decision.metadata["jwt_validation"]["enabled"] is True
    assert decision.metadata["jwt_validation"]["valid"] is False


def scope_with_headers(headers):
    return {"type": "http", "headers": headers, "state": {}}


def start_access_jwks_server() -> tuple[ThreadingHTTPServer, Any]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk.update({"kid": "access-key", "alg": "RS256", "use": "sig"})
    server = ThreadingHTTPServer(("127.0.0.1", 0), AccessJwksHandler)
    server.jwks = {"keys": [public_jwk]}  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.thread = thread  # type: ignore[attr-defined]
    return server, private_key


def make_access_token(
    private_key: Any,
    *,
    issuer: str,
    audience: str,
    email: str,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "sub": "cloudflare-user-id",
            "email": email,
            "type": "app",
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "access-key"},
    )


class AccessJwksHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/cdn-cgi/access/certs":
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(self.server.jwks, sort_keys=True).encode("utf-8")  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

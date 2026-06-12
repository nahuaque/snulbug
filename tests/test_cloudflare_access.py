from __future__ import annotations

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


def scope_with_headers(headers):
    return {"type": "http", "headers": headers, "state": {}}

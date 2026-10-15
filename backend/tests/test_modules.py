import httpx
import pytest
from pydantic import ValidationError

from app.models.enums import Confidence, PrivacyImpact, Severity
from app.scanner.base import ResponseSnapshot
from app.scanner.modules.cache_control import CacheControlModule
from app.scanner.modules.cookies import CookiesModule
from app.scanner.modules.cors import CorsModule
from app.scanner.modules.csp import ContentSecurityPolicyModule
from app.scanner.modules.error_disclosure import ErrorDisclosureModule
from app.scanner.modules.security_headers import SecurityHeadersModule
from app.scanner.modules.server_disclosure import ServerDisclosureModule


def snapshot(headers=None, endpoint="http://localhost/", status=200):
    return ResponseSnapshot(endpoint, status, httpx.Headers(headers or {}))


def test_html_headers_missing_without_hsts_false_positive():
    findings = SecurityHeadersModule().scan(snapshot({"Content-Type": "text/html; charset=utf-8"}))
    assert len(findings) == 4
    assert not any("Strict-Transport" in f.title for f in findings)
    assert all(f.cwe == "CWE-693" and f.owasp_category is None for f in findings)
    assert all(f.privacy_impact == PrivacyImpact.NONE for f in findings)


def test_https_checks_hsts_and_json_skips_document_headers():
    findings = SecurityHeadersModule().scan(
        snapshot({"content-type": "application/json"}, "https://localhost/")
    )
    assert len(findings) == 2
    assert any("Strict-Transport" in f.title for f in findings)


def test_headers_present_and_redirects_not_flagged():
    headers = dict.fromkeys(
        [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Strict-Transport-Security",
        ],
        "configured",
    )
    headers["Content-Type"] = "text/html"
    assert SecurityHeadersModule().scan(snapshot(headers, "https://localhost/")) == []
    assert SecurityHeadersModule().scan(snapshot(status=302)) == []
    assert SecurityHeadersModule().scan(snapshot(status=404)) == []


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Set-Cookie": "theme=dark"},
        {"Set-Cookie": "csrftoken=abc"},
        {"Set-Cookie": "session=; Max-Age=0"},
        {"Set-Cookie": "not a valid cookie"},
        {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"},
    ],
)
def test_no_cookie_findings_without_sufficient_evidence(headers):
    assert CookiesModule().scan(snapshot(headers, "https://localhost/")) == []


def test_sensitive_cookie_flags_redaction_and_local_http_context():
    headers = {"Set-Cookie": "session=super-secret-token; Path=/"}
    findings = CookiesModule().scan(snapshot(headers, "https://localhost/"))
    assert {f.cwe for f in findings} == {"CWE-614", "CWE-1004", "CWE-1275"}
    assert all("super-secret-token" not in f.model_dump_json() for f in findings)
    assert all(f.confidence == Confidence.MEDIUM for f in findings)
    assert all(f.privacy_impact == PrivacyImpact.NONE for f in findings)
    local = CookiesModule().scan(snapshot(headers))
    assert not any(f.cwe == "CWE-614" for f in local)


def test_multiple_cookie_headers_and_samesite_none():
    headers = [
        ("Set-Cookie", "theme=dark"),
        ("Set-Cookie", "session=abc; HttpOnly; SameSite=None"),
        ("Set-Cookie", "JSESSIONID=def; Secure; SameSite=Strict"),
    ]
    findings = CookiesModule().scan(snapshot(headers, "https://localhost/"))
    assert len(findings) == 3
    assert any("SameSite=None" in f.title for f in findings)
    assert not any("theme" in f.evidence for f in findings)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Access-Control-Allow-Origin": "*"},
        {
            "Access-Control-Allow-Origin": "https://clinic.test",
            "Access-Control-Allow-Credentials": "true",
        },
    ],
)
def test_cors_does_not_claim_vulnerability_from_public_access(headers):
    assert CorsModule().scan(snapshot(headers)) == []


def test_cors_credentials_context():
    module = CorsModule()
    wildcard = module.scan(
        snapshot({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    )[0]
    assert wildcard.severity == Severity.INFO
    assert "bloqueiam" in wildcard.description
    null = module.scan(
        snapshot(
            {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"}
        )
    )[0]
    assert null.severity == Severity.LOW
    assert null.privacy_impact == PrivacyImpact.NONE


def test_server_disclosure_and_finding_generation_validation():
    findings = ServerDisclosureModule().scan(
        snapshot({"Server": "nginx/1.2", "X-Powered-By": "Express"})
    )
    assert len(findings) == 2
    assert all(f.severity == Severity.INFO for f in findings)
    assert all(f.owasp_category is None for f in findings)
    assert not ServerDisclosureModule().scan(snapshot())
    with pytest.raises(ValidationError):
        ServerDisclosureModule().generate_finding(
            snapshot(),
            title="Observation",
            description="Observed",
            evidence="Evidence",
            recommendation="Fix",
            cwe="A05",
        )


def test_csp_permissive_directives_are_reported_without_claiming_xss():
    finding = ContentSecurityPolicyModule().scan(
        snapshot(
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            }
        )
    )[0]
    assert finding.cwe == "CWE-693"
    assert finding.confidence == Confidence.MEDIUM
    assert "não comprova" in finding.description


def test_public_cache_with_session_cookie_is_reported_and_redacted():
    finding = CacheControlModule().scan(
        snapshot({"Cache-Control": "max-age=60, public", "Set-Cookie": "session=secret"})
    )[0]
    assert finding.cwe == "CWE-525"
    assert "secret" not in finding.model_dump_json()
    assert CacheControlModule().scan(snapshot({"Cache-Control": "public"})) == []


def test_stack_trace_signature_is_reported_without_body_evidence():
    response = ResponseSnapshot(
        "http://localhost/error",
        500,
        httpx.Headers({"Content-Type": "text/html"}),
        b"Traceback (most recent call last):\nsecret-internal-value",
    )
    finding = ErrorDisclosureModule().scan(response)[0]
    assert finding.cwe == "CWE-209"
    assert "secret-internal-value" not in finding.model_dump_json()

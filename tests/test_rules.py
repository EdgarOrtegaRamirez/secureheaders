"""Tests for security header rules."""

from secureheaders.models import HeaderStatus, Severity
from secureheaders.rules import (
    check_content_security_policy,
    check_cross_origin_embedder_policy,
    check_cross_origin_opener_policy,
    check_cross_origin_resource_policy,
    check_permissions_policy,
    check_referrer_policy,
    check_server_header,
    check_strict_transport_security,
    check_x_content_type_options,
    check_x_frame_options,
    check_x_powered_by,
    check_x_xss_protection,
)


class TestHSTS:
    def test_missing(self):
        f = check_strict_transport_security({})
        assert f.status == HeaderStatus.MISSING
        assert f.severity == Severity.HIGH

    def test_strong(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
        }
        f = check_strict_transport_security(headers)
        assert f.status == HeaderStatus.PASS

    def test_weak_max_age(self):
        headers = {"Strict-Transport-Security": "max-age=300"}
        f = check_strict_transport_security(headers)
        assert f.status == HeaderStatus.WARN
        assert f.severity == Severity.HIGH

    def test_missing_includesubdomains(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        f = check_strict_transport_security(headers)
        assert f.status == HeaderStatus.WARN


class TestCSP:
    def test_missing(self):
        f = check_content_security_policy({})
        assert f.status == HeaderStatus.MISSING
        assert f.severity == Severity.HIGH

    def test_strict(self):
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}
        f = check_content_security_policy(headers)
        assert f.status == HeaderStatus.PASS

    def test_unsafe_inline(self):
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        headers = {"Content-Security-Policy": csp}
        f = check_content_security_policy(headers)
        assert f.status == HeaderStatus.WARN
        assert "unsafe-inline" in f.details

    def test_unsafe_eval(self):
        headers = {"Content-Security-Policy": "script-src 'self' 'unsafe-eval'"}
        f = check_content_security_policy(headers)
        assert f.status == HeaderStatus.WARN
        assert "unsafe-eval" in f.details


class TestXContentTypeOptions:
    def test_missing(self):
        f = check_x_content_type_options({})
        assert f.status == HeaderStatus.MISSING
        assert f.severity == Severity.MEDIUM

    def test_correct(self):
        f = check_x_content_type_options({"X-Content-Type-Options": "nosniff"})
        assert f.status == HeaderStatus.PASS

    def test_wrong_value(self):
        f = check_x_content_type_options({"X-Content-Type-Options": "sniff"})
        assert f.status == HeaderStatus.FAIL


class TestXFrameOptions:
    def test_missing(self):
        f = check_x_frame_options({})
        assert f.status == HeaderStatus.MISSING

    def test_deny(self):
        f = check_x_frame_options({"X-Frame-Options": "DENY"})
        assert f.status == HeaderStatus.PASS

    def test_sameorigin(self):
        f = check_x_frame_options({"X-Frame-Options": "SAMEORIGIN"})
        assert f.status == HeaderStatus.PASS

    def test_invalid(self):
        f = check_x_frame_options({"X-Frame-Options": "ALLOW-FROM http://evil.com"})
        assert f.status == HeaderStatus.WARN


class TestReferrerPolicy:
    def test_missing(self):
        f = check_referrer_policy({})
        assert f.status == HeaderStatus.MISSING

    def test_good(self):
        f = check_referrer_policy({"Referrer-Policy": "strict-origin-when-cross-origin"})
        assert f.status == HeaderStatus.PASS

    def test_unsafe_url(self):
        f = check_referrer_policy({"Referrer-Policy": "unsafe-url"})
        assert f.status == HeaderStatus.WARN


class TestPermissionsPolicy:
    def test_missing(self):
        f = check_permissions_policy({})
        assert f.status == HeaderStatus.MISSING

    def test_good(self):
        headers = {
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        }
        f = check_permissions_policy(headers)
        assert f.status == HeaderStatus.PASS

    def test_incomplete(self):
        headers = {"Permissions-Policy": "camera=(), microphone=()"}
        f = check_permissions_policy(headers)
        assert f.status == HeaderStatus.WARN


class TestXSSProtection:
    def test_missing_with_csp(self):
        headers = {"Content-Security-Policy": "default-src 'self'"}
        f = check_x_xss_protection(headers)
        assert f.status == HeaderStatus.INFO

    def test_disabled(self):
        f = check_x_xss_protection({"X-XSS-Protection": "0"})
        assert f.status == HeaderStatus.PASS

    def test_enabled(self):
        f = check_x_xss_protection({"X-XSS-Protection": "1; mode=block"})
        assert f.status == HeaderStatus.WARN


class TestCOOP:
    def test_missing(self):
        f = check_cross_origin_opener_policy({})
        assert f.status == HeaderStatus.MISSING

    def test_same_origin(self):
        f = check_cross_origin_opener_policy({"Cross-Origin-Opener-Policy": "same-origin"})
        assert f.status == HeaderStatus.PASS


class TestCOEP:
    def test_missing(self):
        f = check_cross_origin_embedder_policy({})
        assert f.status == HeaderStatus.MISSING

    def test_require_corp(self):
        f = check_cross_origin_embedder_policy({"Cross-Origin-Embedder-Policy": "require-corp"})
        assert f.status == HeaderStatus.PASS

    def test_credentialless(self):
        f = check_cross_origin_embedder_policy({"Cross-Origin-Embedder-Policy": "credentialless"})
        assert f.status == HeaderStatus.PASS


class TestCORP:
    def test_missing(self):
        f = check_cross_origin_resource_policy({})
        assert f.status == HeaderStatus.MISSING

    def test_same_origin(self):
        f = check_cross_origin_resource_policy({"Cross-Origin-Resource-Policy": "same-origin"})
        assert f.status == HeaderStatus.PASS


class TestServerHeader:
    def test_not_present(self):
        f = check_server_header({})
        assert f.status == HeaderStatus.PASS

    def test_present(self):
        f = check_server_header({"Server": "nginx/1.21.3"})
        assert f.status == HeaderStatus.WARN
        assert "nginx" in f.details


class TestXPoweredBy:
    def test_not_present(self):
        f = check_x_powered_by({})
        assert f.status == HeaderStatus.PASS

    def test_present(self):
        f = check_x_powered_by({"X-Powered-By": "Express"})
        assert f.status == HeaderStatus.WARN
        assert "Express" in f.details

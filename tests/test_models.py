"""Tests for SecureHeaders models."""

from secureheaders.models import Finding, HeaderStatus, ScanResult, Severity


def _f(status: HeaderStatus, severity: Severity) -> Finding:
    """Helper to create a Finding with minimal boilerplate."""
    return Finding(
        header="X", status=status, severity=severity,
        title="t", description="d",
    )


class TestFinding:
    def test_is_positive_pass(self):
        assert _f(HeaderStatus.PASS, Severity.INFO).is_positive is True

    def test_is_positive_info(self):
        assert _f(HeaderStatus.INFO, Severity.INFO).is_positive is True

    def test_is_negative_fail(self):
        assert _f(HeaderStatus.FAIL, Severity.HIGH).is_positive is False

    def test_is_negative_missing(self):
        assert _f(HeaderStatus.MISSING, Severity.HIGH).is_positive is False

    def test_is_negative_warn(self):
        assert _f(HeaderStatus.WARN, Severity.LOW).is_positive is False


class TestScanResult:
    def _make_result(self, findings=None):
        return ScanResult(
            url="https://example.com",
            status_code=200,
            findings=findings or [],
        )

    def test_empty_result(self):
        r = self._make_result()
        assert r.passed == []
        assert r.failed == []
        assert r.warnings == []

    def test_passed_filter(self):
        findings = [
            _f(HeaderStatus.PASS, Severity.INFO),
            _f(HeaderStatus.FAIL, Severity.HIGH),
            _f(HeaderStatus.MISSING, Severity.MEDIUM),
        ]
        r = self._make_result(findings)
        assert len(r.passed) == 1
        assert len(r.failed) == 2

    def test_severity_counts(self):
        findings = [
            _f(HeaderStatus.FAIL, Severity.CRITICAL),
            _f(HeaderStatus.FAIL, Severity.HIGH),
            _f(HeaderStatus.FAIL, Severity.MEDIUM),
            _f(HeaderStatus.FAIL, Severity.LOW),
        ]
        r = self._make_result(findings)
        assert r.critical_count == 1
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1

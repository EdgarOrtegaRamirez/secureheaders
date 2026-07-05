"""Tests for the scoring analyzer."""

from secureheaders.analyzer import compute_grade, compute_score
from secureheaders.models import Finding, HeaderStatus, ScanResult, Severity


def _f(status: HeaderStatus, severity: Severity, header: str = "A") -> Finding:
    return Finding(
        header=header, status=status, severity=severity,
        title="t", description="d",
    )


class TestComputeScore:
    def test_perfect_score(self):
        findings = [_f(HeaderStatus.PASS, Severity.INFO), _f(HeaderStatus.PASS, Severity.INFO, "B")]
        assert compute_score(findings) == 100

    def test_critical_penalty(self):
        assert compute_score([_f(HeaderStatus.FAIL, Severity.CRITICAL)]) == 75

    def test_high_penalty(self):
        assert compute_score([_f(HeaderStatus.FAIL, Severity.HIGH)]) == 85

    def test_medium_penalty(self):
        assert compute_score([_f(HeaderStatus.FAIL, Severity.MEDIUM)]) == 92

    def test_low_penalty(self):
        assert compute_score([_f(HeaderStatus.FAIL, Severity.LOW)]) == 97

    def test_warn_half_penalty(self):
        assert compute_score([_f(HeaderStatus.WARN, Severity.HIGH)]) == 92

    def test_score_floors_at_zero(self):
        findings = [_f(HeaderStatus.FAIL, Severity.CRITICAL, f"H{i}") for i in range(10)]
        assert compute_score(findings) == 0

    def test_mixed_findings(self):
        findings = [
            _f(HeaderStatus.PASS, Severity.INFO),
            _f(HeaderStatus.FAIL, Severity.HIGH),
            _f(HeaderStatus.WARN, Severity.MEDIUM),
        ]
        # 100 - 15 (HIGH fail) - 4 (MEDIUM warn = 8*0.5) = 81
        assert compute_score(findings) == 81


class TestComputeGrade:
    def test_a_plus(self):
        assert compute_grade(95) == "A+"

    def test_a(self):
        assert compute_grade(85) == "A"

    def test_b(self):
        assert compute_grade(75) == "B"

    def test_c(self):
        assert compute_grade(65) == "C"

    def test_d(self):
        assert compute_grade(55) == "D"

    def test_f(self):
        assert compute_grade(30) == "F"

    def test_boundary_a_plus(self):
        assert compute_grade(90) == "A+"

    def test_boundary_a(self):
        assert compute_grade(80) == "A"

    def test_zero(self):
        assert compute_grade(0) == "F"


class TestAnalyze:
    def test_error_result(self):
        result = ScanResult(url="https://bad.test", error="Connection failed")
        from secureheaders.analyzer import analyze
        analyze(result)
        assert result.score == 0
        assert result.grade == "F"

    def test_headers_analyzed(self):
        from secureheaders.analyzer import analyze
        result = ScanResult(
            url="https://example.com",
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            },
        )
        analyze(result)
        assert result.score > 0
        assert len(result.findings) > 0
        assert result.grade != ""

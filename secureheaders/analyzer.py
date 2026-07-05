"""Scoring engine — applies rules and computes a security score (0–100)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from .models import Finding, HeaderStatus, ScanResult, Severity
from .rules import ALL_RULES

logger = logging.getLogger(__name__)

# Score weights by severity — these determine how much each failure deducts.
# The total possible deduction is 100 points.
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}

# Grade boundaries
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A+"),
    (80, "A"),
    (70, "B"),
    (60, "C"),
    (50, "D"),
    (0, "F"),
]


def compute_score(findings: list[Finding]) -> int:
    """Compute a 0–100 security score from a list of findings.

    Each failed/missing/warned finding deducts points based on severity.
    The score starts at 100 and deductions are subtracted.

    Args:
        findings: List of Finding objects.

    Returns:
        Integer score between 0 and 100.
    """
    score = 100.0

    for finding in findings:
        if finding.status in (HeaderStatus.PASS, HeaderStatus.INFO):
            continue
        weight = SEVERITY_WEIGHTS.get(finding.severity, 0.0)
        if finding.status == HeaderStatus.WARN:
            weight *= 0.5  # Warnings are half the penalty
        score -= weight

    return max(0, min(100, int(round(score))))


def compute_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def analyze(
    result: ScanResult,
    rules: list[Callable[[dict[str, str]], Finding]] | None = None,
) -> ScanResult:
    """Apply all security rules to a scan result and compute the score.

    This mutates the ScanResult in-place and also returns it for chaining.

    Args:
        result: A ScanResult with headers already populated.
        rules: Optional custom rule list (defaults to ALL_RULES).

    Returns:
        The same ScanResult with findings, score, and grade populated.
    """
    if result.error:
        result.score = 0
        result.grade = "F"
        return result

    rule_list = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []

    for rule in rule_list:
        try:
            finding = rule(result.headers)
            findings.append(finding)
        except Exception as exc:
            logger.warning("Rule %s raised an exception: %s", rule.__name__, exc)
            findings.append(
                Finding(
                    header=rule.__name__,
                    status=HeaderStatus.WARN,
                    severity=Severity.LOW,
                    title=f"Rule {rule.__name__} failed to execute",
                    description=str(exc),
                )
            )

    result.findings = findings
    result.score = compute_score(findings)
    result.grade = compute_grade(result.score)

    return result


def analyze_urls(
    results: list[ScanResult],
    rules: list[Callable[[dict[str, str]], Finding]] | None = None,
) -> list[ScanResult]:
    """Analyze multiple scan results.

    Args:
        results: List of ScanResult objects with headers.
        rules: Optional custom rule list.

    Returns:
        The same list with findings, scores, and grades populated.
    """
    for result in results:
        analyze(result, rules=rules)
    return results

"""Report generation — text, JSON, and Markdown output formats."""

from __future__ import annotations

import json
from typing import Any

from .models import Finding, HeaderStatus, ScanResult, Severity


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "header": f.header,
        "status": f.status.value,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "details": f.details,
    }


def result_to_dict(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "url": result.url,
        "status_code": result.status_code,
        "score": result.score,
        "grade": result.grade,
        "error": result.error,
        "redirect_chain": result.redirect_chain,
        "headers": result.headers,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "summary": {
            "total_checks": len(result.findings),
            "passed": len(result.passed),
            "failed": len(result.failed),
            "warnings": len(result.warnings),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        },
    }


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

STATUS_ICONS = {
    HeaderStatus.PASS: "✅",
    HeaderStatus.FAIL: "❌",
    HeaderStatus.WARN: "⚠️",
    HeaderStatus.MISSING: "⬜",
    HeaderStatus.INFO: "ℹ️",
}


def format_text(result: ScanResult) -> str:
    """Generate a plain-text report for a single ScanResult."""
    lines: list[str] = []

    # Header
    lines.append("=" * 70)
    lines.append(f"  SecureHeaders Report: {result.url}")
    lines.append("=" * 70)

    if result.error:
        lines.append(f"\n❌ ERROR: {result.error}")
        return "\n".join(lines)

    lines.append(f"\n  Score: {result.score}/100  Grade: {result.grade}")
    lines.append(f"  Status: HTTP {result.status_code}")

    if result.redirect_chain and len(result.redirect_chain) > 1:
        lines.append(f"  Redirects: {' → '.join(result.redirect_chain)}")

    # Summary
    lines.append(f"\n  Summary: {len(result.passed)} passed, "
                 f"{len(result.failed)} failed, {len(result.warnings)} warnings")

    if result.critical_count:
        lines.append(f"  🔴 Critical: {result.critical_count}")
    if result.high_count:
        lines.append(f"  🟠 High: {result.high_count}")
    if result.medium_count:
        lines.append(f"  🟡 Medium: {result.medium_count}")
    if result.low_count:
        lines.append(f"  🔵 Low: {result.low_count}")

    # Findings
    lines.append("\n" + "-" * 70)
    lines.append("  Findings")
    lines.append("-" * 70)

    for finding in result.findings:
        icon = STATUS_ICONS.get(finding.status, "?")
        sev_icon = SEVERITY_ICONS.get(finding.severity, "")
        lines.append(f"\n  {icon} [{finding.severity.value.upper()}] {finding.title} {sev_icon}")
        lines.append(f"     Header: {finding.header}")
        lines.append(f"     {finding.description}")
        if finding.recommendation:
            lines.append(f"     💡 Fix: {finding.recommendation}")
        if finding.details:
            lines.append(f"     Details: {finding.details}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def format_json(results: list[ScanResult], pretty: bool = True) -> str:
    """Generate a JSON report for one or more ScanResults."""
    if len(results) == 1:
        data = result_to_dict(results[0])
    else:
        data = {
            "results": [result_to_dict(r) for r in results],
            "summary": {
                "total_urls": len(results),
                "average_score": (
                    sum(r.score for r in results) // len(results)
                    if results else 0
                ),
                "passed": sum(1 for r in results if r.score >= 80),
                "failed": sum(1 for r in results if r.score < 80),
            },
        }

    indent = 2 if pretty else None
    return json.dumps(data, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def format_markdown(results: list[ScanResult]) -> str:
    """Generate a Markdown report for one or more ScanResults."""
    lines: list[str] = []
    lines.append("# SecureHeaders Report\n")

    if len(results) == 1:
        r = results[0]
        lines.append(f"**URL:** {r.url}\n")
        if r.error:
            lines.append(f"❌ **Error:** {r.error}\n")
        else:
            lines.append(f"**Score:** {r.score}/100 — Grade: **{r.grade}**\n")
            lines.append(f"**Status:** HTTP {r.status_code}\n")

            if r.redirect_chain and len(r.redirect_chain) > 1:
                lines.append(f"**Redirects:** {' → '.join(r.redirect_chain)}\n")

            lines.append("\n## Summary\n")
            lines.append("| Metric | Count |")
            lines.append("|--------|-------|")
            lines.append(f"| Passed | {len(r.passed)} |")
            lines.append(f"| Failed | {len(r.failed)} |")
            lines.append(f"| Warnings | {len(r.warnings)} |")

            lines.append("\n## Findings\n")
            for finding in r.findings:
                icon = STATUS_ICONS.get(finding.status, "?")
                lines.append(f"### {icon} {finding.title}\n")
                lines.append(f"- **Header:** `{finding.header}`")
                lines.append(f"- **Severity:** {finding.severity.value}")
                lines.append(f"- **Status:** {finding.status.value}")
                lines.append(f"- {finding.description}")
                if finding.recommendation:
                    lines.append(f"- 💡 **Fix:** {finding.recommendation}")
                lines.append("")
    else:
        # Multi-URL summary table
        lines.append("## Summary\n")
        lines.append("| URL | Score | Grade | Failed |")
        lines.append("|-----|-------|-------|--------|")
        for r in results:
            if r.error:
                lines.append(f"| {r.url} | — | F | error |")
            else:
                lines.append(f"| {r.url} | {r.score} | {r.grade} | {len(r.failed)} |")

    lines.append("\n---\n*Generated by SecureHeaders CLI*")
    return "\n".join(lines)

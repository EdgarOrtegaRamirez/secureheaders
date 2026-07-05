"""Data models for SecureHeaders."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Severity level for a security finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HeaderStatus(str, Enum):
    """Status of a header check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    MISSING = "missing"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding from a header check."""

    header: str
    status: HeaderStatus
    severity: Severity
    title: str
    description: str
    recommendation: str = ""
    details: str = ""

    @property
    def is_positive(self) -> bool:
        return self.status in (HeaderStatus.PASS, HeaderStatus.INFO)


@dataclass
class ScanResult:
    """Complete scan result for a URL."""

    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == HeaderStatus.PASS]

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status in (HeaderStatus.FAIL, HeaderStatus.MISSING)]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == HeaderStatus.WARN]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.failed if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.failed if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.failed if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.failed if f.severity == Severity.LOW)

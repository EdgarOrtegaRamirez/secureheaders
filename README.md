# SecureHeaders

**Web Security Header Analyzer CLI** — scan URLs for HTTP security header misconfigurations, get a security score, and receive actionable fix recommendations.

## Features

- **13 security header checks** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP, and more
- **Security scoring** — 0–100 score with letter grade (A+ through F), severity-weighted deductions
- **Actionable recommendations** — specific fix instructions for every failed check
- **Multiple output formats** — rich terminal UI, JSON (for automation), Markdown (for sharing)
- **Batch scanning** — scan multiple URLs from a file with CI/CD threshold support
- **Redirect tracking** — follows redirects and reports the full chain

## Quick Start

```bash
# Install
pip install -e .

# Scan a single URL
secureheaders scan https://example.com

# Scan multiple URLs
secureheaders scan https://example.com https://github.com

# Batch scan from file
secureheaders batch urls.txt

# JSON output for automation
secureheaders scan https://example.com -f json

# Markdown report
secureheaders scan https://example.com -f markdown > report.md

# CI/CD: fail if score < 80
secureheaders batch urls.txt --threshold 80

# List all checks
secureheaders headers
```

## Security Checks

| # | Header | Severity | What it checks |
|---|--------|----------|----------------|
| 1 | Strict-Transport-Security | HIGH | HSTS with adequate max-age, includeSubDomains, preload |
| 2 | Content-Security-Policy | HIGH | CSP presence and strength (unsafe-inline/eval detection) |
| 3 | X-Content-Type-Options | MEDIUM | nosniff directive to prevent MIME sniffing |
| 4 | X-Frame-Options | MEDIUM | DENY or SAMEORIGIN to prevent clickjacking |
| 5 | Referrer-Policy | LOW | Controls referrer information leakage |
| 6 | Permissions-Policy | LOW | Restricts camera, microphone, geolocation, etc. |
| 7 | X-XSS-Protection | LOW | Legacy filter should be disabled (CSP replaces it) |
| 8 | Cross-Origin-Opener-Policy | LOW | Browsing context isolation |
| 9 | Cross-Origin-Embedder-Policy | LOW | Spectre mitigation, required for SharedArrayBuffer |
| 10 | Cross-Origin-Resource-Policy | LOW | Controls cross-origin resource reads |
| 11 | Server | LOW | Should not leak version information |
| 12 | X-Powered-By | LOW | Should not leak technology stack |
| 13 | Cache-Control | INFO | Caching policy for sensitive data |

## Scoring

The score starts at **100** and deductions are applied:

| Severity | Deduction | Example |
|----------|-----------|---------|
| Critical | -25 pts | (reserved for future critical checks) |
| High | -15 pts | Missing HSTS, missing CSP |
| Medium | -8 pts | Missing X-Content-Type-Options, missing X-Frame-Options |
| Low | -3 pts | Missing Referrer-Policy, Server header leaks |
| Warning | Half penalty | CSP with unsafe-inline, weak HSTS max-age |

**Grades:** A+ (90+), A (80+), B (70+), C (60+), D (50+), F (<50)

## Batch Scanning

Create a file with one URL per line:

```
# urls.txt — lines starting with # are ignored
https://example.com
https://github.com
https://google.com
```

Then scan all at once:

```bash
secureheaders batch urls.txt
secureheaders batch urls.txt -f json > results.json
secureheaders batch urls.txt --threshold 80  # CI/CD mode
```

## Python API

```python
from secureheaders.scanner import scan_url
from secureheaders.analyzer import analyze

# Scan a URL
result = scan_url("https://example.com")

# Analyze headers
analyze(result)

# Check results
print(f"Score: {result.score}/100 ({result.grade})")
print(f"Passed: {len(result.passed)}")
print(f"Failed: {len(result.failed)}")

for finding in result.failed:
    print(f"  ❌ {finding.title}")
    print(f"     {finding.recommendation}")
```

## Architecture

```
secureheaders/
├── models.py       # Finding, ScanResult, Severity, HeaderStatus
├── rules.py        # 13 security header check functions
├── scanner.py      # HTTP client (httpx) with redirect tracking
├── analyzer.py     # Scoring engine (severity-weighted, 0-100)
├── reporter.py     # Text, JSON, Markdown output formatters
└── cli.py          # Click CLI: scan, batch, headers commands
```

## License

MIT

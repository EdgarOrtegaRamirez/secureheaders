# AGENTS.md — SecureHeaders

## Project Overview

SecureHeaders is a Python CLI tool and library that scans URLs for HTTP security header misconfigurations, provides a security score (0–100) with letter grade, and gives actionable fix recommendations.

## Build & Test

```bash
# Install dependencies
cd /root/workspace/secureheaders
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=secureheaders --cov-report=term-missing

# Lint
ruff check secureheaders/ tests/
ruff format --check secureheaders/ tests/

# Format
ruff format secureheaders/ tests/
```

## Architecture

- **`models.py`** — Data models: `Finding`, `ScanResult`, `Severity` enum, `HeaderStatus` enum
- **`rules.py`** — 13 security header check functions, each returning a `Finding`. Includes helpers for header lookup and CSP directive parsing.
- **`scanner.py`** — HTTP scanner using `httpx`. Fetches headers, follows redirects, handles timeouts/errors.
- **`analyzer.py`** — Scoring engine. Applies rules to scan results, computes 0–100 score with severity-weighted deductions, assigns letter grades (A+ through F).
- **`reporter.py`** — Output formatters: plain text (with Rich-compatible formatting), JSON, and Markdown.
- **`cli.py`** — Click CLI with 3 commands: `scan`, `batch`, `headers`.

## Key Design Decisions

1. **Severity-weighted scoring** — Critical = 25pts, High = 15pts, Medium = 8pts, Low = 3pts. Warnings are half-penalty. Score starts at 100.
2. **Rule functions are pure** — Each rule takes `dict[str, str]` (headers) and returns a `Finding`. Easy to test in isolation.
3. **httpx over requests** — Modern async-capable HTTP client with better redirect handling and SSL support.
4. **Multiple output formats** — Text for humans, JSON for automation, Markdown for sharing.
5. **CI/CD support** — `--threshold` flag on `batch` command enables exit code 1 for failing scores.

## Common Tasks

### Add a new security header check
1. Create a function in `rules.py` following the pattern: `check_<name>(headers: dict[str, str]) -> Finding`
2. Add it to `ALL_RULES` list at the bottom of `rules.py`
3. Add description to `descriptions` dict in `cli.py` `headers` command
4. Write tests in `tests/test_rules.py`

### Modify scoring weights
Edit `SEVERITY_WEIGHTS` in `analyzer.py`. Total deductions capped at 100.

### Add output format
1. Create `format_<name>()` function in `reporter.py`
2. Add to CLI `--format` choices in `cli.py`
3. Handle in `scan` and `batch` commands

## Testing Strategy

- **test_models.py** — Unit tests for Finding and ScanResult models (filtering, severity counts)
- **test_rules.py** — Tests each rule function with various header combinations (missing, correct, weak, wrong)
- **test_analyzer.py** — Tests scoring algorithm and grade computation with edge cases
- **test_reporter.py** — Tests all output formats produce valid output
- **test_scanner.py** — Integration tests for HTTP scanner (error handling, URL normalization)
- **test_cli.py** — Click CliRunner tests for all CLI commands

## CI

GitHub Actions workflow at `.github/workflows/ci.yml` runs `pytest` and `ruff` checks on push to main.

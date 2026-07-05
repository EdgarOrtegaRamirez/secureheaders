"""Tests for report generation."""

import json

from secureheaders.analyzer import analyze
from secureheaders.models import ScanResult
from secureheaders.reporter import format_json, format_markdown, result_to_dict


def _make_result(headers=None, error=None):
    result = ScanResult(
        url="https://example.com",
        status_code=200,
        headers=headers or {},
        error=error,
    )
    analyze(result)
    return result


class TestResultToDict:
    def test_basic(self):
        r = _make_result({"X-Content-Type-Options": "nosniff"})
        d = result_to_dict(r)
        assert d["url"] == "https://example.com"
        assert d["score"] > 0
        assert d["grade"] != ""
        assert "findings" in d
        assert "summary" in d
        assert d["summary"]["total_checks"] > 0

    def test_error(self):
        r = _make_result(error="Connection failed")
        d = result_to_dict(r)
        assert d["error"] == "Connection failed"
        assert d["score"] == 0


class TestFormatText:
    def test_contains_url(self):
        from secureheaders.reporter import format_text
        r = _make_result()
        text = format_text(r)
        assert "https://example.com" in text

    def test_contains_score(self):
        from secureheaders.reporter import format_text
        r = _make_result()
        text = format_text(r)
        assert "Score:" in text

    def test_error_report(self):
        from secureheaders.reporter import format_text
        r = _make_result(error="Connection failed")
        text = format_text(r)
        assert "ERROR" in text


class TestFormatJson:
    def test_valid_json(self):
        r = _make_result({"X-Content-Type-Options": "nosniff"})
        output = format_json([r])
        data = json.loads(output)
        assert "url" in data
        assert "score" in data

    def test_multi_url(self):
        r1 = _make_result({"X-Content-Type-Options": "nosniff"})
        r2 = _make_result(error="Connection failed")
        output = format_json([r1, r2])
        data = json.loads(output)
        assert "results" in data
        assert len(data["results"]) == 2
        assert "summary" in data


class TestFormatMarkdown:
    def test_single_url(self):
        r = _make_result({"X-Content-Type-Options": "nosniff"})
        md = format_markdown([r])
        assert "# SecureHeaders Report" in md
        assert "https://example.com" in md
        assert "Score:" in md

    def test_multi_url(self):
        r1 = _make_result()
        r2 = _make_result(error="fail")
        md = format_markdown([r1, r2])
        assert "| URL |" in md
        assert "example.com" in md

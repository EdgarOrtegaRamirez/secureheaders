"""Tests for the HTTP scanner."""

from secureheaders.scanner import scan_url


class TestScanUrl:
    def test_invalid_scheme(self):
        result = scan_url("ftp://example.com")
        assert result.error is not None
        assert "Unsupported scheme" in result.error

    def test_relative_url_adds_scheme(self):
        result = scan_url("httpbin.org/get", timeout=5.0)
        # Should auto-prepend https://
        assert result.url.startswith("http")

    def test_nonexistent_host(self):
        result = scan_url("https://this-host-does-not-exist-12345.example.com", timeout=3.0)
        assert result.error is not None

    def test_result_has_headers_dict(self):
        # Even on error, headers should be a dict
        result = scan_url("https://this-host-does-not-exist-12345.example.com", timeout=3.0)
        assert isinstance(result.headers, dict)

    def test_result_has_findings_empty_by_default(self):
        result = scan_url("https://this-host-does-not-exist-12345.example.com", timeout=3.0)
        assert result.findings == []

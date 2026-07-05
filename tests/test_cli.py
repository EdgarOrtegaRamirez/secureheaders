"""Tests for the CLI."""

from click.testing import CliRunner

from secureheaders.cli import main


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_headers_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["headers"])
        assert result.exit_code == 0
        assert "Strict-Transport-Security" in result.output
        assert "Content-Security-Policy" in result.output

    def test_scan_no_urls(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0

    def test_batch_no_file(self):
        runner = CliRunner()
        result = runner.invoke(main, ["batch", "nonexistent.txt"])
        assert result.exit_code != 0

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "SecureHeaders" in result.output

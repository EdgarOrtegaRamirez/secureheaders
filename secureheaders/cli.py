"""CLI interface for SecureHeaders."""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .analyzer import analyze, analyze_urls
from .models import HeaderStatus, ScanResult, Severity
from .reporter import format_json, format_markdown
from .scanner import scan_url, scan_urls

console = Console()

FORMAT_CHOICE = click.Choice(["text", "json", "markdown"])


def _print_rich_result(result: ScanResult) -> None:
    """Print a rich, colored result to the terminal."""
    if result.error:
        console.print(f"\n[bold red]✗ {result.url}[/]")
        console.print(f"  [red]Error: {result.error}[/]\n")
        return

    # Score color
    if result.score >= 80:
        score_color = "bold green"
    elif result.score >= 60:
        score_color = "bold yellow"
    else:
        score_color = "bold red"

    console.print(f"\n[bold]{'=' * 60}[/]")
    console.print(f"  [bold]{result.url}[/]")
    console.print(
        f"  Score: [{score_color}]{result.score}/100"
        f" — Grade: {result.grade}[/]"
    )
    console.print(f"  Status: HTTP {result.status_code}")

    if result.redirect_chain and len(result.redirect_chain) > 1:
        chain = " → ".join(result.redirect_chain)
        console.print(f"  Redirects: {chain}")

    passed = len(result.passed)
    failed = len(result.failed)
    warnings = len(result.warnings)
    console.print(
        f"  [green]✓ {passed} passed[/]  "
        f"[red]✗ {failed} failed[/]  "
        f"[yellow]⚠ {warnings} warnings[/]"
    )

    # Findings table
    table = Table(
        show_header=True, header_style="bold", show_lines=False, pad_edge=False
    )
    table.add_column("Status", width=3, justify="center")
    table.add_column("Severity", width=8)
    table.add_column("Header", width=30)
    table.add_column("Finding", min_width=30)

    for f in result.findings:
        status_style = {
            HeaderStatus.PASS: "[green]✓[/]",
            HeaderStatus.FAIL: "[red]✗[/]",
            HeaderStatus.WARN: "[yellow]⚠[/]",
            HeaderStatus.MISSING: "[dim]—[/]",
            HeaderStatus.INFO: "[blue]i[/]",
        }.get(f.status, "?")

        sev_style = {
            Severity.CRITICAL: "[bold red]CRIT[/]",
            Severity.HIGH: "[red]HIGH[/]",
            Severity.MEDIUM: "[yellow]MED[/]",
            Severity.LOW: "[blue]LOW[/]",
            Severity.INFO: "[dim]INFO[/]",
        }.get(f.severity, f.severity.value.upper())

        table.add_row(status_style, sev_style, f.header, f.title)

    console.print(table)

    # Recommendations
    recs = [f for f in result.failed if f.recommendation]
    if recs:
        console.print("\n  [bold]Recommendations:[/]")
        for f in recs:
            console.print(f"  [yellow]→[/] {f.recommendation}")

    console.print(f"{'=' * 60}\n")


@click.group()
@click.version_option(__version__, prog_name="secureheaders")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
def main(verbose: bool) -> None:
    """SecureHeaders — Web Security Header Analyzer CLI."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


@main.command()
@click.argument("urls", nargs=-1, required=True)
@click.option(
    "--format", "-f", "fmt",
    type=FORMAT_CHOICE, default="text",
)
@click.option(
    "--timeout", "-t", type=float, default=15.0,
    help="Connection timeout in seconds.",
)
@click.option("--no-redirect", is_flag=True, help="Do not follow redirects.")
@click.option("--insecure", is_flag=True, help="Skip SSL certificate verification.")
def scan(
    urls: tuple[str, ...],
    fmt: str,
    timeout: float,
    no_redirect: bool,
    insecure: bool,
) -> None:
    """Scan URLs for security header misconfigurations."""
    results: list[ScanResult] = []

    for url in urls:
        result = scan_url(
            url,
            timeout=timeout,
            follow_redirects=not no_redirect,
            verify_ssl=not insecure,
        )
        analyze(result)
        results.append(result)

    if fmt == "json":
        click.echo(format_json(results))
    elif fmt == "markdown":
        click.echo(format_markdown(results))
    else:
        for result in results:
            _print_rich_result(result)


@main.command()
@click.argument("file", type=click.File("r"))
@click.option(
    "--format", "-f", "fmt",
    type=FORMAT_CHOICE, default="text",
)
@click.option(
    "--timeout", "-t", type=float, default=15.0,
    help="Connection timeout in seconds.",
)
@click.option(
    "--threshold", type=int, default=0,
    help="Exit with code 1 if score is below this threshold.",
)
def batch(
    file: click.utils.LazyFile,
    fmt: str,
    timeout: float,
    threshold: int,
) -> None:
    """Scan multiple URLs from a file (one per line)."""
    urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]

    if not urls:
        click.echo("No URLs found in file.", err=True)
        sys.exit(1)

    click.echo(f"Scanning {len(urls)} URLs...", err=True)
    results = scan_urls(urls, timeout=timeout)
    analyze_urls(results)

    if fmt == "json":
        click.echo(format_json(results))
    elif fmt == "markdown":
        click.echo(format_markdown(results))
    else:
        for result in results:
            _print_rich_result(result)

    # CI/CD threshold check
    if threshold > 0:
        failing = [r for r in results if r.score < threshold]
        if failing:
            click.echo(
                f"\n❌ {len(failing)} URL(s) scored below {threshold}.",
                err=True,
            )
            sys.exit(1)
        else:
            click.echo(f"\n✅ All URLs scored ≥ {threshold}.", err=True)


@main.command()
def headers() -> None:
    """List all security headers that are checked."""
    from .rules import ALL_RULES

    table = Table(
        title="Security Headers Checked",
        show_header=True,
        header_style="bold",
    )
    table.add_column("#", width=3)
    table.add_column("Header", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Description")

    descriptions = {
        "check_strict_transport_security": (
            "Strict-Transport-Security", "HIGH",
            "HSTS prevents downgrade",
        ),
        "check_content_security_policy": (
            "Content-Security-Policy", "HIGH",
            "Prevents XSS/injection",
        ),
        "check_x_content_type_options": (
            "X-Content-Type-Options", "MEDIUM",
            "Prevents MIME sniffing",
        ),
        "check_x_frame_options": (
            "X-Frame-Options", "MEDIUM",
            "Prevents clickjacking",
        ),
        "check_referrer_policy": (
            "Referrer-Policy", "LOW",
            "Controls referrer info",
        ),
        "check_permissions_policy": (
            "Permissions-Policy", "LOW",
            "Restricts browser features",
        ),
        "check_x_xss_protection": (
            "X-XSS-Protection", "LOW",
            "Legacy XSS filter",
        ),
        "check_cross_origin_opener_policy": (
            "Cross-Origin-Opener-Policy", "LOW",
            "Isolates browsing context",
        ),
        "check_cross_origin_embedder_policy": (
            "Cross-Origin-Embedder-Policy", "LOW",
            "Spectre mitigation",
        ),
        "check_cross_origin_resource_policy": (
            "Cross-Origin-Resource-Policy", "LOW",
            "Controls cross-origin reads",
        ),
        "check_server_header": (
            "Server", "LOW",
            "Should not leak version",
        ),
        "check_x_powered_by": (
            "X-Powered-By", "LOW",
            "Should not leak tech info",
        ),
        "check_cache_control": (
            "Cache-Control", "INFO",
            "Caching for sensitive data",
        ),
    }

    for i, rule in enumerate(ALL_RULES, 1):
        info = descriptions.get(rule.__name__, ("Unknown", "INFO", ""))
        table.add_row(str(i), info[0], info[1], info[2])

    console.print(table)


if __name__ == "__main__":
    main()

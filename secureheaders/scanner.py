"""HTTP scanner — fetches headers from a URL."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx

from .models import ScanResult

logger = logging.getLogger(__name__)

# Max redirects to follow before giving up
MAX_REDIRECTS = 10
# Connection timeout in seconds
TIMEOUT = 15.0


def scan_url(
    url: str,
    *,
    timeout: float = TIMEOUT,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
    user_agent: str = "SecureHeaders/0.1",
) -> ScanResult:
    """Scan a single URL and return a ScanResult with its headers.

    Args:
        url: The URL to scan.
        timeout: Connection timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.
        verify_ssl: Whether to verify SSL certificates.
        user_agent: User-Agent string.

    Returns:
        A ScanResult populated with headers and metadata.
    """
    result = ScanResult(url=url)

    # Normalize scheme
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        result.error = f"Unsupported scheme: {parsed.scheme}"
        return result

    redirect_chain: list[str] = []

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify_ssl,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": user_agent},
        ) as client:
            response = client.get(url)
            result.status_code = response.status_code

            # Record redirect chain
            if follow_redirects and response.history:
                for resp in response.history:
                    redirect_chain.append(str(resp.url))
            redirect_chain.append(str(response.url))
            result.redirect_chain = redirect_chain

            # Copy response headers
            result.headers = dict(response.headers)

    except httpx.TimeoutException:
        result.error = f"Connection timed out after {timeout}s"
    except httpx.ConnectError as exc:
        result.error = f"Connection failed: {exc}"
    except httpx.TooManyRedirects:
        result.error = f"Too many redirects (>{MAX_REDIRECTS})"
    except httpx.UnsupportedProtocol as exc:
        result.error = f"Unsupported protocol: {exc}"
    except Exception as exc:
        result.error = f"Unexpected error: {exc}"

    return result


def scan_urls(
    urls: list[str],
    *,
    timeout: float = TIMEOUT,
    follow_redirects: bool = True,
    verify_ssl: bool = True,
) -> list[ScanResult]:
    """Scan multiple URLs and return a list of ScanResults.

    Args:
        urls: List of URLs to scan.
        timeout: Connection timeout per URL.
        follow_redirects: Whether to follow redirects.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        List of ScanResult objects, one per URL.
    """
    results: list[ScanResult] = []
    for url in urls:
        logger.info("Scanning %s", url)
        result = scan_url(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify_ssl=verify_ssl,
        )
        results.append(result)
    return results

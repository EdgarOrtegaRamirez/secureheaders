"""Security header rules — each rule is a function that inspects headers and returns findings."""

from __future__ import annotations

import re

from .models import Finding, HeaderStatus, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _header_value(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None


def _has_header(headers: dict[str, str], name: str) -> bool:
    return _header_value(headers, name) is not None


def _parse_directives(value: str) -> dict[str, str]:
    """Parse a CSP-style header value into a dict of directive → value."""
    directives: dict[str, str] = {}
    for part in re.split(r";\s*", value.strip()):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        key = tokens[0].lower()
        directives[key] = tokens[1] if len(tokens) > 1 else ""
    return directives


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def check_strict_transport_security(headers: dict[str, str]) -> Finding:
    """Check for HSTS header."""
    val = _header_value(headers, "Strict-Transport-Security")
    if val is None:
        return Finding(
            header="Strict-Transport-Security",
            status=HeaderStatus.MISSING,
            severity=Severity.HIGH,
            title="HSTS header missing",
            description=(
                "The Strict-Transport-Security (HSTS) header is not set. "
                "This allows browsers to be downgraded to HTTP via MITM attacks."
            ),
            recommendation=(
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
        )

    # Parse max-age
    m = re.search(r"max-age=(\d+)", val, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0

    issues: list[str] = []
    severity = Severity.MEDIUM

    if max_age < 31536000:
        issues.append(f"max-age={max_age} is too low (recommended ≥ 31536000 = 1 year)")
        severity = Severity.HIGH

    if "includeSubDomains" not in val:
        issues.append("includeSubDomains directive is missing")

    if "preload" not in val:
        issues.append("preload directive is missing (optional but recommended)")

    if issues:
        return Finding(
            header="Strict-Transport-Security",
            status=HeaderStatus.WARN,
            severity=severity,
            title="HSTS header needs improvement",
            description="The HSTS header is present but could be stronger.",
            recommendation="Add includeSubDomains and preload; set max-age ≥ 31536000.",
            details="; ".join(issues),
        )

    return Finding(
        header="Strict-Transport-Security",
        status=HeaderStatus.PASS,
        severity=Severity.INFO,
        title="HSTS header is well-configured",
        description="Strong HSTS policy with adequate max-age, includeSubDomains, and preload.",
    )


def check_content_security_policy(headers: dict[str, str]) -> Finding:
    """Check for Content-Security-Policy header."""
    val = _header_value(headers, "Content-Security-Policy")
    if val is None:
        return Finding(
            header="Content-Security-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.HIGH,
            title="Content-Security-Policy header missing",
            description=(
                "No Content-Security-Policy header is set. This leaves the site vulnerable "
                "to XSS, data injection, and clickjacking attacks."
            ),
            recommendation=(
                "Start with a restrictive policy: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'"
            ),
        )

    directives = _parse_directives(val)
    issues: list[str] = []

    # Check for dangerous directives
    if "default-src" in directives and "'unsafe-inline'" in directives["default-src"]:
        issues.append("default-src allows 'unsafe-inline'")

    if "script-src" in directives:
        if "'unsafe-inline'" in directives["script-src"]:
            issues.append("script-src allows 'unsafe-inline' (XSS risk)")
        if "'unsafe-eval'" in directives["script-src"]:
            issues.append("script-src allows 'unsafe-eval' (XSS risk)")
    elif "'unsafe-inline'" in directives.get("default-src", ""):
        issues.append("No script-src directive; inherits unsafe-inline from default-src")

    if "object-src" in directives and "'none'" not in directives["object-src"]:
        issues.append("object-src is not restricted to 'none'")

    if not issues:
        return Finding(
            header="Content-Security-Policy",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Content-Security-Policy is set",
            description="A Content-Security-Policy header is present.",
        )

    has_script = any("script-src" in i or "unsafe-inline" in i for i in issues)
    severity = Severity.HIGH if has_script else Severity.MEDIUM
    return Finding(
        header="Content-Security-Policy",
        status=HeaderStatus.WARN,
        severity=severity,
        title="Content-Security-Policy has weaknesses",
        description="The CSP header is present but contains directives that weaken protection.",
        recommendation="Remove unsafe-inline and unsafe-eval from script-src.",
        details="; ".join(issues),
    )


def check_x_content_type_options(headers: dict[str, str]) -> Finding:
    """Check for X-Content-Type-Options: nosniff."""
    val = _header_value(headers, "X-Content-Type-Options")
    if val is None:
        return Finding(
            header="X-Content-Type-Options",
            status=HeaderStatus.MISSING,
            severity=Severity.MEDIUM,
            title="X-Content-Type-Options header missing",
            description=(
                "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses "
                "and execute them as scripts, leading to XSS."
            ),
            recommendation="Add: X-Content-Type-Options: nosniff",
        )

    if val.strip().lower() != "nosniff":
        return Finding(
            header="X-Content-Type-Options",
            status=HeaderStatus.FAIL,
            severity=Severity.MEDIUM,
            title="X-Content-Type-Options has invalid value",
            description=f"Expected 'nosniff' but got '{val}'.",
            recommendation="Set to: X-Content-Type-Options: nosniff",
        )

    return Finding(
        header="X-Content-Type-Options",
        status=HeaderStatus.PASS,
        severity=Severity.INFO,
        title="X-Content-Type-Options is correctly set",
        description="The nosniff directive prevents MIME-type sniffing.",
    )


def check_x_frame_options(headers: dict[str, str]) -> Finding:
    """Check for X-Frame-Options."""
    val = _header_value(headers, "X-Frame-Options")
    if val is None:
        return Finding(
            header="X-Frame-Options",
            status=HeaderStatus.MISSING,
            severity=Severity.MEDIUM,
            title="X-Frame-Options header missing",
            description=(
                "Without X-Frame-Options, the site can be embedded in iframes on other sites, "
                "enabling clickjacking attacks."
            ),
            recommendation="Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)",
        )

    normalized = val.strip().upper()
    if normalized not in ("DENY", "SAMEORIGIN"):
        return Finding(
            header="X-Frame-Options",
            status=HeaderStatus.WARN,
            severity=Severity.MEDIUM,
            title="X-Frame-Options has unusual value",
            description=f"Value '{val}' is not standard. Expected DENY or SAMEORIGIN.",
            recommendation="Use DENY or SAMEORIGIN.",
        )

    if normalized == "DENY":
        return Finding(
            header="X-Frame-Options",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="X-Frame-Options is set to DENY",
            description="The page cannot be embedded in any iframe.",
        )

    return Finding(
        header="X-Frame-Options",
        status=HeaderStatus.PASS,
        severity=Severity.INFO,
        title="X-Frame-Options is set to SAMEORIGIN",
        description="The page can only be framed by same-origin pages.",
    )


def check_referrer_policy(headers: dict[str, str]) -> Finding:
    """Check for Referrer-Policy."""
    val = _header_value(headers, "Referrer-Policy")
    if val is None:
        return Finding(
            header="Referrer-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.LOW,
            title="Referrer-Policy header missing",
            description=(
                "Without Referrer-Policy, browsers may send full URLs (including query strings) "
                "to third-party origins, leaking sensitive information."
            ),
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        )

    dangerous = ("unsafe-url", "no-referrer-when-downgrade")
    if val.strip().lower() in dangerous:
        return Finding(
            header="Referrer-Policy",
            status=HeaderStatus.WARN,
            severity=Severity.LOW,
            title="Referrer-Policy is too permissive",
            description=f"Value '{val}' leaks full URLs in referrer headers.",
            recommendation="Use strict-origin-when-cross-origin or no-referrer.",
        )

    return Finding(
        header="Referrer-Policy",
        status=HeaderStatus.PASS,
        severity=Severity.INFO,
        title="Referrer-Policy is set",
        description=f"Referrer-Policy: {val}",
    )


def check_permissions_policy(headers: dict[str, str]) -> Finding:
    """Check for Permissions-Policy (formerly Feature-Policy)."""
    val = _header_value(headers, "Permissions-Policy") or _header_value(headers, "Feature-Policy")
    if val is None:
        return Finding(
            header="Permissions-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.LOW,
            title="Permissions-Policy header missing",
            description=(
                "Without Permissions-Policy, the browser allows access to powerful features "
                "like camera, microphone, geolocation, etc."
            ),
            recommendation=(
                "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=()"
            ),
        )

    # Check that dangerous features are disabled
    dangerous_features = ["camera", "microphone", "geolocation", "payment", "usb"]
    missing_restrictions = []
    for feat in dangerous_features:
        pattern = rf"{feat}\s*="
        if not re.search(pattern, val, re.IGNORECASE):
            missing_restrictions.append(feat)

    if missing_restrictions:
        return Finding(
            header="Permissions-Policy",
            status=HeaderStatus.WARN,
            severity=Severity.LOW,
            title="Permissions-Policy does not restrict all dangerous features",
            description=f"Features not explicitly restricted: {', '.join(missing_restrictions)}",
            recommendation="Explicitly disable unused features with feature=()",
        )

    return Finding(
        header="Permissions-Policy",
        status=HeaderStatus.PASS,
        severity=Severity.INFO,
        title="Permissions-Policy is configured",
        description="Dangerous browser features are restricted.",
    )


def check_x_xss_protection(headers: dict[str, str]) -> Finding:
    """Check for legacy X-XSS-Protection (should be disabled if CSP is present)."""
    val = _header_value(headers, "X-XSS-Protection")
    if val is None:
        # Not having this legacy header is actually fine if CSP is present
        has_csp = _has_header(headers, "Content-Security-Policy")
        if has_csp:
            return Finding(
                header="X-XSS-Protection",
                status=HeaderStatus.INFO,
                severity=Severity.INFO,
                title="Legacy X-XSS-Protection not set (OK with CSP)",
                description=(
                    "The legacy X-XSS-Protection header is not set, which is correct "
                    "when a Content-Security-Policy is in place."
                ),
            )
        return Finding(
            header="X-XSS-Protection",
            status=HeaderStatus.INFO,
            severity=Severity.INFO,
            title="Legacy X-XSS-Protection not set",
            description=(
                "The X-XSS-Protection header is not set. Modern browsers rely on CSP instead."
            ),
            recommendation="If you must support legacy browsers, add: X-XSS-Protection: 0",
        )

    if val.strip() == "0":
        return Finding(
            header="X-XSS-Protection",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Legacy XSS protection correctly disabled",
            description="X-XSS-Protection: 0 is the recommended modern setting.",
        )

    return Finding(
        header="X-XSS-Protection",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="Legacy X-XSS-Protection enabled",
        description=(
            "The legacy X-XSS-Protection filter is enabled. This filter has known bypasses "
            "and can introduce vulnerabilities. Use CSP instead."
        ),
        recommendation="Set X-XSS-Protection: 0 and implement Content-Security-Policy.",
    )


def check_cross_origin_opener_policy(headers: dict[str, str]) -> Finding:
    """Check for Cross-Origin-Opener-Policy."""
    val = _header_value(headers, "Cross-Origin-Opener-Policy")
    if val is None:
        return Finding(
            header="Cross-Origin-Opener-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.LOW,
            title="Cross-Origin-Opener-Policy header missing",
            description=(
                "Without COOP, the site is vulnerable to cross-origin attacks via "
                "window.open and window.opener references."
            ),
            recommendation="Add: Cross-Origin-Opener-Policy: same-origin",
        )

    if val.strip().lower() == "same-origin":
        return Finding(
            header="Cross-Origin-Opener-Policy",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Cross-Origin-Opener-Policy is set",
            description="COOP: same-origin isolates the browsing context.",
        )

    return Finding(
        header="Cross-Origin-Opener-Policy",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="Cross-Origin-Opener-Policy is not same-origin",
        description=f"Value '{val}' may not fully protect against cross-origin attacks.",
        recommendation="Use same-origin for strongest protection.",
    )


def check_cross_origin_embedder_policy(headers: dict[str, str]) -> Finding:
    """Check for Cross-Origin-Embedder-Policy."""
    val = _header_value(headers, "Cross-Origin-Embedder-Policy")
    if val is None:
        return Finding(
            header="Cross-Origin-Embedder-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.LOW,
            title="Cross-Origin-Embedder-Policy header missing",
            description=(
                "Without COEP, the site cannot use cross-origin resources in a "
                "spectre-safe way. Required for SharedArrayBuffer."
            ),
            recommendation="Add: Cross-Origin-Embedder-Policy: require-corp",
        )

    if val.strip().lower() in ("require-corp", "credentialless"):
        return Finding(
            header="Cross-Origin-Embedder-Policy",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Cross-Origin-Embedder-Policy is set",
            description=f"COEP: {val}",
        )

    return Finding(
        header="Cross-Origin-Embedder-Policy",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="Cross-Origin-Embedder-Policy value is unusual",
        description=f"Value '{val}' is not standard.",
        recommendation="Use require-corp or credentialless.",
    )


def check_cross_origin_resource_policy(headers: dict[str, str]) -> Finding:
    """Check for Cross-Origin-Resource-Policy."""
    val = _header_value(headers, "Cross-Origin-Resource-Policy")
    if val is None:
        return Finding(
            header="Cross-Origin-Resource-Policy",
            status=HeaderStatus.MISSING,
            severity=Severity.LOW,
            title="Cross-Origin-Resource-Policy header missing",
            description=("Without CORP, cross-origin reads of this resource are unrestricted."),
            recommendation="Add: Cross-Origin-Resource-Policy: same-origin",
        )

    if val.strip().lower() in ("same-origin", "same-site"):
        return Finding(
            header="Cross-Origin-Resource-Policy",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Cross-Origin-Resource-Policy is set",
            description=f"CORP: {val}",
        )

    return Finding(
        header="Cross-Origin-Resource-Policy",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="Cross-Origin-Resource-Policy is too permissive",
        description=f"Value '{val}' allows cross-origin reads.",
        recommendation="Use same-origin or same-site.",
    )


def check_server_header(headers: dict[str, str]) -> Finding:
    """Check for information-leaking Server header."""
    val = _header_value(headers, "Server")
    if val is None:
        return Finding(
            header="Server",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Server header is not exposed",
            description="The Server header is not present, which is good for security.",
        )

    return Finding(
        header="Server",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="Server header leaks version information",
        description=f"Server header reveals: {val}",
        recommendation="Remove the Server header or remove version information from it.",
        details=f"Server: {val}",
    )


def check_x_powered_by(headers: dict[str, str]) -> Finding:
    """Check for information-leaking X-Powered-By header."""
    val = _header_value(headers, "X-Powered-By")
    if val is None:
        return Finding(
            header="X-Powered-By",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="X-Powered-By header is not exposed",
            description="The X-Powered-By header is not present.",
        )

    return Finding(
        header="X-Powered-By",
        status=HeaderStatus.WARN,
        severity=Severity.LOW,
        title="X-Powered-By header leaks technology information",
        description=f"X-Powered-By reveals: {val}",
        recommendation="Remove the X-Powered-By header.",
        details=f"X-Powered-By: {val}",
    )


def check_cache_control(headers: dict[str, str]) -> Finding:
    """Check Cache-Control for sensitive pages."""
    val = _header_value(headers, "Cache-Control")
    if val is None:
        return Finding(
            header="Cache-Control",
            status=HeaderStatus.INFO,
            severity=Severity.INFO,
            title="Cache-Control header not set",
            description="No Cache-Control header is present.",
        )

    if "no-store" in val.lower():
        return Finding(
            header="Cache-Control",
            status=HeaderStatus.PASS,
            severity=Severity.INFO,
            title="Cache-Control prevents caching sensitive data",
            description="Cache-Control: no-store ensures responses are not cached.",
        )

    if "no-cache" in val.lower():
        return Finding(
            header="Cache-Control",
            status=HeaderStatus.INFO,
            severity=Severity.INFO,
            title="Cache-Control uses no-cache",
            description="Responses can be cached but must revalidate before use.",
        )

    return Finding(
        header="Cache-Control",
        status=HeaderStatus.INFO,
        severity=Severity.INFO,
        title="Cache-Control is set",
        description=f"Cache-Control: {val}",
    )


# ---------------------------------------------------------------------------
# All rules registry
# ---------------------------------------------------------------------------

ALL_RULES = [
    check_strict_transport_security,
    check_content_security_policy,
    check_x_content_type_options,
    check_x_frame_options,
    check_referrer_policy,
    check_permissions_policy,
    check_x_xss_protection,
    check_cross_origin_opener_policy,
    check_cross_origin_embedder_policy,
    check_cross_origin_resource_policy,
    check_server_header,
    check_x_powered_by,
    check_cache_control,
]

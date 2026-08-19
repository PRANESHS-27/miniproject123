"""Audit security-relevant response headers."""

from __future__ import annotations

import re
from typing import Any


SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    # (header, severity_when_missing, title, remediation)
    ("content-security-policy", "HIGH",
     "Missing Content-Security-Policy header",
     "Add a Content-Security-Policy header. Even a restrictive default-src 'self' reduces XSS impact."),
    ("x-frame-options", "MEDIUM",
     "Missing X-Frame-Options header",
     "Add X-Frame-Options: DENY (or use frame-ancestors in CSP)."),
    ("x-content-type-options", "MEDIUM",
     "Missing X-Content-Type-Options header",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "LOW",
     "Missing Referrer-Policy header",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "LOW",
     "Missing Permissions-Policy header",
     "Add a Permissions-Policy header to disable unused browser features."),
    ("strict-transport-security", "MEDIUM",
     "Missing Strict-Transport-Security (HSTS) header",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
]

WEAK_CSP_PATTERNS = [
    (r"unsafe-inline", "HIGH", "CSP allows 'unsafe-inline' — defeats XSS protection"),
    (r"unsafe-eval", "HIGH", "CSP allows 'unsafe-eval' — defeats XSS protection"),
    (r"\*\s+", "MEDIUM", "CSP uses wildcard source — overly permissive"),
]


def audit_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Return a list of ``AssetFinding``-shaped dicts."""
    findings: list[dict[str, Any]] = []
    headers_lc = {k.lower(): v for k, v in (headers or {}).items()}

    for header, severity, title, remediation in SECURITY_HEADERS:
        if header not in headers_lc:
            findings.append({
                "finding_type": "header",
                "severity": severity,
                "title": title,
                "details": {"header": header, "expected": True, "got": None},
                "remediation": remediation,
            })

    csp = headers_lc.get("content-security-policy", "")
    if csp:
        for pat, severity, title in WEAK_CSP_PATTERNS:
            if re.search(pat, csp, re.IGNORECASE):
                findings.append({
                    "finding_type": "header",
                    "severity": severity,
                    "title": title,
                    "details": {"header": "content-security-policy", "value": csp[:200]},
                    "remediation": "Tighten the CSP — remove unsafe-inline / unsafe-eval and replace wildcards.",
                })

    return findings
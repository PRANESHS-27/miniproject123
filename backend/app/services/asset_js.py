"""Public JS library CVE check.

Scans the home page HTML for ``<script src="...">`` tags whose URL points
to a third-party (or first-party CDN) and extracts ``vendor@version`` from
the filename. Each match is checked against a small curated vulnerability
table.

This is intentionally lightweight — RetireJS would be the next step if you
want comprehensive coverage of every known CVE for every popular library.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# vendor regex on filename, max safe version (semver-friendly)
JS_VULN_DB: list[dict[str, Any]] = [
    {
        "vendor": "jquery",
        "filenames": [r"jquery[-_]?(\d+(?:\.\d+){0,3})(\.min)?\.js"],
        "rules": [
            {"below": "3.5.0", "cve_id": "CVE-2020-11022",
             "title": "jQuery XSS via HTML sanitization bypass"},
            {"below": "3.5.0", "cve_id": "CVE-2020-11023",
             "title": "jQuery prototype pollution via $.extend"},
        ],
    },
    {
        "vendor": "lodash",
        "filenames": [r"lodash[._-](\d+(?:\.\d+){0,3})(\.min)?\.js",
                      r"lodash\.js"],
        "rules": [
            {"below": "4.17.21", "cve_id": "CVE-2021-23337",
             "title": "Lodash command injection via template"},
        ],
    },
    {
        "vendor": "bootstrap",
        "filenames": [r"bootstrap[-_](\d+(?:\.\d+){0,3})(\.min)?\.js"],
        "rules": [
            {"below": "3.4.1", "cve_id": "CVE-2019-8331",
             "title": "Bootstrap XSS in tooltip / popover data-template"},
        ],
    },
    {
        "vendor": "angularjs",
        "filenames": [r"angular(?:js)?[-_](\d+(?:\.\d+){0,3})(\.min)?\.js",
                      r"angular\.js"],
        "rules": [
            {"below": "1.8.0", "cve_id": "CVE-2020-7676",
             "title": "AngularJS XSS via SVG / inert"},
        ],
    },
    {
        "vendor": "vue",
        "filenames": [r"vue[-_](\d+(?:\.\d+){0,3})(\.min)?\.js"],
        "rules": [
            {"below": "2.5.18", "cve_id": "CVE-2019-14772",
             "title": "Vue.js template injection via slot resolution"},
        ],
    },
    {
        "vendor": "handlebars",
        "filenames": [r"handlebars(?:[-_.v](\d+(?:\.\d+){0,3}))?(\.min)?\.js"],
        "rules": [
            {"below": "4.3.0", "cve_id": "CVE-2019-19919",
             "title": "Handlebars prototype pollution / RCE"},
        ],
    },
    {
        "vendor": "moment",
        "filenames": [r"moment[-_](\d+(?:\.\d+){0,3})(\.min)?\.js"],
        "rules": [
            {"below": "2.29.4", "cve_id": "CVE-2022-31129",
             "title": "Moment.js ReDoS in date parsing"},
        ],
    },
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def _parse_version(s: str | None) -> tuple[int, ...]:
    if not s:
        return ()
    return tuple(int(p) for p in re.findall(r"\d+", s)[:4])


def _is_below(version: tuple[int, ...], threshold: str) -> bool:
    return version < _parse_version(threshold)


def extract_scripts(body: str, asset_url: str) -> list[str]:
    """Return absolute or root-relative script URLs found in the body."""
    if not body:
        return []
    found = SCRIPT_SRC_RE.findall(body)
    parsed = urlparse(asset_url)
    out: list[str] = []
    for s in found:
        if s.startswith("//"):
            out.append(parsed.scheme + ":" + s)
        elif s.startswith("/"):
            out.append(f"{parsed.scheme}://{parsed.netloc}{s}")
        elif s.startswith("http://") or s.startswith("https://"):
            out.append(s)
        else:
            # relative
            out.append(f"{parsed.scheme}://{parsed.netloc}/{s.lstrip('/')}")
    return out


def match_scripts(script_urls: list[str]) -> list[dict[str, Any]]:
    """For each script URL, extract vendor@version and match against the DB."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for url in script_urls:
        path = urlparse(url).path
        filename = path.rsplit("/", 1)[-1]
        for lib in JS_VULN_DB:
            for fname_pat in lib["filenames"]:
                m = re.search(fname_pat, filename, re.IGNORECASE)
                if not m:
                    continue
                version = m.group(1) if m.lastindex else None
                parsed_version = _parse_version(version)
                if not parsed_version:
                    continue
                for rule in lib["rules"]:
                    if _is_below(parsed_version, rule["below"]):
                        key = (lib["vendor"], rule["cve_id"])
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "finding_type": "js_lib",
                            "severity": "HIGH",
                            "title": f"{lib['vendor']}@{version} vulnerable to {rule['cve_id']} — {rule['title']}",
                            "details": {
                                "library": lib["vendor"],
                                "version": version,
                                "cve_id": rule["cve_id"],
                                "fixed_in": rule["below"],
                                "script_url": url[:500],
                            },
                            "remediation": f"Upgrade {lib['vendor']} to {rule['below']} or later.",
                        })
                break  # matched one filename pattern; move to next library
    return findings
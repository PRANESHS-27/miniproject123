"""Vendor allow/deny filtering for vulnerabilities.

The CVE feed includes CVEs for ecosystems you may not care about (Apple iOS,
Google Chrome, etc.). This module centralises the "is this vendor relevant?"
check so the fetcher, the matcher, and the dashboard endpoint all agree.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Iterable

from app.core.config import settings


@functools.lru_cache(maxsize=1)
def excluded() -> frozenset[str]:
    """Lower-cased set of vendor strings currently excluded.

    Cached so we don't re-parse the env-var list on every CVE row (the
    matcher calls this in a hot loop over 200k+ rows).
    """
    raw = (settings.excluded_vendors or "").strip()
    if not raw:
        return frozenset()
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _normalise(value: str) -> str:
    """Collapse separators so that "Google LLC", "google_llc", "google,llc"
    all compare equal to "google". Whitespace, commas, dots, underscores and
    hyphens are treated as the same word boundary."""
    return re.sub(r"[\s,._\-]+", " ", value.lower()).strip()


def is_vendor_excluded(vendor: str | None) -> bool:
    """True if ``vendor`` (case-insensitive) is in the exclusion list.

    NVD sometimes expands these to "Google LLC", "google_inc",
    "google.com". We accept the entry after normalising separators
    (whitespace, comma, dot, underscore, hyphen all collapse to a single
    space). We do NOT use substring matching — "pineapple" must NOT match
    "apple".
    """
    if not vendor:
        return False
    v = _normalise(vendor)
    if not v:
        return False
    for ex in excluded():
        if not ex:
            continue
        ex_norm = _normalise(ex)
        if v == ex_norm:
            return True
        # Word-prefix match: "google llc" starts with "google ", but
        # "googleplus" does not (no separator between "google" and
        # "plus").
        if v.startswith(ex_norm + " "):
            return True
    return False


def is_cve_excluded(products: Iterable[Any] | None) -> bool:
    """True when *every* ``affected_products`` entry belongs to an excluded
    vendor. A CVE that mixes e.g. Apache + Google is *kept* (Apache is
    relevant); a CVE that lists only Apple products is *dropped*."""
    prods = [p for p in (products or []) if isinstance(p, dict)]
    if not prods:
        return False
    return all(is_vendor_excluded(p.get("vendor")) for p in prods)


def filter_affected_products(products: Iterable[Any] | None) -> list[dict[str, Any]]:
    """Return only the entries whose vendor is **not** excluded."""
    out: list[dict[str, Any]] = []
    for p in products or []:
        if not isinstance(p, dict):
            continue
        if is_vendor_excluded(p.get("vendor")):
            continue
        out.append(dict(p))  # shallow copy so caller can't mutate the original
    return out

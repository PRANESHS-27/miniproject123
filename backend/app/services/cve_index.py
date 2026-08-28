"""In-memory indexes over the ``vulnerabilities`` and ``assets`` tables.

The dashboard and search endpoints previously walked every row's JSON
``affected_products`` on every request — at 200k+ CVEs that's 3-5 seconds.
This module builds pre-computed indexes once and serves them from memory.

Design
------
* ``VendorIndex`` is a singleton holding immutable references to the
  per-vendor sets and pre-computed counters. It is rebuilt on app
  startup, after each NVD sync, and after each KEV sync.
* Reads from ``search_vulnerabilities`` and ``dashboard_stats`` only read
  from this index — no per-request table scans.
* Writes that affect the underlying data (NVD ingest, KEV ingest, asset
  scan results) call :func:`invalidate` and :func:`refresh` to refresh.

The module is thread-safe enough for FastAPI's sync handlers — we use a
plain module-level dict and rely on the GIL for read-only access between
``refresh`` calls.
"""

from __future__ import annotations

import threading
from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetCveMatch,
    AssetFinding,
    AssetTechnology,
    Severity,
    SeverityLevel,
    Vulnerability,
)
from app.services.vendor_filter import (
    is_cve_excluded,
    is_vendor_excluded,
)

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Snapshot — what ``dashboard_stats`` / ``search_vulnerabilities`` consult.
# Each attribute is populated by ``refresh()``.
# ---------------------------------------------------------------------------
_state: dict[str, Any] = {
    "ready": False,
    "total_cves": 0,
    "by_severity": {},                   # {Severity: int}
    "kev_count": 0,
    "recent": [],                        # list[dict] (VulnerabilitySummary-shaped)
    "excluded_cve_ids": set(),           # set[str]
    "vendor_to_cves": {},                # dict[lower-vendor, set[cve_id]]
    "top_vendors": [],                   # list[dict] global, top 10
    "asset_top_vendors": [],             # list[dict] over active assets
    "asset_top_products": [],            # list[dict]
    "tech_counter": [],                  # list[dict]
    "findings_by_type": {},              # dict[str, int]
    "total_assets": 0,
    "active_assets": 0,
    "open_findings": 0,
    "critical_findings": 0,
    "cves_affecting_us": 0,
    "assets_with_critical": 0,
    "built_at": None,
}


def get() -> dict[str, Any]:
    """Return the current snapshot."""
    return _state


def ready() -> bool:
    return bool(_state.get("ready"))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _build_excluded(db: Session) -> set[str]:
    excluded_ids: set[str] = set()
    for cve_id, affected in db.query(
        Vulnerability.cve_id, Vulnerability.affected_products
    ).all():
        if is_cve_excluded(affected):
            excluded_ids.add(cve_id)
    return excluded_ids


def _build_vendor_index(db: Session) -> dict[str, set[str]]:
    """vendor_lower -> set of CVE ids that reference it."""
    idx: dict[str, set[str]] = {}
    for cve_id, affected in db.query(
        Vulnerability.cve_id, Vulnerability.affected_products
    ).all():
        if not affected:
            continue
        for prod in affected:
            if not isinstance(prod, dict):
                continue
            v = (prod.get("vendor") or "").lower().strip()
            if not v or is_vendor_excluded(v):
                continue
            idx.setdefault(v, set()).add(cve_id)
    return idx


def _build_global_vendor_counts(idx: dict[str, set[str]]) -> list[dict[str, Any]]:
    counter = Counter({v: len(s) for v, s in idx.items()})
    return [{"vendor": v, "count": c} for v, c in counter.most_common(10)]


def _build_asset_vendor_counts(
    db: Session,
    institution_id: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Top vendors / products on the actually-detected stack for active assets.

    IMPORTANT: This must come from ``AssetTechnology`` rows on the asset — the
    CVE's ``affected_products`` list belongs on the *global* vendor index,
    not here. Counting affected_products here would inflate the dashboard
    "Vendors affecting your stack" with vendored CVEs that have no link to
    the asset's actual technology footprint.

    RBAC 22 — when ``institution_id`` is set, scope to that tenant's
    active assets.
    """
    q = (
        db.query(
            AssetTechnology.vendor.label("vendor"),
            AssetTechnology.product.label("product"),
        )
        .join(Asset, Asset.id == AssetTechnology.asset_id)
        .filter(Asset.is_active.is_(True))
    )
    if institution_id is not None:
        q = q.filter(Asset.institution_id == institution_id)
    rows = q.all()
    v_counter: Counter[str] = Counter()
    p_counter: Counter[str] = Counter()
    seen_v: set[str] = set()
    seen_p: set[str] = set()
    for vendor, product in rows:
        v = (vendor or "").strip()
        p = (product or "").strip()
        if v and not is_vendor_excluded(v):
            key = v.lower()
            if key not in seen_v:
                seen_v.add(key)
                v_counter[v] += 1
        if p:
            key = p.lower()
            if key not in seen_p:
                seen_p.add(key)
                p_counter[p] += 1
    return (
        [{"vendor": v, "count": c} for v, c in v_counter.most_common(10)],
        [{"product": p, "count": c} for p, c in p_counter.most_common(10)],
    )


def _build_tech_counts(
    db: Session,
    institution_id: int | None = None,
) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    q = db.query(AssetTechnology.vendor, AssetTechnology.product)
    if institution_id is not None:
        q = q.join(
            Asset, Asset.id == AssetTechnology.asset_id
        ).filter(Asset.institution_id == institution_id)
    for row in q.all():
        if row.vendor:
            counter[f"{row.vendor}:{row.product}"] += 1
    return [{"tech": k, "count": v} for k, v in counter.most_common(10)]


def _build_recent(db: Session, limit: int = 10) -> list[dict[str, Any]]:
    rows = (
        db.query(Vulnerability)
        .order_by(desc(Vulnerability.published))
        .limit(limit)
        .all()
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "cve_id": r.cve_id,
                "title": r.title,
                "severity": r.severity.value if r.severity else None,
                "cvss_v3_score": r.cvss_v3_score,
                "published": r.published,
                "in_kev": r.in_kev,
            }
        )
    return out


def refresh(db: Session, institution_id: int | None = None) -> dict[str, Any]:
    """Rebuild the whole snapshot. Call from app startup and after bulk writes.

    Returns the new snapshot.

    RBAC 22 — when ``institution_id`` is provided, the asset-derived
    counters (total_assets, open_findings, etc.) are scoped to that
    institution. CVE-derived counters (total_cves, by_severity, kev_count,
    recent, top_vendors) stay global — CVE data is cross-tenant by
    definition. ``institution_id=None`` (default) preserves the historical
    global view.
    """
    # Severity histogram in one round-trip.
    # IMPORTANT: SQLite stores enum *values* (strings), Postgres returns
    # enum *members*. Normalise both into ``Severity`` enum members so the
    # downstream ``by_sev.get(Severity.CRITICAL, 0)`` lookup works regardless
    # of the engine — without this the dashboard's severity counts silently
    # zero out on SQLite.
    by_sev: dict[Any, int] = {}
    for raw_key, count in (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    ):
        if raw_key is None:
            continue
        if isinstance(raw_key, Severity):
            key = raw_key
        else:
            try:
                key = Severity(raw_key)
            except ValueError:
                continue
        by_sev[key] = by_sev.get(key, 0) + int(count or 0)
    for s in Severity:
        by_sev.setdefault(s, 0)

    total = db.query(Vulnerability).count()
    kev_count = db.query(Vulnerability).filter(Vulnerability.in_kev.is_(True)).count()

    excluded_ids = _build_excluded(db)
    vendor_idx = _build_vendor_index(db)
    top_vendors = _build_global_vendor_counts(vendor_idx)
    asset_v, asset_p = _build_asset_vendor_counts(db, institution_id=institution_id)
    tech = _build_tech_counts(db, institution_id=institution_id)
    recent = _build_recent(db, 10)

    asset_q = db.query(Asset)
    if institution_id is not None:
        asset_q = asset_q.filter(Asset.institution_id == institution_id)
    total_assets = asset_q.count()
    active_assets = asset_q.filter(Asset.is_active.is_(True)).count()

    finding_q = db.query(AssetFinding)
    if institution_id is not None:
        finding_q = finding_q.join(
            Asset, Asset.id == AssetFinding.asset_id
        ).filter(Asset.institution_id == institution_id)
    open_findings = finding_q.filter(AssetFinding.resolved_at.is_(None)).count()

    critical_findings = (
        finding_q.filter(AssetFinding.resolved_at.is_(None))
        .filter(AssetFinding.severity == SeverityLevel.CRITICAL)
        .count()
    )

    match_q = db.query(func.count(func.distinct(AssetCveMatch.cve_id))).join(
        Asset, Asset.id == AssetCveMatch.asset_id
    )
    if institution_id is not None:
        match_q = match_q.filter(Asset.institution_id == institution_id)
    cves_affecting_us = (
        match_q.filter(Asset.is_active.is_(True)).scalar() or 0
    )
    assets_with_critical = (
        db.query(func.count(func.distinct(AssetFinding.asset_id)))
        .filter(AssetFinding.resolved_at.is_(None))
        .filter(AssetFinding.severity == SeverityLevel.CRITICAL)
        .join(Asset, Asset.id == AssetFinding.asset_id)
        .filter(Asset.is_active.is_(True))
        .scalar()
        or 0
    )
    fbt_q = (
        db.query(AssetFinding.finding_type, func.count(AssetFinding.id))
        .filter(AssetFinding.resolved_at.is_(None))
    )
    if institution_id is not None:
        fbt_q = fbt_q.join(
            Asset, Asset.id == AssetFinding.asset_id
        ).filter(Asset.institution_id == institution_id)
    findings_by_type_rows = fbt_q.group_by(AssetFinding.finding_type).all()
    findings_by_type = {
        (ft.value if hasattr(ft, "value") else str(ft)): count
        for ft, count in findings_by_type_rows
    }

    new_state = {
        "ready": True,
        "total_cves": total,
        "by_severity": by_sev,
        "kev_count": kev_count,
        "recent": recent,
        "excluded_cve_ids": excluded_ids,
        "vendor_to_cves": vendor_idx,
        "top_vendors": top_vendors,
        "asset_top_vendors": asset_v,
        "asset_top_products": asset_p,
        "tech_counter": tech,
        "findings_by_type": findings_by_type,
        "total_assets": total_assets,
        "active_assets": active_assets,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "cves_affecting_us": cves_affecting_us,
        "assets_with_critical": assets_with_critical,
        "built_at": datetime.utcnow(),
    }
    with _lock:
        _state.clear()
        _state.update(new_state)
    return _state


def vendor_match(vendor: str) -> set[str]:
    """Return set of CVE ids whose affected_products reference ``vendor``.

    Case-insensitive prefix-free substring match against cached index.
    """
    if not vendor:
        return set()
    needle = vendor.lower().strip()
    idx = _state.get("vendor_to_cves") or {}
    # Exact match first, then prefix match (so "go" → "google", "microsoft").
    out: set[str] = set()
    if needle in idx:
        out |= idx[needle]
    for v, s in idx.items():
        if v != needle and v.startswith(needle):
            out |= s
    return out
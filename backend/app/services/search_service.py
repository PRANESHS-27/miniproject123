"""Full-text-ish search over the vulnerability table.

Performance: per-request table scans are offloaded to ``cve_index`` which
pre-computes a vendor→CVE index and the excluded-CVE set in memory.
Keyword search still hits the DB (LIKE on title/description/cve_id), but
the JSON product walk has been removed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from app.models import Severity, Vulnerability
from app.schemas.vulnerability import DashboardStats, VulnerabilitySummary
from app.services import cve_index


def search_vulnerabilities(
    db: Session,
    query: str | None = None,
    severity: str | None = None,
    in_kev: bool | None = None,
    vendor: str | None = None,
    days: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Vulnerability], int]:
    """Search the vulnerability store.

    The vendor filter and the excluded-vendor filter are served from the
    in-memory ``cve_index`` snapshot.
    """
    q = db.query(Vulnerability)

    excluded_ids = cve_index.get().get("excluded_cve_ids") or set()
    if excluded_ids:
        q = q.filter(~Vulnerability.cve_id.in_(excluded_ids))

    if query:
        # Split into per-term ANDs so "microsoft 2025" matches rows that
        # contain both words anywhere, rather than the exact phrase as one
        # LIKE. Each term still ORs across title / description / cve_id.
        terms = [t for t in query.lower().split() if t]
        for term in terms:
            pat = f"%{term}%"
            q = q.filter(
                or_(
                    func.lower(Vulnerability.cve_id).like(pat),
                    func.lower(func.coalesce(Vulnerability.title, "")).like(pat),
                    func.lower(func.coalesce(Vulnerability.description, "")).like(pat),
                )
            )

    if severity:
        try:
            q = q.filter(Vulnerability.severity == Severity(severity.upper()))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown severity: {severity}")

    if in_kev is not None:
        q = q.filter(Vulnerability.in_kev == in_kev)

    if vendor:
        matched = cve_index.vendor_match(vendor)
        if not matched:
            return [], 0
        q = q.filter(Vulnerability.cve_id.in_(matched))

    if days:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        q = q.filter(Vulnerability.published >= since)

    total = q.count()
    rows = (
        q.order_by(desc(Vulnerability.published))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def dashboard_stats(
    db: Session,
    institution_id: Optional[int] = None,
) -> DashboardStats:
    """Aggregate stats for the dashboard view.

    Served entirely from the in-memory ``cve_index`` snapshot. Falls back
    to a one-shot rebuild if the index hasn't been built yet.

    RBAC 22 — ``institution_id`` is the caller's tenant (or ``None`` for
    SUPER_ADMIN without an X-Institution-Id header). v1 keeps a single
    global snapshot for performance; non-super-admin callers see the
    global counters. A per-tenant snapshot is tracked under #19.
    """
    snap = cve_index.get()
    if not snap.get("ready"):
        cve_index.refresh(db, institution_id=institution_id)
        snap = cve_index.get()

    by_sev = snap["by_severity"]
    # Build the histogram keyed by enum *value* (the string the frontend
    # expects). ``by_sev`` is normalised to ``Severity`` enum members during
    # ``cve_index.refresh`` — but accept either form here so the endpoint
    # works on any backend version.
    severity_distribution: dict[str, int] = {}
    for s in Severity:
        val = s.value
        severity_distribution[val] = (
            by_sev.get(s, 0)
            if s in by_sev
            else by_sev.get(val, 0)
        )

    recent_objs = [VulnerabilitySummary(**r) for r in snap["recent"]]

    return DashboardStats(
        total_cves=snap["total_cves"],
        critical=by_sev.get(Severity.CRITICAL, 0),
        high=by_sev.get(Severity.HIGH, 0),
        medium=by_sev.get(Severity.MEDIUM, 0),
        low=by_sev.get(Severity.LOW, 0),
        kev_count=snap["kev_count"],
        recent_cves=recent_objs,
        top_vendors=snap["top_vendors"],
        severity_distribution=severity_distribution,
        total_assets=snap["total_assets"],
        active_assets=snap["active_assets"],
        open_findings=snap["open_findings"],
        critical_findings=snap["critical_findings"],
        cves_affecting_us=snap["cves_affecting_us"],
        findings_by_type=snap["findings_by_type"],
        tech_distribution_top=snap["tech_counter"],
        top_vendors_for_assets=snap["asset_top_vendors"],
        top_products_for_assets=snap["asset_top_products"],
    )


def get_by_cve_id(db: Session, cve_id: str) -> Vulnerability | None:
    return db.query(Vulnerability).filter_by(cve_id=cve_id.upper()).one_or_none()

"""Dashboard summary endpoint for institutional overview."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_tenant_context
from app.db import get_db
from app.db.tenant import tenant_filter
from app.models import (
    Asset,
    AssetScan,
    Finding,
    FindingRiskLabel,
    FindingStatus,
    SyncRun,
    User,
    Vulnerability,
)
from app.services.search_service import dashboard_stats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Complete security dashboard summary for the institution."""
    base_stats = dashboard_stats(db, institution_id=ctx)

    # Remediation status breakdown
    findings_q = db.query(Finding.status, func.count(Finding.id)).join(Asset)
    findings_q = tenant_filter(findings_q, Asset, ctx=ctx)
    status_counts = dict(findings_q.group_by(Finding.status).all())

    remediation_summary = {
        "open": status_counts.get(FindingStatus.OPEN, 0),
        "in_progress": status_counts.get(FindingStatus.IN_PROGRESS, 0),
        "verified": status_counts.get(FindingStatus.VERIFIED, 0),
        "resolved": status_counts.get(FindingStatus.RESOLVED, 0),
        "accepted_risk": status_counts.get(FindingStatus.ACCEPTED_RISK, 0),
    }

    # Latest synchronization runs for NVD and CISA KEV
    latest_nvd = (
        db.query(SyncRun)
        .filter(SyncRun.source == "nvd")
        .order_by(desc(SyncRun.started_at))
        .first()
    )
    latest_kev = (
        db.query(SyncRun)
        .filter(SyncRun.source == "kev")
        .order_by(desc(SyncRun.started_at))
        .first()
    )

    # Recent scans scoped to institution
    scans_q = (
        db.query(AssetScan, Asset.label, Asset.url)
        .join(Asset, AssetScan.asset_id == Asset.id)
        .order_by(desc(AssetScan.started_at))
    )
    scans_q = tenant_filter(scans_q, Asset, ctx=ctx)
    recent_scans_rows = scans_q.limit(5).all()

    recent_scans = [
        {
            "id": s.id,
            "asset_id": s.asset_id,
            "asset_label": label,
            "asset_url": url,
            "status": s.status,
            "scan_profile": getattr(s, "scan_profile", "web_standard"),
            "items_found": s.items_found,
            "inserted_count": s.inserted_count,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        }
        for s, label, url in recent_scans_rows
    ]

    # Top critical findings
    crit_q = (
        db.query(Finding, Asset.label, Asset.url)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Finding.status == FindingStatus.OPEN,
            Finding.risk_label.in_([FindingRiskLabel.CRITICAL, FindingRiskLabel.HIGH]),
        )
        .order_by(desc(Finding.risk_score))
    )
    crit_q = tenant_filter(crit_q, Asset, ctx=ctx)
    top_findings_rows = crit_q.limit(6).all()

    top_critical_findings = [
        {
            "id": f.id,
            "cve_id": f.vulnerability_cve_id,
            "asset_id": f.asset_id,
            "asset_label": label,
            "asset_url": url,
            "risk_score": f.risk_score,
            "risk_label": f.risk_label.value if f.risk_label else None,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f, label, url in top_findings_rows
    ]

    return {
        "total_assets": base_stats.total_assets,
        "active_assets": base_stats.active_assets,
        "open_findings": base_stats.open_findings,
        "critical_findings": base_stats.critical_findings,
        "cves_affecting_us": base_stats.cves_affecting_us,
        "total_cves": base_stats.total_cves,
        "kev_count": base_stats.kev_count,
        "severity_distribution": base_stats.severity_distribution,
        "remediation_summary": remediation_summary,
        "recent_scans": recent_scans,
        "top_critical_findings": top_critical_findings,
        "last_sync": {
            "nvd": {
                "started_at": latest_nvd.started_at.isoformat() if latest_nvd and latest_nvd.started_at else None,
                "finished_at": latest_nvd.finished_at.isoformat() if latest_nvd and latest_nvd.finished_at else None,
                "status": latest_nvd.status if latest_nvd else "never",
                "items_fetched": latest_nvd.items_fetched if latest_nvd else 0,
            } if latest_nvd else None,
            "kev": {
                "started_at": latest_kev.started_at.isoformat() if latest_kev and latest_kev.started_at else None,
                "finished_at": latest_kev.finished_at.isoformat() if latest_kev and latest_kev.finished_at else None,
                "status": latest_kev.status if latest_kev else "never",
                "items_fetched": latest_kev.items_fetched if latest_kev else 0,
            } if latest_kev else None,
        },
    }

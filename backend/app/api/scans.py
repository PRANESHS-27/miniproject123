"""Centralized scans API router."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_user,
    get_tenant_context,
    require_permission,
)
from app.db import SessionLocal, get_db
from app.db.tenant import tenant_filter
from app.models import Asset, AssetFinding, AssetScan, Finding, User
from app.scanner.orchestrator import run_orchestrated_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

# In-process set of asset IDs currently being scanned to prevent concurrent races
_active_scans: set[int] = set()


class ScanRequest(BaseModel):
    asset_id: int
    profile: str = Field(default="web_standard", description="Scan profile: quick, web_standard, network_discovery, vulnerability_audit, full")


def _run_scan_task(asset_id: int, profile: str, actor_username: str) -> None:
    db = SessionLocal()
    try:
        run_orchestrated_scan(
            db,
            asset_id,
            profile=profile,
            triggered_by="manual",
            actor_username=actor_username,
        )
    finally:
        _active_scans.discard(asset_id)
        db.close()


@router.get("")
def list_scans(
    status_filter: Optional[str] = Query(None, alias="status"),
    asset_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """List all scans for the institution with optional status/asset filters."""
    q = (
        db.query(AssetScan, Asset.label, Asset.url)
        .join(Asset, AssetScan.asset_id == Asset.id)
        .order_by(desc(AssetScan.started_at))
    )
    q = tenant_filter(q, Asset, ctx=ctx)

    if status_filter:
        q = q.filter(AssetScan.status == status_filter)
    if asset_id:
        q = q.filter(AssetScan.asset_id == asset_id)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = []
    for s, label, url in rows:
        duration_s = None
        if s.finished_at and s.started_at:
            duration_s = round((s.finished_at - s.started_at).total_seconds(), 1)
        items.append({
            "id": s.id,
            "asset_id": s.asset_id,
            "asset_label": label,
            "asset_url": url,
            "status": s.status,
            "scan_profile": getattr(s, "scan_profile", "web_standard"),
            "items_found": s.items_found,
            "inserted_count": s.inserted_count,
            "re_seen_count": s.re_seen_count,
            "closed_count": s.closed_count,
            "technologies_detected": s.technologies_detected,
            "cves_matched": s.cves_matched,
            "error": s.error,
            "triggered_by": s.triggered_by,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "duration_seconds": duration_s,
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("asset", "scan")),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Queue a scan for an authorized institution asset."""
    # Ensure asset belongs to caller's tenant
    asset_q = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.is_active.is_(True))
    asset_q = tenant_filter(asset_q, Asset, ctx=ctx)
    asset = asset_q.first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found or not active")

    if payload.asset_id in _active_scans:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan already in progress for asset {asset.label}",
        )

    _active_scans.add(payload.asset_id)
    background_tasks.add_task(
        _run_scan_task,
        payload.asset_id,
        payload.profile,
        user.username,
    )

    return {
        "status": "queued",
        "asset_id": payload.asset_id,
        "asset_label": asset.label,
        "asset_url": asset.url,
        "profile": payload.profile,
        "message": f"Scan job queued for {asset.label} using {payload.profile} profile",
    }


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Retrieve full details of a specific scan."""
    q = (
        db.query(AssetScan, Asset.label, Asset.url)
        .join(Asset, AssetScan.asset_id == Asset.id)
        .filter(AssetScan.id == scan_id)
    )
    q = tenant_filter(q, Asset, ctx=ctx)
    row = q.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    s, label, url = row
    duration_s = None
    if s.finished_at and s.started_at:
        duration_s = round((s.finished_at - s.started_at).total_seconds(), 1)

    return {
        "id": s.id,
        "asset_id": s.asset_id,
        "asset_label": label,
        "asset_url": url,
        "status": s.status,
        "scan_profile": getattr(s, "scan_profile", "web_standard"),
        "raw_output": getattr(s, "raw_output", {}) or {},
        "items_found": s.items_found,
        "inserted_count": s.inserted_count,
        "re_seen_count": s.re_seen_count,
        "closed_count": s.closed_count,
        "technologies_detected": s.technologies_detected,
        "cves_matched": s.cves_matched,
        "error": s.error,
        "triggered_by": s.triggered_by,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "duration_seconds": duration_s,
    }


@router.get("/{scan_id}/findings")
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> list[dict[str, Any]]:
    """Get raw findings observed for the asset of this scan."""
    q = (
        db.query(AssetScan, Asset.id)
        .join(Asset, AssetScan.asset_id == Asset.id)
        .filter(AssetScan.id == scan_id)
    )
    q = tenant_filter(q, Asset, ctx=ctx)
    row = q.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, asset_id = row
    findings = (
        db.query(AssetFinding)
        .filter(AssetFinding.asset_id == asset_id)
        .order_by(desc(AssetFinding.discovered_at))
        .limit(100)
        .all()
    )

    return [
        {
            "id": f.id,
            "asset_id": f.asset_id,
            "finding_type": f.finding_type.value,
            "severity": f.severity.value,
            "title": f.title,
            "details": f.details or {},
            "remediation": f.remediation,
            "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
            "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        }
        for f in findings
    ]

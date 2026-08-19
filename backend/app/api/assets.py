"""Asset-driven vulnerability monitoring routes.

Endpoints:
  POST   /api/assets                admin: create asset
  GET    /api/assets                any user: list with summary counts
  GET    /api/assets/{id}           any user: detail (techs + counts)
  PATCH  /api/assets/{id}           admin: update
  DELETE /api/assets/{id}           admin: soft-delete (is_active=False)
  POST   /api/assets/{id}/scan      admin: trigger scan in background
  GET    /api/assets/{id}/findings  any user: list findings, filterable
  PATCH  /api/assets/{id}/findings/{fid}/resolve   admin: mark resolved
  GET    /api/assets/{id}/cves      any user: matched CVEs sorted by CVSS
  GET    /api/assets/scans/recent   admin: recent scan history
  GET    /api/assets/stats          any user: dashboard counters
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin, require_permission
from app.db import SessionLocal, get_db
from app.models import (
    Asset,
    AssetCveMatch,
    AssetFinding,
    AssetScan,
    AssetTechnology,
    FindingType,
    SeverityLevel,
    User,
    Vulnerability,
)
from app.schemas.asset import (
    AssetCreate,
    AssetCveMatchOut,
    AssetFindingOut,
    AssetListItem,
    AssetOut,
    AssetScanOut,
    AssetStats,
    AssetTechnologyOut,
    AssetUpdate,
    ScanTriggerResponse,
)

router = APIRouter(prefix="/api/assets", tags=["assets"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _asset_to_list_item(db: Session, asset: Asset) -> AssetListItem:
    """Compute summary counts without heavy joins."""
    open_q = db.query(AssetFinding).filter(
        AssetFinding.asset_id == asset.id,
        AssetFinding.resolved_at.is_(None),
    )
    open_count = open_q.count()
    critical_count = (
        open_q.filter(AssetFinding.severity == SeverityLevel.CRITICAL).count()
    )
    cves_count = (
        db.query(func.count(func.distinct(AssetCveMatch.cve_id)))
        .filter(AssetCveMatch.asset_id == asset.id)
        .scalar()
        or 0
    )
    return AssetListItem(
        id=asset.id,
        label=asset.label,
        url=asset.url,
        env=asset.env,
        is_active=asset.is_active,
        tags=asset.tags or [],
        created_at=asset.created_at,
        last_scanned_at=asset.last_scanned_at,
        last_scan_status=asset.last_scan_status,
        open_findings_count=open_count,
        critical_findings_count=critical_count,
        cves_matched_count=cves_count,
    )


def _asset_to_detail(db: Session, asset: Asset) -> AssetOut:
    techs = (
        db.query(AssetTechnology)
        .filter(AssetTechnology.asset_id == asset.id)
        .order_by(desc(AssetTechnology.confidence), AssetTechnology.vendor)
        .all()
    )
    summary = _asset_to_list_item(db, asset)
    return AssetOut(
        id=asset.id,
        label=asset.label,
        url=asset.url,
        env=asset.env,
        is_active=asset.is_active,
        tags=asset.tags or [],
        created_at=asset.created_at,
        last_scanned_at=asset.last_scanned_at,
        last_scan_status=asset.last_scan_status,
        technologies=[AssetTechnologyOut.model_validate(t) for t in techs],
        open_findings_count=summary.open_findings_count,
        critical_findings_count=summary.critical_findings_count,
        cves_matched_count=summary.cves_matched_count,
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
@router.post("", response_model=AssetOut)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

    # Strip platform-tracking query strings (Vercel share, etc.) so the
    # scanner hits the app and not the platform's SSO interstitial.
    raw_url = payload.url
    parts = urlsplit(raw_url)
    if parts.query:
        kept = [
            (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not k.startswith("_vercel")
        ]
        raw_url = urlunsplit(parts._replace(query=urlencode(kept)))

    existing = db.query(Asset).filter(Asset.url == raw_url).one_or_none()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Asset already exists: {raw_url}",
        )
    asset = Asset(
        owner_id=user.id,
        label=payload.label,
        url=raw_url,
        env=payload.env,
        tags=payload.tags or [],
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_to_detail(db, asset)


@router.get("", response_model=list[AssetListItem])
def list_assets(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    include_inactive: bool = Query(False),
):
    q = db.query(Asset)
    if not include_inactive:
        q = q.filter(Asset.is_active.is_(True))
    rows = q.order_by(Asset.label.asc()).all()
    return [_asset_to_list_item(db, a) for a in rows]


@router.get("/stats", response_model=AssetStats)
def get_asset_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    # Read from the same in-memory cve_index snapshot the dashboard uses
    # so the two pages always agree. Falls back to a one-shot rebuild if
    # the index hasn't been built yet. Without this the assets page and
    # the dashboard could disagree on aggregate counts (e.g. when a scan
    # just finished but the index hasn't been refreshed yet).
    from app.services import cve_index
    snap = cve_index.get()
    if not snap.get("ready"):
        cve_index.refresh(db)
        snap = cve_index.get()

    return AssetStats(
        total_assets=snap["total_assets"],
        active_assets=snap["active_assets"],
        open_findings=snap["open_findings"],
        critical_findings=snap["critical_findings"],
        cves_affecting_us=snap["cves_affecting_us"],
        assets_with_critical=snap.get("assets_with_critical", 0),
        findings_by_type=snap["findings_by_type"],
        tech_distribution_top=snap["tech_counter"],
    )


@router.get("/scans/recent", response_model=list[AssetScanOut])
def recent_scans(
    db: Session = Depends(get_db),
    _user: User = Depends(require_admin),
    limit: int = Query(50, ge=1, le=200),
):
    rows = db.query(AssetScan).order_by(desc(AssetScan.started_at)).limit(limit).all()
    return [AssetScanOut.model_validate(r) for r in rows]


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_detail(db, asset)


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_admin),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    data = payload.model_dump(exclude_unset=True)
    if "url" in data and data["url"]:
        dup = db.query(Asset).filter(Asset.url == data["url"], Asset.id != asset_id).first()
        if dup:
            raise HTTPException(status_code=409, detail="Another asset already uses that URL")
    for k, v in data.items():
        setattr(asset, k, v)
    db.commit()
    db.refresh(asset)
    # Refresh the index if is_active / env changed — these affect the
    # active_assets count and tech distribution shown on the dashboard.
    if "is_active" in data or "env" in data:
        try:
            from app.services import cve_index
            cve_index.refresh(db)
        except Exception:  # pragma: no cover
            pass
    return _asset_to_detail(db, asset)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_admin),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.is_active = False
    db.commit()
    # active_assets / tech distribution / cves_affecting_us all change when
    # an asset is deactivated — refresh so the dashboard reflects it.
    try:
        from app.services import cve_index
        cve_index.refresh(db)
    except Exception:  # pragma: no cover
        pass
    return {"status": "ok", "asset_id": asset_id, "is_active": False}


# ---------------------------------------------------------------------------
# Scan trigger
# ---------------------------------------------------------------------------
# Tracks scans currently being scanned in this process so the user can't
# accidentally fire two concurrent scans against the same URL.
_active_scans: set[int] = set()


def _has_running_scan(db: Session, asset_id: int) -> bool:
    """Authoritative check across processes/workers. ``AssetScan.status``
    is set to ``running`` when a scan starts and cleared to ``success``
    or ``failed`` when it finishes."""
    from sqlalchemy import exists, select

    stmt = select(
        exists().where(
            AssetScan.asset_id == asset_id,
            AssetScan.status == "running",
        )
    )
    return bool(db.execute(stmt).scalar())


def _run_asset_scan(asset_id: int) -> None:
    db = SessionLocal()
    try:
        from app.services.asset_scanner import scan_one_asset

        scan_one_asset(db, asset_id, triggered_by="manual")
    finally:
        _active_scans.discard(asset_id)
        db.close()


@router.post("/{asset_id}/scan", response_model=ScanTriggerResponse)
def trigger_scan(
    asset_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("asset", "scan")),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    # Fast-path: in-process check (cheap, no DB round-trip).
    if asset_id in _active_scans:
        raise HTTPException(
            status_code=409,
            detail="Scan already in progress for this asset. Please wait.",
        )
    # Authoritative check via DB (covers multi-worker / multi-process).
    if _has_running_scan(db, asset_id):
        raise HTTPException(
            status_code=409,
            detail="Scan already in progress for this asset (across workers).",
        )
    _active_scans.add(asset_id)
    background.add_task(_run_asset_scan, asset_id)
    return ScanTriggerResponse(
        status="started", job="asset_scan", asset_id=asset_id,
        message="Scan started. Findings will appear within ~10-30 seconds.",
    )


# ---------------------------------------------------------------------------
# Findings & CVEs
# ---------------------------------------------------------------------------
@router.get("/{asset_id}/findings", response_model=list[AssetFindingOut])
def list_findings(
    asset_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    type: Optional[str] = Query(None, description="Filter by finding_type"),
    severity: Optional[str] = Query(None),
    include_resolved: bool = Query(False),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    q = db.query(AssetFinding).filter(AssetFinding.asset_id == asset_id)
    if not include_resolved:
        q = q.filter(AssetFinding.resolved_at.is_(None))
    if type:
        try:
            q = q.filter(AssetFinding.finding_type == FindingType(type))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown finding_type: {type}")
    if severity:
        try:
            q = q.filter(AssetFinding.severity == SeverityLevel(severity.upper()))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown severity: {severity}")
    rows = q.order_by(desc(AssetFinding.discovered_at)).limit(500).all()
    out: list[AssetFindingOut] = []
    for r in rows:
        out.append(AssetFindingOut(
            id=r.id,
            finding_type=r.finding_type.value if hasattr(r.finding_type, "value") else str(r.finding_type),
            severity=r.severity.value if hasattr(r.severity, "value") else str(r.severity),
            title=r.title,
            details=r.details,
            remediation=r.remediation,
            discovered_at=r.discovered_at,
            resolved_at=r.resolved_at,
            last_seen_at=r.last_seen_at,
        ))
    return out


@router.patch("/{asset_id}/findings/{finding_id}/resolve")
def resolve_finding(
    asset_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("asset_finding", "resolve")),
):
    f = (
        db.query(AssetFinding)
        .filter(AssetFinding.id == finding_id, AssetFinding.asset_id == asset_id)
        .one_or_none()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.resolved_at = datetime.now(timezone.utc)
    db.commit()
    # The dashboard's open_findings / critical_findings counters come from
    # the in-memory cve_index snapshot. Refresh it so the user sees the
    # number drop on the next dashboard request rather than next reload.
    try:
        from app.services import cve_index
        cve_index.refresh(db)
    except Exception:  # pragma: no cover - never fail a resolve over the cache
        pass
    return {"status": "ok", "finding_id": finding_id}


@router.get("/{asset_id}/cves", response_model=list[AssetCveMatchOut])
def list_asset_cves(
    asset_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    tech_by_id = {
        t.id: t for t in db.query(AssetTechnology).filter(AssetTechnology.asset_id == asset_id).all()
    }
    matches = (
        db.query(AssetCveMatch)
        .filter(AssetCveMatch.asset_id == asset_id)
        .order_by(desc(AssetCveMatch.matched_at))
        .all()
    )
    cve_ids = [m.cve_id for m in matches]
    cve_rows: dict[str, Vulnerability] = {}
    if cve_ids:
        for c in db.query(Vulnerability).filter(Vulnerability.cve_id.in_(cve_ids)).all():
            cve_rows[c.cve_id] = c

    out: list[AssetCveMatchOut] = []
    for m in matches:
        tech = tech_by_id.get(m.technology_id)
        cve = cve_rows.get(m.cve_id)
        out.append(AssetCveMatchOut(
            cve_id=m.cve_id,
            matched_at=m.matched_at,
            technology_vendor=tech.vendor if tech else None,
            technology_product=tech.product if tech else None,
            cve_severity=cve.severity.value if cve and cve.severity else None,
            cve_cvss_v3_score=cve.cvss_v3_score if cve else None,
            cve_title=cve.title if cve else None,
        ))
    out.sort(
        key=lambda r: (r.cve_cvss_v3_score or 0),
        reverse=True,
    )
    return out
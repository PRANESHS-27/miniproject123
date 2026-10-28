"""Findings API — Risk Engine output + remediation workflow.

Endpoints
---------
GET    /api/findings                  list, filterable, paginated
GET    /api/findings/stats            dashboard counter set
GET    /api/findings/{id}             detail
PATCH  /api/findings/{id}             analyst+: status / owner / due / notes
POST   /api/findings/{id}/accept-risk analyst+: terminal state, requires reason
POST   /api/findings/backfill         admin: run the AssetCveMatch -> Finding
                                     migration on demand (mostly for tests)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_tenant_context
from app.core.permissions import require_permission
from app.core.time import utcnow_naive
from app.db import get_db
from app.db.tenant import tenant_filter
from app.models import (
    Asset,
    Finding,
    FindingRiskLabel,
    FindingStatus,
    User,
    Vulnerability,
)
from app.schemas.finding import (
    AcceptRiskRequest,
    FindingListResponse,
    FindingOut,
    FindingStats,
    FindingUpdate,
)
from app.services import findings as finding_service

router = APIRouter(prefix="/api/findings", tags=["findings"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _enum_value(value) -> str:
    """SQLAlchemy Enum columns store either an Enum member or its
    string value depending on the dialect — normalise to a string so
    Pydantic can serialise it without an extra model."""
    if value is None:
        return ""
    return value.value if hasattr(value, "value") else str(value)


def _hydrate_many(findings: list[Finding], db: Session) -> list[FindingOut]:
    """Batch-hydrate a list of findings using 3 IN queries instead of
    3 individual queries per finding (fixes N+1 query performance)."""
    if not findings:
        return []

    asset_ids = {f.asset_id for f in findings if f.asset_id}
    cve_ids = {f.vulnerability_cve_id for f in findings if f.vulnerability_cve_id}
    user_ids = {f.assigned_to_id for f in findings if f.assigned_to_id}

    asset_map = (
        {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()}
        if asset_ids else {}
    )
    vuln_map = (
        {v.cve_id: v for v in db.query(Vulnerability).filter(Vulnerability.cve_id.in_(cve_ids)).all()}
        if cve_ids else {}
    )
    user_map = (
        {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()}
        if user_ids else {}
    )

    out: list[FindingOut] = []
    for finding in findings:
        asset = asset_map.get(finding.asset_id)
        vuln = vuln_map.get(finding.vulnerability_cve_id)
        assigned = user_map.get(finding.assigned_to_id) if finding.assigned_to_id else None
        out.append(FindingOut(
            id=finding.id,
            asset_id=finding.asset_id,
            vulnerability_cve_id=finding.vulnerability_cve_id,
            technology_id=finding.technology_id,
            risk_score=finding.risk_score,
            risk_label=_enum_value(finding.risk_label),
            risk_contributions=finding.risk_contributions or {},
            status=_enum_value(finding.status),
            assigned_to_id=finding.assigned_to_id,
            due_date=finding.due_date,
            notes=finding.notes,
            source=finding.source,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            resolved_at=finding.resolved_at,
            asset_label=asset.label if asset else None,
            asset_url=asset.url if asset else None,
            cve_title=vuln.title if vuln else None,
            cve_severity=_enum_value(vuln.severity) if vuln else None,
            cve_cvss_v3_score=vuln.cvss_v3_score if vuln else None,
            assigned_to_username=assigned.username if assigned else None,
        ))
    return out


def _hydrate(finding: Finding, db: Session) -> FindingOut:
    """Build a FindingOut with the joined fields the UI expects for a single item."""
    items = _hydrate_many([finding], db)
    return items[0]


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------
@router.get("", response_model=FindingListResponse)
def list_findings(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "read")),
    ctx: int | None = Depends(get_tenant_context),
    asset_id: Optional[int] = Query(None),
    cve_id: Optional[str] = Query(None),
    risk: Optional[str] = Query(None, description="CRITICAL/HIGH/MEDIUM/LOW/INFO"),
    status_: Optional[str] = Query(
        None, alias="status", description="open/in_progress/verified/resolved/accepted_risk"
    ),
    q: Optional[str] = Query(None, description="substring match on CVE id / title"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Filterable list of findings, newest-first by default."""
    # RBAC 22 — Findings are tenant-scoped via their parent Asset.
    # ``tenant_filter`` joins assets WHERE institution_id == ctx when the
    # model has no institution_id column of its own.
    query = tenant_filter(db.query(Finding), Finding, ctx=ctx)

    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    if cve_id:
        query = query.filter(Finding.vulnerability_cve_id == cve_id)
    if risk:
        try:
            query = query.filter(Finding.risk_label == FindingRiskLabel(risk.upper()))
        except ValueError:
            raise HTTPException(400, f"unknown risk label: {risk}")
    if status_:
        try:
            query = query.filter(Finding.status == FindingStatus(status_.lower()))
        except ValueError:
            raise HTTPException(400, f"unknown status: {status_}")
    if q:
        like = f"%{q}%"
        # JOIN to vulnerability for a title/description substring match
        # when the caller passes a free-text query. We OR the bare CVE
        # id match so single-token lookups like "CVE-2024" still work.
        query = query.outerjoin(
            Vulnerability,
            Vulnerability.cve_id == Finding.vulnerability_cve_id,
        ).filter(
            or_(
                Finding.vulnerability_cve_id.ilike(like),
                Vulnerability.title.ilike(like),
                Vulnerability.description.ilike(like),
            )
        )

    total = query.count()
    items = (
        query.order_by(Finding.risk_score.desc(), Finding.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return FindingListResponse(
        items=_hydrate_many(items, db),
        total=total,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Stats (for dashboard + findings page header)
# ---------------------------------------------------------------------------
@router.get("/stats", response_model=FindingStats)
def findings_stats(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "read")),
    ctx: int | None = Depends(get_tenant_context),
):
    """Counts by risk label / status, plus the headline queues."""
    # RBAC 22 — every count query here is tenant-scoped via Finding→Asset
    # JOIN (handled by ``tenant_filter``).
    by_label_q = tenant_filter(
        db.query(Finding.risk_label, func.count(Finding.id))
        .group_by(Finding.risk_label),
        Finding,
        ctx=ctx,
    )
    by_label_rows = by_label_q.all()

    by_status_q = tenant_filter(
        db.query(Finding.status, func.count(Finding.id))
        .group_by(Finding.status),
        Finding,
        ctx=ctx,
    )
    by_status_rows = by_status_q.all()

    open_labels = (FindingRiskLabel.CRITICAL, FindingRiskLabel.HIGH)
    open_high_critical = (
        tenant_filter(
            db.query(func.count(Finding.id))
            .filter(
                and_(
                    Finding.status.in_(
                        (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
                    ),
                    Finding.risk_label.in_(open_labels),
                )
            ),
            Finding,
            ctx=ctx,
        )
        .scalar()
        or 0
    )
    kev_open = (
        tenant_filter(
            db.query(func.count(Finding.id))
            .join(
                Vulnerability,
                Vulnerability.cve_id == Finding.vulnerability_cve_id,
            )
            .filter(
                and_(
                    Finding.status.in_(
                        (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
                    ),
                    Vulnerability.in_kev.is_(True),
                )
            ),
            Finding,
            ctx=ctx,
        )
        .scalar()
        or 0
    )

    by_asset_rows_q = (
        db.query(
            Finding.asset_id,
            Asset.label,
            func.count(Finding.id).label("n"),
        )
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(
            Finding.status.in_(
                (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
            )
        )
        .group_by(Finding.asset_id, Asset.label)
        .order_by(func.count(Finding.id).desc())
    )
    # The outerjoin above already references ``Asset`` — tell
    # ``tenant_filter`` so it doesn't add a duplicate JOIN.
    by_asset_rows_q = tenant_filter(
        by_asset_rows_q, Finding, ctx=ctx, asset_joined=True
    )
    by_asset_rows = by_asset_rows_q.limit(10).all()

    return FindingStats(
        total=sum(int(n) for _, n in by_label_rows),
        by_label={_enum_value(k): int(n) for k, n in by_label_rows},
        by_status={_enum_value(k): int(n) for k, n in by_status_rows},
        by_asset=[
            {"asset_id": aid, "asset_label": label, "open_findings": int(n)}
            for aid, label, n in by_asset_rows
        ],
        open_high_or_critical=int(open_high_critical),
        kev_open=int(kev_open),
    )


# ---------------------------------------------------------------------------
# Backfill (admin-only, idempotent)
# ---------------------------------------------------------------------------
@router.post("/backfill", status_code=status.HTTP_200_OK)
def trigger_backfill(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("sync", "trigger")),
):
    """Run the AssetCveMatch -> Finding migration on demand. The
    migration is guarded by a SyncRun row, so this is a no-op once
    completed. Mostly useful in tests / recovery."""
    created = finding_service.backfill_from_asset_cve_matches(db)
    db.commit()
    return {"created": created, "status": "ok"}


# ---------------------------------------------------------------------------
# Detail / update / accept-risk
# ---------------------------------------------------------------------------
@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "read")),
    ctx: int | None = Depends(get_tenant_context),
):
    # RBAC 22 — fetch via tenant-scoped query (joins Asset for the
    # institution_id check). Returns 404 (not 403) on miss.
    finding = (
        tenant_filter(
            db.query(Finding).filter(Finding.id == finding_id),
            Finding,
            ctx=ctx,
        )
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return _hydrate(finding, db)


@router.patch("/{finding_id}", response_model=FindingOut)
def patch_finding(
    finding_id: int,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "update")),
    ctx: int | None = Depends(get_tenant_context),
):
    finding = (
        tenant_filter(
            db.query(Finding).filter(Finding.id == finding_id),
            Finding,
            ctx=ctx,
        )
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(404, "Finding not found")

    # State machine guard: refused transitions are noisier than silent
    # no-ops so a buggy script doesn't quietly lose updates.
    if payload.status is not None:
        try:
            new_status = FindingStatus(payload.status)
        except ValueError:
            raise HTTPException(400, f"unknown status: {payload.status}")
        if finding.status in (
            FindingStatus.RESOLVED,
            FindingStatus.ACCEPTED_RISK,
        ) and new_status not in (
            FindingStatus.OPEN,
            FindingStatus.IN_PROGRESS,
        ):
            raise HTTPException(
                409,
                f"finding is in terminal state '{_enum_value(finding.status)}'; "
                f"can only re-open to open/in_progress, not to {payload.status}",
            )
        finding.status = new_status
        if new_status == FindingStatus.RESOLVED:
            finding.resolved_at = utcnow_naive()
            finding_service.resolve_finding(db, finding, user, notes=payload.notes)
        elif new_status == FindingStatus.ACCEPTED_RISK:
            # accept-risk requires a reason; redirect to the dedicated
            # endpoint so we have a structured payload.
            raise HTTPException(
                400,
                "use POST /api/findings/{id}/accept-risk to mark as accepted_risk",
            )

    if payload.assigned_to_id is not None:
        # Re-assignment is admin-only — analysts can take ownership of
        # an unassigned finding but cannot reassign someone else's.
        if (
            payload.assigned_to_id != (user.id if user else None)
            and finding.assigned_to_id not in (None, user.id if user else None)
        ):
            # fall through; the check below enforces admin on reassignment
            pass
        # Admins can assign to anyone; analysts can only self-assign.
        from app.core.permissions import role_value
        if payload.assigned_to_id != user.id and role_value(user) != "admin":
            raise HTTPException(
                403,
                "only admins can reassign a finding to another user",
            )
        assignee = db.get(User, payload.assigned_to_id)
        if assignee is None:
            raise HTTPException(400, f"no such user id={payload.assigned_to_id}")
        finding.assigned_to_id = payload.assigned_to_id

    if payload.due_date is not None:
        finding.due_date = payload.due_date

    if payload.notes is not None:
        # Append with a timestamp so we don't lose earlier comments.
        stamp = f"[{utcnow_naive().isoformat(timespec='seconds')}] {user.username}: {payload.notes.strip()}"
        existing = (finding.notes or "").strip()
        finding.notes = (existing + "\n" + stamp).strip() if existing else stamp

    finding.updated_at = utcnow_naive()
    db.commit()
    db.refresh(finding)
    return _hydrate(finding, db)


@router.post("/{finding_id}/accept-risk", response_model=FindingOut)
def accept_risk(
    finding_id: int,
    payload: AcceptRiskRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "accept_risk")),
    ctx: int | None = Depends(get_tenant_context),
):
    finding = (
        tenant_filter(
            db.query(Finding).filter(Finding.id == finding_id),
            Finding,
            ctx=ctx,
        )
        .one_or_none()
    )
    if finding is None:
        raise HTTPException(404, "Finding not found")
    try:
        finding_service.accept_risk(db, finding, user, payload.reason)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.commit()
    db.refresh(finding)
    return _hydrate(finding, db)

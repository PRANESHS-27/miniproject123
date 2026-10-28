"""Vulnerability search & dashboard routes."""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_tenant_context
from app.db import get_db
from app.models import User
from app.schemas.vulnerability import (
    DashboardStats,
    SearchResponse,
    VulnerabilityDetail,
)
from app.services.search_service import dashboard_stats, get_by_cve_id, search_vulnerabilities

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
):
    """Aggregated stats for the dashboard view.

    RBAC 22 — ``ctx`` is the caller's institution id (or ``None`` for
    SUPER_ADMIN without a header). Asset-derived counters scope by it;
    CVE-derived counters stay global (CVE data is cross-tenant).
    """
    return dashboard_stats(db, institution_id=ctx)


def _log_search(user_id: int, query: str, total: int) -> None:
    from app.db import SessionLocal
    from app.models import SearchLog
    db = SessionLocal()
    try:
        db.add(SearchLog(user_id=user_id, query=query, result_count=total, source="sql"))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()


@router.get("/search", response_model=SearchResponse)
def search(
    background_tasks: BackgroundTasks,
    q: Optional[str] = Query(None, description="Free-text query"),
    severity: Optional[str] = None,
    in_kev: Optional[bool] = None,
    vendor: Optional[str] = None,
    days: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Search the vulnerability store with optional filters."""
    rows, total = search_vulnerabilities(
        db,
        query=q,
        severity=severity,
        in_kev=in_kev,
        vendor=vendor,
        days=days,
        limit=limit,
        offset=offset,
    )
    # Log the search query asynchronously without blocking the response
    if q:
        background_tasks.add_task(_log_search, user.id, q, total)

    return SearchResponse(
        query=q or "",
        total=total,
        results=[VulnerabilityDetail.model_validate(r) for r in rows],
    )


@router.get("/{cve_id}", response_model=VulnerabilityDetail)
def get_vulnerability(
    cve_id: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return the full detail for a single CVE."""
    vuln = get_by_cve_id(db, cve_id)
    if not vuln:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return vuln

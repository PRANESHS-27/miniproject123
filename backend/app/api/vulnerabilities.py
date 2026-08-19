"""Vulnerability search & dashboard routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
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
):
    """Aggregated stats for the dashboard view."""
    return dashboard_stats(db)


@router.get("/search", response_model=SearchResponse)
def search(
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
    # Log the search query for audit
    from app.models import SearchLog

    db.add(
        SearchLog(
            user_id=user.id,
            query=q or "",
            result_count=total,
            source="sql",
        )
    )
    db.commit()
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

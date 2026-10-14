"""Alerts API router."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_tenant_context, require_permission
from app.db import get_db
from app.models import Alert, Asset, User

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    unread_only: bool = False,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """List security alerts scoped to caller's institution."""
    q = db.query(Alert).filter(Alert.is_dismissed.is_(False))
    if ctx is not None:
        q = q.filter(Alert.institution_id == ctx)

    if unread_only:
        q = q.filter(Alert.is_read.is_(False))
    if severity:
        q = q.filter(Alert.severity == severity.upper())

    total = q.count()
    alerts = q.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()

    return {
        "items": [a.to_dict() for a in alerts],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/summary")
def get_alerts_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Get counts of active and unread alerts."""
    q = db.query(Alert).filter(Alert.is_dismissed.is_(False))
    if ctx is not None:
        q = q.filter(Alert.institution_id == ctx)

    total_active = q.count()
    unread_count = q.filter(Alert.is_read.is_(False)).count()
    critical_count = q.filter(Alert.severity == "CRITICAL", Alert.is_read.is_(False)).count()

    return {
        "active_alerts": total_active,
        "unread_alerts": unread_count,
        "critical_unread": critical_count,
    }


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "update")),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Mark an alert as read / acknowledged."""
    q = db.query(Alert).filter(Alert.id == alert_id)
    if ctx is not None:
        q = q.filter(Alert.institution_id == ctx)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_read = True
    db.commit()
    return alert.to_dict()


@router.post("/{alert_id}/dismiss")
def dismiss_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("finding", "update")),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Dismiss an alert from the active view."""
    q = db.query(Alert).filter(Alert.id == alert_id)
    if ctx is not None:
        q = q.filter(Alert.institution_id == ctx)
    alert = q.first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_dismissed = True
    alert.is_read = True
    db.commit()
    return {"message": "Alert dismissed", "id": alert_id}

"""Unified security audit logs API router."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_tenant_context, require_admin
from app.db import get_db
from app.models import AuditLog, LoginAudit, User

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("")
def list_audit_logs(
    category: str = Query("all", description="Event category: all, security, login, scan"),
    actor: Optional[str] = None,
    outcome: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
    ctx: int | None = Depends(get_tenant_context),
) -> dict[str, Any]:
    """Retrieve audit logs for institutional compliance and security observability."""
    results = []

    # If login logs requested or 'all'
    if category in ("all", "login"):
        login_q = db.query(LoginAudit).order_by(desc(LoginAudit.created_at))
        if actor:
            login_q = login_q.filter(LoginAudit.username == actor)
        if outcome:
            login_q = login_q.filter(LoginAudit.outcome == outcome)
        login_rows = login_q.limit(limit).all()
        for r in login_rows:
            results.append({
                "id": f"login-{r.id}",
                "timestamp": r.created_at.isoformat() if r.created_at else None,
                "actor": r.username,
                "action": "auth:login",
                "resource_type": "user",
                "resource_id": str(r.user_id) if r.user_id else None,
                "ip": r.ip,
                "outcome": r.outcome,
                "details": {"user_agent": r.user_agent},
            })

    # If general audit logs requested or 'all'
    if category in ("all", "security", "scan"):
        audit_q = db.query(AuditLog)
        if ctx is not None:
            audit_q = audit_q.filter(AuditLog.institution_id == ctx)
        if actor:
            audit_q = audit_q.filter(AuditLog.actor_username == actor)
        if outcome:
            audit_q = audit_q.filter(AuditLog.outcome == outcome)
        if category == "scan":
            audit_q = audit_q.filter(AuditLog.resource_type == "scan")

        audit_rows = audit_q.order_by(desc(AuditLog.created_at)).limit(limit).all()
        for r in audit_rows:
            results.append({
                "id": f"audit-{r.id}",
                "timestamp": r.created_at.isoformat() if r.created_at else None,
                "actor": r.actor_username,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "ip": r.ip,
                "outcome": r.outcome,
                "details": r.details or {},
            })

    # Sort combined results descending by timestamp
    results.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    paged = results[offset : offset + limit]

    return {
        "items": paged,
        "total": len(results),
        "limit": limit,
        "offset": offset,
    }

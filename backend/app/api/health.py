"""Health + readiness probes (free-priority #19).

Two-tier probe:

  * ``GET /health``  — anonymous liveness probe, always 200 if the
    process is up. Safe for Kubernetes / load balancers. Does NOT
    check dependencies (a DB outage shouldn't cause k8s to restart
    the pod; the app is still alive, just degraded).

  * ``GET /api/health/status`` — authenticated readiness probe,
    super_admin only. Pings the DB, checks cve_index readiness,
    reads scheduler status, and reports per-sync-source staleness.
    Returns ``503`` when the DB is unreachable so an operator /
    uptime monitor can alert.

The split exists because public probes (Kubernetes ``livenessProbe``,
monitoring uptime checks) must never require credentials, but the
detailed readiness view is privileged information — it leaks which
syncs are stale and how many assets we have.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.permissions import require_permission
from app.db import get_db
from app.db.session import engine
from app.models import Asset, Institution, SyncRun, User

# cve_index is a lazy import — importing it at module top would force
# the module to load during cold-start before the lifespan hook has
# seeded the default institution, and it has its own internal lock
# state we don't want to instantiate twice.

router = APIRouter(prefix="/api/health", tags=["health"])


# ---------------------------------------------------------------------------
# Liveness — always 200 unless the process is wedged.
# ---------------------------------------------------------------------------
@router.get("/liveness")
def liveness():
    """Cheap, dependency-free liveness probe.

    Public — no auth required. Use this for Kubernetes ``livenessProbe``
    so a downstream DB outage doesn't trigger a pod restart loop.
    """
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": "1.0.0",
    }


# Keep the legacy route at ``/health`` working too — older deployments
# may have load balancer health checks pointing there. Same semantics.
liveness_router = APIRouter(tags=["health"])


@liveness_router.get("/health")
def legacy_health():
    """Legacy ``/health`` alias for ``/api/health/liveness``."""
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# Readiness — privileged view for operators / uptime dashboards.
# ---------------------------------------------------------------------------
def _db_ok() -> tuple[bool, str | None]:
    """Round-trip a ``SELECT 1`` against the live engine.

    Returns ``(ok, error_message)`` so the caller can include the
    failure cause in the response body. Never raises — DB errors here
    must be reported, not propagated (the caller returns 503).
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1")).scalar()
        return True, None
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _cve_index_status() -> dict[str, Any]:
    """Snapshot of the in-memory cve_index state.

    ``ready=False`` is the "index not built" condition the lifespan
    hook runs into on a cold start. We don't 503 on this alone — the
    app is still serving traffic, just with empty dashboard numbers.
    """
    try:
        from app.services import cve_index as cix

        state = cix.get()
        built_at = state.get("built_at")
        age_seconds = None
        if built_at is not None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            built = built_at if built_at.tzinfo is None else built_at.replace(tzinfo=None)
            age_seconds = int((now - built).total_seconds())
        return {
            "ready": bool(state.get("ready")),
            "total_cves": int(state.get("total_cves") or 0),
            "kev_count": int(state.get("kev_count") or 0),
            "built_at": built_at.isoformat() if built_at else None,
            "age_seconds": age_seconds,
        }
    except Exception as exc:
        return {
            "ready": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _scheduler_status() -> dict[str, Any]:
    """Wrap the scheduler introspection helper so a failure here
    doesn't take down the whole /api/health/status response."""
    try:
        from app.services.scheduler_jobs import scheduler_status

        return scheduler_status()
    except Exception as exc:
        return {"running": False, "error": f"{type(exc).__name__}: {exc}"}


def _sync_source_status(db: Session) -> list[dict[str, Any]]:
    """Per-source last-success age, same shape as /api/sync/status.

    Implemented locally (not by calling the sync router) so the
    /api/health/status response doesn't depend on a second router's
    permission stack — the operator is already authenticated.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stale_threshold = settings.sync_stale_hours
    sources = ("nvd", "kev")
    # ``UtcDateTime`` re-attaches tzinfo on read so we compare against
    # an aware ``now``. We normalise both sides to naive UTC for the
    # subtraction so a TZ-aware source row minus a TZ-naive now never
    # trips a TypeError.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    success_rows = (
        db.query(SyncRun.source, SyncRun.finished_at, SyncRun.started_at)
        .filter(SyncRun.status.in_(("ok", "success", "completed")))
        .order_by(SyncRun.started_at.desc())
        .all()
    )
    latest: dict[str, datetime] = {}
    for source, finished_at, started_at in success_rows:
        if source in latest:
            continue
        ts = finished_at or started_at
        if ts is not None:
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
            latest[source] = ts

    running_rows = {
        row[0]
        for row in db.query(SyncRun.source).filter(SyncRun.status == "running").all()
    }
    out = []
    for src in sources:
        ts = latest.get(src)
        age_hours = (
            round((now - ts).total_seconds() / 3600, 1) if ts is not None else None
        )
        out.append({
            "source": src,
            "last_success_at": ts.isoformat() if ts else None,
            "age_hours": age_hours,
            "stale": (age_hours is None) or (age_hours > stale_threshold),
            "running": src in running_rows,
        })
    return out


def _asset_scan_status(db: Session) -> dict[str, Any]:
    """Asset-scan freshness.

    Two numbers matter for the operator:
      * ``active_assets`` — total active targets we should be scanning.
      * ``overdue_assets`` — assets that haven't been scanned within
        ``settings.asset_scan_stale_hours`` (a daily schedule + 12h
        grace = 36h default).

    The latter is the actionable flag: if it's > 0, the scheduler's
    asset-scan job is broken.
    """
    from datetime import timedelta

    from app.models import AssetScan

    active_assets = db.query(Asset).filter(Asset.is_active.is_(True)).count()
    # A scan "covers" an asset when Asset.last_scanned_at was updated.
    # We could derive overdue from Asset, but joining to AssetScan makes
    # the threshold explicit (an asset can have many scans; only the
    # newest finished scan counts).
    # Normalise to naive UTC so a tz-aware AssetScan.finished_at can
    # be compared without TypeError.
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now_naive - timedelta(
        hours=settings.asset_scan_stale_hours
    )
    latest_scan_subq = (
        db.query(
            AssetScan.asset_id,
            AssetScan.finished_at,
        )
        .filter(AssetScan.finished_at.isnot(None))
        .order_by(AssetScan.asset_id, AssetScan.finished_at.desc())
        .subquery()
    )
    # Cheap aggregate: count assets with no scan newer than the cutoff.
    overdue = (
        db.query(Asset)
        .outerjoin(
            latest_scan_subq,
            latest_scan_subq.c.asset_id == Asset.id,
        )
        .filter(Asset.is_active.is_(True))
        .filter(
            (latest_scan_subq.c.finished_at.is_(None))
            | (latest_scan_subq.c.finished_at < cutoff)
        )
        .count()
    )
    return {
        "active_assets": int(active_assets),
        "overdue_assets": int(overdue),
        "stale_hours": settings.asset_scan_stale_hours,
    }


@router.get("/status")
def readiness(
    response: Response,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("sync", "trigger")),
):
    """Detailed readiness probe — operators / uptime dashboards only.

    Returns ``200`` with a structured payload, or ``503`` when the DB
    is unreachable (the only condition severe enough to fail the
    probe). Stale syncs / unbuilt cve_index / dormant scheduler are
    reported in the body but do NOT change the HTTP status — those
    are operational issues, not outages.
    """
    db_ok, db_error = _db_ok()

    payload: dict[str, Any] = {
        "status": "ok" if db_ok else "degraded",
        "app": settings.app_name,
        "version": "1.0.0",
        "checks": {
            "database": {"ok": db_ok, "error": db_error},
            "cve_index": _cve_index_status(),
            "scheduler": _scheduler_status(),
        },
        "syncs": {
            "stale_hours": settings.sync_stale_hours,
            "sources": _sync_source_status(db),
        },
        "asset_scans": _asset_scan_status(db),
        "totals": {
            "institutions": db.query(Institution).count(),
            "users": db.query(User).count(),
        },
        "now": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }

    if not db_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload
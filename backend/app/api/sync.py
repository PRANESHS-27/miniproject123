"""Manual sync triggers and sync-status routes (admin-only)."""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.config import settings
from app.db import get_db
from app.models import SyncRun, User
from app.services.cve_fetcher import (
    run_sync_nvd,
    run_sync_kev,
    run_sync_recent_nvd,
    latest_sync_runs,
)

router = APIRouter(prefix="/api/sync", tags=["sync"])


# Sources the dashboard cares about. ``last_success_at`` is computed
# against this set so an operator sees a uniform row per source even
# if a source has never run (``None``).
_KNOWN_SOURCES = ("nvd", "kev")


def _run_nvd_full(db_factory) -> None:
    db = db_factory()
    try:
        run_sync_nvd(db)
    finally:
        db.close()


def _run_nvd_incremental(db_factory) -> None:
    db = db_factory()
    try:
        run_sync_recent_nvd(db)
    finally:
        db.close()


def _run_kev(db_factory) -> None:
    db = db_factory()
    try:
        run_sync_kev(db)
    finally:
        db.close()


@router.post("/nvd/full")
def trigger_nvd_full(
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Kick off a full NVD backfill in the background (admin only)."""
    from app.db import SessionLocal

    background.add_task(_run_nvd_full, SessionLocal)
    return {"status": "started", "job": "nvd_full", "message": "Backfill running in background."}


@router.post("/nvd/incremental")
def trigger_nvd_incremental(
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Fetch only CVEs modified since the last run (live data)."""
    from app.db import SessionLocal

    background.add_task(_run_nvd_incremental, SessionLocal)
    return {"status": "started", "job": "nvd_incremental", "message": "Sync started."}


@router.post("/kev")
def trigger_kev(
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    """Refresh CISA KEV flags."""
    from app.db import SessionLocal

    background.add_task(_run_kev, SessionLocal)
    return {"status": "started", "job": "kev", "message": "KEV refresh started."}


@router.get("/status")
def sync_status(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Per-source sync health for the dashboard (admin only).

    Returns the recent SyncRun history (capped at 20) plus an aggregate
    ``sources`` array — one entry per known source (``nvd`` / ``kev``)
    with last-success age, currently-running flag, and a ``stale`` flag
    computed against ``settings.sync_stale_hours``. ``stale_hours`` is
    echoed so the frontend doesn't need its own threshold.
    """
    # ``UtcDateTime`` columns re-attach tzinfo on read so we normalise
    # both ``now`` and the column values to naive UTC — subtraction of
    # an aware vs naive datetime would raise ``TypeError``.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stale_threshold = settings.sync_stale_hours

    # Pre-compute "latest success per source" in one query so we don't
    # round-trip per known source.
    success_rows = (
        db.query(SyncRun.source, SyncRun.finished_at, SyncRun.started_at, SyncRun.status)
        .filter(SyncRun.status.in_(("ok", "success", "completed")))
        .order_by(SyncRun.started_at.desc())
        .all()
    )
    latest_success: dict[str, datetime] = {}
    for source, finished_at, started_at, _status in success_rows:
        if source in latest_success:
            continue
        ts = finished_at or started_at
        if ts is not None:
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
            latest_success[source] = ts

    # Currently-running: any SyncRun whose status == "running".
    running_rows = (
        db.query(SyncRun.source)
        .filter(SyncRun.status == "running")
        .all()
    )
    running_sources = {row[0] for row in running_rows}

    sources = []
    for src in _KNOWN_SOURCES:
        ts = latest_success.get(src)
        age_hours = None
        stale = None
        if ts is not None:
            age_hours = round((now - ts).total_seconds() / 3600, 1)
            stale = age_hours > stale_threshold
        sources.append({
            "source": src,
            "last_success_at": ts.isoformat() if ts else None,
            "age_hours": age_hours,
            "stale": stale,
            "running": src in running_sources,
        })

    # Any sources in the DB we don't know about — surface them too so a
    # future job added without updating _KNOWN_SOURCES is still visible.
    known = set(_KNOWN_SOURCES)
    extras = []
    for src, finished_at, started_at, _status in success_rows:
        if src in known:
            continue
        ts = finished_at or started_at
        if ts is not None and ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        extras.append({
            "source": src,
            "last_success_at": ts.isoformat() if ts else None,
            "age_hours": round((now - ts).total_seconds() / 3600, 1) if ts else None,
            "stale": (ts is None) or ((now - ts).total_seconds() / 3600 > stale_threshold),
            "running": src in running_sources,
        })

    return {
        "stale_hours": stale_threshold,
        "now": now.isoformat(),
        "sources": sources + extras,
        "runs": latest_sync_runs(db, limit=20),
    }
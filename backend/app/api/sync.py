"""Manual sync triggers and sync-status routes (admin-only)."""

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db import get_db
from app.models import SyncRun, User
from app.services.cve_fetcher import (
    run_sync_nvd,
    run_sync_kev,
    run_sync_recent_nvd,
    latest_sync_runs,
)

router = APIRouter(prefix="/api/sync", tags=["sync"])


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
    """Return the most recent sync runs (admin only)."""
    return {"runs": latest_sync_runs(db, limit=20)}
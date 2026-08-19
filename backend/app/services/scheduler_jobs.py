"""APScheduler integration — runs NVD + CISA fetches on a cadence.

The NVD job uses **incremental sync** (lastModStartDate window) so it only
fetches CVEs modified since the last successful run. This is the "live data"
behaviour — typically <1000 records per run, completes in seconds.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import settings
from app.core.logging_config import get_logger
from app.db import SessionLocal
from app.services.cve_fetcher import (
    run_sync_nvd,
    run_sync_kev,
    run_sync_recent_nvd,
)

log = get_logger("scheduler")
_scheduler: BackgroundScheduler | None = None


# ---------------------------------------------------------------------------
# Job implementations
# ---------------------------------------------------------------------------
def _nvd_incremental_job() -> None:
    """Fetch only CVEs modified since the last successful run (live data)."""
    db = SessionLocal()
    try:
        result = run_sync_recent_nvd(db)
        log.info(
            "Incremental NVD sync: %s fetched / %s inserted / %s updated",
            result.get("fetched"),
            result.get("inserted"),
            result.get("updated"),
        )
    except Exception as exc:
        log.exception("Scheduled incremental NVD fetch failed: %s", exc)
    finally:
        db.close()


def _kev_job() -> None:
    """Refresh CISA KEV flags (small payload, run hourly)."""
    db = SessionLocal()
    try:
        result = run_sync_kev(db)
        log.info("KEV sync: %s fetched", result.get("fetched"))
    except Exception as exc:
        log.exception("Scheduled KEV fetch failed: %s", exc)
    finally:
        db.close()


def _bootstrap_job() -> None:
    """One-shot backfill on first start (or if DB is empty)."""
    db = SessionLocal()
    try:
        from app.models import Vulnerability

        count = db.query(Vulnerability).count()
        if count == 0:
            log.info("DB empty — running initial NVD backfill (this may take a while)…")
            run_sync_nvd(db, max_pages=20)  # first ~40k CVEs for a useful demo
        else:
            log.info("DB already has %d CVEs — skipping bootstrap", count)
    except Exception as exc:
        log.exception("Bootstrap sync failed: %s", exc)
    finally:
        db.close()


def _asset_scan_job() -> None:
    """Daily scan of all active company-owned assets."""
    db = SessionLocal()
    try:
        from app.services.asset_scanner import scan_all_active_assets
        from app.models import Asset

        if db.query(Asset).count() == 0:
            return
        log.info("Asset scan: scanning all active assets")
        n = scan_all_active_assets(db)
        log.info("Asset scan complete: %d asset(s)", n)
    except Exception as exc:
        log.exception("Scheduled asset scan failed: %s", exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Scheduler lifecycle
# ---------------------------------------------------------------------------
def start_scheduler() -> None:
    """Start the background scheduler. Idempotent.

    If ``settings.enable_scheduler`` is False (e.g. the operator wants
    manual control only), this is a no-op.
    """
    global _scheduler
    if _scheduler is not None:
        return

    if not settings.enable_scheduler:
        log.info("Scheduler disabled via ENABLE_SCHEDULER=false — staying dormant.")
        return

    _scheduler = BackgroundScheduler(timezone="UTC")

    # Live incremental NVD sync — every 30 minutes
    _scheduler.add_job(
        _nvd_incremental_job,
        IntervalTrigger(minutes=30),
        id="nvd_incremental",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),  # run immediately on startup
    )

    # CISA KEV — every 6 hours
    _scheduler.add_job(
        _kev_job,
        IntervalTrigger(hours=6),
        id="kev_refresh",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),
    )

    # First-run backfill — runs once on startup, then is removed
    _scheduler.add_job(
        _bootstrap_job,
        "date",
        run_date=datetime.now(timezone.utc),
        id="bootstrap_sync",
    )

    # Daily asset scan (only triggers if at least one asset exists)
    _scheduler.add_job(
        _asset_scan_job,
        IntervalTrigger(hours=max(1, settings.asset_scan_interval_hours)),
        id="asset_scan_all",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
    )

    _scheduler.start()
    log.info(
        "Scheduler started: NVD incremental every 30min, KEV every 6h, "
        "bootstrap on startup, asset scan every %dh",
        settings.asset_scan_interval_hours,
    )


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("Scheduler stopped")

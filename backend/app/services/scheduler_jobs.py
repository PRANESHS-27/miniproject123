"""APScheduler integration — runs NVD + CISA fetches on a cadence.

The NVD job uses **incremental sync** (lastModStartDate window) so it only
fetches CVEs modified since the last successful run. This is the "live data"
behaviour — typically <1000 records per run, completes in seconds.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
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
        # Risk Engine: re-score every active Finding. CVSS or KEV may
        # have changed upstream. Cheap (pure function, indexed SELECTs).
        _rescore_all_open_findings(db, reason="nvd_incremental")
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
        _rescore_all_open_findings(db, reason="kev")
    except Exception as exc:
        log.exception("Scheduled KEV fetch failed: %s", exc)
    finally:
        db.close()


def _rescore_all_open_findings(db, *, reason: str) -> None:
    """Re-score every open Finding. Called after NVD/KEV sync so CVSS
    or KEV changes propagate to the risk dashboard without waiting for
    the next asset scan.

    The scorer is a pure function; this is a SELECT over the indexed
    ``status`` column + N UPDATEs, where N is the open-finding count.
    Even at 10k open findings this completes in well under a second.
    """
    try:
        from app.models import Asset, Finding, FindingStatus, Vulnerability
        from app.services.findings import recompute_for_cve

        # Collect the set of CVEs that actually changed since the last
        # run. We don't currently have a per-CVE diff from the fetcher
        # so we re-score every CVE that has at least one open Finding —
        # bounded by the active-finding count, not the full CVE table.
        cve_ids = [
            row[0]
            for row in db.query(Finding.vulnerability_cve_id)
            .filter(
                Finding.status.in_(
                    (FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFIED)
                )
            )
            .distinct()
            .all()
        ]
        total = 0
        for cve_id in cve_ids:
            total += recompute_for_cve(db, cve_id)
        if total:
            db.commit()
            log.info(
                "Risk Engine: re-scored %d finding(s) after %s sync",
                total,
                reason,
            )
    except Exception as exc:  # pragma: no cover - never fail a sync over scoring
        log.warning("Risk Engine re-score after %s failed: %s", reason, exc)


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

        # Phase 4: copy any pre-existing AssetCveMatch rows into the
        # new findings table so the dashboard has data to show on
        # first load. Idempotent — guarded by a SyncRun row.
        from app.services.findings import backfill_from_asset_cve_matches
        n = backfill_from_asset_cve_matches(db)
        if n:
            db.commit()
            log.info("Backfilled %d finding(s) from existing asset_cve_matches", n)
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


def _backup_job() -> None:
    """Daily database backup. Opt-in via ``BACKUP_ENABLED=true``.

    Runs the same code path as the operator-facing CLI:
    ``python -m scripts.backup backup [--upload]``. The CLI is the
    source of truth — this wrapper just calls it and never raises (so
    the scheduler survives transient I/O / S3 outages).
    """
    from scripts.backup import _cmd_backup

    class _Args:
        output = None
        upload = True  # honour settings.backup_upload_to_s3 if set

    try:
        rc = _cmd_backup(_Args())
        if rc == 0:
            log.info("Daily backup OK")
        else:
            log.warning("Daily backup returned %d", rc)
    except Exception as exc:
        # NEVER raise from a scheduled job — APScheduler logs the traceback
        # at ERROR level and runs the next interval anyway, but we'd
        # rather log our own structured line.
        log.exception("Daily backup failed: %s", exc)


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

    # Live incremental NVD sync — every 30 minutes (starts after 5 min so startup is instant)
    _scheduler.add_job(
        _nvd_incremental_job,
        IntervalTrigger(minutes=30),
        id="nvd_incremental",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    # CISA KEV — every 6 hours (starts after 15 min)
    _scheduler.add_job(
        _kev_job,
        IntervalTrigger(hours=6),
        id="kev_refresh",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=15),
    )

    # First-run backfill — runs once on startup after 10s, then is removed
    _scheduler.add_job(
        _bootstrap_job,
        "date",
        run_date=datetime.now(timezone.utc) + timedelta(seconds=10),
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

    # Daily backup — opt-in via BACKUP_ENABLED=true. Runs at
    # BACKUP_SCHEDULE_HOUR_UTC (default 03:00 UTC).
    if settings.backup_enabled:
        _scheduler.add_job(
            _backup_job,
            CronTrigger(hour=settings.backup_schedule_hour_utc, minute=0),
            id="daily_backup",
            replace_existing=True,
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        log.info(
            "Daily backup scheduled at %02d:00 UTC → %s",
            settings.backup_schedule_hour_utc,
            settings.backup_dir,
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


# ---------------------------------------------------------------------------
# Introspection (free-priority #19)
# ---------------------------------------------------------------------------
def scheduler_status() -> dict:
    """Return a structured view of the scheduler for /api/health.

    Safe to call when the scheduler is dormant (``_scheduler is None``)
    or has been started but not yet entered its run loop — the API layer
    relies on ``running`` being a bool, never ``None`` or ``Missing``.
    """
    if _scheduler is None:
        return {
            "running": False,
            "jobs": [],
        }
    jobs = []
    for job in _scheduler.get_jobs():
        try:
            next_run = job.next_run_time
            next_run_iso = (
                next_run.isoformat() if next_run is not None else None
            )
        except Exception:
            next_run_iso = None
        jobs.append({
            "id": job.id,
            "name": job.name,
            "trigger": job.trigger.__class__.__name__,
            "next_run_at": next_run_iso,
        })
    return {
        "running": _scheduler.running,
        "jobs": jobs,
    }

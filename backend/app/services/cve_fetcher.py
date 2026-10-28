"""Fetch and normalize CVE / KEV data from NVD & CISA."""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any, Iterable

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models import Severity, SyncRun, Vulnerability
from app.services import cve_index
from app.services.vendor_filter import (
    filter_affected_products,
    is_cve_excluded,
    is_vendor_excluded,
)

logger = get_logger(__name__)


def _ssl_verify() -> bool | str | ssl.SSLContext:
    """Return the value httpx wants for ``verify=``.

    Resolution order (driven by ``settings.ssl_verify``):
      - empty string / true / default -> use system trust store (SSLContext with default certs)
      - ``"false"`` / ``"0"`` / ``"no"`` / ``"off"`` -> disable verification
      - any other value -> treat as path to a CA bundle (returned verbatim to httpx).
    """
    v = (settings.ssl_verify or "").strip()
    if not v or v.lower() in ("true", "1", "yes", "on", "default", "system"):
        try:
            ctx = ssl.create_default_context()
            ctx.load_default_certs()
            return ctx
        except Exception:
            return True
    if v.lower() in ("false", "0", "no", "off"):
        return False
    return v  # treat as path to a CA bundle


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
def _score_to_severity(score: float | None) -> Severity:
    """Bucket a CVSS base score into a Severity enum.

    NB: a score of exactly 0.0 is bucketed as LOW (not NONE) — informational
    CVEs that publish a 0.0 baseScore should still be findable.
    """
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.0:
        return Severity.LOW
    return Severity.NONE


# ---------------------------------------------------------------------------
# NVD 2.0 parser
# ---------------------------------------------------------------------------
def _parse_nvd_entry(item: dict[str, Any]) -> dict[str, Any] | None:
    cve = item.get("cve")
    if not cve:
        return None
    cve_id_raw = cve.get("id")
    if not cve_id_raw:
        return None
    # CVE IDs are uppercase by convention — normalise so lookups via
    # ``get_by_cve_id`` (which calls ``.upper()``) match consistently.
    cve_id = cve_id_raw.upper() if isinstance(cve_id_raw, str) else cve_id_raw

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), None
    )

    metrics = cve.get("metrics", {}) or {}
    cvss_v3 = None
    cvss_v2 = None
    # Prefer the NVD-published CVSS entry. The previous logic iterated
    # V3.1 then V3.0 and broke on the first version with *any* entry,
    # so a CVE with only a CNA-supplied V3.1 score would never fall back
    # to the NVD's V3.0 score. Iterate both keys first looking for an
    # NVD entry; only fall back to "any entry" if no NVD entry exists
    # for either version.
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        nvd_entry = next(
            (e for e in entries if e.get("cvssData", {}).get("source") == "nvd@nist.gov"),
            None,
        )
        if nvd_entry:
            cvss_v3 = nvd_entry["cvssData"]
            break
    if cvss_v3 is None:
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                cvss_v3 = entries[0]["cvssData"]
                break
    # Same NVD-preference logic for V2.
    v2_entries = metrics.get("cvssMetricV2") or []
    v2_nvd = next(
        (e for e in v2_entries if e.get("cvssData", {}).get("source") == "nvd@nist.gov"),
        None,
    )
    if v2_nvd:
        cvss_v2 = v2_nvd["cvssData"]
    elif v2_entries:
        cvss_v2 = v2_entries[0]["cvssData"]

    # Use explicit ``is not None`` so a 0.0 baseScore (informational CVE)
    # correctly takes precedence over a missing v3 entry.
    v3_score = (cvss_v3 or {}).get("baseScore")
    v2_score = (cvss_v2 or {}).get("baseScore")
    if v3_score is not None:
        score = v3_score
    elif v2_score is not None:
        score = v2_score
    else:
        score = None

    # Affected products — flatten CPE URIs to vendor:product strings.
    # We also propagate the version range fields (NVD's CPE match object
    # provides ``versionStartIncluding``, ``versionEndExcluding``,
    # ``versionEndIncluding``) so the matcher can honour version ranges.
    # Deduplicate by (vendor, product, version) so we don't grow the JSON
    # when NVD repeats the same CPE across multiple match strings.
    seen_keys: set[tuple[str, str, str]] = set()
    affected: list[dict[str, str]] = []
    for node in cve.get("configurations", []) or []:
        for match in node.get("cpeMatch", []) or []:
            uri = (match.get("criteria") or "").strip()
            parts = uri.split(":")
            if len(parts) < 5:
                continue
            vendor = parts[3]
            product = parts[4]
            version = (
                match.get("versionEndExcluding")
                or match.get("versionEndIncluding")
                or match.get("versionStartIncluding")
                or "*"
            )
            key = (vendor, product, version)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            entry: dict[str, str] = {"vendor": vendor, "product": product, "version": version}
            for fld in ("versionStartIncluding", "versionEndExcluding", "versionEndIncluding"):
                v = match.get(fld)
                if v:
                    entry[fld] = v
            affected.append(entry)

    references = [
        {"url": r.get("url"), "tags": r.get("tags", [])}
        for r in (cve.get("references") or [])
        if isinstance(r, dict) and r.get("url")
    ]
    weaknesses = []
    for w in cve.get("weaknesses") or []:
        descs = w.get("description") or []
        if not descs:
            continue
        val = descs[0].get("value") if isinstance(descs[0], dict) else None
        if val:
            weaknesses.append(val)

    published = _iso(cve.get("published"))
    last_modified = _iso(cve.get("lastModified"))

    return {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "last_modified": last_modified,
        "cvss_v3_score": (cvss_v3 or {}).get("baseScore"),
        "cvss_v3_vector": (cvss_v3 or {}).get("vectorString"),
        "cvss_v2_score": (cvss_v2 or {}).get("baseScore"),
        "severity": _score_to_severity(score),
        "affected_products": affected,
        "references": references,
        "cwe_ids": weaknesses,
        "title": (description or "")[:120] if description else None,
    }


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# NVD fetch (paginated, optional API key)
# ---------------------------------------------------------------------------
async def _fetch_nvd_page(
    client: httpx.AsyncClient,
    start_index: int,
    results_per_page: int,
    last_mod_start: str | None = None,
    last_mod_end: str | None = None,
) -> dict[str, Any]:
    headers = {"User-Agent": "VulnWatch/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    params: dict[str, Any] = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    if last_mod_start:
        params["lastModStartDate"] = last_mod_start
    if last_mod_end:
        params["lastModEndDate"] = last_mod_end
    resp = await client.get(
        settings.nvd_api_url, headers=headers, params=params, timeout=60.0
    )
    resp.raise_for_status()
    return resp.json()


async def fetch_all_cves(db: Session, max_pages: int | None = None) -> dict[str, int]:
    """Fetch all CVEs from NVD in pages and upsert them into PostgreSQL."""
    run = SyncRun(source="nvd", status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    fetched = inserted = updated = 0
    try:
        async with httpx.AsyncClient(verify=_ssl_verify()) as client:
            start = 0
            pages = 0
            while True:
                page = await _fetch_nvd_page(
                    client, start, settings.fetch_results_per_page
                )
                items = page.get("vulnerabilities", []) or []
                if not items:
                    break
                fetched += len(items)
                ins, upd = _upsert_nvd(db, (_parse_nvd_entry(i) for i in items))
                inserted += ins
                updated += upd
                pages += 1
                if max_pages and pages >= max_pages:
                    break
                start += settings.fetch_results_per_page
                if fetched >= page.get("totalResults", 0):
                    break

        run.finished_at = datetime.now(timezone.utc)
        run.items_fetched = fetched
        run.items_inserted = inserted
        run.items_updated = updated
        run.status = "success"
        db.commit()
        logger.info("NVD sync OK: %d fetched / %d inserted / %d updated", fetched, inserted, updated)
        _refresh_index(db)
        return {"fetched": fetched, "inserted": inserted, "updated": updated}
    except Exception as exc:  # pragma: no cover - reported via DB
        logger.exception("NVD sync failed: %s", exc)
        # Rollback any in-flight changes so the session is usable, then
        # record the failure on the SyncRun row.
        db.rollback()
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.error = str(exc)[:1000]
        db.commit()
        raise


def _upsert_nvd(db: Session, records: Iterable[dict[str, Any] | None]) -> tuple[int, int]:
    valid_recs: list[dict[str, Any]] = []
    for rec in records:
        if not rec:
            continue
        # Honour the vendor allowlist — drop CVEs whose only affected
        # products are from excluded vendors (Apple / Google / etc.),
        # and strip excluded entries from CVEs that mix relevant vendors.
        products = rec.get("affected_products") or []
        if is_cve_excluded(products):
            continue
        cleaned = filter_affected_products(products)
        if cleaned:
            rec["affected_products"] = cleaned
        valid_recs.append(rec)

    if not valid_recs:
        return 0, 0

    cve_ids = [r["cve_id"] for r in valid_recs]
    # Single batch query to find existing rows instead of thousands of individual queries
    existing_map = {
        v.cve_id: v
        for v in db.query(Vulnerability).filter(Vulnerability.cve_id.in_(cve_ids)).all()
    }

    inserted = updated = 0
    for rec in valid_recs:
        existing = existing_map.get(rec["cve_id"])
        if existing:
            for key, val in rec.items():
                setattr(existing, key, val)
            updated += 1
        else:
            db.add(Vulnerability(**rec))
            inserted += 1
    db.commit()
    return inserted, updated


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------
async def fetch_cisa_kev(db: Session) -> dict[str, int]:
    """Download the CISA Known Exploited Vulnerabilities catalog and flag rows in DB."""
    run = SyncRun(source="kev", status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    fetched = inserted = updated = 0
    try:
        async with httpx.AsyncClient(verify=_ssl_verify()) as client:
            resp = await client.get(settings.cisa_kev_url, timeout=60.0)
            resp.raise_for_status()
            catalog = resp.json()

        vulns = catalog.get("vulnerabilities", [])
        fetched = len(vulns)

        for entry in vulns:
            cve_id = entry.get("cveID")
            if not cve_id:
                continue
            row = db.query(Vulnerability).filter_by(cve_id=cve_id).one_or_none()
            if row:
                row.in_kev = True
                row.kev_added_at = _iso(entry.get("dateAdded"))
                row.kev_due_date = _iso(entry.get("dueDate"))
                updated += 1
            else:
                db.add(
                    Vulnerability(
                        cve_id=cve_id.upper() if isinstance(cve_id, str) else cve_id,
                        title=entry.get("shortDescription", "")[:120] or None,
                        description=entry.get("shortDescription"),
                        severity=Severity.UNKNOWN,
                        in_kev=True,
                        kev_added_at=_iso(entry.get("dateAdded")),
                        kev_due_date=_iso(entry.get("dueDate")),
                        affected_products=[
                            {
                                "vendor": entry.get("vendorProject", ""),
                                "product": entry.get("product", ""),
                            }
                        ],
                    )
                )
                inserted += 1
        db.commit()

        run.finished_at = datetime.now(timezone.utc)
        run.items_fetched = fetched
        run.items_inserted = inserted
        run.items_updated = updated
        run.status = "success"
        db.commit()
        logger.info("CISA KEV sync OK: %d flagged", fetched)
        _refresh_index(db)
        return {"fetched": fetched, "inserted": inserted, "updated": updated}
    except Exception as exc:  # pragma: no cover
        logger.exception("CISA KEV sync failed: %s", exc)
        db.rollback()
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.error = str(exc)[:1000]
        db.commit()
        raise


# ---------------------------------------------------------------------------
# Convenience for synchronous callers (scheduler / scripts)
# ---------------------------------------------------------------------------
def run_sync_nvd(db: Session, max_pages: int | None = None) -> dict[str, int]:
    return asyncio.run(fetch_all_cves(db, max_pages=max_pages))


def run_sync_kev(db: Session) -> dict[str, int]:
    return asyncio.run(fetch_cisa_kev(db))


# ---------------------------------------------------------------------------
# Incremental / live sync (uses NVD lastModStartDate window)
# ---------------------------------------------------------------------------
async def fetch_recent_cves(
    db: Session,
    since: datetime | None = None,
    max_pages: int | None = None,
) -> dict[str, Any]:
    """Fetch CVEs modified since `since` (or last 24h by default).

    This is the **live data** sync — only deltas, so it runs in seconds and can
    be triggered every few minutes. If we have no record of a previous run,
    we fall back to the last 24 hours.
    """
    from datetime import timedelta

    if since is None:
        # Try last successful NVD run from sync_runs
        last = (
            db.query(SyncRun)
            .filter(SyncRun.source == "nvd", SyncRun.status == "success")
            .order_by(SyncRun.finished_at.desc())
            .first()
        )
        if last and last.finished_at:
            since = last.finished_at
        else:
            since = datetime.now(timezone.utc) - timedelta(hours=24)

    # NVD wants ISO with offset (Z works too)
    mod_start = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mod_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    run = SyncRun(source="nvd", status="running", items_fetched=0)
    db.add(run)
    db.commit()
    db.refresh(run)

    fetched = inserted = updated = 0
    try:
        async with httpx.AsyncClient(verify=_ssl_verify()) as client:
            start = 0
            pages = 0
            while True:
                page = await _fetch_nvd_page(
                    client,
                    start,
                    settings.fetch_results_per_page,
                    last_mod_start=mod_start,
                    last_mod_end=mod_end,
                )
                items = page.get("vulnerabilities", []) or []
                if not items:
                    break
                fetched += len(items)
                ins, upd = _upsert_nvd(db, (_parse_nvd_entry(i) for i in items))
                inserted += ins
                updated += upd
                pages += 1
                if max_pages and pages >= max_pages:
                    break
                start += settings.fetch_results_per_page
                if fetched >= page.get("totalResults", 0):
                    break

        run.finished_at = datetime.now(timezone.utc)
        run.items_fetched = fetched
        run.items_inserted = inserted
        run.items_updated = updated
        run.status = "success"
        db.commit()
        logger.info(
            "NVD incremental sync OK: %d fetched / %d inserted / %d updated since %s",
            fetched, inserted, updated, mod_start,
        )
        _refresh_index(db)
        return {
            "fetched": fetched,
            "inserted": inserted,
            "updated": updated,
            "since": mod_start,
            "until": mod_end,
        }
    except Exception as exc:  # pragma: no cover
        logger.exception("NVD incremental sync failed: %s", exc)
        db.rollback()
        run.finished_at = datetime.now(timezone.utc)
        run.status = "failed"
        run.error = str(exc)[:1000]
        db.commit()
        raise


def _refresh_index(db: Session) -> None:
    """Rebuild the in-memory CVE index on a fresh session.

    Runs in a thread (the request that triggered the sync may still hold
    ``db`` open) so it sees the just-committed rows.
    """
    import threading
    from app.db import SessionLocal

    def _do() -> None:
        try:
            cve_index.refresh(SessionLocal())
        except Exception:  # pragma: no cover - never let index ops kill a sync
            logger.exception("cve_index refresh failed")

    t = threading.Thread(target=_do, daemon=True, name="cve-index-refresh")
    t.start()


def run_sync_recent_nvd(db: Session, since: datetime | None = None) -> dict[str, Any]:
    return asyncio.run(fetch_recent_cves(db, since=since))


# ---------------------------------------------------------------------------
# Sync status (last runs) — exposed via API for the dashboard
# ---------------------------------------------------------------------------
def latest_sync_runs(db: Session, limit: int = 10) -> list[dict]:
    rows = (
        db.query(SyncRun)
        .order_by(SyncRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "source": r.source,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "items_fetched": r.items_fetched,
            "items_inserted": r.items_inserted,
            "items_updated": r.items_updated,
            "status": r.status,
            "error": r.error,
        }
        for r in rows
    ]
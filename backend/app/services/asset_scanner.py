"""Asset scanner orchestrator — runs the full set of scanners for one asset.

Idempotent: findings are upserted on ``(asset_id, finding_type, title)``
so repeat scans don't pile up duplicates — they bump ``last_seen_at``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging_config import get_logger
from app.core.time import utcnow_naive
from app.models import (
    Asset,
    AssetCveMatch,
    AssetFinding,
    AssetScan,
    AssetTechnology,
    FindingType,
    SeverityLevel,
)
from app.services import asset_fingerprint, asset_headers, asset_js, asset_paths, asset_tls
from app.services.cve_fetcher import _ssl_verify

logger = get_logger("asset_scanner")


async def _run_scan(asset: Asset) -> dict[str, Any]:
    """Run every scanner for one asset and return raw findings + matches."""
    url = asset.url
    verify = _ssl_verify()
    timeout = float(settings.asset_scan_timeout_seconds)

    probed_meta, technologies = await asset_fingerprint.fingerprint_asset(
        url, timeout=timeout, verify=verify
    )

    # Run independent scanners concurrently
    path_results, tls_findings, js_findings, header_findings = await asyncio.gather(
        asset_fingerprint.probe_paths(
            url,
            settings.asset_probe_paths,
            timeout=timeout,
            verify=verify,
            max_concurrency=settings.asset_scan_max_concurrency,
        ),
        asset_tls.probe_tls(url, timeout=timeout),
        _async_match_js(probed_meta.get("body") or "", url),
        _async_audit_headers(probed_meta.get("headers") or {}),
        return_exceptions=False,
    )

    path_findings = asset_paths.findings_for_path_results(path_results)

    return {
        "probed_meta": probed_meta,
        "technologies": technologies,
        "findings": tls_findings + header_findings + path_findings + js_findings,
        "path_results": path_results,
    }


async def _async_match_js(body: str, url: str) -> list[dict[str, Any]]:
    scripts = asset_js.extract_scripts(body, url) if body else []
    return asset_js.match_scripts(scripts)


async def _async_audit_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    return asset_headers.audit_headers(headers)


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def _replace_technologies(db: Session, asset_id: int, techs: list[dict[str, Any]]) -> None:
    """Upsert technologies on ``(asset_id, vendor, product)``.

    Why upsert and not delete-then-insert: ``AssetCveMatch.technology_id`` has
    ``ondelete="CASCADE"``, so a hard delete would wipe every historical
    CVE bridge for this asset on every re-scan. Upserting preserves the
    primary-key IDs that ``AssetCveMatch`` rows point at — the bridge
    stays intact across re-scans.
    """
    # Re-link any orphan AssetCveMatch rows (FK pointing at a missing tech)
    # to the soon-to-be-replaced set so they don't get cascade-killed.
    existing = (
        db.query(AssetTechnology).filter(AssetTechnology.asset_id == asset_id).all()
    )
    existing_by_key = {(t.vendor, t.product): t for t in existing}

    if not techs:
        # Empty scan result: keep the previous tech rows so the asset's
        # CVEs remain visible. The fingerprint detector often returns []
        # for auth-walled assets (3xx with no body) — without this guard
        # the asset's full CVE history disappears on the next scan.
        return

    seen_keys: set[tuple[str, str]] = set()
    now = utcnow_naive()
    for t in techs:
        key = (t["vendor"], t["product"])
        seen_keys.add(key)
        row = existing_by_key.get(key)
        if row is not None:
            row.version = t.get("version")
            row.source = t["source"]
            row.confidence = t.get("confidence", 0.8)
            row.detected_at = now
            continue
        db.add(AssetTechnology(
            asset_id=asset_id,
            vendor=t["vendor"],
            product=t["product"],
            version=t.get("version"),
            source=t["source"],
            confidence=t.get("confidence", 0.8),
            detected_at=now,
        ))

    # Drop tech rows that genuinely disappeared (no fresh match for them)
    # only AFTER the upsert so FKs don't cascade-delete AssetCveMatch
    # rows whose tech was just re-created.
    to_remove = [
        t for t in existing
        if (t.vendor, t.product) not in seen_keys
    ]
    for t in to_remove:
        db.delete(t)


def _replace_open_findings(
    db: Session, asset_id: int, new_findings: list[dict[str, Any]]
) -> tuple[int, int, int, int]:
    """Upsert open findings on ``(asset_id, finding_type, title)``.

    Repeat scans don't pile up duplicates: any pre-existing **open** finding
    with the same key gets its ``last_seen_at`` bumped. New keys get inserted.
    Open findings whose key disappeared from this scan are closed.

    Returns (inserted, re_seen, closed, matched_cves).
    """
    # First, collapse any historical duplicates that pre-date the dedup
    # logic. This is a no-op when the table is already clean.
    _reconcile_duplicates(db, asset_id)

    fresh_keys = {(f["finding_type"], f["title"]) for f in new_findings}

    # Pull every open finding once; we'll mutate it in place below.
    open_findings = (
        db.query(AssetFinding)
        .filter(AssetFinding.asset_id == asset_id, AssetFinding.resolved_at.is_(None))
        .all()
    )
    open_by_key: dict[tuple[str, str], AssetFinding] = {}
    for f in open_findings:
        ft = f.finding_type.value if hasattr(f.finding_type, "value") else f.finding_type
        open_by_key[(ft, f.title)] = f

    inserted = 0
    re_seen = 0
    closed = 0
    seen_keys: set[tuple[str, str]] = set()
    now = utcnow_naive()
    for nf in new_findings:
        key = (nf["finding_type"], nf["title"])
        seen_keys.add(key)
        existing = open_by_key.get(key)
        if existing:
            existing.last_seen_at = now
            re_seen += 1
            continue
        db.add(AssetFinding(
            asset_id=asset_id,
            finding_type=FindingType(nf["finding_type"]),
            severity=SeverityLevel(nf.get("severity", "UNKNOWN")),
            title=nf["title"],
            details=nf.get("details"),
            remediation=nf.get("remediation"),
            discovered_at=now,
            last_seen_at=now,
        ))
        inserted += 1

    # Close open findings whose key disappeared from this scan.
    # IMPORTANT: only auto-close findings for *detection categories* that
    # actually produced fresh results in this scan. If a scanner returned
    # nothing (auth-wall, transient failure, etc.), its previous findings
    # are preserved — otherwise a transient empty scan would silently wipe
    # the asset's entire finding history. This is what caused
    # "scans but no results shown": a 3xx to an auth-wall produced
    # ``findings=[]`` and the auto-close closed everything.
    fresh_categories: set[str] = {
        f["finding_type"] for f in new_findings
    }
    for key, finding in open_by_key.items():
        if key[0] not in fresh_categories:
            # Category is silent this scan — don't trust it.
            continue
        if key not in seen_keys:
            finding.resolved_at = now
            closed += 1

    return inserted, re_seen, closed, 0


def _reconcile_duplicates(db: Session, asset_id: int) -> int:
    """Collapse historical duplicate open findings on
    ``(asset_id, finding_type, title)``.

    Keeps the oldest row, bumps its ``last_seen_at`` to the newest of the
    group, and marks the rest resolved with a note in the scan history.
    Returns the number of duplicate rows merged.

    This is safe to run repeatedly — once the table is clean it's a no-op.
    """
    open_findings = (
        db.query(AssetFinding)
        .filter(AssetFinding.asset_id == asset_id, AssetFinding.resolved_at.is_(None))
        .all()
    )
    if not open_findings:
        return 0

    groups: dict[tuple[str, str], list[AssetFinding]] = {}
    for f in open_findings:
        ft = f.finding_type.value if hasattr(f.finding_type, "value") else f.finding_type
        groups.setdefault((ft, f.title), []).append(f)

    merged = 0
    now = utcnow_naive()
    for key, rows in groups.items():
        if len(rows) <= 1:
            continue
        # Oldest wins (smallest id); bump its last_seen_at to the newest's.
        rows.sort(key=lambda r: r.id)
        keeper = rows[0]
        latest_seen = max((r.last_seen_at or keeper.discovered_at for r in rows), default=now)
        keeper.last_seen_at = latest_seen
        for r in rows[1:]:
            r.resolved_at = now
            merged += 1

    if merged:
        logger.info(
            "Reconciled %d duplicate open findings on asset_id=%d",
            merged,
            asset_id,
        )
        db.flush()
    return merged


def scan_one_asset(
    db: Session,
    asset_id: int,
    *,
    triggered_by: str = "manual",
) -> AssetScan | None:
    """Run the full scan for one asset. Synchronous wrapper used by
    BackgroundTasks. Returns the AssetScan row."""
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        return None

    scan = AssetScan(asset_id=asset_id, status="running", triggered_by=triggered_by)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = asyncio.run(_run_scan(asset))

        # 1. Technologies
        techs = result["technologies"]
        _replace_technologies(db, asset.id, techs)
        db.commit()

        # Refresh tech ids so the matcher can link them
        tech_rows = (
            db.query(AssetTechnology)
            .filter(AssetTechnology.asset_id == asset.id)
            .all()
        )
        tech_dict_by_key = {(t.vendor, t.product): t for t in tech_rows}

        # 2. CVE matching — add technology_id to each tech pair the matcher will use
        tech_pairs_for_match = []
        for t in techs:
            row = tech_dict_by_key.get((t["vendor"], t["product"]))
            tech_pairs_for_match.append({**t, "id": row.id if row else None})
        from app.services.asset_matcher import match_cves
        matched = match_cves(db, asset.id, tech_pairs_for_match)

        # 2b. Risk Engine — create / refresh Findings for the matches the
        # matcher just produced. Done here (rather than inside
        # ``match_cves``) so the matcher stays a pure data-lookup helper
        # and the scoring side-effect is visible at the scan boundary.
        try:
            from app.models import AssetCveMatch
            from app.services.findings import upsert_many as findings_upsert_many
            fresh_matches = (
                db.query(AssetCveMatch)
                .filter(AssetCveMatch.asset_id == asset.id)
                .all()
            )
            findings_upsert_many(db, fresh_matches, source="scan")
            db.commit()
        except Exception as exc:  # pragma: no cover - never fail a scan over scoring
            logger.warning("findings upsert after scan failed for %s: %s", asset.url, exc)

        # 3. Append CVE findings as a separate finding_type
        all_findings = list(result["findings"])
        # Guardrail: cap CVE-derived findings per scan to keep the
        # ``asset_findings`` table readable when a noisy stack (e.g. many
        # CVEs match a generic nginx banner) would otherwise produce
        # hundreds of rows for a single asset.
        CVE_FINDING_CAP = 50
        if len(matched) > CVE_FINDING_CAP:
            logger.warning(
                "Asset %s matched %d CVEs — capping CVE-derived findings at %d for this scan",
                asset.url, len(matched), CVE_FINDING_CAP,
            )
        for m in matched[:CVE_FINDING_CAP]:
            all_findings.append({
                "finding_type": "cve",
                "severity": (m.get("cve_severity") or "UNKNOWN").upper(),
                "title": f"{m['cve_id']} affects {m['technology_vendor']}:{m['technology_product']}",
                "details": {
                    "cve_id": m["cve_id"],
                    "vendor": m["technology_vendor"],
                    "product": m["technology_product"],
                    "cvss_v3_score": m.get("cve_cvss_v3_score"),
                    "title": m.get("cve_title"),
                },
                "remediation": f"Review {m['cve_id']} on NVD; patch or upgrade the affected component.",
            })

        # 4. Findings: replace open ones
        inserted, re_seen, closed, _ = _replace_open_findings(db, asset.id, all_findings)
        scan.items_found = inserted + re_seen
        scan.inserted_count = inserted
        scan.re_seen_count = re_seen
        scan.closed_count = closed
        scan.technologies_detected = len(tech_rows)
        scan.cves_matched = len(matched)
        scan.status = "success"
        scan.finished_at = utcnow_naive()
        asset.last_scanned_at = scan.finished_at
        asset.last_scan_status = "success"
        db.commit()
        # Refresh the in-memory CVE/asset index so the dashboard and
        # search endpoints see the same numbers as the asset detail
        # page (which reads straight from the DB). Without this the
        # dashboard stays stale until the next scheduled refresh.
        try:
            from app.services import cve_index
            cve_index.refresh(db)
        except Exception as exc:  # pragma: no cover - never fail a scan over the cache
            logger.warning("cve_index refresh after scan failed: %s", exc)
        logger.info(
            "Asset scan OK: id=%d url=%s techs=%d new=%d re_seen=%d closed=%d cves=%d",
            asset.id, asset.url, len(tech_rows), inserted, re_seen, closed, len(matched),
        )
        return scan

    except Exception as exc:
        logger.exception("Asset scan failed for %s: %s", asset.url, exc)
        scan.status = "failed"
        scan.error = str(exc)[:1000]
        scan.finished_at = utcnow_naive()
        asset.last_scanned_at = scan.finished_at
        asset.last_scan_status = "failed"
        db.commit()
        return scan


def scan_all_active_assets(db: Session) -> int:
    """Used by the daily scheduler. Returns the number of assets scanned."""
    assets = db.query(Asset).filter(Asset.is_active.is_(True)).all()
    count = 0
    for asset in assets:
        scan_one_asset(db, asset.id, triggered_by="scheduler")
        count += 1
    return count
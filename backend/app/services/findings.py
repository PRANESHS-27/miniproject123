"""Risk Engine service layer.

This module owns the writing side of the findings workflow:

  - ``upsert_from_match`` — called by the asset scanner whenever a new
    AssetCveMatch row appears. Computes the risk score, creates a new
    Finding if there is no open one, otherwise refreshes the score.
  - ``backfill_from_asset_cve_matches`` — one-shot migration that
    copies existing AssetCveMatch rows into Findings so the dashboard
    has data to show immediately after Phase 4 ships. Idempotent: we
    record a SyncRun row so we never re-run.
  - ``recompute_for_cve`` — called by the NVD incremental / KEV
    schedulers. When a CVE's CVSS or KEV status changes, every open
    Finding for that CVE gets re-scored.
  - ``recompute_for_asset`` — called when an asset's criticality or
    internet_exposed flag changes (PATCH /api/assets/{id}).

The read side lives in the API router — this module only writes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.core.time import utcnow_naive
from app.models import (
    Asset,
    AssetCveMatch,
    Finding,
    FindingStatus,
    SyncRun,
    User,
    Vulnerability,
)
from app.services.risk import RiskInputs, score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_inputs(asset: Asset, vuln: Vulnerability | None) -> RiskInputs:
    """Assemble a RiskInputs from ORM rows. Tolerates a missing CVE row
    (e.g. backfilling before a CVE has been ingested): missing CVSS
    becomes None, missing KEV defaults to False."""
    cvss = None
    in_kev = False
    if vuln is not None:
        cvss = vuln.cvss_v3_score
        in_kev = bool(getattr(vuln, "in_kev", False))
    return RiskInputs(
        cvss_v3=cvss,
        in_kev=in_kev,
        asset_criticality=getattr(asset, "criticality", "LOW").value
        if hasattr(getattr(asset, "criticality", None), "value")
        else str(getattr(asset, "criticality", "LOW") or "LOW"),
        internet_exposed=bool(getattr(asset, "internet_exposed", False)),
    )


def _apply_risk(finding: Finding, asset: Asset, vuln: Vulnerability | None) -> None:
    """Mutate ``finding`` in-place with the current risk output."""
    result = score(_build_inputs(asset, vuln))
    finding.risk_score = result.score
    finding.risk_label = result.label  # type: ignore[assignment]
    finding.risk_contributions = result.contributions


def _has_open_finding(
    db: Session, asset_id: int, cve_id: str
) -> Optional[Finding]:
    """Return the open Finding for (asset, CVE) if one exists, else None.
    We treat ``in_progress`` and ``verified`` as "still active" — only
    ``resolved`` and ``accepted_risk`` free the slot for a new row.
    """
    active_statuses = (
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFIED,
    )
    return (
        db.query(Finding)
        .filter(
            and_(
                Finding.asset_id == asset_id,
                Finding.vulnerability_cve_id == cve_id,
                Finding.status.in_(active_statuses),
            )
        )
        .first()
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def upsert_from_match(
    db: Session,
    match: AssetCveMatch,
    source: str = "scan",
) -> Finding:
    """Create or refresh the Finding for a single (asset, CVE) match.

    The asset scan path calls this in a loop over the matches it just
    produced. Re-scoring is cheap (pure function), so always recompute
    rather than cache — CVSS and KEV may have changed since the last
    scan.
    """
    asset = db.get(Asset, match.asset_id)
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.cve_id == match.cve_id)
        .first()
    )
    if asset is None:
        # Defensive: a stale match that points at a deleted asset.
        return None  # type: ignore[return-value]

    existing = _has_open_finding(db, asset.id, match.cve_id)
    if existing is not None:
        _apply_risk(existing, asset, vuln)
        existing.technology_id = match.technology_id
        existing.source = source
        existing.updated_at = utcnow_naive()
        return existing

    finding = Finding(
        asset_id=asset.id,
        vulnerability_cve_id=match.cve_id,
        technology_id=match.technology_id,
        status=FindingStatus.OPEN,
        source=source,
    )
    _apply_risk(finding, asset, vuln)
    db.add(finding)
    return finding


def upsert_many(
    db: Session, matches: Iterable[AssetCveMatch], source: str = "scan"
) -> list[Finding]:
    """Bulk variant of ``upsert_from_match`` for the asset scan path."""
    out: list[Finding] = []
    for m in matches:
        f = upsert_from_match(db, m, source=source)
        if f is not None:
            out.append(f)
    return out


def recompute_for_cve(db: Session, cve_id: str) -> int:
    """Re-score every active Finding for one CVE. Used by the sync
    scheduler after NVD incremental / KEV runs. Returns the number of
    Findings updated."""
    vuln = (
        db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    )
    if vuln is None:
        return 0
    active = (
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFIED,
    )
    findings = (
        db.query(Finding)
        .filter(
            and_(
                Finding.vulnerability_cve_id == cve_id,
                Finding.status.in_(active),
            )
        )
        .all()
    )
    n = 0
    for f in findings:
        asset = db.get(Asset, f.asset_id)
        if asset is None:
            continue
        _apply_risk(f, asset, vuln)
        f.updated_at = utcnow_naive()
        n += 1
    return n


def recompute_for_asset(db: Session, asset_id: int) -> int:
    """Re-score every active Finding for one asset. Used when an
    analyst changes criticality or internet_exposed via PATCH."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        return 0
    active = (
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFIED,
    )
    findings = (
        db.query(Finding)
        .filter(and_(Finding.asset_id == asset_id, Finding.status.in_(active)))
        .all()
    )
    n = 0
    for f in findings:
        vuln = (
            db.query(Vulnerability)
            .filter(Vulnerability.cve_id == f.vulnerability_cve_id)
            .first()
        )
        _apply_risk(f, asset, vuln)
        f.updated_at = utcnow_naive()
        n += 1
    return n


def backfill_from_asset_cve_matches(db: Session) -> int:
    """One-shot migration. Copies every AssetCveMatch that does not
    already have a Finding into the findings table. Idempotent — the
    SyncRun guard means a second call is a no-op.

    Returns the number of Findings created.
    """
    # Guard: a SyncRun row with source='findings_backfill' that finished
    # successfully means we are done. Re-runs are safe to skip.
    existing_run = (
        db.query(SyncRun)
        .filter(
            and_(
                SyncRun.source == "findings_backfill",
                SyncRun.status == "ok",
            )
        )
        .first()
    )
    if existing_run is not None:
        return 0

    run = SyncRun(source="findings_backfill", status="running")
    db.add(run)
    db.flush()

    matches = db.query(AssetCveMatch).all()
    created = 0
    for m in matches:
        # Skip if a finding already exists for this (asset, cve) pair in
        # any state — covers the case where the user has been running
        # with the new code and some findings already exist.
        already = (
            db.query(Finding)
            .filter(
                and_(
                    Finding.asset_id == m.asset_id,
                    Finding.vulnerability_cve_id == m.cve_id,
                )
            )
            .first()
        )
        if already is not None:
            continue
        f = upsert_from_match(db, m, source="backfill")
        if f is not None:
            created += 1

    run.finished_at = utcnow_naive()
    run.items_fetched = len(matches)
    run.items_inserted = created
    run.status = "ok"
    return created


def resolve_finding(
    db: Session,
    finding: Finding,
    actor: User,
    notes: Optional[str] = None,
) -> Finding:
    """Mark a finding RESOLVED. Sets ``resolved_at`` so reports can
    compute time-to-remediate."""
    finding.status = FindingStatus.RESOLVED
    finding.resolved_at = utcnow_naive()
    if notes is not None:
        existing = (finding.notes or "").strip()
        stamp = f"[{utcnow_naive().isoformat(timespec='seconds')}] {actor.username}: {notes.strip()}"
        finding.notes = (existing + "\n" + stamp).strip() if existing else stamp
    finding.updated_at = utcnow_naive()
    return finding


def accept_risk(
    db: Session,
    finding: Finding,
    actor: User,
    reason: str,
) -> Finding:
    """Terminal state. The finding stays in the registry but is hidden
    from the "open" queues. The reason is mandatory and stored in
    ``notes`` for audit."""
    if not reason or not reason.strip():
        raise ValueError("accept-risk requires a non-empty reason")
    finding.status = FindingStatus.ACCEPTED_RISK
    finding.resolved_at = utcnow_naive()
    stamp = (
        f"[{utcnow_naive().isoformat(timespec='seconds')}] "
        f"{actor.username} accepted risk: {reason.strip()}"
    )
    existing = (finding.notes or "").strip()
    finding.notes = (existing + "\n" + stamp).strip() if existing else stamp
    finding.updated_at = utcnow_naive()
    return finding

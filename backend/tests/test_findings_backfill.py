"""End-to-end tests for the findings backfill + recompute paths.

These tests use an isolated in-memory SQLite DB so we don't touch the
project's real ``vulnwatch.db``. They exercise the parts of the
service layer that the API router and the sync scheduler call into.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.session import Base
from app.models import (
    Asset,
    AssetCveMatch,
    AssetCriticality,
    Finding,
    FindingStatus,
    SyncRun,
    User,
    Vulnerability,
)
from app.services import findings as service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield SessionLocal


@pytest.fixture()
def seed(db):
    """Populate a small but realistic data set:

    - 2 users (admin, analyst)
    - 2 assets (one internet-exposed CRITICAL, one internal LOW)
    - 3 CVEs: a high-CVSS one, a KEV one, a low-CVSS non-KEV one
    - 3 AssetCveMatches spread across the assets and CVEs
    """
    Session = db
    s = Session()

    admin = User(
        username="admin", email="admin@x", hashed_password="x",
        role="admin", is_active=True,
    )
    analyst = User(
        username="alice", email="alice@x", hashed_password="x",
        role="analyst", is_active=True,
    )
    s.add_all([admin, analyst])
    s.flush()

    a_public = Asset(
        label="Public Moodle",
        url="https://moodle.example.edu",
        env="production",
        criticality=AssetCriticality.CRITICAL,
        internet_exposed=True,
    )
    a_internal = Asset(
        label="Internal Wiki",
        url="https://wiki.internal",
        env="production",
        criticality=AssetCriticality.LOW,
        internet_exposed=False,
    )
    s.add_all([a_public, a_internal])
    s.flush()

    cve_high = Vulnerability(
        cve_id="CVE-2024-0001",
        title="Apache RCE",
        description="Remote code execution in Apache.",
        cvss_v3_score=9.8,
        in_kev=False,
    )
    cve_kev = Vulnerability(
        cve_id="CVE-2024-0002",
        title="Moodle SQLi",
        description="SQL injection in Moodle login.",
        cvss_v3_score=8.0,
        in_kev=True,
    )
    cve_low = Vulnerability(
        cve_id="CVE-2024-0003",
        title="Wiki info disclosure",
        description="Minor info disclosure.",
        cvss_v3_score=3.0,
        in_kev=False,
    )
    s.add_all([cve_high, cve_kev, cve_low])
    s.flush()

    s.add_all([
        AssetCveMatch(asset_id=a_public.id, cve_id=cve_high.cve_id),
        AssetCveMatch(asset_id=a_public.id, cve_id=cve_kev.cve_id),
        AssetCveMatch(asset_id=a_internal.id, cve_id=cve_low.cve_id),
    ])
    s.commit()
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------
def test_backfill_creates_one_finding_per_match(seed):
    n = service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    assert n == 3
    assert seed.query(Finding).count() == 3


def test_backfill_is_idempotent(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # Second call should be a no-op because the SyncRun guard fires.
    n = service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    assert n == 0
    assert seed.query(Finding).count() == 3


def test_backfill_records_a_sync_run(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    run = (
        seed.query(SyncRun)
        .filter(SyncRun.source == "findings_backfill")
        .one()
    )
    assert run.status == "ok"
    assert run.items_inserted == 3


def test_backfill_risk_scores_match_scorer(seed):
    """The headline guarantee: every backfilled Finding must have been
    scored by the engine. The Public Moodle + KEV CVE combo must come
    out CRITICAL."""
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # CVE-2024-0002 (KEV, CVSS 8.0) on the public CRITICAL asset
    # -> cvss 80 + kev 25 + crit 30 + exposure 15 = 150 -> clamped 100.
    kev_finding = (
        seed.query(Finding)
        .filter(Finding.vulnerability_cve_id == "CVE-2024-0002")
        .one()
    )
    assert kev_finding.risk_score == 100
    assert kev_finding.risk_label == "CRITICAL"

    # CVE-2024-0001 (CVSS 9.8, no KEV) on the same asset
    # -> 98 + 0 + 30 + 15 = 143 -> clamped 100
    high_finding = (
        seed.query(Finding)
        .filter(Finding.vulnerability_cve_id == "CVE-2024-0001")
        .one()
    )
    assert high_finding.risk_score == 100
    assert high_finding.risk_label == "CRITICAL"

    # CVE-2024-0003 (CVSS 3.0, no KEV) on an internal LOW asset
    # -> 30 + 0 + 0 + 0 = 30 -> MEDIUM
    low_finding = (
        seed.query(Finding)
        .filter(Finding.vulnerability_cve_id == "CVE-2024-0003")
        .one()
    )
    assert low_finding.risk_score == 30
    assert low_finding.risk_label == "MEDIUM"


def test_backfill_skips_existing_findings(seed):
    """If a Finding already exists for a (asset, CVE) pair, backfill
    must not duplicate it."""
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # Manually delete the SyncRun guard and run again — the service
    # should still skip because the Finding row exists.
    seed.query(SyncRun).delete()
    seed.commit()
    n = service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    assert n == 0
    assert seed.query(Finding).count() == 3


# ---------------------------------------------------------------------------
# Recompute (called by sync scheduler when CVE data changes)
# ---------------------------------------------------------------------------
def test_recompute_for_cve_refreshes_keV_status(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # Mark the high-CVSS CVE as KEV — re-score should bump the public
    # asset's Finding to CRITICAL.
    cve = seed.query(Vulnerability).filter_by(cve_id="CVE-2024-0001").one()
    cve.in_kev = True
    seed.commit()
    n = service.recompute_for_cve(seed, cve.cve_id)
    seed.commit()
    assert n == 1  # one Finding for this CVE
    f = (
        seed.query(Finding)
        .filter(Finding.vulnerability_cve_id == cve.cve_id)
        .one()
    )
    # New score: 98 (cvss) + 25 (kev) + 30 (crit) + 15 (exposed) = 168
    # -> clamped 100 -> CRITICAL
    assert f.risk_score == 100
    assert f.risk_label == "CRITICAL"


def test_recompute_for_asset_updates_criticality_change(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # Demote the public asset from CRITICAL to LOW
    a = seed.query(Asset).filter_by(label="Public Moodle").one()
    a.criticality = AssetCriticality.LOW
    seed.commit()
    n = service.recompute_for_asset(seed, a.id)
    seed.commit()
    assert n == 2  # two Findings for this asset
    # All findings on this asset should now have lost the criticality
    # weight (+30 -> +0), so CVE-2024-0001 drops from 100 to 70 (HIGH).
    f = (
        seed.query(Finding)
        .filter(Finding.vulnerability_cve_id == "CVE-2024-0001")
        .one()
    )
    # 98 + 0 + 0 + 15 = 113 -> clamped 100 -> still CRITICAL because
    # the 9.8 CVSS + exposure alone maxes the score.
    assert f.risk_score == 100
    assert f.risk_label == "CRITICAL"


def test_upsert_from_match_does_not_duplicate(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    # Re-apply the same match — should be a no-op (one Finding stays).
    m = (
        seed.query(AssetCveMatch)
        .filter_by(cve_id="CVE-2024-0002")
        .first()
    )
    service.upsert_from_match(seed, m, source="scan")
    seed.commit()
    assert (
        seed.query(Finding)
        .filter_by(asset_id=m.asset_id, vulnerability_cve_id=m.cve_id)
        .count()
    ) == 1


def test_upsert_from_match_creates_new_after_resolve(seed):
    """Once a finding is RESOLVED, a fresh match for the same (asset,
    CVE) should create a new open Finding — the slot is freed."""
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    f = (
        seed.query(Finding)
        .filter_by(vulnerability_cve_id="CVE-2024-0002")
        .one()
    )
    f.status = FindingStatus.RESOLVED
    seed.commit()
    m = (
        seed.query(AssetCveMatch)
        .filter_by(cve_id="CVE-2024-0002")
        .first()
    )
    service.upsert_from_match(seed, m, source="scan")
    seed.commit()
    open_for_pair = (
        seed.query(Finding)
        .filter_by(
            asset_id=m.asset_id,
            vulnerability_cve_id=m.cve_id,
            status=FindingStatus.OPEN,
        )
        .count()
    )
    assert open_for_pair == 1


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------
def test_accept_risk_sets_terminal_state(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    f = seed.query(Finding).first()
    admin = seed.query(User).filter_by(username="admin").one()
    service.accept_risk(seed, f, admin, reason="compensating control in place")
    seed.commit()
    assert f.status == FindingStatus.ACCEPTED_RISK
    assert f.resolved_at is not None
    assert "accepted risk" in (f.notes or "").lower()
    assert "compensating control" in (f.notes or "").lower()


def test_accept_risk_rejects_empty_reason(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    f = seed.query(Finding).first()
    admin = seed.query(User).filter_by(username="admin").one()
    with pytest.raises(ValueError):
        service.accept_risk(seed, f, admin, reason="   ")


def test_resolve_finding_appends_note_with_actor(seed):
    service.backfill_from_asset_cve_matches(seed)
    seed.commit()
    f = seed.query(Finding).first()
    admin = seed.query(User).filter_by(username="admin").one()
    service.resolve_finding(seed, f, admin, notes="patched in 4.5.1")
    seed.commit()
    assert f.status == FindingStatus.RESOLVED
    assert "patched in 4.5.1" in f.notes
    assert "admin" in f.notes

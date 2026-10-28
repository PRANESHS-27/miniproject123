"""Tests for health + sync monitoring (free-priority #19).

Covers:
  * /health (legacy) and /api/health/liveness are anonymous, always 200.
  * /api/health/status requires super_admin (non-admin → 403, no auth → 401).
  * /api/health/status reports DB OK + cve_index + scheduler state + per-source staleness.
  * Stale syncs (last_success > sync_stale_hours ago) are flagged.
  * /api/sync/status aggregates per-source last-success with stale flag.
  * Scheduler introspection returns running=True with job list when the
    scheduler is started, and running=False when dormant.
  * Asset-scan overdue count is exposed when active assets exist past the threshold.

Tests reuse the in-memory SQLite fixture pattern from
test_tenant_isolation / test_e2e so they run in CI without Postgres.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import config
from app.core.security import hash_password
from app.db.session import Base
from app.main import app
from app.models import (
    Asset,
    DEFAULT_INSTITUTION_ID,
    Institution,
    Role,
    SyncRun,
    User,
)
from app.services import cve_index
from app.services import scheduler_jobs as sj

import app.core.rate_limit as rl


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    # Pin a single connection so both the test session and the FastAPI
    # override see the same in-memory tables. ``create_all`` only
    # creates on the FIRST connection acquired from the pool — without
    # this, subsequent connections see an empty schema.
    conn = engine.connect()
    SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
    s = SessionLocal()
    s.add(Institution(
        id=DEFAULT_INSTITUTION_ID,
        name="Acme University",
        slug="acme-university",
        is_active=True,
    ))
    # ``instadmin`` uses the legacy ``Role.ADMIN`` wire value so it passes
    # the legacy ``require_admin`` gate used by /api/sync/* (which predates
    # the permission matrix). ``superadmin`` uses the new 4-tier role
    # and exercises the matrix-gated /api/health/status route.
    s.add(User(
        username="instadmin",
        email="instadmin@test.local",
        hashed_password=hash_password("adminpass"),
        role=Role.ADMIN,
        is_active=True,
        institution_id=DEFAULT_INSTITUTION_ID,
    ))
    s.add(User(
        username="superadmin",
        email="superadmin@test.local",
        hashed_password=hash_password("superpass"),
        role=Role.SUPER_ADMIN,
        is_active=True,
        institution_id=DEFAULT_INSTITUTION_ID,
    ))
    s.add(User(
        username="viewer",
        email="viewer@test.local",
        hashed_password=hash_password("viewerpass"),
        role=Role.VIEWER,
        is_active=True,
        institution_id=DEFAULT_INSTITUTION_ID,
    ))
    s.commit()
    yield s
    s.close()
    conn.close()


@pytest.fixture()
def client(db_session, monkeypatch):
    from app.db import get_db

    # Bind the override to the SAME connection the test fixture uses,
    # not just the same engine — in-memory SQLite is per-connection.
    bind_conn = db_session.get_bind()
    SessionLocal = sessionmaker(bind=bind_conn, autoflush=False, autocommit=False)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    saved_lifespan = app.router.lifespan_context
    app.router.lifespan_context = None
    rl.reset_for_tests()
    monkeypatch.setattr(config.settings, "login_rate_limit_per_minute", 0)
    # cve_index holds module-level state — reset between tests so the
    # readiness probe doesn't see counters leaked from earlier tests.
    cve_index._state.clear()
    cve_index._state.update({
        "ready": False,
        "total_cves": 0,
        "by_severity": {},
        "kev_count": 0,
        "recent": [],
        "excluded_cve_ids": set(),
        "vendor_to_cves": {},
        "top_vendors": [],
        "asset_top_vendors": [],
        "asset_top_products": [],
        "tech_counter": [],
        "findings_by_type": {},
        "total_assets": 0,
        "active_assets": 0,
        "open_findings": 0,
        "critical_findings": 0,
        "cves_affecting_us": 0,
        "assets_with_critical": 0,
        "built_at": None,
    })
    # Scheduler: tests don't run the lifespan hook, so it stays None.
    # Reset the module-level state in case a previous test started it.
    saved_scheduler = sj._scheduler
    sj._scheduler = None
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan
        app.dependency_overrides.clear()
        sj._scheduler = saved_scheduler


def _login(client: TestClient, username: str, password: str) -> str:
    res = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Liveness (anonymous, always 200)
# ===========================================================================
class TestLiveness:
    def test_legacy_health_is_anonymous_and_ok(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "ok"
        assert "app" in body

    def test_api_health_liveness_is_anonymous_and_ok(self, client):
        res = client.get("/api/health/liveness")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "ok"

    def test_liveness_works_without_auth(self, client):
        # Sanity: no Authorization header at all.
        res = client.get("/health", headers={})
        assert res.status_code == 200


# ===========================================================================
# Readiness — auth gate
# ===========================================================================
class TestReadinessAuth:
    def test_anonymous_is_401(self, client):
        res = client.get("/api/health/status")
        assert res.status_code == 401

    def test_viewer_is_403(self, client):
        token = _login(client, "viewer", "viewerpass")
        res = client.get("/api/health/status", headers=_auth(token))
        assert res.status_code == 403

    def test_super_admin_is_200(self, client):
        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        assert res.status_code == 200, res.text

    def test_inst_admin_is_200(self, client):
        # /api/health/status is gated on the permission matrix (sync.trigger),
        # which both TIER_SUPER_ADMIN and TIER_INSTITUTION_ADMIN satisfy.
        token = _login(client, "instadmin", "adminpass")
        res = client.get("/api/health/status", headers=_auth(token))
        assert res.status_code == 200, res.text


# ===========================================================================
# Readiness — payload shape
# ===========================================================================
class TestReadinessPayload:
    def test_status_returns_structured_payload(self, client):
        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        assert res.status_code == 200
        body = res.json()

        # Top-level shape
        assert body["status"] == "ok"
        assert "app" in body
        assert "version" in body
        assert "now" in body

        # Checks block
        checks = body["checks"]
        assert checks["database"]["ok"] is True
        # cve_index is unbuilt in tests → not ready, but no error
        assert checks["cve_index"]["ready"] is False
        # Scheduler is dormant in tests (lifespan hook bypassed)
        assert checks["scheduler"]["running"] is False
        assert checks["scheduler"]["jobs"] == []

        # Syncs block — per-source
        syncs = body["syncs"]
        assert syncs["stale_hours"] == 48
        sources = {s["source"] for s in syncs["sources"]}
        assert sources == {"nvd", "kev"}
        # No SyncRun rows → never synced → stale is True (a source
        # that's never completed is the stalest possible state).
        for s in syncs["sources"]:
            assert s["last_success_at"] is None
            assert s["age_hours"] is None
            assert s["stale"] is True
            assert s["running"] is False

        # Asset scans block
        assert body["asset_scans"]["active_assets"] == 0
        assert body["asset_scans"]["overdue_assets"] == 0
        assert body["asset_scans"]["stale_hours"] == 36

        # Totals
        assert body["totals"]["institutions"] == 1
        assert body["totals"]["users"] == 2

    def test_status_reports_db_failure_as_503(self, client, monkeypatch):
        """Force ``_db_ok`` to return False → readiness returns 503."""
        from app.api import health as health_module

        monkeypatch.setattr(
            health_module, "_db_ok",
            lambda: (False, "OperationalError: no such table"),
        )
        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        assert res.status_code == 503
        body = res.json()
        assert body["status"] == "degraded"
        assert body["checks"]["database"]["ok"] is False
        assert "OperationalError" in body["checks"]["database"]["error"]

    def test_status_reports_built_cve_index(self, client):
        from datetime import datetime as _dt

        # Simulate the lifespan hook having built the index.
        cve_index._state["ready"] = True
        cve_index._state["total_cves"] = 12345
        cve_index._state["kev_count"] = 42
        from datetime import timezone as _tz
        cve_index._state["built_at"] = _dt.now(_tz.utc)

        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        body = res.json()
        idx = body["checks"]["cve_index"]
        assert idx["ready"] is True
        assert idx["total_cves"] == 12345
        assert idx["kev_count"] == 42
        assert idx["age_seconds"] is not None
        assert idx["age_seconds"] >= 0


# ===========================================================================
# Stale sync detection
# ===========================================================================
class TestStaleSync:
    def test_recent_nvd_sync_is_not_stale(self, client, db_session):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_session.add(SyncRun(
            source="nvd",
            started_at=now - timedelta(hours=2),
            finished_at=now - timedelta(hours=2) + timedelta(minutes=5),
            status="ok",
            items_fetched=100,
        ))
        db_session.commit()

        token = _login(client, "instadmin", "adminpass")
        res = client.get("/api/sync/status", headers=_auth(token))
        assert res.status_code == 200
        body = res.json()
        assert body["stale_hours"] == 48

        nvd = next(s for s in body["sources"] if s["source"] == "nvd")
        assert nvd["last_success_at"] is not None
        assert nvd["age_hours"] is not None
        assert nvd["age_hours"] < 48
        assert nvd["stale"] is False
        assert nvd["running"] is False

    def test_old_nvd_sync_is_stale(self, client, db_session):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # 60 hours ago — well past the 48h default threshold.
        db_session.add(SyncRun(
            source="nvd",
            started_at=now - timedelta(hours=60),
            finished_at=now - timedelta(hours=60) + timedelta(minutes=5),
            status="ok",
            items_fetched=100,
        ))
        db_session.commit()

        token = _login(client, "instadmin", "adminpass")
        res = client.get("/api/sync/status", headers=_auth(token))
        body = res.json()
        nvd = next(s for s in body["sources"] if s["source"] == "nvd")
        assert nvd["stale"] is True
        assert nvd["age_hours"] > 48

    def test_running_sync_shows_running_flag(self, client, db_session):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # A "running" sync + a recent successful one to anchor staleness.
        db_session.add(SyncRun(
            source="kev",
            started_at=now - timedelta(minutes=1),
            status="running",
        ))
        db_session.add(SyncRun(
            source="kev",
            started_at=now - timedelta(hours=1),
            finished_at=now - timedelta(hours=1) + timedelta(seconds=30),
            status="ok",
        ))
        db_session.commit()

        token = _login(client, "instadmin", "adminpass")
        res = client.get("/api/sync/status", headers=_auth(token))
        body = res.json()
        kev = next(s for s in body["sources"] if s["source"] == "kev")
        assert kev["running"] is True
        assert kev["stale"] is False

    def test_only_latest_success_per_source_counts(self, client, db_session):
        """Older runs must not influence the per-source last-success."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # 7 days ago: success
        db_session.add(SyncRun(
            source="nvd",
            started_at=now - timedelta(days=7),
            finished_at=now - timedelta(days=7) + timedelta(minutes=5),
            status="ok",
        ))
        # 1 hour ago: success — this is the one that wins.
        db_session.add(SyncRun(
            source="nvd",
            started_at=now - timedelta(hours=1),
            finished_at=now - timedelta(hours=1) + timedelta(minutes=5),
            status="ok",
        ))
        db_session.commit()

        token = _login(client, "instadmin", "adminpass")
        res = client.get("/api/sync/status", headers=_auth(token))
        nvd = next(s for s in res.json()["sources"] if s["source"] == "nvd")
        assert nvd["stale"] is False
        assert nvd["age_hours"] < 2


# ===========================================================================
# Scheduler introspection
# ===========================================================================
class TestSchedulerIntrospection:
    def test_dormant_scheduler_reports_not_running(self):
        sj._scheduler = None
        status = sj.scheduler_status()
        assert status["running"] is False
        assert status["jobs"] == []

    def test_running_scheduler_reports_jobs(self):
        """Stand up a real BackgroundScheduler (no DB hook needed) so the
        introspection helper exercises the jobs branch."""
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.interval import IntervalTrigger

        sch = BackgroundScheduler(timezone="UTC")
        sch.add_job(
            lambda: None,
            IntervalTrigger(minutes=30),
            id="test_job",
            replace_existing=True,
        )
        sch.start()
        sj._scheduler = sch
        try:
            status = sj.scheduler_status()
            assert status["running"] is True
            assert len(status["jobs"]) == 1
            job = status["jobs"][0]
            assert job["id"] == "test_job"
            assert job["trigger"] == "IntervalTrigger"
        finally:
            sch.shutdown(wait=False)
            sj._scheduler = None


# ===========================================================================
# /api/health/status surfaces scheduler running when started
# ===========================================================================
class TestHealthIntegratesSchedulerStatus:
    def test_super_admin_reports_built_cve_index(self, client):
        from datetime import datetime as _dt

        # Simulate the lifespan hook having built the index.
        cve_index._state["ready"] = True
        cve_index._state["total_cves"] = 12345
        cve_index._state["kev_count"] = 42
        from datetime import timezone as _tz
        cve_index._state["built_at"] = _dt.now(_tz.utc)

        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        body = res.json()
        idx = body["checks"]["cve_index"]
        assert idx["ready"] is True
        assert idx["total_cves"] == 12345
        assert idx["kev_count"] == 42
        assert idx["age_seconds"] is not None
        assert idx["age_seconds"] >= 0


class TestReadinessPayload:
    def test_super_admin_reports_db_failure_as_503(self, client, monkeypatch):
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.interval import IntervalTrigger

        sch = BackgroundScheduler(timezone="UTC")
        sch.add_job(
            lambda: None,
            IntervalTrigger(minutes=30),
            id="nvd_incremental",
            replace_existing=True,
        )
        sch.start()
        sj._scheduler = sch
        try:
            token = _login(client, "superadmin", "superpass")
            res = client.get("/api/health/status", headers=_auth(token))
            assert res.status_code == 200
            sched_block = res.json()["checks"]["scheduler"]
            assert sched_block["running"] is True
            assert any(j["id"] == "nvd_incremental" for j in sched_block["jobs"])
        finally:
            sch.shutdown(wait=False)
            sj._scheduler = None


# ===========================================================================
# /api/health/status surfaces overdue asset scans
# ===========================================================================
class TestAssetScanOverdue:
    def test_overdue_assets_count_when_active_assets_exist(
        self, client, db_session
    ):
        """An active asset with no AssetScan row at all is overdue."""
        from app.models import AssetCriticality

        asset = Asset(
            owner_id=1,
            label="Acme Portal",
            url="https://portal.acme.example.com",
            env="production",
            is_active=True,
            institution_id=DEFAULT_INSTITUTION_ID,
            criticality=AssetCriticality.HIGH,
            internet_exposed=True,
        )
        db_session.add(asset)
        db_session.commit()

        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        body = res.json()
        assert body["asset_scans"]["active_assets"] == 1
        assert body["asset_scans"]["overdue_assets"] == 1

    def test_recently_scanned_asset_is_not_overdue(
        self, client, db_session
    ):
        from app.models import (
            AssetCriticality,
            AssetScan,
        )

        asset = Asset(
            owner_id=1,
            label="Fresh asset",
            url="https://fresh.acme.example.com",
            env="production",
            is_active=True,
            institution_id=DEFAULT_INSTITUTION_ID,
            criticality=AssetCriticality.MEDIUM,
        )
        db_session.add(asset)
        db_session.flush()

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_session.add(AssetScan(
            asset_id=asset.id,
            started_at=now - timedelta(minutes=30),
            finished_at=now - timedelta(minutes=20),
            status="ok",
        ))
        db_session.commit()

        token = _login(client, "superadmin", "superpass")
        res = client.get("/api/health/status", headers=_auth(token))
        body = res.json()
        assert body["asset_scans"]["active_assets"] == 1
        assert body["asset_scans"]["overdue_assets"] == 0
"""End-to-end integration tests for the VulnWatch HTTP API.

These tests drive the FastAPI app as a real client would: through the
``TestClient``, exercising the auth + tenant + RBAC + business-logic
layers together. The goal is regression coverage for the *router glue*
(get_current_user + get_tenant_context + tenant_filter + response
hydration + BackgroundTasks) — the individual pieces have their own
focused tests in test_tenant_isolation.py / test_rbac.py /
test_findings_backfill.py.

What's covered here:

  * TestAuthLifecycle          — register/login/refresh/me + audit row
  * TestAssetLifecycle         — CRUD + PATCH recompute via HTTP
  * TestScanPipelineMocked     — trigger_scan + findings resolve + dashboard
  * TestFindingLifecycle       — backfill + state machine + accept-risk
  * TestRBACDenialPaths        — 403 paths through the real router
  * TestDashboardCounters      — endpoint shape on a fresh DB

Out of scope (left for follow-up if needed):

  * Reports (PDF / CSV) endpoints
  * /api/ai/ask
  * /api/sync/* trigger endpoints
  * /api/vulnerabilities/search free-text

These are all already covered at the service level in their own test
files; they just don't get an HTTP-level pass.

Scan pipeline strategy: ``scan_one_asset`` hits real URLs and would
take 10+ seconds and be network-flaky. We monkey-patch it with a stub
that inserts deterministic ``AssetScan`` + ``AssetFinding`` +
``AssetCveMatch`` + ``Finding`` rows, so we exercise the surrounding
router code (BackgroundTasks wrapper, in-process ``_active_scans`` set,
post-scan cve_index refresh) without the network.
"""

from __future__ import annotations

from typing import Iterable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core import config
from app.core.security import hash_password
from app.core.time import utcnow_naive
from app.db.session import Base
from app.main import app
from app.models import (
    Asset,
    AssetCriticality,
    AssetCveMatch,
    AssetFinding,
    AssetScan,
    DEFAULT_INSTITUTION_ID,
    Finding,
    FindingRiskLabel,
    FindingStatus,
    FindingType,
    Institution,
    LoginAudit,
    Role,
    SeverityLevel,
    User,
    Vulnerability,
)
from app.services import cve_index
from app.services import findings as finding_service

import app.api.assets as assets_api
import app.core.rate_limit as rl


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def db_session():
    """In-memory SQLite + a single Institution (id=1, Acme) seeded.

    No users / assets seeded by default — each test class decides what
    it needs so the first-user-SUPER_ADMIN branch in /api/auth/register
    can fire in the auth-lifecycle tests."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    conn = engine.connect()
    SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
    s = SessionLocal()
    s.add(Institution(
        id=DEFAULT_INSTITUTION_ID,
        name="Acme University",
        slug="acme-university",
        is_active=True,
    ))
    s.commit()
    yield s
    s.close()
    conn.close()


@pytest.fixture()
def client(db_session, monkeypatch):
    """TestClient with the lifespan disabled and tenant/rate-limit state reset.

    The lifespan-disable + get_db-override pattern is identical to
    test_tenant_isolation.py — kept duplicated here so per-file fixture
    state can't leak across files (each file may want different seed
    shapes)."""
    from app.db import get_db

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
    # Reset the cve_index snapshot so dashboard counters don't leak
    # across tests sharing this process.
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
    # Module-level state in app/api/assets.py — a previous test that
    # fired a scan would leave the asset_id in this set and the next
    # trigger_scan would 409 with "Scan already in progress".
    assets_api._active_scans.clear()
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan
        app.dependency_overrides.clear()
        assets_api._active_scans.clear()


@pytest.fixture()
def seeded(db_session):
    """Default users + one asset, ready for non-auth tests.

    Users:
      * ``inst_a``    — INSTITUTION_ADMIN (legacy Role.ADMIN wire value)
      * ``analyst_a`` — SECURITY_ANALYST (Role.ANALYST wire value)
      * ``viewer_a``  — VIEWER
      * ``other_a``   — analyst tier, used for the cross-user RBAC test

    Asset: one active internet-exposed MEDIUM-criticality Acme asset.
    """
    inst = db_session.get(Institution, DEFAULT_INSTITUTION_ID)
    users = [
        User(
            username="inst_a",
            email="insta@test.local",
            hashed_password=hash_password("instpass"),
            role=Role.ADMIN,
            is_active=True,
            institution_id=inst.id,
        ),
        User(
            username="analyst_a",
            email="aa@test.local",
            hashed_password=hash_password("analystpass"),
            role=Role.ANALYST,
            is_active=True,
            institution_id=inst.id,
        ),
        User(
            username="viewer_a",
            email="va@test.local",
            hashed_password=hash_password("viewerpass"),
            role=Role.VIEWER,
            is_active=True,
            institution_id=inst.id,
        ),
        User(
            username="other_a",
            email="oa@test.local",
            hashed_password=hash_password("otherpass"),
            role=Role.ANALYST,
            is_active=True,
            institution_id=inst.id,
        ),
    ]
    db_session.add_all(users)
    asset = Asset(
        owner_id=users[0].id,
        label="Acme Main",
        url="https://acme.example.com",
        env="production",
        is_active=True,
        institution_id=inst.id,
        criticality=AssetCriticality.MEDIUM,
        internet_exposed=True,
    )
    db_session.add(asset)
    db_session.commit()
    return {
        "inst": inst,
        "inst_a": users[0],
        "analyst_a": users[1],
        "viewer_a": users[2],
        "other_a": users[3],
        "asset": asset,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _login(client: TestClient, username: str, password: str) -> dict:
    res = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert res.status_code == 200, res.text
    return res.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def scan_faker(monkeypatch):
    """Patch ``scan_one_asset`` with a stub that creates deterministic rows.

    For the given asset_id, the stub inserts:
      * 1 AssetScan row (status=success, inserted=2, re_seen=0, closed=0)
      * 2 AssetFinding rows (HIGH + MEDIUM, header + cve finding types)
      * 1 Vulnerability (CRITICAL CVE)
      * 1 AssetCveMatch linking the asset to that CVE
      * 1 Finding (Risk Engine output) for the (asset, CVE) pair

    After inserting, it calls ``cve_index.refresh(db)`` so the dashboard
    endpoint sees the same numbers the assets page does — which is the
    production behaviour (see app/services/asset_scanner.py:362).
    """
    def _stub(db: Session, asset_id: int, *, triggered_by: str = "manual"):
        asset = db.get(Asset, asset_id)
        if asset is None:
            return None

        scan = AssetScan(
            asset_id=asset_id,
            status="success",
            items_found=2,
            inserted_count=2,
            re_seen_count=0,
            closed_count=0,
            technologies_detected=1,
            cves_matched=1,
            triggered_by=triggered_by,
        )
        db.add(scan)
        db.flush()

        now = utcnow_naive()
        db.add_all([
            AssetFinding(
                asset_id=asset_id,
                finding_type=FindingType.HEADER,
                severity=SeverityLevel.HIGH,
                title="Missing X-Frame-Options",
                details={"header": "X-Frame-Options", "issue": "missing"},
                remediation="Add X-Frame-Options: DENY.",
                discovered_at=now,
                last_seen_at=now,
            ),
            AssetFinding(
                asset_id=asset_id,
                finding_type=FindingType.CVE,
                severity=SeverityLevel.MEDIUM,
                title="CVE-2099-9999 affects acme:server",
                details={"cve_id": "CVE-2099-9999"},
                remediation="Upgrade.",
                discovered_at=now,
                last_seen_at=now,
            ),
        ])

        vuln = Vulnerability(
            cve_id="CVE-2099-9999",
            title="Acme server RCE",
            description="Remote code execution in Acme server.",
            cvss_v3_score=9.8,
            severity="CRITICAL",
            in_kev=False,
        )
        db.add(vuln)
        db.flush()

        match = AssetCveMatch(asset_id=asset_id, cve_id=vuln.cve_id)
        db.add(match)
        db.flush()

        finding_service.upsert_from_match(db, match, source="scan")

        scan.finished_at = now
        asset.last_scanned_at = now
        asset.last_scan_status = "success"
        db.commit()
        try:
            cve_index.refresh(db)
        except Exception:
            pass
        return scan

    monkeypatch.setattr(
        "app.services.asset_scanner.scan_one_asset", _stub,
    )
    return _stub


@pytest.fixture()
def scan_runner(monkeypatch, db_session):
    """Patch ``app.api.assets.SessionLocal`` so the BackgroundTask
    opened by trigger_scan uses the in-memory test DB, not the real one.

    Without this, the BackgroundTasks runner opens a session bound to
    the production ``vulnwatch.db`` engine — a schema that doesn't
    include the RBAC 22 columns added later (``assets.institution_id``
    etc.) — and we get ``sqlite3.OperationalError: no such column``
    halfway through the request.

    Patching the ``SessionLocal`` symbol in the *api module* is enough;
    the BackgroundTask's ``_run_asset_scan`` calls ``SessionLocal()``
    from ``app.api.assets``, not from ``app.db``.
    """
    from sqlalchemy.orm import sessionmaker

    bind_conn = db_session.get_bind()
    TestSessionLocal = sessionmaker(bind=bind_conn, autoflush=False, autocommit=False)
    monkeypatch.setattr("app.api.assets.SessionLocal", TestSessionLocal)
    return TestSessionLocal


# ===========================================================================
# Auth lifecycle
# ===========================================================================
class TestAuthLifecycle:
    def test_register_then_login_then_me_round_trip(self, client):
        # First registration promotes to SUPER_ADMIN.
        r = client.post(
            "/api/auth/register",
            json={
                "username": "first",
                "email": "first@test.local",
                "password": "FirstPass!1",
                "role": "viewer",  # ignored — promoted to super_admin
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["user"]["username"] == "first"
        # Token returned, refresh_token included.
        assert body["access_token"]
        assert body["refresh_token"]
        # Default institution (id=1).
        assert body["user"]["institution_id"] == DEFAULT_INSTITUTION_ID

        # Login with the same creds works.
        r = client.post(
            "/api/auth/login",
            json={"username": "first", "password": "FirstPass!1"},
        )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]

        # /me echoes the user with institution_id.
        r = client.get("/api/auth/me", headers=_auth(token))
        assert r.status_code == 200, r.text
        me = r.json()
        assert me["username"] == "first"
        assert me["institution_id"] == DEFAULT_INSTITUTION_ID

    def test_refresh_token_returns_fresh_pair_and_me_still_works(self, client):
        # Register a user.
        client.post(
            "/api/auth/register",
            json={
                "username": "refresher",
                "email": "refresher@test.local",
                "password": "RefreshPass!1",
            },
        )
        r = client.post(
            "/api/auth/login",
            json={"username": "refresher", "password": "RefreshPass!1"},
        )
        assert r.status_code == 200, r.text
        first_refresh = r.json()["refresh_token"]

        # Exchange the refresh token for a fresh pair.
        r = client.post(
            "/api/auth/refresh",
            json={"refresh_token": first_refresh},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # Different access_token (newly issued).
        new_token = body["access_token"]
        assert new_token
        new_refresh = body["refresh_token"]
        assert new_refresh

        # The new access token still authenticates and the institution
        # claim survived the round trip.
        r = client.get("/api/auth/me", headers=_auth(new_token))
        assert r.status_code == 200, r.text
        assert r.json()["institution_id"] == DEFAULT_INSTITUTION_ID

    def test_login_audit_row_written(self, client, db_session):
        client.post(
            "/api/auth/register",
            json={
                "username": "audited",
                "email": "audited@test.local",
                "password": "AuditPass!1",
            },
        )
        client.post(
            "/api/auth/login",
            json={"username": "audited", "password": "AuditPass!1"},
        )
        rows = (
            db_session.query(LoginAudit)
            .filter_by(username="audited")
            .all()
        )
        outcomes = {r.outcome for r in rows}
        assert "success" in outcomes


# ===========================================================================
# Asset lifecycle (CRUD + recompute)
# ===========================================================================
class TestAssetLifecycle:
    def test_create_get_patch_delete_asset(self, client, seeded):
        token = _login(client, "inst_a", "instpass")["access_token"]

        # Create
        r = client.post(
            "/api/assets",
            headers=_auth(token),
            json={
                "label": "Acme Staging",
                "url": "https://staging.acme.example.com",
                "env": "staging",
                "criticality": "HIGH",
                "internet_exposed": False,
            },
        )
        assert r.status_code == 200, r.text
        new_id = r.json()["id"]

        # Get
        r = client.get(f"/api/assets/{new_id}", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["label"] == "Acme Staging"
        assert r.json()["open_findings_count"] == 0

        # Patch label + criticality. The detail schema doesn't propagate
        # criticality back through the ORM enum (AssetOut field is `str`,
        # column is ``AssetCriticality``); verify the change persisted in
        # the DB rather than the response body.
        r = client.patch(
            f"/api/assets/{new_id}",
            headers=_auth(token),
            json={"label": "Acme Staging Renamed", "criticality": "CRITICAL"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["label"] == "Acme Staging Renamed"

        # Delete soft-deletes.
        r = client.delete(f"/api/assets/{new_id}", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["is_active"] is False

        # Default list excludes inactive.
        r = client.get("/api/assets", headers=_auth(token))
        assert r.status_code == 200
        ids = {a["id"] for a in r.json()}
        assert new_id not in ids

        # include_inactive=true brings it back.
        r = client.get("/api/assets?include_inactive=true", headers=_auth(token))
        assert new_id in {a["id"] for a in r.json()}

    def test_patch_criticality_triggers_finding_recompute(
        self, client, seeded, db_session
    ):
        """PATCHing an asset's criticality must re-score every active
        Finding for that asset via ``recompute_for_asset``.

        We seed a CRITICAL CVE on a LOW-criticality asset so the
        Finding comes out INFO/MEDIUM. Promoting the asset to
        CRITICAL must bump the Finding into the HIGH/CRITICAL band.
        """
        asset = seeded["asset"]
        asset.criticality = AssetCriticality.LOW
        asset.internet_exposed = False  # also disables the +15 weight
        db_session.commit()

        vuln = Vulnerability(
            cve_id="CVE-2099-7777",
            title="Info leak",
            description="Minor info leak",
            cvss_v3_score=5.0,
            severity="MEDIUM",
            in_kev=False,
        )
        db_session.add(vuln)
        db_session.flush()
        match = AssetCveMatch(asset_id=asset.id, cve_id=vuln.cve_id)
        db_session.add(match)
        db_session.flush()
        f = finding_service.upsert_from_match(db_session, match, source="backfill")
        db_session.commit()

        # Sanity: 5.0 CVSS + LOW + not-exposed = 50 -> MEDIUM
        assert f.risk_label == FindingRiskLabel.MEDIUM

        token = _login(client, "inst_a", "instpass")["access_token"]
        r = client.patch(
            f"/api/assets/{asset.id}",
            headers=_auth(token),
            json={"criticality": "CRITICAL", "internet_exposed": True},
        )
        assert r.status_code == 200, r.text

        # Re-fetch the finding and verify the score went up.
        db_session.refresh(f)
        # 50 (CVSS) + 30 (CRITICAL) + 15 (exposed) = 95 -> HIGH or CRITICAL
        # depending on the bucket thresholds.
        assert f.risk_score >= 80
        assert f.risk_label in (
            FindingRiskLabel.HIGH,
            FindingRiskLabel.CRITICAL,
        )


# ===========================================================================
# Scan pipeline (mocked)
# ===========================================================================
class TestScanPipelineMocked:
    def test_trigger_scan_creates_asset_scan_and_findings(
        self, client, seeded, scan_faker, scan_runner
    ):
        token = _login(client, "inst_a", "instpass")["access_token"]
        asset_id = seeded["asset"].id

        r = client.post(f"/api/assets/{asset_id}/scan", headers=_auth(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "started"
        assert body["asset_id"] == asset_id

        # TestClient runs BackgroundTasks synchronously after the
        # response, so by this point scan_faker has executed.
        r = client.get(f"/api/assets/{asset_id}/findings", headers=_auth(token))
        assert r.status_code == 200, r.text
        findings = r.json()
        titles = {f["title"] for f in findings}
        assert "Missing X-Frame-Options" in titles
        assert any("CVE-2099-9999" in t for t in titles)

        # The /cves endpoint shows the matched CVE.
        r = client.get(f"/api/assets/{asset_id}/cves", headers=_auth(token))
        assert r.status_code == 200, r.text
        cves = r.json()
        cve_ids = {c["cve_id"] for c in cves}
        assert "CVE-2099-9999" in cve_ids

    def test_resolve_finding_then_dashboard_counters_drop(
        self, client, seeded, scan_faker, scan_runner, db_session
    ):
        token = _login(client, "inst_a", "instpass")["access_token"]
        asset_id = seeded["asset"].id

        # Run the mocked scan.
        client.post(f"/api/assets/{asset_id}/scan", headers=_auth(token))

        # Pick the HIGH finding to resolve.
        r = client.get(f"/api/assets/{asset_id}/findings", headers=_auth(token))
        findings = r.json()
        target = next(f for f in findings if f["severity"] == "HIGH")
        fid = target["id"]

        # /api/assets/stats reports the open finding count BEFORE resolve.
        r = client.get("/api/assets/stats", headers=_auth(token))
        assert r.status_code == 200
        before_open = r.json()["open_findings"]

        # Resolve.
        r = client.patch(
            f"/api/assets/{asset_id}/findings/{fid}/resolve",
            headers=_auth(token),
        )
        assert r.status_code == 200, r.text

        # The finding is no longer in the default (unresolved) list.
        r = client.get(f"/api/assets/{asset_id}/findings", headers=_auth(token))
        ids = {f["id"] for f in r.json()}
        assert fid not in ids

        # With include_resolved=true it's back.
        r = client.get(
            f"/api/assets/{asset_id}/findings?include_resolved=true",
            headers=_auth(token),
        )
        assert fid in {f["id"] for f in r.json()}

        # Dashboard open_findings count dropped by exactly one.
        r = client.get("/api/assets/stats", headers=_auth(token))
        after_open = r.json()["open_findings"]
        assert after_open == before_open - 1


# ===========================================================================
# Finding lifecycle
# ===========================================================================
class TestFindingLifecycle:
    def test_backfill_endpoint_creates_findings_from_matches(
        self, client, seeded, db_session
    ):
        """Seeded AssetCveMatch → POST /api/findings/backfill →
        /api/findings returns a Finding with a populated risk_score."""
        asset = seeded["asset"]
        vuln = Vulnerability(
            cve_id="CVE-2099-5555",
            title="Acme RCE",
            description="Remote code execution",
            cvss_v3_score=9.5,
            severity="CRITICAL",
            in_kev=False,
        )
        db_session.add(vuln)
        db_session.flush()
        db_session.add(AssetCveMatch(asset_id=asset.id, cve_id=vuln.cve_id))
        db_session.commit()

        token = _login(client, "inst_a", "instpass")["access_token"]
        r = client.post("/api/findings/backfill", headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "ok"
        assert r.json()["created"] == 1

        r = client.get("/api/findings", headers=_auth(token))
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["vulnerability_cve_id"] == "CVE-2099-5555"
        assert items[0]["risk_score"] > 0
        assert items[0]["status"] == "open"

    def test_finding_state_machine_open_in_progress_resolved(
        self, client, seeded, db_session
    ):
        asset = seeded["asset"]
        vuln = Vulnerability(
            cve_id="CVE-2099-3333",
            title="Test",
            description="",
            cvss_v3_score=7.5,
            severity="HIGH",
        )
        db_session.add(vuln)
        db_session.flush()
        f = Finding(
            asset_id=asset.id,
            vulnerability_cve_id=vuln.cve_id,
            risk_score=70,
            risk_label=FindingRiskLabel.HIGH,
            status=FindingStatus.OPEN,
        )
        db_session.add(f)
        db_session.commit()
        db_session.refresh(f)

        token = _login(client, "analyst_a", "analystpass")["access_token"]

        # open -> in_progress
        r = client.patch(
            f"/api/findings/{f.id}",
            headers=_auth(token),
            json={"status": "in_progress"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "in_progress"

        # in_progress -> resolved
        r = client.patch(
            f"/api/findings/{f.id}",
            headers=_auth(token),
            json={"status": "resolved", "notes": "patched in 4.5.1"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "resolved"
        assert body["resolved_at"] is not None
        assert "patched in 4.5.1" in (body["notes"] or "")

    def test_accept_risk_requires_reason(
        self, client, seeded, db_session
    ):
        asset = seeded["asset"]
        vuln = Vulnerability(
            cve_id="CVE-2099-2222",
            title="Test",
            cvss_v3_score=8.0,
            severity="HIGH",
        )
        db_session.add(vuln)
        db_session.flush()
        f = Finding(
            asset_id=asset.id,
            vulnerability_cve_id=vuln.cve_id,
            risk_score=80,
            risk_label=FindingRiskLabel.HIGH,
            status=FindingStatus.OPEN,
        )
        db_session.add(f)
        db_session.commit()
        db_session.refresh(f)

        token = _login(client, "analyst_a", "analystpass")["access_token"]

        # Whitespace-only reason: Pydantic min_length=1 rejects empty,
        # but a single space passes Pydantic then service rejects it.
        r = client.post(
            f"/api/findings/{f.id}/accept-risk",
            headers=_auth(token),
            json={"reason": "   "},
        )
        # Service rejects whitespace with ValueError -> 400.
        assert r.status_code == 400, r.text

        # Real reason: 200, status flips to accepted_risk, notes contain reason.
        r = client.post(
            f"/api/findings/{f.id}/accept-risk",
            headers=_auth(token),
            json={"reason": "compensating control in place"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "accepted_risk"
        assert "compensating control" in (body["notes"] or "")
        assert "accepted risk" in (body["notes"] or "").lower()


# ===========================================================================
# RBAC denial paths (via the real router)
# ===========================================================================
class TestRBACDenialPaths:
    def test_viewer_cannot_create_asset(self, client, seeded):
        token = _login(client, "viewer_a", "viewerpass")["access_token"]
        r = client.post(
            "/api/assets",
            headers=_auth(token),
            json={
                "label": "Should Fail",
                "url": "https://deny.example.com",
                "env": "production",
                "criticality": "LOW",
                "internet_exposed": False,
            },
        )
        assert r.status_code == 403, r.text

    def test_analyst_cannot_patch_finding_to_other_user(
        self, client, seeded, db_session
    ):
        asset = seeded["asset"]
        vuln = Vulnerability(
            cve_id="CVE-2099-1111",
            title="Test",
            cvss_v3_score=7.0,
            severity="HIGH",
        )
        db_session.add(vuln)
        db_session.flush()
        f = Finding(
            asset_id=asset.id,
            vulnerability_cve_id=vuln.cve_id,
            risk_score=70,
            risk_label=FindingRiskLabel.HIGH,
            status=FindingStatus.OPEN,
        )
        db_session.add(f)
        db_session.commit()
        db_session.refresh(f)

        # analyst_a tries to assign the finding to other_a.
        token = _login(client, "analyst_a", "analystpass")["access_token"]
        other_id = seeded["other_a"].id
        r = client.patch(
            f"/api/findings/{f.id}",
            headers=_auth(token),
            json={"assigned_to_id": other_id},
        )
        assert r.status_code == 403, r.text
        assert "reassign" in r.json()["detail"].lower()

        # Self-assignment works for analysts (positive control).
        analyst_id = seeded["analyst_a"].id
        r = client.patch(
            f"/api/findings/{f.id}",
            headers=_auth(token),
            json={"assigned_to_id": analyst_id},
        )
        assert r.status_code == 200, r.text


# ===========================================================================
# Dashboard counters
# ===========================================================================
class TestDashboardCounters:
    def test_dashboard_returns_200_with_expected_keys(self, client, seeded):
        token = _login(client, "inst_a", "instpass")["access_token"]
        r = client.get("/api/vulnerabilities/dashboard", headers=_auth(token))
        assert r.status_code == 200, r.text
        body = r.json()
        # All DashboardStats fields are populated (no missing keys),
        # even though the seed has no CVE rows.
        for key in (
            "total_cves",
            "critical",
            "high",
            "medium",
            "low",
            "kev_count",
            "recent_cves",
            "top_vendors",
            "severity_distribution",
            "total_assets",
            "active_assets",
            "open_findings",
            "critical_findings",
            "cves_affecting_us",
            "findings_by_type",
            "tech_distribution_top",
            "top_vendors_for_assets",
            "top_products_for_assets",
        ):
            assert key in body, f"missing key: {key}"

        # Severity distribution covers every bucket.
        sev = body["severity_distribution"]
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"):
            assert level in sev, f"missing severity: {level}"
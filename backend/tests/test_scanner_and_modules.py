"""Tests for scanner scope validation, parsers, scans API, alerts, audit logs, and institutions."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import config
from app.core.security import hash_password
from app.db.session import Base, get_db
from app.main import app
from app.models import (
    Alert,
    Asset,
    AssetCriticality,
    AssetScan,
    DEFAULT_INSTITUTION_ID,
    Institution,
    Role,
    User,
)
from app.scanner.parsers import parse_nmap_output, parse_nuclei_json_line, redact_evidence
from app.scanner.scope_validation import ScopeValidationError, validate_scan_target


# ---------------------------------------------------------------------------
# Unit tests: Scope Validation & SSRF Prevention
# ---------------------------------------------------------------------------
class TestScopeValidation:
    def test_cloud_metadata_blocked(self):
        with pytest.raises(ScopeValidationError, match="restricted cloud metadata"):
            validate_scan_target("http://169.254.169.254/latest/meta-data")

    def test_cloud_metadata_hostname_blocked(self):
        with pytest.raises(ScopeValidationError, match="restricted cloud metadata"):
            validate_scan_target("http://metadata.google.internal")

    def test_loopback_blocked_by_default(self):
        with pytest.raises(ScopeValidationError, match="restricted network"):
            validate_scan_target("http://127.0.0.1:8000")

    def test_loopback_allowed_when_flag_enabled(self):
        res = validate_scan_target("http://127.0.0.1:8000", allow_loopback_for_testing=True)
        assert res["hostname"] == "127.0.0.1"
        assert res["port"] == 8000

    def test_private_network_blocked_without_permission(self):
        with pytest.raises(ScopeValidationError, match="private network address"):
            validate_scan_target("http://192.168.1.100")

    def test_invalid_scheme_rejected(self):
        with pytest.raises(ScopeValidationError, match="Unsupported protocol scheme"):
            validate_scan_target("ftp://example.com")

    def test_empty_target_rejected(self):
        with pytest.raises(ScopeValidationError, match="cannot be empty"):
            validate_scan_target("")


# ---------------------------------------------------------------------------
# Unit tests: Parsers & Evidence Redaction
# ---------------------------------------------------------------------------
class TestScannerParsers:
    def test_redact_bearer_token(self):
        raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdef"
        redacted = redact_evidence(raw)
        assert "[REDACTED" in redacted
        assert "eyJhbGciOiJIUzI1Ni" not in redacted

    def test_redact_password_parameter(self):
        raw = "POST /login HTTP/1.1\r\nusername=admin&password=SuperSecretPassword123"
        redacted = redact_evidence(raw)
        assert "password=[REDACTED]" in redacted
        assert "SuperSecretPassword123" not in redacted

    def test_parse_nmap_service_output(self):
        sample = """
        PORT    STATE SERVICE VERSION
        80/tcp  open  http    Apache httpd 2.4.49
        443/tcp open  https   OpenSSL 1.1.1
        22/tcp  closed ssh
        """
        services = parse_nmap_output(sample)
        assert len(services) == 2
        assert services[0]["port"] == 80
        assert services[0]["service"] == "http"
        assert "Apache" in services[0]["version"]

    def test_parse_nuclei_json_line(self):
        json_line = (
            '{"template-id":"cve-2021-41773","info":{"name":"Apache Path Traversal",'
            '"severity":"critical","classification":{"cve-id":["CVE-2021-41773"],"cvss-score":9.8},'
            '"remediation":"Upgrade to Apache 2.4.51"},"matched-at":"https://example.com/icons/.%2e/"}'
        )
        parsed = parse_nuclei_json_line(json_line)
        assert parsed is not None
        assert parsed["cve_id"] == "CVE-2021-41773"
        assert parsed["severity"] == "CRITICAL"
        assert parsed["confidence"] == "scanner-confirmed"


# ---------------------------------------------------------------------------
# Integration tests: Scans, Alerts, Audit, Institutions APIs
# ---------------------------------------------------------------------------
@pytest.fixture()
def api_test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    conn = engine.connect()
    SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
    db = SessionLocal()

    # Seed Institution 1 and 2
    inst1 = Institution(id=1, name="Acme University", slug="acme-university", is_active=True)
    inst2 = Institution(id=2, name="Beta College", slug="beta-college", is_active=True)
    db.add_all([inst1, inst2])

    # Super Admin and Institution Admin
    super_admin = User(
        username="sadmin",
        email="sadmin@test.local",
        hashed_password=hash_password("adminpass"),
        role=Role.SUPER_ADMIN,
        institution_id=1,
    )
    inst_admin = User(
        username="iadmin",
        email="iadmin@test.local",
        hashed_password=hash_password("adminpass"),
        role=Role.INSTITUTION_ADMIN,
        institution_id=1,
    )
    db.add_all([super_admin, inst_admin])
    db.commit()

    # Asset for inst 1
    asset1 = Asset(
        id=10,
        label="Acme Portal",
        url="https://portal.acme.edu",
        institution_id=1,
        criticality=AssetCriticality.HIGH,
        internet_exposed=True,
    )
    db.add(asset1)

    # Pre-existing scan
    scan1 = AssetScan(
        id=100,
        asset_id=10,
        status="success",
        items_found=4,
        inserted_count=2,
        scan_profile="web_standard",
    )
    db.add(scan1)

    # Pre-existing alert
    alert1 = Alert(
        id=50,
        institution_id=1,
        asset_id=10,
        title="Critical Finding",
        message="A critical CVE was detected",
        severity="CRITICAL",
        is_read=False,
        is_dismissed=False,
    )
    db.add(alert1)
    db.commit()

    yield db
    db.close()
    conn.close()


@pytest.fixture()
def client(api_test_db, monkeypatch):
    bind_conn = api_test_db.get_bind()
    SessionLocal = sessionmaker(bind=bind_conn, autoflush=False, autocommit=False)

    def _override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    saved_lifespan = app.router.lifespan_context
    app.router.lifespan_context = None
    monkeypatch.setattr(config.settings, "login_rate_limit_per_minute", 0)
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan
        app.dependency_overrides.clear()


def _login_token(client: TestClient, username: str) -> str:
    res = client.post("/api/auth/login", json={"username": username, "password": "adminpass"})
    return res.json()["access_token"]


def test_dashboard_summary_endpoint(client):
    token = _login_token(client, "iadmin")
    res = client.get("/api/dashboard/summary", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "total_assets" in data
    assert "remediation_summary" in data
    assert "last_sync" in data
    assert "recent_scans" in data


def test_scans_list_and_detail(client):
    token = _login_token(client, "iadmin")
    # List scans
    res = client.get("/api/scans", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert data["items"][0]["asset_label"] == "Acme Portal"

    # Get scan detail
    detail_res = client.get("/api/scans/100", headers={"Authorization": f"Bearer {token}"})
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_profile"] == "web_standard"


def test_alerts_lifecycle(client):
    token = _login_token(client, "iadmin")
    # Summary
    s_res = client.get("/api/alerts/summary", headers={"Authorization": f"Bearer {token}"})
    assert s_res.status_code == 200
    assert s_res.json()["active_alerts"] >= 1

    # List
    list_res = client.get("/api/alerts", headers={"Authorization": f"Bearer {token}"})
    assert list_res.status_code == 200
    assert len(list_res.json()["items"]) >= 1

    # Acknowledge
    ack_res = client.post("/api/alerts/50/acknowledge", headers={"Authorization": f"Bearer {token}"})
    assert ack_res.status_code == 200
    assert ack_res.json()["is_read"] is True

    # Dismiss
    dis_res = client.post("/api/alerts/50/dismiss", headers={"Authorization": f"Bearer {token}"})
    assert dis_res.status_code == 200
    assert dis_res.json()["message"] == "Alert dismissed"


def test_audit_logs_list(client):
    token = _login_token(client, "iadmin")
    res = client.get("/api/audit-logs", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert "items" in res.json()


def test_institutions_super_admin(client):
    sadmin_token = _login_token(client, "sadmin")
    # Super-admin lists all
    res = client.get("/api/institutions", headers={"Authorization": f"Bearer {sadmin_token}"})
    assert res.status_code == 200
    assert len(res.json()) >= 2

    # Super-admin creates institution
    create_res = client.post(
        "/api/institutions",
        json={"name": "Gamma Tech", "slug": "gamma-tech"},
        headers={"Authorization": f"Bearer {sadmin_token}"},
    )
    assert create_res.status_code == 201
    assert create_res.json()["slug"] == "gamma-tech"

    # Institution admin cannot list all institutions
    iadmin_token = _login_token(client, "iadmin")
    forbidden_res = client.get("/api/institutions", headers={"Authorization": f"Bearer {iadmin_token}"})
    assert forbidden_res.status_code == 403


def test_assistant_query_endpoint(client):
    token = _login_token(client, "iadmin")
    res = client.post(
        "/api/assistant/query",
        json={"query": "Which critical vulnerabilities affect Apache?"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert "answer" in res.json()
    assert "sources" in res.json()

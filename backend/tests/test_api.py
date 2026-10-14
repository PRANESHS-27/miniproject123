"""Backend test suite — uses SQLite in-memory + patched external calls."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app


# ---------------------------------------------------------------------------
# Test DB (SQLite)
# ---------------------------------------------------------------------------
@pytest.fixture()
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    conn = engine.connect()
    TestingSessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)

    from app.models import DEFAULT_INSTITUTION_ID, Institution
    import app.core.rate_limit as rl

    rl.reset_for_tests()
    init_db = TestingSessionLocal()
    init_db.add(Institution(
        id=DEFAULT_INSTITUTION_ID,
        name="Acme University",
        slug="acme-university",
        is_active=True,
    ))
    init_db.commit()
    init_db.close()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "openai_api_key", None)
    monkeypatch.setattr(settings, "groq_api_key", None)
    monkeypatch.setattr(settings, "gemini_api_key", None)
    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 0)
    app.dependency_overrides[get_db] = override_get_db
    yield TestingSessionLocal
    app.dependency_overrides.clear()
    conn.close()


@pytest.fixture()
def client(db_session):
    saved_lifespan = app.router.lifespan_context
    app.router.lifespan_context = None
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_register_login_and_me(client):
    r = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "S3cret!pwd",
            "role": "admin",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user"]["username"] == "alice"

    r = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "S3cret!pwd"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_login_invalid_credentials(client):
    client.post(
        "/api/auth/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "S3cret!pwd",
            "role": "viewer",
        },
    )
    r = client.post(
        "/api/auth/login",
        json={"username": "bob", "password": "wrong"},
    )
    assert r.status_code == 401


def test_search_requires_auth(client):
    r = client.get("/api/vulnerabilities/search")
    assert r.status_code == 401

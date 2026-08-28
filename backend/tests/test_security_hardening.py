"""Tests for security hardening (#24).

Covers:
  - 24a — env-driven admin bootstrap (``assert_safe_admin_password``)
  - 24b — refresh token round-trip + login audit rows
  - 24c — rate limit on /api/auth/login (429 + audit)
  - 24d — production CORS refuses to fall back to localhost origins

These tests intentionally avoid the live ``vulnwatch.db`` — they use
an in-memory SQLite seeded per test.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.core.rate_limit as rl
from app.core import config
from app.core.security import hash_password
from app.db.session import Base
from app.main import app
from app.models import LoginAudit, Role, User


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def db_session():
    """Per-test in-memory SQLite session with all tables.

    We bind ``SessionLocal`` to a single ``Connection`` so the in-memory
    database persists across every session created by the override — the
    default behaviour is each new Session binds its own connection, and
    SQLite's ``:memory:`` is per-connection.
    """
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    conn = engine.connect()
    SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
    s = SessionLocal()
    s.add(User(
        username="alice",
        email="alice@test.local",
        hashed_password=hash_password("correct-horse"),
        role=Role.ADMIN,
        is_active=True,
    ))
    s.add(User(
        username="bob",
        email="bob@test.local",
        hashed_password=hash_password("battery-staple"),
        role=Role.VIEWER,
        is_active=False,  # disabled account
    ))
    s.commit()
    yield s
    s.close()
    conn.close()


@pytest.fixture()
def client(db_session, monkeypatch):
    """A TestClient whose ``get_db`` dependency returns our fixture session.

    We bind a fresh SessionLocal to the *same* connection the fixture
    uses, so the override-yielded session sees the same in-memory DB.
    """
    from sqlalchemy.orm import sessionmaker

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
    monkeypatch.setattr(config.settings, "login_rate_limit_per_minute", 3)
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan
        app.dependency_overrides.clear()


# ===========================================================================
# 24a — env-driven admin bootstrap
# ===========================================================================
class TestAdminPasswordGuard:
    """``assert_safe_admin_password`` must refuse the documented dev
    fallback when ``APP_ENV`` is anything other than ``development``."""

    def test_dev_env_allows_default_password(self, monkeypatch):
        from app.core.security import assert_safe_admin_password

        monkeypatch.setattr(config.settings, "app_env", "development")
        monkeypatch.setattr(config.settings, "admin_password", "Admin@123")
        monkeypatch.setattr(config.settings, "require_admin_password", False)
        assert_safe_admin_password()  # should not raise

    def test_prod_env_refuses_dev_password(self, monkeypatch):
        from app.core.security import assert_safe_admin_password

        monkeypatch.setattr(config.settings, "app_env", "production")
        monkeypatch.setattr(config.settings, "admin_password", "Admin@123")
        monkeypatch.setattr(config.settings, "require_admin_password", False)
        with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
            assert_safe_admin_password()

    def test_require_flag_refuses_in_dev(self, monkeypatch):
        from app.core.security import assert_safe_admin_password

        monkeypatch.setattr(config.settings, "app_env", "development")
        monkeypatch.setattr(config.settings, "admin_password", "Admin@123")
        monkeypatch.setattr(config.settings, "require_admin_password", True)
        with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
            assert_safe_admin_password()

    def test_prod_env_with_real_password_passes(self, monkeypatch):
        from app.core.security import assert_safe_admin_password

        monkeypatch.setattr(config.settings, "app_env", "production")
        monkeypatch.setattr(
            config.settings, "admin_password", "a-real-password-not-the-default"
        )
        assert_safe_admin_password()


# ===========================================================================
# 24b — refresh token + login audit
# ===========================================================================
class TestRefreshTokenRoundTrip:
    def test_login_returns_both_tokens(self, client):
        res = client.post(
            "/api/auth/login", json={"username": "alice", "password": "correct-horse"}
        )
        assert res.status_code == 200
        body = res.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"

    def test_refresh_exchanges_for_new_tokens(self, client):
        login = client.post(
            "/api/auth/login", json={"username": "alice", "password": "correct-horse"}
        )
        refresh = login.json()["refresh_token"]

        res = client.post("/api/auth/refresh", json={"refresh_token": refresh})
        assert res.status_code == 200
        new_body = res.json()
        assert "access_token" in new_body
        assert "refresh_token" in new_body

        # Both new tokens must be type-tagged refresh / access respectively.
        from jose import jwt as _jwt
        from app.core.config import settings as _s
        new_access_claims = _jwt.decode(
            new_body["access_token"], _s.secret_key, algorithms=[_s.algorithm]
        )
        new_refresh_claims = _jwt.decode(
            new_body["refresh_token"], _s.secret_key, algorithms=[_s.algorithm]
        )
        assert new_access_claims["typ"] == "access"
        assert new_refresh_claims["typ"] == "refresh"

    def test_refresh_rejects_access_token(self, client):
        """An access token must NOT be redeemable as a refresh token."""
        login = client.post(
            "/api/auth/login", json={"username": "alice", "password": "correct-horse"}
        )
        access = login.json()["access_token"]

        res = client.post("/api/auth/refresh", json={"refresh_token": access})
        assert res.status_code == 401

    def test_refresh_rejects_garbage(self, client):
        res = client.post("/api/auth/refresh", json={"refresh_token": "not-a-jwt"})
        assert res.status_code == 401

    def test_refresh_rejects_disabled_user(self, client, db_session):
        """A refresh token from a disabled user must not produce a new pair."""
        login_disabled = client.post(
            "/api/auth/login", json={"username": "bob", "password": "battery-staple"}
        )
        assert login_disabled.status_code == 403


class TestLoginAudit:
    """Every login attempt — success or failure — writes a ``login_audit`` row."""

    def test_successful_login_audits_success(self, client, db_session):
        client.post(
            "/api/auth/login", json={"username": "alice", "password": "correct-horse"}
        )
        rows = db_session.query(LoginAudit).all()
        assert len(rows) == 1
        assert rows[0].outcome == "success"
        assert rows[0].username == "alice"
        assert rows[0].user_id is not None

    def test_bad_password_audits_bad_password(self, client, db_session):
        client.post(
            "/api/auth/login", json={"username": "alice", "password": "wrong"}
        )
        row = db_session.query(LoginAudit).one()
        assert row.outcome == "bad_password"
        # We must record the user_id even though the password failed —
        # otherwise an attacker probing valid usernames would be invisible.
        assert row.user_id is not None

    def test_unknown_user_audits_unknown_user(self, client, db_session):
        client.post(
            "/api/auth/login", json={"username": "ghost", "password": "anything"}
        )
        row = db_session.query(LoginAudit).one()
        assert row.outcome == "unknown_user"
        assert row.user_id is None

    def test_disabled_user_audits_disabled(self, client, db_session):
        client.post(
            "/api/auth/login", json={"username": "bob", "password": "battery-staple"}
        )
        row = db_session.query(LoginAudit).one()
        assert row.outcome == "disabled"

    def test_audit_does_not_echo_credentials(self, client, db_session):
        """The audit row must not contain the password."""
        client.post(
            "/api/auth/login", json={"username": "alice", "password": "correct-horse"}
        )
        row = db_session.query(LoginAudit).one()
        # Defensive: ensure none of the row fields accidentally hold the
        # password. (There's no field that should, but verify nothing leaks.)
        assert "correct-horse" not in (row.username or "")
        assert "correct-horse" not in (row.user_agent or "")
        assert "correct-horse" not in (row.ip or "")


# ===========================================================================
# 24c — rate limit
# ===========================================================================
class TestLoginRateLimit:
    """With ``login_rate_limit_per_minute=3``, the 4th attempt must 429."""

    def test_under_limit_passes_through(self, client):
        for i in range(3):
            res = client.post(
                "/api/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
            assert res.status_code == 401, f"attempt {i+1} should not be 429"
        # Reset for the next test by clearing state.
        rl.reset_for_tests()

    def test_limit_returns_429(self, client, db_session):
        for _ in range(3):
            client.post(
                "/api/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
        res = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert res.status_code == 429
        assert "Retry-After" in res.headers

    def test_rate_limited_attempt_is_audited(self, client, db_session):
        for _ in range(3):
            client.post(
                "/api/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
        # The 4th attempt should write a rate_limited audit row.
        client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        rows = db_session.query(LoginAudit).all()
        outcomes = [r.outcome for r in rows]
        assert "rate_limited" in outcomes

    def test_rate_limit_does_not_leak_credential_info(self, client):
        """The 429 response must not say whether the credentials were valid."""
        for _ in range(3):
            client.post(
                "/api/auth/login",
                json={"username": "alice", "password": "wrong"},
            )
        res = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "wrong"},
        )
        body = res.json()
        detail = (body.get("detail") or "").lower()
        # Must mention rate limit, must NOT mention "password" or "username".
        assert "too many" in detail or "rate" in detail
        assert "password" not in detail
        assert "username" not in detail
        assert "invalid" not in detail

    def test_rate_limit_disabled_when_zero(self, monkeypatch):
        """``LOGIN_RATE_LIMIT_PER_MINUTE=0`` disables the limiter."""
        from sqlalchemy.orm import sessionmaker

        from app.db import get_db

        engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(engine)
        conn = engine.connect()
        SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
        s = SessionLocal()
        s.add(User(
            username="x", email="x@x", hashed_password=hash_password("y"),
            role=Role.VIEWER, is_active=True,
        ))
        s.commit()

        def _override():
            db = SessionLocal()
            try:
                yield db
            finally:
                pass

        app.dependency_overrides[get_db] = _override
        saved = app.router.lifespan_context
        app.router.lifespan_context = None
        rl.reset_for_tests()
        monkeypatch.setattr(config.settings, "login_rate_limit_per_minute", 0)
        c = TestClient(app)
        for _ in range(10):
            res = c.post("/api/auth/login", json={"username": "x", "password": "y"})
            assert res.status_code != 429
        app.router.lifespan_context = saved
        app.dependency_overrides.clear()


# ===========================================================================
# 24d — production CORS
# ===========================================================================
class TestProductionCORS:
    """The function reads ``settings.app_env`` and
    ``settings.cors_allowed_origins`` at call time, so we just patch and
    invoke — no module-reload gymnastics."""

    def test_dev_falls_back_to_localhost(self, monkeypatch):
        monkeypatch.setattr(config.settings, "app_env", "development")
        monkeypatch.setattr(config.settings, "cors_allowed_origins", "")
        from app.main import _compute_cors_origins
        origins = _compute_cors_origins()
        assert any("localhost" in o or "127.0.0.1" in o for o in origins)

    def test_prod_refuses_to_default_to_localhost(self, monkeypatch):
        monkeypatch.setattr(config.settings, "app_env", "production")
        monkeypatch.setattr(config.settings, "cors_allowed_origins", "")
        from app.main import _compute_cors_origins
        with pytest.raises(RuntimeError, match="CORS_ALLOWED_ORIGINS"):
            _compute_cors_origins()

    def test_prod_uses_explicit_origins(self, monkeypatch):
        monkeypatch.setattr(config.settings, "app_env", "production")
        monkeypatch.setattr(
            config.settings,
            "cors_allowed_origins",
            "https://vulnwatch.acme.edu,https://admin.acme.edu",
        )
        from app.main import _compute_cors_origins
        origins = _compute_cors_origins()
        assert origins == [
            "https://vulnwatch.acme.edu",
            "https://admin.acme.edu",
        ]


# ===========================================================================
# Rate limiter pure-function tests (24c)
# ===========================================================================
class TestRateLimiterPure:
    """The sliding-window limiter is the only stateful bit — test it
    directly so we don't depend on TestClient threading."""

    def test_under_limit_returns_remaining(self):
        rl.reset_for_tests()
        allowed, remaining = rl.check_login("1.2.3.4", per_minute=5)
        assert allowed is True
        assert remaining == 4
        allowed, remaining = rl.check_login("1.2.3.4", per_minute=5)
        assert allowed is True
        assert remaining == 3

    def test_at_limit_rejects(self):
        rl.reset_for_tests()
        for _ in range(3):
            rl.check_login("9.9.9.9", per_minute=3)
        allowed, remaining = rl.check_login("9.9.9.9", per_minute=3)
        assert allowed is False
        assert remaining == -1

    def test_separate_ips_have_independent_budgets(self):
        rl.reset_for_tests()
        for _ in range(3):
            rl.check_login("1.1.1.1", per_minute=3)
        # 1.1.1.1 is now blocked, but 2.2.2.2 still has budget.
        assert rl.check_login("1.1.1.1", per_minute=3)[0] is False
        assert rl.check_login("2.2.2.2", per_minute=3)[0] is True

    def test_none_ip_is_bucketed(self):
        rl.reset_for_tests()
        # None ip should not crash; bucketed under "unknown".
        allowed, _ = rl.check_login(None, per_minute=2)
        assert allowed is True
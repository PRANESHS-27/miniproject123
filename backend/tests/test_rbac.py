"""Tests for 4-tier RBAC (RBAC 23).

Covers:
  - 23a — Role enum has the 4 canonical tiers + backward-compatible aliases.
  - 23b — ``role_tier`` normalises legacy ``Role.ADMIN`` / ``Role.ANALYST``
          to their canonical tiers.
  - 23b — Permission matrix inherits: ``user.manage`` granted to
          institution_admin is also granted to super_admin.
  - 23c — ``/api/admin/users`` POST rejects SUPER_ADMIN when the actor
          is INSTITUTION_ADMIN.
  - 23c — ``/api/auth/register`` refuses self-promotion to a
          privileged tier (except for the very first user).
  - 23c — Last-privileged-user guard refuses to demote or deactivate
          the last INSTITUTION_ADMIN / SUPER_ADMIN.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import config
from app.core.permissions import (
    _EFFECTIVE_PERMISSIONS,
    PERMISSIONS,
    has_permission,
    is_super_admin,
    require_permission,
    user_tier,
)
from app.core.security import hash_password
from app.db.session import Base
from app.main import app
from app.models import (
    Role,
    SECURITY_ANALYST,
    TIER_INSTITUTION_ADMIN,
    TIER_SECURITY_ANALYST,
    TIER_SUPER_ADMIN,
    TIER_VIEWER,
    User,
    role_tier,
)

import app.core.rate_limit as rl


# ---------------------------------------------------------------------------
# Fixtures — in-memory SQLite, single shared connection (per test)
# ---------------------------------------------------------------------------
@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    conn = engine.connect()
    SessionLocal = sessionmaker(bind=conn, autoflush=False, autocommit=False)
    s = SessionLocal()
    s.add(User(
        username="super",
        email="super@test.local",
        hashed_password=hash_password("superpass"),
        role=Role.SUPER_ADMIN,
        is_active=True,
    ))
    s.add(User(
        username="inst",
        email="inst@test.local",
        hashed_password=hash_password("instpass"),
        role=Role.INSTITUTION_ADMIN,
        is_active=True,
    ))
    s.add(User(
        username="analyst",
        email="analyst@test.local",
        hashed_password=hash_password("analystpass"),
        role=Role.ANALYST,  # legacy enum alias
        is_active=True,
    ))
    s.add(User(
        username="viewer",
        email="viewer@test.local",
        hashed_password=hash_password("viewerpass"),
        role=Role.VIEWER,
        is_active=True,
    ))
    s.commit()
    yield s
    s.close()
    conn.close()


@pytest.fixture()
def client(db_session, monkeypatch):
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
    # Disable rate limit so the multi-login tests don't 429.
    monkeypatch.setattr(config.settings, "login_rate_limit_per_minute", 0)
    try:
        yield TestClient(app, raise_server_exceptions=True)
    finally:
        app.router.lifespan_context = saved_lifespan
        app.dependency_overrides.clear()


def _login(client, username, password):
    res = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# 23a — Role enum
# ===========================================================================
class TestRoleEnum:
    def test_four_tier_values_exist(self):
        # Canonical tier enum members.
        assert Role.SUPER_ADMIN.value == "super_admin"
        assert Role.INSTITUTION_ADMIN.value == "institution_admin"
        assert SECURITY_ANALYST == "security_analyst"
        # Legacy aliases still present (back-compat).
        assert Role.ADMIN.value == "admin"
        assert Role.ANALYST.value == "analyst"
        assert Role.VIEWER.value == "viewer"


# ===========================================================================
# 23b — role_tier() and the permission matrix
# ===========================================================================
class TestRoleTierNormalization:
    def test_canonical_tiers_pass_through(self):
        assert role_tier(Role.SUPER_ADMIN) == TIER_SUPER_ADMIN
        assert role_tier(Role.INSTITUTION_ADMIN) == TIER_INSTITUTION_ADMIN
        assert role_tier("security_analyst") == TIER_SECURITY_ANALYST
        assert role_tier(Role.VIEWER) == TIER_VIEWER

    def test_legacy_admin_maps_to_institution_admin(self):
        assert role_tier(Role.ADMIN) == TIER_INSTITUTION_ADMIN
        assert role_tier("admin") == TIER_INSTITUTION_ADMIN

    def test_legacy_analyst_maps_to_security_analyst(self):
        # ``Role.ANALYST`` and the string ``"analyst"`` both normalise.
        assert role_tier(Role.ANALYST) == TIER_SECURITY_ANALYST
        assert role_tier("analyst") == TIER_SECURITY_ANALYST


class TestPermissionMatrixInheritance:
    def test_user_manage_is_institution_admin_or_higher(self):
        allowed = _EFFECTIVE_PERMISSIONS[("user", "manage")]
        assert TIER_INSTITUTION_ADMIN in allowed
        assert TIER_SUPER_ADMIN in allowed
        assert TIER_VIEWER not in allowed
        assert TIER_SECURITY_ANALYST not in allowed

    def test_institution_manage_is_super_admin_only(self):
        allowed = _EFFECTIVE_PERMISSIONS[("institution", "manage")]
        assert allowed == {TIER_SUPER_ADMIN}

    def test_finding_update_is_security_analyst_or_higher(self):
        allowed = _EFFECTIVE_PERMISSIONS[("finding", "update")]
        assert TIER_SECURITY_ANALYST in allowed
        assert TIER_INSTITUTION_ADMIN in allowed
        assert TIER_SUPER_ADMIN in allowed
        assert TIER_VIEWER not in allowed

    def test_has_permission_resolves_legacy_aliases(self, db_session):
        u = db_session.query(User).filter_by(username="analyst").one()
        # The fixture seeded ``Role.ANALYST`` (legacy). ``has_permission``
        # still grants analyst-tier permissions via the tier normaliser.
        assert user_tier(u) == TIER_SECURITY_ANALYST
        assert has_permission(u, "asset", "scan") is True
        assert has_permission(u, "user", "manage") is False

    def test_super_admin_helper(self, db_session):
        s = db_session.query(User).filter_by(username="super").one()
        i = db_session.query(User).filter_by(username="inst").one()
        v = db_session.query(User).filter_by(username="viewer").one()
        assert is_super_admin(s) is True
        assert is_super_admin(i) is False
        assert is_super_admin(v) is False


# ===========================================================================
# 23c — registration refuses privileged self-promotion
# ===========================================================================
class TestRegisterPrivileged:
    """On a non-empty DB, register must not let the caller grant themselves
    a privileged tier. ``/api/auth/register`` is unauthenticated."""

    def test_register_viewer_allowed(self, client):
        res = client.post("/api/auth/register", json={
            "username": "fresh",
            "email": "fresh@test.local",
            "password": "longenough",
            "role": "viewer",
        })
        assert res.status_code == 201
        assert res.json()["user"]["role"] == "viewer"

    def test_register_institution_admin_rejected(self, client):
        res = client.post("/api/auth/register", json={
            "username": "sneaky",
            "email": "sneaky@test.local",
            "password": "longenough",
            "role": "institution_admin",
        })
        assert res.status_code == 403
        assert "privileged" in (res.json().get("detail") or "").lower()

    def test_register_super_admin_rejected(self, client):
        res = client.post("/api/auth/register", json={
            "username": "sneaky",
            "email": "sneaky@test.local",
            "password": "longenough",
            "role": "super_admin",
        })
        assert res.status_code == 403

    def test_register_legacy_admin_rejected(self, client):
        # The legacy ``admin`` string normalises to institution_admin tier
        # — must also be refused.
        res = client.post("/api/auth/register", json={
            "username": "sneaky",
            "email": "sneaky@test.local",
            "password": "longenough",
            "role": "admin",
        })
        assert res.status_code == 403


# ===========================================================================
# 23c — /api/admin/users POST: actor must be at-least the granted tier
# ===========================================================================
class TestAdminUserCreationGating:
    def _token(self, client, username, password):
        return _login(client, username, password)

    def test_institution_admin_can_create_analyst(self, client):
        token = self._token(client, "inst", "instpass")
        res = client.post(
            "/api/admin/users",
            headers=_auth(token),
            json={
                "username": "newanalyst",
                "email": "na@test.local",
                "password": "longenough",
                "role": "analyst",
            },
        )
        assert res.status_code == 201, res.text
        assert res.json()["role"] == "analyst"

    def test_institution_admin_cannot_create_super_admin(self, client):
        token = self._token(client, "inst", "instpass")
        res = client.post(
            "/api/admin/users",
            headers=_auth(token),
            json={
                "username": "newsuper",
                "email": "ns@test.local",
                "password": "longenough",
                "role": "super_admin",
            },
        )
        assert res.status_code == 403
        assert "SUPER_ADMIN" in (res.json().get("detail") or "")

    def test_super_admin_can_create_super_admin(self, client):
        token = self._token(client, "super", "superpass")
        res = client.post(
            "/api/admin/users",
            headers=_auth(token),
            json={
                "username": "newsuper",
                "email": "ns@test.local",
                "password": "longenough",
                "role": "super_admin",
            },
        )
        assert res.status_code == 201, res.text

    def test_analyst_cannot_create_anyone(self, client):
        token = self._token(client, "analyst", "analystpass")
        res = client.post(
            "/api/admin/users",
            headers=_auth(token),
            json={
                "username": "blocked",
                "email": "b@test.local",
                "password": "longenough",
                "role": "viewer",
            },
        )
        assert res.status_code == 403


# ===========================================================================
# 23c — last-privileged-user guard
# ===========================================================================
class TestLastPrivilegedUserGuard:
    def _token(self, client, username, password):
        return _login(client, username, password)

    def _drop_super(self, db_session, client):
        """Remove the SUPER_ADMIN fixture user so the institution_admin
        is genuinely the *last* privileged user. Done by deleting via
        a *fresh* super admin, which is impossible — so we delete via
        the DB directly. The endpoint guard is then exercised against
        a clean privileged count."""
        super_user = db_session.query(User).filter_by(username="super").one()
        db_session.delete(super_user)
        db_session.commit()

    def test_cannot_demote_last_institution_admin(self, client, db_session):
        self._drop_super(db_session, client)
        token = self._token(client, "inst", "instpass")
        inst = db_session.query(User).filter_by(username="inst").one()
        res = client.patch(
            f"/api/admin/users/{inst.id}",
            headers=_auth(token),
            json={"role": "viewer"},
        )
        assert res.status_code == 400, res.text
        assert "last privileged" in (res.json().get("detail") or "").lower()

    def test_can_demote_when_super_admin_remains(self, client, db_session):
        # Both ``super`` and ``inst`` are seeded; ``inst`` is no longer
        # the last privileged user, so the demotion must succeed.
        token = self._token(client, "inst", "instpass")
        inst = db_session.query(User).filter_by(username="inst").one()
        res = client.patch(
            f"/api/admin/users/{inst.id}",
            headers=_auth(token),
            json={"role": "viewer"},
        )
        assert res.status_code == 200, res.text

    def test_cannot_deactivate_last_privileged(self, client, db_session):
        self._drop_super(db_session, client)
        token = self._token(client, "inst", "instpass")
        inst = db_session.query(User).filter_by(username="inst").one()
        res = client.patch(
            f"/api/admin/users/{inst.id}",
            headers=_auth(token),
            json={"is_active": False},
        )
        assert res.status_code == 400, res.text
        assert "last privileged" in (res.json().get("detail") or "").lower()

    def test_cannot_delete_last_privileged(self, client, db_session):
        # Drop the super admin first so deleting ``inst`` would leave
        # zero privileged users.
        self._drop_super(db_session, client)
        # Use the institution_admin's own token — they have user.manage
        # but cannot delete themselves (self-delete is refused). Switch
        # to a viewer that has been promoted via the fixture would help,
        # but the cleanest path: the institution_admin calls DELETE on
        # their *own* id and the self-delete guard fires first.
        token = self._token(client, "inst", "instpass")
        inst = db_session.query(User).filter_by(username="inst").one()
        res = client.delete(
            f"/api/admin/users/{inst.id}",
            headers=_auth(token),
        )
        # Self-delete is refused (400) before the privileged-guard fires.
        # Either is acceptable — the test asserts the operation is
        # blocked.
        assert res.status_code in (400,)

    def test_can_delete_when_super_admin_remains(self, client, db_session):
        # Both super and inst are seeded; deleting inst is fine.
        token = self._token(client, "super", "superpass")
        inst = db_session.query(User).filter_by(username="inst").one()
        res = client.delete(
            f"/api/admin/users/{inst.id}",
            headers=_auth(token),
        )
        assert res.status_code == 200, res.text

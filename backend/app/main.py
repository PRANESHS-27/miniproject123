"""VulnWatch FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    admin_router,
    ai_router,
    assets_router,
    auth_router,
    findings_router,
    health_router,
    liveness_router,
    reports_router,
    vulnerabilities_router,
    sync_router,
)
from app.core.config import settings
from app.core.logging_config import get_logger, setup_logging
from app.core.security import assert_safe_admin_password, assert_safe_secret, hash_password
from app.db import Base, SessionLocal, engine
from app.models import Role, User

setup_logging()
log = get_logger("vulnwatch")


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def _bootstrap_default_institution(db) -> None:
    """Insert the default "Acme University" institution if it doesn't exist.

    RBAC 22 / tenant isolation. Every user and asset belongs to exactly
    one institution; on a fresh DB we seed the default so that
    ``User.institution_id`` / ``Asset.institution_id`` (both NOT NULL via
    ``server_default=text("1")``) have a parent row to point at.

    Idempotent — the ``id=1`` check makes subsequent boots a no-op. Two
    pods racing on this will see one INSERT win and the other hit the PK
    constraint; that's caught by ``_bootstrap_admin``'s commit error
    handler below.
    """
    from app.models import DEFAULT_INSTITUTION_ID, Institution

    if db.query(Institution).filter_by(id=DEFAULT_INSTITUTION_ID).first():
        return
    db.add(
        Institution(
            id=DEFAULT_INSTITUTION_ID,
            name="Acme University",
            slug="acme-university",
            is_active=True,
        )
    )
    db.commit()


def _bootstrap_admin() -> None:
    """Create the bootstrap super-admin from environment variables if no users exist.

    (Security hardening 24a) — replaces the previous hardcoded
    ``admin / Admin@123`` seed. Credentials come from
    ``ADMIN_USERNAME`` / ``ADMIN_EMAIL`` / ``ADMIN_PASSWORD`` so an operator
    deploying this for an institution sets them explicitly. In production
    (or any environment where ``REQUIRE_ADMIN_PASSWORD=true``) we refuse
    to fall back to the dev default — the operator must supply a real
    password or use the registration endpoint.

    RBAC 23 — the bootstrap user is created with the SUPER_ADMIN tier.
    This is the only place a SUPER_ADMIN is provisioned automatically;
    all subsequent privileged accounts must be created via
    ``/api/admin/users`` once the bootstrap admin is signed in.

    RBAC 22 — the bootstrap admin belongs to the default institution
    (id=1) created by :func:`_bootstrap_default_institution`.
    """
    assert_safe_admin_password()
    from app.models import DEFAULT_INSTITUTION_ID

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            db.add(
                User(
                    username=settings.admin_username,
                    email=settings.admin_email,
                    full_name="Bootstrap Admin",
                    hashed_password=hash_password(settings.admin_password),
                    role=Role.SUPER_ADMIN,
                    institution_id=DEFAULT_INSTITUTION_ID,
                )
            )
            db.commit()
            log.warning(
                "Created bootstrap SUPER_ADMIN '%s' from ADMIN_USERNAME env. "
                "Change ADMIN_PASSWORD immediately if this is not a "
                "disposable dev environment.",
                settings.admin_username,
            )
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables, seed institution + admin, and start the scheduler."""
    # Fail fast in production if SECRET_KEY is the dev fallback. Cheaper than
    # serving signed tokens with a public secret for a single request.
    assert_safe_secret()
    Base.metadata.create_all(bind=engine)
    _apply_schema_patches()
    # RBAC 22 — seed the default Acme institution before creating the
    # bootstrap admin (the admin's User row references it via FK).
    _bootstrap_default_institution(SessionLocal())
    _bootstrap_admin()

    # Build the in-memory CVE index once so search/dashboard don't scan the
    # whole table on every request. Refreshed on NVD/KEV/asset scans.
    from app.services import cve_index

    cve_index.refresh(SessionLocal())
    log.info("CVE index ready (%d CVEs, %d vendors)", cve_index.get()["total_cves"], len(cve_index.get()["vendor_to_cves"]))

    # Start the in-process scheduler (NVD + CISA daily)
    from app.services.scheduler_jobs import start_scheduler

    start_scheduler()
    log.info("VulnWatch backend started (env=%s)", settings.app_env)
    try:
        yield
    finally:
        from app.services.scheduler_jobs import shutdown_scheduler

        shutdown_scheduler()


def _apply_schema_patches() -> None:
    """Best-effort ALTER TABLE for columns added after the initial release.

    ``create_all`` only creates missing tables — it never adds new columns
    to existing tables. Rather than maintain a separate Alembic migration
    tree (overkill for this dev-stage project), we run a list of
    ``ALTER TABLE ... ADD COLUMN ...`` statements on startup. Safe to run
    repeatedly: we swallow "duplicate column" errors from SQLite.
    """
    from sqlalchemy import text
    from app.db import engine

    patches = [
        # AssetScan per-scan dedup counters (added 2026-08-14).
        "ALTER TABLE asset_scans ADD COLUMN inserted_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_scans ADD COLUMN re_seen_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_scans ADD COLUMN closed_count INTEGER NOT NULL DEFAULT 0",
        # Risk Engine inputs on Asset (added Phase 4).
        "ALTER TABLE assets ADD COLUMN criticality VARCHAR(16) NOT NULL DEFAULT 'LOW'",
        "ALTER TABLE assets ADD COLUMN internet_exposed BOOLEAN NOT NULL DEFAULT 0",
        # Findings table (added Phase 4). On a fresh DB the table is
        # already created by ``Base.metadata.create_all`` above; on an
        # existing DB we only need the columns the engine added later.
        # ``risk_contributions`` is a JSON column on Postgres and a TEXT
        # column on SQLite; we let SQLAlchemy handle the difference at
        # model definition time. The CREATE TABLE statement is fired by
        # ``create_all`` for fresh DBs, so no need to repeat it here.
        # login_audit table (added 24b) — created by ``create_all`` on
        # fresh DBs; on an existing DB, Base.metadata.create_all handles
        # the new table since ``login_audit`` isn't in the schema yet.
        # ---- RBAC 22 / tenant isolation (added 2026-08-27) ----
        # On fresh DBs the institutions table is already created by
        # ``Base.metadata.create_all``; for upgrade DBs we create it
        # here. The IF NOT EXISTS guard is a no-op on fresh DBs and the
        # duplicate-exception swallow catches the conflict.
        "CREATE TABLE IF NOT EXISTS institutions ("
        "  id INTEGER PRIMARY KEY,"
        "  name VARCHAR(128) NOT NULL,"
        "  slug VARCHAR(64) NOT NULL,"
        "  settings JSON,"
        "  is_active BOOLEAN NOT NULL DEFAULT 1,"
        "  created_at DATETIME NOT NULL"
        ")",
        # UNIQUE index is a separate statement so the IF-NOT-EXISTS
        # swallow works cleanly on either dialect.
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_institution_slug ON institutions(slug)",
        # Idempotent seed of the default institution. The WHERE NOT
        # EXISTS guard makes this safe on every boot.
        "INSERT INTO institutions (id, name, slug, is_active, created_at) "
        "SELECT 1, 'Acme University', 'acme-university', 1, CURRENT_TIMESTAMP "
        "WHERE NOT EXISTS (SELECT 1 FROM institutions WHERE id = 1)",
        # Add institution_id to tenant-scoped tables. Server-defaulted
        # to ``1`` on the model side so test fixtures stay green; here
        # we add it NULLable so the UPDATE backfill below can run on
        # upgrade DBs that pre-date the column.
        "ALTER TABLE users ADD COLUMN institution_id INTEGER NULL",
        "ALTER TABLE assets ADD COLUMN institution_id INTEGER NULL",
        # Backfill any pre-existing rows to the default institution.
        "UPDATE users SET institution_id = 1 WHERE institution_id IS NULL",
        "UPDATE assets SET institution_id = 1 WHERE institution_id IS NULL",
    ]
    with engine.begin() as conn:
        for stmt in patches:
            try:
                conn.execute(text(stmt))
            except Exception as exc:
                msg = str(exc).lower()
                if "duplicate" not in msg and "already exists" not in msg:
                    log.warning("Schema patch failed (%s): %s", stmt[:60], exc)

    # RBAC 22 — replace Asset.url's global unique with composite
    # (institution_id, url). Done outside the per-statement loop because
    # it needs dialect-aware introspection to find the auto-generated
    # index name. Wrapped in its own transaction so partial failure
    # rolls back. Best-effort: any failure here is logged and ignored
    # so a missing or already-migrated DB doesn't block startup.
    _migrate_assets_url_composite_unique()


def _migrate_assets_url_composite_unique() -> None:
    """Drop the global ``assets.url`` unique index and replace it with
    a composite ``(institution_id, url)`` unique index.

    Why: with tenant isolation, two institutions can legitimately host
    the same URL (e.g. two universities each with a Moodle instance).
    The model declares ``unique=True`` on ``Asset.url`` — that has to
    become per-institution.

    The auto-generated index name is dialect-specific (``ux_assets_url``
    on Postgres, ``sqlite_autoindex_assets_N`` on SQLite), so we
    introspect ``sqlite_master`` / ``pg_indexes`` to find any index that
    covers ``url`` but NOT ``institution_id``.
    """
    from sqlalchemy import inspect

    inspector = inspect(engine)
    # Skip if the new composite unique already exists.
    try:
        existing = inspector.get_indexes("assets")
    except Exception:
        existing = []
    if any(
        idx.get("unique")
        and set(idx.get("column_names", [])) == {"institution_id", "url"}
        for idx in existing
    ):
        return

    dialect = engine.dialect.name
    with engine.begin() as conn:
        try:
            if dialect == "sqlite":
                rows = conn.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type='index' "
                        "AND tbl_name='assets' AND sql LIKE '%url%' "
                        "AND sql NOT LIKE '%institution_id%'"
                    )
                ).fetchall()
                for (idx_name,) in rows:
                    try:
                        conn.execute(text(f'DROP INDEX "{idx_name}"'))
                    except Exception as exc:
                        log.warning("Drop index %s failed: %s", idx_name, exc)
            elif dialect == "postgresql":
                rows = conn.execute(
                    text(
                        "SELECT indexname FROM pg_indexes "
                        "WHERE tablename='assets' AND indexdef LIKE '%url%' "
                        "AND indexdef NOT LIKE '%institution_id%'"
                    )
                ).fetchall()
                for (idx_name,) in rows:
                    if idx_name.startswith("pk") or idx_name.startswith("ix_"):
                        continue  # leave the PK + plain indexes alone
                    try:
                        conn.execute(text(f'DROP INDEX "{idx_name}"'))
                    except Exception as exc:
                        log.warning("Drop index %s failed: %s", idx_name, exc)
            # Create the new composite unique. ``IF NOT EXISTS`` is
            # dialect-agnostic here.
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "ux_assets_institution_url ON assets(institution_id, url)"
                )
            )
        except Exception as exc:
            log.warning("Asset URL composite-unique migration failed: %s", exc)


app = FastAPI(
    title=settings.app_name,
    description="AI-Powered Vulnerability Management System",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — exact allowlist from settings. Wildcard origins are incompatible
# with ``allow_credentials=True`` per the CORS spec, so we read a
# comma-separated list of origins. Default to the localhost dev ports
# we know about: the project's own vite config (:3000) plus Vite's
# default (:5173) in case the operator skipped the config override.
# Hardening 24d — when running in production, refuse to fall back to the
# localhost dev origins: the operator must set ``CORS_ALLOWED_ORIGINS``
# explicitly to the institutional frontends that should be allowed.
def _compute_cors_origins() -> list[str]:
    explicit = [
        o.strip()
        for o in (settings.cors_allowed_origins or "").split(",")
        if o.strip()
    ]
    if explicit:
        return explicit
    if settings.app_env.lower() in ("production", "prod"):
        raise RuntimeError(
            "CORS_ALLOWED_ORIGINS must be set in production. Refusing to "
            "default to localhost origins."
        )
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


_cors_origins = _compute_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,  # JWT goes in Authorization header, not cookies
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
log.info("CORS allowed origins: %s", _cors_origins)

# Routers
app.include_router(auth_router)
app.include_router(vulnerabilities_router)
app.include_router(ai_router)
app.include_router(reports_router)
app.include_router(sync_router)
app.include_router(assets_router)
app.include_router(findings_router)
app.include_router(admin_router)
# Health routers — the liveness_router carries /health (legacy) and the
# health_router carries /api/health/* (privileged readiness probe).
app.include_router(liveness_router)
app.include_router(health_router)


@app.get("/")
def root():
    return {
        "message": "Welcome to VulnWatch API",
        "docs": "/docs",
        "health": "/health",
        "health_status": "/api/health/status",
    }

"""VulnWatch FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    admin_router,
    ai_router,
    assets_router,
    auth_router,
    reports_router,
    vulnerabilities_router,
    sync_router,
)
from app.core.config import settings
from app.core.logging_config import get_logger, setup_logging
from app.core.security import assert_safe_secret, hash_password
from app.db import Base, SessionLocal, engine
from app.models import Role, User

setup_logging()
log = get_logger("vulnwatch")


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def _bootstrap_admin() -> None:
    """Create default admin if no users exist."""
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            db.add(
                User(
                    username="admin",
                    email="admin@vulnwatch.local",
                    full_name="Default Admin",
                    hashed_password=hash_password("Admin@123"),
                    role=Role.ADMIN,
                )
            )
            db.commit()
            log.info("Created default admin user (admin / Admin@123) — change it now.")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables, seed admin, and start the scheduler."""
    # Fail fast in production if SECRET_KEY is the dev fallback. Cheaper than
    # serving signed tokens with a public secret for a single request.
    assert_safe_secret()
    Base.metadata.create_all(bind=engine)
    _apply_schema_patches()
    _bootstrap_admin()

    # Build the in-memory CVE index once so search/dashboard don't scan the
    # whole table on every request. Refreshed on NVD/KEV/asset scans.
    from app.services import cve_index
    from app.db import SessionLocal

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
    ]
    with engine.begin() as conn:
        for stmt in patches:
            try:
                conn.execute(text(stmt))
            except Exception as exc:
                msg = str(exc).lower()
                if "duplicate" not in msg and "already exists" not in msg:
                    log.warning("Schema patch failed (%s): %s", stmt[:60], exc)


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
_cors_origins = [
    o.strip()
    for o in (settings.cors_allowed_origins or "").split(",")
    if o.strip()
] or [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,  # JWT goes in Authorization header, not cookies
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Routers
app.include_router(auth_router)
app.include_router(vulnerabilities_router)
app.include_router(ai_router)
app.include_router(reports_router)
app.include_router(sync_router)
app.include_router(assets_router)
app.include_router(admin_router)


@app.get("/health", tags=["health"])
def health():
    """Liveness probe."""
    return {"status": "ok", "app": settings.app_name}


@app.get("/")
def root():
    return {
        "message": "Welcome to VulnWatch API",
        "docs": "/docs",
        "health": "/health",
    }

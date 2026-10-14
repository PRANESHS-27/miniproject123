"""HTTP routers."""

from app.api.admin import router as admin_router
from app.api.ai import assistant_router, router as ai_router
from app.api.alerts import router as alerts_router
from app.api.assets import router as assets_router
from app.api.audit_logs import router as audit_logs_router
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.health import liveness_router, router as health_router
from app.api.institutions import router as institutions_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.api.sync import router as sync_router
from app.api.vulnerabilities import router as vulnerabilities_router

__all__ = [
    "admin_router",
    "ai_router",
    "assistant_router",
    "alerts_router",
    "assets_router",
    "audit_logs_router",
    "auth_router",
    "dashboard_router",
    "findings_router",
    "health_router",
    "institutions_router",
    "liveness_router",
    "reports_router",
    "scans_router",
    "sync_router",
    "vulnerabilities_router",
]

"""Report generation routes.

Reports are generated in-memory and streamed to the client via
``StreamingResponse`` so we never write to disk. The frontend should send
the JWT in the ``Authorization`` header (as for every other request) — not
in the URL — and read the bytes from the response body.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.permissions import require_permission
from app.db import get_db
from app.models import User
from app.services.report_service import generate_csv_report, generate_pdf_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _chunked(payload: bytes, chunk_size: int = 64 * 1024):
    """Yield payload in fixed-size chunks so StreamingResponse can flush
    progressively instead of holding the entire PDF/CSV in one buffer."""
    for i in range(0, len(payload), chunk_size):
        yield payload[i : i + chunk_size]


@router.get("/pdf")
def pdf_report(
    severity: str | None = None,
    kev: bool | None = None,
    days: int | None = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("report", "generate")),
):
    filename, payload = generate_pdf_report(db, severity=severity, kev=kev, days=days, limit=limit)
    return StreamingResponse(
        _chunked(payload),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(payload)),
            "Cache-Control": "no-store",
        },
    )


@router.get("/csv")
def csv_report(
    severity: str | None = None,
    kev: bool | None = None,
    days: int | None = None,
    limit: int = Query(5000, ge=1, le=50000),
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("report", "generate")),
):
    filename, payload = generate_csv_report(db, severity=severity, kev=kev, days=days, limit=limit)
    return StreamingResponse(
        _chunked(payload),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(payload)),
            "Cache-Control": "no-store",
        },
    )

"""Generate PDF and CSV reports for filtered vulnerability data.

Reports stream from the DB query to an in-memory buffer; we never write to
disk. Filenames include a UUID + ms suffix so two requests landing in the
same second can't clobber each other if the caller persists the result.
"""

from __future__ import annotations

import csv
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from app.models import Severity, Vulnerability


def _filtered_query(
    db: Session,
    severity: str | None,
    kev: bool | None,
    days: int | None,
):
    q = db.query(Vulnerability)
    if severity:
        try:
            q = q.filter(Vulnerability.severity == Severity(severity.upper()))
        except ValueError:
            q = q.filter(False)  # unknown severity → empty result
    if kev is not None:
        q = q.filter(Vulnerability.in_kev == kev)
    if days:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        q = q.filter(Vulnerability.published >= since)
    return q.order_by(Vulnerability.published.desc())


def _row_payload(r: Vulnerability) -> dict:
    return {
        "cve_id": r.cve_id,
        "title": r.title or "",
        "severity": r.severity.value if r.severity else "",
        "cvss": r.cvss_v3_score,
        "published": r.published,
        "in_kev": r.in_kev,
        "products": r.affected_products or [],
    }


def generate_csv_report(
    db: Session,
    severity: str | None = None,
    kev: bool | None = None,
    days: int | None = None,
) -> tuple[str, bytes]:
    """Build a CSV in memory. Returns (filename, bytes)."""
    q = _filtered_query(db, severity, kev, days)

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "CVE ID",
            "Title",
            "Severity",
            "CVSS v3",
            "Published",
            "In KEV",
            "Affected Products",
        ]
    )
    # yield_per bounds memory even when the filtered set is large.
    for r in q.yield_per(1000):
        d = _row_payload(r)
        w.writerow(
            [
                d["cve_id"],
                d["title"],
                d["severity"],
                d["cvss"] if d["cvss"] is not None else "",
                d["published"].isoformat() if d["published"] else "",
                "Y" if d["in_kev"] else "N",
                ", ".join(
                    f"{p.get('vendor')}:{p.get('product')}"
                    for p in d["products"]
                    if isinstance(p, dict)
                ),
            ]
        )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"vuln-report-{stamp}-{uuid.uuid4().hex[:8]}.csv"
    return fname, buf.getvalue().encode("utf-8")


def generate_pdf_report(
    db: Session,
    severity: str | None = None,
    kev: bool | None = None,
    days: int | None = None,
    title: str = "Vulnerability Report",
) -> tuple[str, bytes]:
    """Build a PDF in memory. Returns (filename, bytes)."""
    q = _filtered_query(db, severity, kev, days)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=title)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]

    data = [["CVE", "Severity", "CVSS", "Published", "Title"]]
    count = 0
    for r in q.yield_per(1000):
        d = _row_payload(r)
        data.append(
            [
                d["cve_id"],
                d["severity"],
                f"{d['cvss']:.1f}" if d["cvss"] is not None else "-",
                d["published"].strftime("%Y-%m-%d") if d["published"] else "",
                d["title"][:60],
            ]
        )
        count += 1
    story.insert(1, Paragraph(f"{count} record(s)", styles["Normal"]))

    if count:
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No vulnerabilities matched the filters.", styles["Italic"]))

    doc.build(story)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"vuln-report-{stamp}-{uuid.uuid4().hex[:8]}.pdf"
    return fname, buf.getvalue()

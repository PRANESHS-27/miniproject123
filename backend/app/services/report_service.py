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
    limit: int = 10000,
) -> tuple[str, bytes]:
    """Build a CSV in memory. Returns (filename, bytes)."""
    q = _filtered_query(db, severity, kev, days)
    if limit:
        q = q.limit(limit)

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
    limit: int = 500,
) -> tuple[str, bytes]:
    """Build a high-performance, cleanly formatted PDF in memory. Returns (filename, bytes)."""
    q = _filtered_query(db, severity, kev, days)
    total_matches = q.count()

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=title,
    )
    styles = getSampleStyleSheet()

    # Criteria description for header
    kev_str = "Yes" if kev is True else ("No" if kev is False else "Any")
    filter_desc = f"Severity: {severity or 'ALL'}  |  KEV: {kev_str}  |  Timeframe: {f'Last {days} days' if days else 'All time'}"

    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(
            f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}  &bull;  {filter_desc}",
            styles["Normal"],
        ),
        Spacer(1, 8),
    ]

    rows = q.limit(limit).all()
    count = len(rows)

    if total_matches > count:
        summary_msg = f"Matching records in database: <b>{total_matches:,}</b> (Displaying top {count:,} most recent entries below)"
    else:
        summary_msg = f"Total matching records: <b>{total_matches:,}</b>"
    story.append(Paragraph(summary_msg, styles["Normal"]))
    story.append(Spacer(1, 12))

    data = [["CVE ID", "Severity", "CVSS", "Published", "Title"]]
    for r in rows:
        d = _row_payload(r)
        pub_str = d["published"].strftime("%Y-%m-%d") if d["published"] else ""
        cvss_str = f"{d['cvss']:.1f}" if d["cvss"] is not None else "-"
        raw_title = d["title"] or ""
        short_title = (raw_title[:55] + "…") if len(raw_title) > 55 else raw_title
        data.append([d["cve_id"], d["severity"], cvss_str, pub_str, short_title])

    if count:
        table = Table(data, colWidths=[90, 60, 45, 75, 270], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No vulnerabilities matched the selected filters.", styles["Italic"]))

    doc.build(story)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"vuln-report-{stamp}-{uuid.uuid4().hex[:8]}.pdf"
    return fname, buf.getvalue()


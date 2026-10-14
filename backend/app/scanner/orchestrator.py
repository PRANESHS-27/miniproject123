"""Scanner orchestrator — executes scoped scan jobs, persists findings, triggers alerts, and logs audit entries."""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging_config import get_logger
from app.core.time import utcnow_naive
from app.models import (
    Alert,
    Asset,
    AssetCveMatch,
    AssetFinding,
    AssetScan,
    AssetTechnology,
    AuditLog,
    Finding,
    FindingRiskLabel,
    FindingStatus,
    FindingType,
    SeverityLevel,
    Vulnerability,
)
from app.scanner.parsers import redact_evidence
from app.scanner.runner import execute_scan
from app.services import asset_scanner

logger = get_logger("scanner_orchestrator")


def run_orchestrated_scan(
    db: Session,
    asset_id: int,
    *,
    profile: str = "web_standard",
    triggered_by: str = "manual",
    actor_username: str = "system",
) -> AssetScan | None:
    """Run an orchestrated scan with profile selection, alert generation, and audit logging."""
    asset = db.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if not asset:
        return None

    # Create scan job record
    scan = AssetScan(
        asset_id=asset_id,
        status="running",
        triggered_by=triggered_by,
        scan_profile=profile,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Execute scan with scope validation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(
                execute_scan(
                    asset.url,
                    profile=profile,
                    allow_private_ranges=False,
                    allow_loopback_for_testing=False,
                )
            )
        finally:
            loop.close()

        scan.raw_output = {
            "profile": profile,
            "engine": results.get("scanner_engine", "integrated"),
            "services_count": len(results.get("services", [])),
            "findings_count": len(results.get("findings", [])),
            "technologies_count": len(results.get("technologies", [])),
            "tools_available": results.get("tools_available", {}),
        }

        # 1. Update detected technologies
        techs = results.get("technologies", [])
        asset_scanner._replace_technologies(db, asset.id, techs)
        db.commit()

        # 2. CVE Matching
        tech_rows = db.query(AssetTechnology).filter(AssetTechnology.asset_id == asset.id).all()
        tech_dict_by_key = {(t.vendor, t.product): t for t in tech_rows}
        tech_pairs_for_match = []
        for t in techs:
            row = tech_dict_by_key.get((t["vendor"], t["product"]))
            tech_pairs_for_match.append({**t, "id": row.id if row else None})

        from app.services.asset_matcher import match_cves
        matched = match_cves(db, asset.id, tech_pairs_for_match)

        # 3. Upsert Findings (Risk Engine)
        from app.services.findings import upsert_many as findings_upsert_many
        fresh_matches = db.query(AssetCveMatch).filter(AssetCveMatch.asset_id == asset.id).all()
        findings_upsert_many(db, fresh_matches, source="scan")
        db.commit()

        # 4. Standardize and cap findings
        all_findings = list(results.get("findings", []))
        for m in matched[:50]:
            all_findings.append({
                "finding_type": "cve",
                "severity": (m.get("cve_severity") or "UNKNOWN").upper(),
                "title": f"{m['cve_id']} affects {m['technology_vendor']}:{m['technology_product']}",
                "details": {
                    "cve_id": m["cve_id"],
                    "vendor": m["technology_vendor"],
                    "product": m["technology_product"],
                    "cvss_v3_score": m.get("cve_cvss_v3_score"),
                    "title": m.get("cve_title"),
                },
                "remediation": f"Review {m['cve_id']} on NVD; patch or upgrade {m['technology_vendor']}:{m['technology_product']}.",
            })

        inserted, re_seen, closed, _ = asset_scanner._replace_open_findings(db, asset.id, all_findings)
        scan.items_found = inserted + re_seen
        scan.inserted_count = inserted
        scan.re_seen_count = re_seen
        scan.closed_count = closed
        scan.technologies_detected = len(tech_rows)
        scan.cves_matched = len(matched)
        scan.status = "success"
        scan.finished_at = utcnow_naive()
        asset.last_scanned_at = scan.finished_at
        asset.last_scan_status = "success"
        db.commit()

        # 5. Evaluate and generate Alerts for critical risks or KEV vulnerabilities
        try:
            critical_findings = (
                db.query(Finding)
                .filter(
                    Finding.asset_id == asset.id,
                    Finding.status == FindingStatus.OPEN,
                    Finding.risk_label.in_([FindingRiskLabel.CRITICAL, FindingRiskLabel.HIGH]),
                )
                .all()
            )
            for f in critical_findings:
                # Avoid duplicate unread alerts for same finding
                existing_alert = (
                    db.query(Alert)
                    .filter(
                        Alert.finding_id == f.id,
                        Alert.is_dismissed.is_(False),
                    )
                    .first()
                )
                if not existing_alert:
                    db.add(Alert(
                        institution_id=asset.institution_id,
                        asset_id=asset.id,
                        finding_id=f.id,
                        title=f"{f.risk_label.value} Risk: {f.vulnerability_cve_id} on {asset.label}",
                        message=f"A {f.risk_label.value} finding was detected on {asset.url} (Risk Score: {f.risk_score}/100). Immediate remediation required.",
                        severity=f.risk_label.value,
                        is_read=False,
                        is_dismissed=False,
                    ))
            db.commit()
        except Exception as exc:
            logger.warning("Alert creation after scan failed: %s", exc)

        # 6. Record Audit Log
        try:
            db.add(AuditLog(
                institution_id=asset.institution_id,
                actor_username=actor_username,
                action="scan_completed",
                resource_type="scan",
                resource_id=str(scan.id),
                details={
                    "asset_id": asset.id,
                    "asset_url": asset.url,
                    "profile": profile,
                    "items_found": scan.items_found,
                    "inserted": inserted,
                    "cves_matched": scan.cves_matched,
                },
                outcome="success",
            ))
            db.commit()
        except Exception as exc:
            logger.warning("AuditLog recording failed: %s", exc)

        # 7. Refresh in-memory index
        try:
            from app.services import cve_index
            cve_index.refresh(db)
        except Exception:
            pass

        return scan

    except Exception as exc:
        logger.exception("Orchestrated scan failed for asset %d: %s", asset_id, exc)
        scan.status = "failed"
        scan.error = str(exc)[:1000]
        scan.finished_at = utcnow_naive()
        asset.last_scanned_at = scan.finished_at
        asset.last_scan_status = "failed"
        db.commit()

        try:
            db.add(AuditLog(
                institution_id=asset.institution_id,
                actor_username=actor_username,
                action="scan_failed",
                resource_type="scan",
                resource_id=str(scan.id),
                details={"asset_id": asset.id, "error": str(exc)},
                outcome="failure",
            ))
            db.commit()
        except Exception:
            pass

        return scan

"""Output parsers and evidence normalizers for security scanner outputs."""

from __future__ import annotations

import json
import re
from typing import Any

# Sensitive patterns to redact from scan evidence
REDACTION_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(authorization:\s*)[^\r\n]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(password|passwd|pwd|secret|api_key|token)[=:]\s*["\']?[^"\'&\s]{4,}'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(phpsessid|sessionid|jsessionid|csrftoken)=[a-zA-Z0-9_\-]+'), r'\1=[REDACTED_SESSION]'),
]


def redact_evidence(text: str | None) -> str | None:
    """Strip authentication tokens, session cookies, and secrets from evidence text."""
    if not text:
        return text
    clean = text
    for pattern, repl in REDACTION_PATTERNS:
        clean = pattern.sub(repl, clean)
    return clean


def parse_nmap_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse nmap service probe output or lines into standardized service observations."""
    services = []
    # Match port/proto state service version lines:
    # e.g., "80/tcp  open  http    Apache httpd 2.4.49 ((Unix))"
    pattern = re.compile(
        r'(\d+)/(tcp|udp)\s+(\w+)\s+([a-zA-Z0-9_\-]+)\s*(.*)',
        re.MULTILINE,
    )
    for match in pattern.finditer(raw_output):
        port, proto, state, service, version = match.groups()
        if state.lower() == "open":
            services.append({
                "port": int(port),
                "protocol": proto.upper(),
                "state": state,
                "service": service,
                "version": redact_evidence(version.strip()) or None,
                "confidence": "scanner-confirmed",
            })
    return services


def parse_nuclei_json_line(line: str) -> dict[str, Any] | None:
    """Parse a single JSON line emitted by Nuclei into a normalized finding record."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except Exception:
        return None

    info = data.get("info", {})
    severity_raw = (info.get("severity") or "unknown").upper()
    cve_id = None
    classification = info.get("classification", {})
    cve_ids = classification.get("cve-id", [])
    if isinstance(cve_ids, list) and cve_ids:
        cve_id = cve_ids[0].upper()
    elif isinstance(cve_ids, str) and cve_ids:
        cve_id = cve_ids.upper()

    # Extract template id or title
    template_id = data.get("template-id") or data.get("templateID", "nuclei-finding")
    name = info.get("name") or template_id

    # Evidence details
    extracted = data.get("extracted-results", [])
    matcher_name = data.get("matcher-name")
    curl_command = redact_evidence(data.get("curl-command"))

    return {
        "finding_type": "cve" if cve_id else "nuclei",
        "title": name,
        "cve_id": cve_id,
        "severity": severity_raw,
        "confidence": "scanner-confirmed",
        "remediation": info.get("remediation"),
        "details": {
            "template_id": template_id,
            "matched_at": data.get("matched-at"),
            "matcher_name": matcher_name,
            "extracted_results": [redact_evidence(str(x)) for x in extracted] if extracted else [],
            "curl_command": curl_command,
            "cvss_score": classification.get("cvss-score"),
        },
    }


def normalize_confidence(detection_source: str, has_version: bool) -> str:
    """Determine confidence label: potential, scanner-confirmed, or verified."""
    source_lower = (detection_source or "").lower()
    if "verified" in source_lower or "manual" in source_lower:
        return "verified"
    if "nuclei" in source_lower or "direct_probe" in source_lower or "payload" in source_lower:
        return "scanner-confirmed"
    if has_version:
        return "potential"
    return "potential"

"""Exposed admin / sensitive path probe.

A path is **exposed** if GET returns 200 — anything else (401/403/404) is
either protected or absent. Severity scales with how dangerous the path is.
"""

from __future__ import annotations

from typing import Any

# Path -> default severity when it returns 200. The orchestrator may override
# based on the actual HTTP status (e.g. 401/403 -> INFO "detectable but blocked").
EXPOSED_PATH_SEVERITY: dict[str, str] = {
    "/.env": "CRITICAL",
    "/.git/HEAD": "HIGH",
    "/.git/config": "HIGH",
    "/wp-admin/": "MEDIUM",
    "/wp-login.php": "MEDIUM",
    "/administrator/": "MEDIUM",
    "/admin/": "MEDIUM",
    "/phpmyadmin/": "CRITICAL",
    "/server-status": "MEDIUM",
    "/server-info": "MEDIUM",
    "/elmah.axd": "HIGH",
    "/manager/html": "CRITICAL",
    "/actuator/env": "CRITICAL",
    "/api/": "LOW",
    "/.well-known/security.txt": "INFO",
}

EXPOSED_PATH_FIXES: dict[str, str] = {
    "/.env": "Block public access to /.env — return 404 or 403 from the web server. Rotate any secrets that may have been exposed.",
    "/.git/HEAD": "Block /.git/ from the web server. Check git history for leaked credentials.",
    "/.git/config": "Block /.git/ from the web server.",
    "/wp-admin/": "If unintended: block /wp-admin/ via web-server config or IP allow-list. If intended: enforce MFA and rate limiting.",
    "/wp-login.php": "If unintended: block /wp-login.php. If intended: enforce MFA and rate limit login attempts.",
    "/administrator/": "If unintended: block /administrator/. If intended: enforce MFA and rate limiting.",
    "/admin/": "If unintended: block /admin/. If intended: enforce MFA.",
    "/phpmyadmin/": "Block /phpmyadmin/ from the public internet. Use a VPN or IP allow-list.",
    "/server-status": "Restrict /server-status (Apache) to localhost / internal IPs.",
    "/server-info": "Restrict /server-info (Apache) to localhost / internal IPs.",
    "/elmah.axd": "Disable Elmah remote viewing or restrict to administrators.",
    "/manager/html": "Block /manager/html (Tomcat) from the public internet.",
    "/actuator/env": "Restrict Spring Boot Actuator endpoints; never expose /env publicly.",
    "/api/": "Verify API endpoints require authentication. Add rate limiting and audit access.",
    "/.well-known/security.txt": "Missing security.txt is informational only — add a disclosure contact if you want coordinated disclosure.",
}


def findings_for_path_results(
    path_results: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path, info in path_results.items():
        status = info.get("status")
        default_sev = EXPOSED_PATH_SEVERITY.get(path, "LOW")
        fix = EXPOSED_PATH_FIXES.get(path, "Review whether this endpoint should be reachable from the public internet.")
        if status == 200:
            findings.append({
                "finding_type": "admin_path",
                "severity": default_sev,
                "title": f"Publicly accessible sensitive path: {path}",
                "details": {"path": path, "status": 200, "length": info.get("length")},
                "remediation": fix,
            })
        elif status in (401, 403):
            findings.append({
                "finding_type": "admin_path",
                "severity": "INFO",
                "title": f"Sensitive path detected but protected: {path}",
                "details": {"path": path, "status": status},
                "remediation": "Endpoint exists and is reachable — confirm it requires authentication and rate limiting.",
            })
        # 404 / 5xx / network error -> don't surface anything
    return findings
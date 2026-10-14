"""Controlled security scanner runner with safe execution profiles and fallbacks."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
from typing import Any

from app.core.config import settings
from app.core.logging_config import get_logger
from app.scanner.parsers import parse_nmap_output, parse_nuclei_json_line, redact_evidence
from app.scanner.scope_validation import validate_scan_target
from app.services import asset_fingerprint, asset_headers, asset_js, asset_paths, asset_tls
from app.services.cve_fetcher import _ssl_verify

logger = get_logger("scanner_runner")

# Common network ports checked by the safe integrated TCP probe fallback
DEFAULT_PROBE_PORTS = [80, 443, 8080, 8443, 8000, 3000, 22, 21, 25, 3306, 5432, 6379, 8081, 9000]


def check_tool_availability() -> dict[str, bool]:
    """Check which external scanning CLI tools are installed on the host."""
    return {
        "nmap": bool(shutil.which("nmap")),
        "nuclei": bool(shutil.which("nuclei")),
        "httpx": bool(shutil.which("httpx")),
    }


async def run_tcp_port_probe(host: str, ports: list[int] = DEFAULT_PROBE_PORTS, timeout: float = 1.5) -> list[dict[str, Any]]:
    """Safe integrated Python TCP socket probe when external nmap is not installed."""
    open_ports = []
    loop = asyncio.get_running_loop()

    def _probe_port(p: int) -> dict[str, Any] | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, p))
                if res == 0:
                    service = "http" if p in (80, 8080, 8000, 3000) else "https" if p in (443, 8443) else f"port-{p}"
                    return {
                        "port": p,
                        "protocol": "TCP",
                        "state": "open",
                        "service": service,
                        "version": None,
                        "confidence": "scanner-confirmed",
                        "engine": "integrated-tcp-probe",
                    }
        except Exception:
            pass
        return None

    tasks = [loop.run_in_executor(None, _probe_port, p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, dict) and res:
            open_ports.append(res)
    return open_ports


async def run_nmap_scan(target_ip: str, timeout: int = 45) -> tuple[list[dict[str, Any]], str | None]:
    """Execute Nmap service detection with safe, non-intrusive arguments."""
    if not shutil.which("nmap"):
        return [], "nmap executable not found in PATH"

    cmd = [
        "nmap",
        "-F",              # Fast scan: 100 most common ports
        "-sV",             # Service version probe
        "--version-light", # Fast light version detection
        "-T3",             # Polite/normal timing
        "--host-timeout", f"{timeout}s",
        target_ip,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        raw = stdout.decode("utf-8", errors="replace")
        services = parse_nmap_output(raw)
        return services, None
    except asyncio.TimeoutError:
        return [], "Nmap scan timed out"
    except Exception as exc:
        logger.warning("Nmap execution failed: %s", exc)
        return [], str(exc)


async def run_nuclei_scan(target_url: str, timeout: int = 60) -> tuple[list[dict[str, Any]], str | None]:
    """Execute Nuclei vulnerability scan targeting CVEs with safe timeouts."""
    if not shutil.which("nuclei"):
        return [], "nuclei executable not found in PATH"

    cmd = [
        "nuclei",
        "-u", target_url,
        "-tags", "cve",
        "-severity", "critical,high",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        "-json",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        raw = stdout.decode("utf-8", errors="replace")
        findings = []
        for line in raw.splitlines():
            item = parse_nuclei_json_line(line)
            if item:
                findings.append(item)
        return findings, None
    except asyncio.TimeoutError:
        return [], "Nuclei scan timed out"
    except Exception as exc:
        logger.warning("Nuclei execution failed: %s", exc)
        return [], str(exc)


async def execute_scan(
    target: str,
    *,
    profile: str = "web_standard",
    allow_private_ranges: bool = False,
    allow_loopback_for_testing: bool = False,
) -> dict[str, Any]:
    """Execute a complete scoped scan according to the chosen profile.

    Profiles:
      - 'quick': Fast HTTP headers + TLS + meta fingerprinting
      - 'web_standard': Complete HTTP fingerprint + JS + Path audit + TLS
      - 'network_discovery': Nmap / TCP port discovery + service identification
      - 'vulnerability_audit': Web fingerprint + Nuclei CVE scans (or CPE correlation)
      - 'full': Network discovery + Web fingerprint + Vulnerability checks
    """
    # 1. Scope and SSRF validation
    validated = validate_scan_target(
        target,
        allow_private_ranges=allow_private_ranges,
        allow_loopback_for_testing=allow_loopback_for_testing,
    )

    url = validated["url"]
    host = validated["hostname"]
    primary_ip = validated["primary_ip"]
    tools = check_tool_availability()

    raw_results: dict[str, Any] = {
        "target": validated,
        "profile": profile,
        "tools_available": tools,
        "services": [],
        "technologies": [],
        "findings": [],
        "probed_meta": {},
        "scanner_engine": "integrated",
    }

    verify = _ssl_verify()
    timeout = float(settings.asset_scan_timeout_seconds)

    # 2. Network service discovery (if requested or in full profile)
    if profile in ("network_discovery", "full"):
        if tools["nmap"]:
            services, err = await run_nmap_scan(primary_ip, timeout=40)
            raw_results["services"] = services
            raw_results["scanner_engine"] = "nmap"
            if err:
                raw_results["nmap_error"] = err
        else:
            services = await run_tcp_port_probe(primary_ip)
            raw_results["services"] = services
            raw_results["scanner_engine"] = "integrated-tcp-probe"

    # 3. Web fingerprinting and vulnerability checks
    if profile in ("quick", "web_standard", "vulnerability_audit", "full"):
        try:
            probed_meta, technologies = await asset_fingerprint.fingerprint_asset(
                url, timeout=timeout, verify=verify
            )
            raw_results["probed_meta"] = probed_meta
            raw_results["technologies"] = technologies

            # Run web inspections
            path_tasks = []
            if profile != "quick":
                path_tasks.append(
                    asset_fingerprint.probe_paths(
                        url,
                        settings.asset_probe_paths,
                        timeout=timeout,
                        verify=verify,
                        max_concurrency=settings.asset_scan_max_concurrency,
                    )
                )
            else:
                path_tasks.append(asyncio.sleep(0, result=[]))

            tls_task = asset_tls.probe_tls(url, timeout=timeout)
            js_task = _async_match_js(probed_meta.get("body") or "", url)
            headers_task = _async_audit_headers(probed_meta.get("headers") or {})

            path_results, tls_findings, js_findings, header_findings = await asyncio.gather(
                *path_tasks, tls_task, js_task, headers_task, return_exceptions=True
            )

            web_findings = []
            if isinstance(path_results, list):
                web_findings.extend(asset_paths.findings_for_path_results(path_results))
            if isinstance(tls_findings, list):
                web_findings.extend(tls_findings)
            if isinstance(js_findings, list):
                web_findings.extend(js_findings)
            if isinstance(header_findings, list):
                web_findings.extend(header_findings)

            raw_results["findings"].extend(web_findings)

        except Exception as exc:
            logger.warning("Web probe failed for %s: %s", url, exc)
            raw_results["web_probe_error"] = str(exc)

    # 4. Nuclei Vulnerability Checks (if requested)
    if profile in ("vulnerability_audit", "full") and tools["nuclei"]:
        nuclei_findings, err = await run_nuclei_scan(url, timeout=45)
        if nuclei_findings:
            raw_results["findings"].extend(nuclei_findings)
            raw_results["scanner_engine"] = "nuclei"
        if err:
            raw_results["nuclei_error"] = err

    return raw_results


async def _async_match_js(body: str, url: str) -> list[dict[str, Any]]:
    scripts = asset_js.extract_scripts(body, url) if body else []
    return asset_js.match_scripts(scripts)


async def _async_audit_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    return asset_headers.audit_headers(headers)

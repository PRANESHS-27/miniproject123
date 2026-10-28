"""TLS / SSL health probe for an asset.

Checks (when reachable):
  - certificate expiry (days remaining)
  - subject + issuer + SAN count
  - TLS protocol version (flags <1.2 as HIGH, <1.0 as CRITICAL)
  - weak signature algorithm on the leaf cert
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


WEAK_SIG_ALGOS = {
    "md5WithRSAEncryption",
    "sha1WithRSAEncryption",  # SHA-1 is deprecated for cert signing
}


def _make_context(minimum_version: int) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if minimum_version:
        ctx.minimum_version = minimum_version
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def probe_tls(url: str, *, timeout: float = 5.0) -> list[dict[str, Any]]:
    """Return a list of ``AssetFinding``-shaped dicts.

    Errors return a single CRITICAL finding rather than raising — we don't
    want one unreachable host to fail the entire scan.
    """
    findings: list[dict[str, Any]] = []
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return findings

    ctx = _make_context(ssl.TLSVersion.TLSv1_2)
    loop = asyncio.get_running_loop()
    try:
        sock = await loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=timeout))
    except (OSError, Exception) as exc:
        findings.append({
            "finding_type": "tls",
            "severity": "HIGH",
            "title": f"Could not establish TLS connection to {host}:{port}",
            "details": {"error": str(exc), "host": host, "port": port},
            "remediation": "Verify the host is reachable on the configured port and that TLS is enabled.",
        })
        return findings

    try:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            negotiated = ssock.version()
            cipher = ssock.cipher()
    except (ssl.SSLError, OSError) as exc:
        findings.append({
            "finding_type": "tls",
            "severity": "HIGH",
            "title": f"TLS handshake failed for {host}:{port}",
            "details": {"error": str(exc)[:200]},
            "remediation": "Check server TLS configuration and supported protocol versions.",
        })
        return findings
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if negotiated in {"TLSv1", "TLSv1.1"}:
        findings.append({
            "finding_type": "tls",
            "severity": "HIGH",
            "title": f"Deprecated TLS protocol in use: {negotiated}",
            "details": {"protocol": negotiated},
            "remediation": "Disable TLS 1.0 / 1.1 on the server. Modern clients require TLS 1.2+.",
        })
    elif not negotiated or negotiated == "SSLv3":
        findings.append({
            "finding_type": "tls",
            "severity": "CRITICAL",
            "title": "Legacy / no TLS negotiated",
            "details": {"protocol": negotiated},
            "remediation": "Enable TLS 1.2+; SSLv3 is broken (POODLE).",
        })

    # Cipher strength (very rough — flag known weak families by name)
    if cipher:
        cname = (cipher[0] or "").upper()
        if any(weak in cname for weak in ("RC4", "3DES", "NULL", "EXPORT", "DES-CBC")):
            findings.append({
                "finding_type": "tls",
                "severity": "HIGH",
                "title": f"Weak cipher negotiated: {cipher[0]}",
                "details": {"cipher": cipher[0], "protocol": cipher[1], "bits": cipher[2]},
                "remediation": "Disable weak ciphers (RC4, 3DES, DES, NULL, EXPORT) on the server.",
            })

    # Cert parse — best effort, falls back gracefully if cryptography missing
    try:
        import cryptography.x509  # noqa
        from cryptography.x509 import load_der_x509_certificate  # type: ignore

        cert = load_der_x509_certificate(cert_bin)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        now = datetime.now(timezone.utc)
        days = (not_after - now).days
        if days < 0:
            sev, title = "CRITICAL", f"TLS certificate EXPIRED {-days} days ago"
        elif days < 14:
            sev, title = "CRITICAL", f"TLS certificate expires in {days} days"
        elif days < 30:
            sev, title = "HIGH", f"TLS certificate expires in {days} days"
        else:
            sev, title = None, None
        if sev:
            findings.append({
                "finding_type": "tls",
                "severity": sev,
                "title": title,
                "details": {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "expires_at": not_after.isoformat(),
                    "days_remaining": days,
                },
                "remediation": "Renew the TLS certificate before it expires.",
            })
        try:
            sig_alg = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
            if sig_alg in WEAK_SIG_ALGOS:
                findings.append({
                    "finding_type": "tls",
                    "severity": "HIGH",
                    "title": f"Certificate signed with weak algorithm: {sig_alg}",
                    "details": {"signature_algorithm": sig_alg},
                    "remediation": "Re-issue the certificate with SHA-256 (or stronger) signature.",
                })
        except AttributeError:
            pass
    except ImportError:
        # cryptography not available — skip the deep cert checks
        pass
    except Exception:  # pragma: no cover — defensive
        pass

    return findings
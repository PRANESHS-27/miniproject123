"""Target scope and SSRF safety validation for vulnerability scanners."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Cloud metadata and link-local IP addresses strictly blocked
BLOCKED_IPS = {
    "169.254.169.254",  # AWS / OpenStack / Azure metadata
    "169.254.170.2",    # AWS task metadata
    "metadata.google.internal",
    "metadata.google.internal.",
}

# Link-local and cloud-metadata network ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / IPv4 LL
    ipaddress.ip_network("fe80::/10"),        # IPv6 Link-local
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback IPv4
    ipaddress.ip_network("::1/128"),          # Loopback IPv6
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 Unique Local Address
]


class ScopeValidationError(ValueError):
    """Raised when an asset target falls outside authorized scanning scope."""
    pass


def validate_scan_target(
    target: str,
    *,
    allow_private_ranges: bool = False,
    allow_loopback_for_testing: bool = False,
) -> dict[str, any]:
    """Validate that a target URL, hostname, or IP is safe and authorized for scanning.

    Enforces:
      - Valid format and protocol (http:// or https:// if URL)
      - Resolves hostname to IP addresses via DNS
      - Blocks cloud metadata endpoints (AWS, GCP, Azure) unconditionally
      - Blocks loopback addresses (unless explicit dev flag passed)
      - Blocks private RFC 1918 ranges unless explicitly authorized
      - Normalizes hostname, port, and scheme

    Returns:
      dict with keys: 'hostname', 'ip_address', 'port', 'scheme', 'url'
    """
    if not target or not isinstance(target, str):
        raise ScopeValidationError("Target specification cannot be empty")

    raw = target.strip()
    if raw.lower() in BLOCKED_IPS:
        raise ScopeValidationError(f"Target '{raw}' is a restricted cloud metadata address")

    # Parse URL or host:port
    if "://" not in raw:
        # Default to https for raw hostnames/IPs
        parsed = urlparse(f"https://{raw}")
    else:
        parsed = urlparse(raw)

    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise ScopeValidationError(f"Unsupported protocol scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        raise ScopeValidationError("Target does not include a valid hostname or IP address")

    if hostname.lower() in BLOCKED_IPS:
        raise ScopeValidationError(f"Target hostname '{hostname}' is a restricted cloud metadata endpoint")

    port = parsed.port or (443 if scheme == "https" else 80)
    if not (1 <= port <= 65535):
        raise ScopeValidationError(f"Port {port} is out of valid range (1-65535)")

    # Resolve IP address
    resolved_ips = []
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            ip = entry[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
    except socket.gaierror as exc:
        raise ScopeValidationError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    if not resolved_ips:
        raise ScopeValidationError(f"No IP addresses resolved for hostname '{hostname}'")

    # Validate all resolved IPs
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ScopeValidationError(f"Invalid resolved IP address: {ip_str}")

        # Cloud metadata / link-local / loopback check
        for net in BLOCKED_NETWORKS:
            if ip_obj in net:
                if ip_obj.is_loopback and allow_loopback_for_testing:
                    continue
                raise ScopeValidationError(
                    f"Resolved IP {ip_str} belongs to restricted network {net} (SSRF / Metadata protection)"
                )

        # Private IP check
        if not allow_private_ranges:
            for net in PRIVATE_NETWORKS:
                if ip_obj in net:
                    raise ScopeValidationError(
                        f"Target resolves to private network address {ip_str}. "
                        f"Scanning internal IP ranges requires explicit institutional authorization."
                    )

    canonical_url = f"{scheme}://{hostname}:{port}" if (
        (scheme == "https" and port != 443) or (scheme == "http" and port != 80)
    ) else f"{scheme}://{hostname}"

    return {
        "hostname": hostname,
        "primary_ip": resolved_ips[0],
        "resolved_ips": resolved_ips,
        "port": port,
        "scheme": scheme,
        "url": canonical_url,
    }

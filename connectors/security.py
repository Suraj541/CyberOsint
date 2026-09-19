"""
Network Security & SSRF Protection Module
Enforces strict boundaries on external network requests initiated by connectors.
Conforms to IMPLEMENT.md Section 37 (SSRF Protection).
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Optional


class SSRFSecurityError(Exception):
    """Raised when an outgoing connection attempts to access prohibited network ranges."""

    pass


# Prohibited IP networks for SSRF defense
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private Class A
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private Class C
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved / Future use
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),          # IPv6 Multicast
]


def is_ip_allowed(ip_str: str, allow_private: bool = False) -> bool:
    """
    Check whether an IP address is a safe public routable internet address.
    Rejects loopback, private, link-local, multicast, and cloud metadata addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if allow_private:
        # In test environments with allow_private=True, allow private IPs except cloud metadata
        metadata_ip = ipaddress.ip_address("169.254.169.254")
        return ip != metadata_ip

    NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
    if isinstance(ip, ipaddress.IPv6Address) and ip in NAT64_PREFIX:
        embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        return is_ip_allowed(str(embedded_v4), allow_private=allow_private)

    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return False

    return True


def resolve_and_validate_hostname(hostname: str, allow_private: bool = False) -> List[str]:
    """
    Resolve a hostname via DNS and ensure all resolved IP addresses are safe.
    Raises SSRFSecurityError if any IP is in a prohibited range.
    """
    if not hostname:
        raise SSRFSecurityError("Target hostname is empty")

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFSecurityError(f"Failed to resolve hostname '{hostname}': {exc}")

    resolved_ips = list({info[4][0] for info in addr_info})

    for ip in resolved_ips:
        if not is_ip_allowed(ip, allow_private=allow_private):
            raise SSRFSecurityError(
                f"Hostname '{hostname}' resolved to prohibited address '{ip}' (SSRF protection violation)"
            )

    return resolved_ips


def validate_url_for_ssrf(url: str, allow_private: bool = False) -> str:
    """
    Validate a complete target URL against SSRF rules:
    1. Scheme must be http or https.
    2. Hostname must be present and not be localhost.
    3. Hostname must resolve strictly to permitted public IPs.
    Returns the validated URL string or raises SSRFSecurityError.
    """
    if not url:
        raise SSRFSecurityError("Target URL cannot be empty")

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("http", "https"):
        raise SSRFSecurityError(f"Unsupported or dangerous URL scheme: '{scheme}'. Only http and https are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFSecurityError("Target URL missing valid hostname")

    # Reject known localhost aliases immediately
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"):
        if not allow_private:
            raise SSRFSecurityError(f"Direct loopback or metadata host prohibited: '{hostname}'")

    # Resolve hostname and validate IPs
    resolve_and_validate_hostname(hostname, allow_private=allow_private)

    return url

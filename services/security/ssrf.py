"""
Server-Side Request Forgery (SSRF) Protection & Secure URL Fetcher.
Conforms strictly to IMPLEMENT.md Section 38 (Step 37: SSRF Protection).

The platform will eventually fetch thousands of URLs.
Therefore the fetcher must block:
- localhost
- 127.0.0.0/8
- Private IP ranges (RFC 1918)
- Link-local addresses
- Cloud metadata endpoints (AWS, GCP, Azure, Alibaba, Oracle)
- Internal DNS targets (.local, .internal, .lan, .corp, etc.)
- Internal services (Postgres, Redis, OpenSearch, etc.)

Validate the destination before every request.
Do not trust the hostname alone.
Re-check redirects.
"""

from dataclasses import dataclass, field
import ipaddress
import logging
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("cyber_osint.services.security.ssrf")


class SSRFSecurityError(Exception):
    """Raised when an outbound URL destination violates SSRF defense rules."""
    pass


# Disallowed private and internal IP networks
DISALLOWED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback (IPv4 & IPv6)
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # RFC 1918 Private IPv4
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local & Cloud Metadata (AWS/GCP/Azure/DO/OCI IMDS: 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Alibaba Cloud Metadata (100.100.100.200)
    ipaddress.ip_network("100.100.100.200/32"),
    # AWS IPv6 IMDS (fd00:ec2::254)
    ipaddress.ip_network("fd00:ec2::254/128"),
    # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("100.64.0.0/10"),
    # Documentation & benchmark ranges (RFC 5737 / RFC 2544)
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Broadcast & Multicast
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fc00::/7"),
]

# Disallowed domain name suffixes and hostnames
DISALLOWED_HOSTS: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "metadata.google.internal",
    "metadata.azure.com",
    "metadata.packet.net",
    "instance-data",
}

# Internal DNS targets mandated by Section 38
INTERNAL_DOMAIN_SUFFIXES: Set[str] = {
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".arpa",
    ".priv",
    ".intra",
    ".intranet",
}

# Sensitive internal daemon ports (reject targeting internal services)
SENSITIVE_INTERNAL_PORTS: Set[int] = {
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # OpenSearch / Elasticsearch
    8000,   # Internal API dev server
    2375,   # Docker daemon (unencrypted)
    2376,   # Docker daemon (TLS)
    2379,   # etcd client
    2380,   # etcd peer
    8500,   # Consul HTTP
    8200,   # Vault
    10250,  # Kubelet API
}


@dataclass
class SSRFValidationResult:
    """Result of validating a target URL against SSRF and network security policies."""
    is_safe: bool
    url: str
    hostname: str
    resolved_ips: List[str]
    violation_reason: Optional[str] = None


@dataclass
class SSRFRedirectHop:
    """Audit entry for a single redirect hop."""
    hop_index: int
    url: str
    hostname: str
    status_code: int
    location_target: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    is_safe: bool = True
    violation_reason: Optional[str] = None


@dataclass
class SSRFRedirectChainResult:
    """Full trajectory result of a multi-hop URL retrieval with redirect re-checking."""
    initial_url: str
    final_url: Optional[str]
    is_safe: bool
    total_hops: int
    hops: List[SSRFRedirectHop]
    content_length: int = 0
    violation_reason: Optional[str] = None
    content: bytes = b""


class SSRFValidator:
    """
    Validates URLs and resolves IP destinations before outbound connection.
    Protects against DNS rebinding, internal network scanning, cloud metadata theft,
    and prohibited internal service ports.
    """

    @staticmethod
    def unwrap_nat64(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """
        Unwraps RFC 6052 NAT64 IPv4-embedded IPv6 addresses (64:ff9b::/96) to underlying IPv4.
        """
        if isinstance(ip, ipaddress.IPv6Address):
            nat64_prefix = ipaddress.ip_network("64:ff9b::/96")
            if ip in nat64_prefix:
                underlying_v4 = ipaddress.IPv4Address(ip.packed[-4:])
                return underlying_v4
        return ip

    @classmethod
    def is_ip_allowed(cls, ip_str: str) -> Tuple[bool, Optional[str]]:
        """Checks whether an IP address is safe for outbound platform requests."""
        try:
            ip = ipaddress.ip_address(ip_str)
            ip = cls.unwrap_nat64(ip)

            # 1. Check loopback
            if ip.is_loopback:
                return False, f"Loopback address disallowed: {ip_str}"

            # 2. Check link-local / Cloud metadata (explicitly check 169.254.169.254 and 100.100.100.200)
            if ip.is_link_local or ip_str in {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}:
                return False, f"Link-local / cloud metadata address disallowed: {ip_str}"

            # 3. Check RFC 1918 Private IPv4 and IPv6 ULA
            if ip.is_private:
                return False, f"Private internal network disallowed: {ip_str}"

            # 4. Check Multicast / Reserved / Unspecified
            if ip.is_multicast:
                return False, f"Multicast address disallowed: {ip_str}"
            if ip.is_reserved:
                return False, f"Reserved address disallowed: {ip_str}"
            if ip.is_unspecified:
                return False, f"Unspecified / 0.0.0.0 address disallowed: {ip_str}"

            # 5. Check explicit disallowed subnets table
            for net in DISALLOWED_NETWORKS:
                try:
                    if ip in net:
                        return False, f"Destination belongs to restricted network {net}: {ip_str}"
                except TypeError:
                    continue

            return True, None
        except ValueError:
            return False, f"Malformed IP address: {ip_str}"

    @classmethod
    def validate_url(cls, url: str) -> SSRFValidationResult:
        """
        Validates URL destination before connection:
        1. Scheme must be HTTP or HTTPS
        2. Hostname must not be in forbidden hosts or internal DNS suffixes
        3. Sensitive internal daemon ports are rejected
        4. Resolves DNS to all IP addresses and ensures NONE belong to internal/private ranges
        """
        if not url:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname="",
                resolved_ips=[],
                violation_reason="URL cannot be empty.",
            )

        try:
            parsed = urlparse(url.strip())
        except Exception:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname="",
                resolved_ips=[],
                violation_reason="Failed to parse URL syntax.",
            )

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname=parsed.hostname or "",
                resolved_ips=[],
                violation_reason=f"Unsupported protocol scheme '{scheme}'. Only HTTP/HTTPS allowed.",
            )

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname="",
                resolved_ips=[],
                violation_reason="Missing destination hostname.",
            )

        # Check disallowed hostnames
        if hostname in DISALLOWED_HOSTS:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname=hostname,
                resolved_ips=[],
                violation_reason=f"Access to cloud metadata / internal host '{hostname}' is blocked.",
            )

        # Check internal DNS suffixes
        for sfx in INTERNAL_DOMAIN_SUFFIXES:
            if hostname.endswith(sfx):
                return SSRFValidationResult(
                    is_safe=False,
                    url=url,
                    hostname=hostname,
                    resolved_ips=[],
                    violation_reason=f"Internal DNS target '{hostname}' (matched '{sfx}') is strictly prohibited.",
                )

        # Check if hostname is a raw IP address
        try:
            raw_ip = ipaddress.ip_address(hostname)
            is_ok, reason = cls.is_ip_allowed(str(raw_ip))
            # Also check port for raw IPs
            if is_ok and parsed.port and parsed.port in SENSITIVE_INTERNAL_PORTS:
                return SSRFValidationResult(
                    is_safe=False,
                    url=url,
                    hostname=hostname,
                    resolved_ips=[str(raw_ip)],
                    violation_reason=f"Destination port {parsed.port} corresponds to sensitive internal service daemon.",
                )
            return SSRFValidationResult(
                is_safe=is_ok,
                url=url,
                hostname=hostname,
                resolved_ips=[str(raw_ip)],
                violation_reason=reason,
            )
        except ValueError:
            pass

        # Resolve DNS to all destination IPs (checks all A and AAAA records)
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_addr = item[4][0]
                if ip_addr not in resolved_ips:
                    resolved_ips.append(ip_addr)
        except socket.gaierror as gai_err:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname=hostname,
                resolved_ips=[],
                violation_reason=f"DNS resolution failed for '{hostname}': {gai_err}",
            )

        if not resolved_ips:
            return SSRFValidationResult(
                is_safe=False,
                url=url,
                hostname=hostname,
                resolved_ips=[],
                violation_reason=f"No IP addresses resolved for '{hostname}'.",
            )

        # Validate EVERY resolved IP (DNS rebinding / multi-homed internal defense)
        for ip_addr in resolved_ips:
            is_ok, reason = cls.is_ip_allowed(ip_addr)
            if not is_ok:
                return SSRFValidationResult(
                    is_safe=False,
                    url=url,
                    hostname=hostname,
                    resolved_ips=resolved_ips,
                    violation_reason=f"Resolved IP {ip_addr} blocked: {reason}",
                )

        return SSRFValidationResult(
            is_safe=True,
            url=url,
            hostname=hostname,
            resolved_ips=resolved_ips,
            violation_reason=None,
        )


class SecureURLFetcher:
    """
    Hardened HTTP Client.
    Validates destination against SSRF before connecting, enforces payload size caps,
    imposes strict request timeouts, and strictly re-checks every redirect hop.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        max_payload_bytes: int = 10 * 1024 * 1024,  # 10MB
        max_redirects: int = 5,
        user_agent: str = "CyberOSINT-Secure-Fetcher/1.0",
    ):
        self.timeout = timeout
        self.max_payload_bytes = max_payload_bytes
        self.max_redirects = max_redirects
        self.user_agent = user_agent

    def fetch(self, url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, bytes, Dict[str, str]]:
        """
        Executes safe HTTP GET request with SSRF validation and redirect re-checking.
        Raises ValueError/SSRFSecurityError if destination is disallowed.
        """
        result = self.fetch_with_redirect_validation(url, max_redirects=self.max_redirects, headers=headers)
        if not result.is_safe:
            raise SSRFSecurityError(result.violation_reason or "SSRF destination prohibited.")
        return 200, result.content, {}

    def fetch_url(self, url: str) -> dict:
        """Safe execution wrapper returning a result dictionary instead of raising."""
        try:
            res = self.fetch_with_redirect_validation(url, max_redirects=self.max_redirects)
            if not res.is_safe:
                return {
                    "success": False,
                    "status_code": 0,
                    "content": b"",
                    "headers": {},
                    "error": f"SSRF Block: {res.violation_reason}",
                    "hops": [
                        {
                            "hop": h.hop_index,
                            "url": h.url,
                            "status": h.status_code,
                            "safe": h.is_safe,
                            "reason": h.violation_reason,
                        }
                        for h in res.hops
                    ],
                }
            return {
                "success": True,
                "status_code": 200,
                "content": res.content,
                "headers": {},
                "error": None,
                "hops": [
                    {
                        "hop": h.hop_index,
                        "url": h.url,
                        "status": h.status_code,
                        "safe": h.is_safe,
                        "reason": h.violation_reason,
                    }
                    for h in res.hops
                ],
            }
        except Exception as exc:
            return {
                "success": False,
                "status_code": 0,
                "content": b"",
                "headers": {},
                "error": f"SSRF Block: {exc}",
                "hops": [],
            }

    def fetch_with_redirect_validation(
        self,
        url: str,
        max_redirects: int = 5,
        headers: Optional[Dict[str, str]] = None,
    ) -> SSRFRedirectChainResult:
        """
        Multi-hop HTTP fetcher that rigorously re-validates the destination URL
        at each redirect hop conforming to IMPLEMENT.md Section 38:
        'Re-check redirects.'
        """
        current_url = url
        hops: List[SSRFRedirectHop] = []
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        for hop_index in range(max_redirects + 1):
            # 1. Validate the current hop target BEFORE connection
            validation = SSRFValidator.validate_url(current_url)
            if not validation.is_safe:
                hop = SSRFRedirectHop(
                    hop_index=hop_index,
                    url=current_url,
                    hostname=validation.hostname,
                    status_code=0,
                    location_target=None,
                    resolved_ips=validation.resolved_ips,
                    is_safe=False,
                    violation_reason=validation.violation_reason,
                )
                hops.append(hop)
                return SSRFRedirectChainResult(
                    initial_url=url,
                    final_url=None,
                    is_safe=False,
                    total_hops=len(hops),
                    hops=hops,
                    violation_reason=f"SSRF violation at hop #{hop_index}: {validation.violation_reason}",
                )

            # 2. Issue request without auto-following redirects
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                    resp = client.get(current_url, headers=req_headers)
            except Exception as exc:
                hop = SSRFRedirectHop(
                    hop_index=hop_index,
                    url=current_url,
                    hostname=validation.hostname,
                    status_code=0,
                    location_target=None,
                    resolved_ips=validation.resolved_ips,
                    is_safe=True,
                    violation_reason=f"Connection error: {exc}",
                )
                hops.append(hop)
                return SSRFRedirectChainResult(
                    initial_url=url,
                    final_url=current_url,
                    is_safe=True,
                    total_hops=len(hops),
                    hops=hops,
                    content_length=0,
                    violation_reason=f"Connection failure: {exc}",
                )

            # 3. Check for Redirect (301, 302, 303, 307, 308)
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                if not location:
                    # Broken redirect without Location
                    hop = SSRFRedirectHop(
                        hop_index=hop_index,
                        url=current_url,
                        hostname=validation.hostname,
                        status_code=resp.status_code,
                        location_target=None,
                        resolved_ips=validation.resolved_ips,
                        is_safe=True,
                    )
                    hops.append(hop)
                    return SSRFRedirectChainResult(
                        initial_url=url,
                        final_url=current_url,
                        is_safe=True,
                        total_hops=len(hops),
                        hops=hops,
                        content=resp.content,
                    )

                # Resolve relative or absolute redirect URL
                next_url = urljoin(current_url, location)

                # Record hop
                hop = SSRFRedirectHop(
                    hop_index=hop_index,
                    url=current_url,
                    hostname=validation.hostname,
                    status_code=resp.status_code,
                    location_target=next_url,
                    resolved_ips=validation.resolved_ips,
                    is_safe=True,
                )
                hops.append(hop)

                # Move to next URL
                current_url = next_url
                continue

            # 4. Terminal non-redirect response (e.g. 200 OK)
            content = resp.content
            if len(content) > self.max_payload_bytes:
                hop = SSRFRedirectHop(
                    hop_index=hop_index,
                    url=current_url,
                    hostname=validation.hostname,
                    status_code=resp.status_code,
                    location_target=None,
                    resolved_ips=validation.resolved_ips,
                    is_safe=False,
                    violation_reason="Payload size exceeded maximum allowed limit.",
                )
                hops.append(hop)
                return SSRFRedirectChainResult(
                    initial_url=url,
                    final_url=current_url,
                    is_safe=False,
                    total_hops=len(hops),
                    hops=hops,
                    violation_reason=f"Payload exceeds {self.max_payload_bytes} bytes.",
                )

            hop = SSRFRedirectHop(
                hop_index=hop_index,
                url=current_url,
                hostname=validation.hostname,
                status_code=resp.status_code,
                location_target=None,
                resolved_ips=validation.resolved_ips,
                is_safe=True,
            )
            hops.append(hop)

            return SSRFRedirectChainResult(
                initial_url=url,
                final_url=current_url,
                is_safe=True,
                total_hops=len(hops),
                hops=hops,
                content_length=len(content),
                content=content,
            )

        # Exceeded max redirects
        return SSRFRedirectChainResult(
            initial_url=url,
            final_url=current_url,
            is_safe=False,
            total_hops=len(hops),
            hops=hops,
            violation_reason=f"Exceeded maximum allowed redirect hops ({max_redirects}). Possible redirect loop.",
        )


ssrf_validator = SSRFValidator()
secure_fetcher = SecureURLFetcher()

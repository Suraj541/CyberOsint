"""
Deterministic Regex Patterns
Regular expressions for pattern-based cybersecurity intelligence extraction:
CVE, CWE, MITRE ATT&CK techniques, hashes (MD5/SHA1/SHA256), IP addresses, and domains.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

import ipaddress
import re
from typing import Optional, Tuple

# -------------------------------------------------------------
# Structured Cyber Identifiers
# -------------------------------------------------------------
RE_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
RE_CWE = re.compile(r"\b(CWE-\d{1,5})\b", re.IGNORECASE)
RE_MITRE_TECHNIQUE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

# -------------------------------------------------------------
# Cryptographic Hashes (Hexadecimal)
# -------------------------------------------------------------
RE_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")
RE_SHA1 = re.compile(r"\b([a-fA-F0-9]{40})\b")
RE_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")

# -------------------------------------------------------------
# Network Identifiers (IPv4 and Domains, including defanged)
# -------------------------------------------------------------
# Matches IPv4 addresses with standard dots or defanged separators ([.], (.), {.})
RE_IPV4 = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.|\[\.\]|\(\.\)|\{\.\})){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)
# Retain aliases for backward compatibility if referenced
RE_IPV4_STANDARD = RE_IPV4
RE_IPV4_DEFANGED = RE_IPV4

# Defanged domain syntax like evil[.]com, c2[.]malicious-site[.]ru, malware-dl(.)net
RE_DEFANGED_DOMAIN = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:(?:\.|\[\.\]|\(\.\)|\{\.\})[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(?:\[\.\]|\(\.\)|\{\.\})[a-zA-Z]{2,63})\b"
)

# Defanged URLs: hxxp:// or hxxps://
RE_DEFANGED_URL = re.compile(
    r"\b(hxxps?://[^\s\"'<>]+)\b", re.IGNORECASE
)

# Known benign domains to exclude from threat domain extraction
EXCLUDED_DOMAINS = {
    "github.com",
    "microsoft.com",
    "google.com",
    "cisa.gov",
    "nist.gov",
    "nvd.nist.gov",
    "mitre.org",
    "apache.org",
    "kernel.org",
    "python.org",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "wikipedia.org",
}


def normalize_defanged(text: str) -> str:
    """Normalize defanged IOCs back into standard notation."""
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[dot]", ".")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )


# Non-public networks: RFC 1918, Loopback, Link-Local, Multicast, Broadcast, Class E
_NON_PUBLIC_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)


def is_valid_public_ip(ip_str: str) -> bool:
    """Validate whether an IPv4 address is valid and non-private/non-loopback."""
    clean_ip = normalize_defanged(ip_str)
    try:
        ip = ipaddress.IPv4Address(clean_ip)
        if clean_ip == "255.255.255.255":
            return False
        return not any(ip in net for net in _NON_PUBLIC_NETWORKS)
    except ValueError:
        return False

"""
Credential Masking and Sanitization Utilities.
Strictly guarantees that raw secret values, passwords, and tokens are never leaked to logs or API responses.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
"""

import re
from typing import Optional
from urllib.parse import urlparse, urlunparse


def mask_secret(value: Optional[str], prefix_len: int = 4, suffix_len: int = 4) -> str:
    """
    Masks a sensitive string while preserving identifying prefixes/suffixes.
    Example: 'ghp_AbCdEf1234567890XyZ' -> 'ghp_************0XyZ'
    """
    if not value:
        return ""

    val = str(value).strip()
    length = len(val)

    if length <= 8:
        return "********"

    # If it's a known token type (like ghp_ or bearer), preserve prefix
    if val.startswith("ghp_"):
        prefix = "ghp_"
        suffix = val[-4:]
        stars = "*" * (length - len(prefix) - len(suffix))
        return f"{prefix}{stars}{suffix}"

    prefix = val[:prefix_len]
    suffix = val[-suffix_len:]
    stars = "*" * max(8, length - prefix_len - suffix_len)
    return f"{prefix}{stars}{suffix}"


def mask_connection_url(url: Optional[str]) -> str:
    """
    Masks user credentials inside a database, Redis, or HTTP connection URL.
    Example: 'postgresql://postgres:secret_pass@localhost:5432/db'
             -> 'postgresql://postgres:******@localhost:5432/db'
    """
    if not url:
        return ""

    raw_url = str(url).strip()
    try:
        parsed = urlparse(raw_url)
        if not parsed.scheme or not parsed.netloc:
            # Fallback regex masking for malformed/custom URLs
            return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:******@", raw_url)

        if parsed.password:
            user = parsed.username or ""
            host_port = parsed.hostname or ""
            if parsed.port:
                host_port = f"{host_port}:{parsed.port}"

            netloc = f"{user}:******@{host_port}" if user else f":******@{host_port}"
            sanitized_parts = parsed._replace(netloc=netloc)
            return urlunparse(sanitized_parts)

        return raw_url
    except Exception:
        # Extreme fallback
        return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:******@", raw_url)

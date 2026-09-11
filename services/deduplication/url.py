"""
URL Normalization & Canonical Resolution Module
Normalizes URLs for robust deduplication by stripping tracking parameters,
standardizing default ports and index paths, sorting query parameters, and lowercasing.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

import re
from typing import Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Comprehensive marketing, telemetry, and session tracking parameters to strip
STRIP_QUERY_PARAMS: Set[str] = {
    # Google Analytics & UTM
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_cid",
    # Ad and Social Referrals
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "wbraid",
    "gbraid",
    "msclkid",
    "twclid",
    "li_fat_id",
    "mc_cid",
    "mc_eid",
    "igshid",
    # Generic Tracking & Session IDs
    "ref",
    "referrer",
    "source",
    "trk",
    "sc_cid",
    "_hsenc",
    "_hsmi",
    "mkt_tok",
    "session_id",
    "sid",
    "spm",
}

# Default index documents to normalize to directory root
INDEX_FILES_REGEX = re.compile(r"/(?:index|default)\.(?:html?|php|asp[x]?|jsp)$", re.IGNORECASE)


def normalize_url(url: str) -> str:
    """
    Canonicalize a URL for deterministic deduplication:
    - Strips whitespace
    - Lowercases scheme and network location (hostname:port)
    - Removes default protocol ports (:80 for http, :443 for https)
    - Collapses redundant consecutive slashes (e.g. //path -> /path)
    - Strips default index files (/index.html, /index.php -> /)
    - Removes trailing slashes (except root '/')
    - Strips marketing/analytics tracking parameters
    - Sorts remaining query parameters deterministically
    - Strips URL anchor fragments
    """
    if not url:
        return ""

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return url.lower()

    # Standardize scheme and netloc
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()

    # Strip default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Clean path
    path = parsed.path or ""
    # Collapse multiple slashes into single slash
    path = re.sub(r"/{2,}", "/", path)
    # Strip default index filenames
    path = INDEX_FILES_REGEX.sub("/", path)
    # Lowercase path
    path = path.lower()
    # Remove trailing slash unless path is exactly root '/'
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Filter and sort query parameters
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        filtered = [
            (k, v) for (k, v) in pairs if k.lower() not in STRIP_QUERY_PARAMS
        ]
        filtered.sort(key=lambda x: (x[0].lower(), x[1]))
        clean_query = urlencode(filtered)
    else:
        clean_query = ""

    # Fragment is intentionally omitted for canonical equality
    return urlunparse((scheme, netloc, path, parsed.params, clean_query, ""))


def get_url_domain(url: str) -> str:
    """Extract lowercase network host from URL."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        return (parsed.netloc or "").lower().split(":")[0]
    except Exception:
        return ""

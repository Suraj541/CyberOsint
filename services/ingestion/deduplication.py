"""
Deduplication Engine & SHA-256 Hashing Module
Computes deterministic SHA-256 cryptographic fingerprints for normalized intelligence items
and detects duplicates against existing database records and in-flight batches.
Conforms strictly to IMPLEMENT.md Section 6 and Section 9 specifications.
"""

import hashlib
import logging
import re
from typing import Optional, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from sqlalchemy.orm import Session

from app.models.content import Content

logger = logging.getLogger("cyber_osint.services.ingestion.deduplication")

# Tracking parameters to strip during URL normalization
STRIP_QUERY_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
}


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent hashing:
    - Lowercases scheme and network location (hostname and port)
    - Strips common analytics tracking parameters (e.g. UTM tags)
    - Removes trailing slashes from path
    - Sorts remaining query parameters deterministically
    - Strips fragment identifiers
    """
    if not url:
        return ""

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return url.lower()

    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()

    # Clean path: lowercase and remove redundant trailing slash unless it's root
    path = (parsed.path or "").lower()
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Filter tracking query parameters and sort deterministically
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_pairs = [
            (k, v) for (k, v) in query_pairs if k.lower() not in STRIP_QUERY_PARAMS
        ]
        filtered_pairs.sort(key=lambda x: (x[0], x[1]))
        query = urlencode(filtered_pairs)
    else:
        query = ""

    # Fragment is stripped for canonical comparison
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def normalize_title(title: str) -> str:
    """Normalize article title by collapsing whitespace and lowercasing."""
    if not title:
        return ""
    clean = re.sub(r"\s+", " ", title).strip()
    return clean.lower()


def compute_content_hash(
    url: str,
    title: str,
    raw_content: Optional[str] = None,
) -> str:
    """
    Compute deterministic SHA-256 fingerprint for deduplication.
    Uses canonical URL + title as primary entropy.
    Falls back to title + content snippet if URL is absent or generic URN.
    """
    clean_url = normalize_url(url)
    clean_title = normalize_title(title)

    if clean_url and not clean_url.startswith("urn:"):
        payload = f"{clean_url}|{clean_title}"
    else:
        # Fallback when URL is not a unique web locator
        snippet = (raw_content or "")[:512].strip().lower()
        payload = f"{clean_title}|{snippet}"

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Deduplicator:
    """
    Evaluates incoming items for duplicate status against in-memory batch sets
    and persistent database Content records using the SHA-256 content_hash.
    """

    @staticmethod
    def is_duplicate(
        db: Session,
        content_hash: str,
        in_memory_seen: Optional[Set[str]] = None,
    ) -> bool:
        """
        Check if an item with the given content_hash has already been ingested.
        First checks in-memory cache, then queries the indexed content.content_hash column.
        """
        if not content_hash:
            return False

        # 1. Fast in-memory check for current batch
        if in_memory_seen is not None and content_hash in in_memory_seen:
            logger.debug("Duplicate detected in batch in-memory cache: %s", content_hash)
            return True

        # 2. Database query against indexed content_hash
        existing = (
            db.query(Content.id)
            .filter(Content.content_hash == content_hash)
            .first()
        )
        if existing is not None:
            logger.debug("Duplicate detected in database: %s (id=%s)", content_hash, existing[0])
            return True

        return False

    @staticmethod
    def register_seen(content_hash: str, in_memory_seen: Set[str]) -> None:
        """Register content_hash into batch in-memory seen set."""
        if content_hash:
            in_memory_seen.add(content_hash)

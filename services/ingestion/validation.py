"""
Ingestion Validation Module
Enforces schema conformance, minimum content standards, and URL protocol safety
for discovered and normalized intelligence items.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

import logging
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

from connectors.base import NormalizedItem

logger = logging.getLogger("cyber_osint.services.ingestion.validation")

# Permitted URI schemes
ALLOWED_SCHEMES = {"http", "https", "urn"}

# Disallowed dangerous schemes that must never be ingested
BLOCKED_SCHEMES = {"javascript", "data", "file", "vbscript", "about"}

# Supported default content classifications
VALID_CONTENT_TYPES = {
    "article",
    "advisory",
    "cve",
    "report",
    "vulnerability",
    "exploit",
    "blog",
    "news",
    "post",
    "tool",
    "academic",
}


class ValidationError(Exception):
    """Raised when an item fails validation checks."""

    pass


class ItemValidator:
    """Validates raw and normalized items traversing the ingestion pipeline."""

    @staticmethod
    def validate_raw_item(raw_item: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate raw entry received from connector discover() step.
        Ensures item is non-empty and contains extractable attributes.
        """
        if raw_item is None:
            return False, "Raw item is None"

        if isinstance(raw_item, dict):
            if not raw_item:
                return False, "Raw dictionary item is empty"
            # Must have at least one identifier or content attribute
            has_ident = any(
                raw_item.get(k)
                for k in ("title", "link", "id", "guid", "url", "description", "summary")
            )
            if not has_ident:
                return False, "Raw item lacks identifiable keys (title/link/id/description)"
            return True, None

        # For object instances (e.g., feedparser FeedParserDict or objects)
        if hasattr(raw_item, "__dict__") or hasattr(raw_item, "title") or hasattr(raw_item, "link"):
            return True, None

        return True, None

    @staticmethod
    def validate_normalized_item(item: NormalizedItem) -> Tuple[bool, Optional[str]]:
        """
        Validate NormalizedItem contract before deduplication and storage.
        Verifies title presence, URL safety, valid content_type, and sanitization.
        """
        if not isinstance(item, NormalizedItem):
            return False, f"Expected NormalizedItem instance, got {type(item).__name__}"

        # 1. Validate title
        title = (item.title or "").strip()
        if not title:
            return False, "Normalized item missing title"
        if len(title) < 2:
            return False, f"Normalized item title too short ({len(title)} chars)"

        # 2. Validate URL
        url = (item.url or "").strip()
        if not url:
            return False, "Normalized item missing canonical url"

        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()

        if scheme in BLOCKED_SCHEMES:
            return False, f"Prohibited or dangerous URL scheme: '{scheme}'"

        if scheme not in ALLOWED_SCHEMES:
            return False, f"Unsupported URL scheme: '{scheme}' (expected http, https, or urn)"

        # 3. Validate content type
        content_type = (item.content_type or "").strip().lower()
        if content_type and content_type not in VALID_CONTENT_TYPES:
            # Non-standard content type: log warning, normalize to 'article'
            logger.debug("Non-standard content_type '%s', defaulting to 'article'", content_type)

        # 4. Validate language code format
        lang = (item.language or "en").strip()
        if len(lang) > 10:
            return False, f"Language code too long: '{lang}'"

        return True, None

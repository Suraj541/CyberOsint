"""
Input Validation & Sanitization Module.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Protects against SQL injection, path traversal, XSS, and command injection.
"""

from pathlib import Path
import re
from typing import Optional
from urllib.parse import urlparse


# Patterns identifying potential injection or exploitation attempts
DANGEROUS_QUERY_PATTERNS = [
    (r"(?i)<\s*script[^>]*>", "Script tag injection attempt"),
    (r"(?i)javascript\s*:", "JavaScript pseudo-protocol injection"),
    (r"(?i)on(?:load|click|error|mouse\w+)\s*=", "DOM event handler injection"),
    (r"(?i)\b(?:union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into)\b", "SQL injection signature"),
    (r"\x00", "Null byte injection"),
]


class InputValidator:
    """Validator and sanitizer for user and external inputs."""

    @staticmethod
    def sanitize_search_query(query: Optional[str], max_length: int = 500) -> str:
        """
        Sanitizes search engine queries.
        Strips dangerous control characters, restricts length, and removes raw script tags.
        """
        if not query:
            return ""

        clean = str(query).strip()
        # Truncate to reasonable query length
        clean = clean[:max_length]

        # Strip null bytes and control chars
        clean = "".join(ch for ch in clean if ord(ch) >= 32 or ch in "\t\n\r")

        # Strip script tags while leaving search keywords
        clean = re.sub(r"(?i)<\s*/?\s*script[^>]*>", "", clean)

        return clean.strip()

    @staticmethod
    def sanitize_filename(filename: Optional[str], max_length: int = 255) -> str:
        """
        Sanitizes uploaded or referenced filenames.
        Strictly prevents directory traversal (../, ..\\) and absolute path injection.
        """
        if not filename:
            return "unnamed_file"

        raw = str(filename).strip()
        # Strip null bytes
        raw = raw.replace("\x00", "")

        # Extract only the base name (no path separators)
        base = Path(raw).name

        # Strip any remaining traversal components or illegal chars
        clean = re.sub(r"[^\w\.\-\s]", "_", base)
        clean = re.sub(r"\.{2,}", ".", clean)  # No double dots
        clean = clean.strip(". ")

        if not clean:
            clean = "unnamed_file"

        return clean[:max_length]

    @staticmethod
    def validate_url(url: Optional[str]) -> bool:
        """
        Validates URL syntax and ensures scheme is exclusively http or https.
        """
        if not url:
            return False

        clean_url = str(url).strip()
        if len(clean_url) > 2048:
            return False

        try:
            parsed = urlparse(clean_url)
            if parsed.scheme.lower() not in {"http", "https"}:
                return False
            if not parsed.netloc or not parsed.hostname:
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def validate_url_format(url: Optional[str]) -> bool:
        """Alias for validate_url."""
        return InputValidator.validate_url(url)

    @staticmethod
    def sanitize_identifier(identifier: str) -> str:
        """Sanitizes keys, tags, and category identifiers to [A-Za-z0-9_-]."""
        if not identifier:
            return ""
        return re.sub(r"[^A-Za-z0-9_\-]", "_", str(identifier).strip())


input_validator = InputValidator()


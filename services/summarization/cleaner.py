"""
Text Cleaner for AI Summarization Pipeline
Prepares raw source content into clean, normalized text.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28):
Source Content -> Clean Text -> AI Model -> Summary -> Validation -> Stored Summary.
"""

import html
import re
from typing import Optional


def clean_text_for_summarization(
    title: str,
    description: Optional[str] = None,
    raw_content: Optional[str] = None,
    source_name: Optional[str] = None,
    max_length: int = 12000,
) -> str:
    """
    Clean, deduplicate, and normalize raw content for input into the AI model.
    Strips HTML tags, boilerplate script/style blocks, tracking codes, and redundant whitespace.
    Preserves section headings, CVEs, technical hashes, and code blocks.
    """
    parts = []

    if source_name:
        parts.append(f"SOURCE: {source_name.strip()}")

    if title:
        clean_title = re.sub(r"\s+", " ", title).strip()
        parts.append(f"TITLE: {clean_title}\n")

    combined_body = ""
    if raw_content:
        combined_body += raw_content + "\n\n"
    if description and description not in (raw_content or ""):
        combined_body += description + "\n"

    if not combined_body.strip():
        return "\n".join(parts).strip()

    text = combined_body

    # 1. Unescape HTML entities (&amp;, &lt;, &gt;, &quot;, &#39;)
    text = html.unescape(text)

    # 2. Strip script, style, iframe, nav, header, and footer tags
    text = re.sub(r"<script[^>]*>[\s\S]*?</script>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<style[^>]*>[\s\S]*?</style>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<iframe[^>]*>[\s\S]*?</iframe>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<nav[^>]*>[\s\S]*?</nav>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<header[^>]*>[\s\S]*?</header>", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"<footer[^>]*>[\s\S]*?</footer>", " ", text, flags=re.IGNORECASE)

    # 3. Replace common HTML layout breaks with newlines
    text = re.sub(r"<(?:p|div|h[1-6]|li|br|tr)[^>]*>", "\n", text, flags=re.IGNORECASE)

    # 4. Strip remaining HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # 5. Remove cookie banners, social share boilerplate patterns
    text = re.sub(r"(?i)\b(subscribe to our newsletter|share this article on (?:twitter|linkedin|facebook)|all rights reserved|cookie policy|manage consent)\b.*", "", text)

    # 6. Normalize multiple whitespaces and excessive newlines
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    text = text.strip()

    parts.append(text)
    full_cleaned = "\n".join(parts).strip()

    # Intelligent truncation to max_length while preserving sentence/paragraph bounds
    if len(full_cleaned) > max_length:
        truncated = full_cleaned[:max_length]
        last_punct = max(truncated.rfind(". "), truncated.rfind("\n"))
        if last_punct > max_length // 2:
            full_cleaned = truncated[: last_punct + 1] + "\n[... Content truncated for analysis ...]"
        else:
            full_cleaned = truncated + "\n[... Content truncated for analysis ...]"

    return full_cleaned

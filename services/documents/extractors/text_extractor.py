"""
Plain Text Document Extractor
Extracts title, section headings (all-caps or numbered headers),
abstracts, and clean structured body text from plain text advisories and reports.
"""

import re
from typing import List, Optional, Tuple
from services.documents.models import DocumentMetadata, DocumentType


class TextExtractor:
    """Extracts metadata and structured sections from plain text content."""

    def extract(self, raw_text: str, source_url: Optional[str] = None) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        if not raw_text:
            return DocumentMetadata(title="Untitled Text Document", document_type=DocumentType.TXT), "", []

        clean_text = raw_text.strip()
        lines = [line.strip() for line in clean_text.splitlines()]

        # 1. Determine Title
        title = "Untitled Text Document"
        for line in lines:
            if line and len(line) > 3 and not line.startswith("---"):
                title = line
                break

        # Check for copyright notice
        copyright_notice = None
        copy_m = re.search(r"(?:copyright|©|\(c\))\s*(\d{4}[^\n\r]+)", clean_text, re.IGNORECASE)
        if copy_m:
            copyright_notice = copy_m.group(0).strip()

        # Check for author / date headers
        authors: List[str] = []
        author_m = re.search(r"^(?:author|by|researcher):\s*(.+)$", clean_text, re.MULTILINE | re.IGNORECASE)
        if author_m:
            authors = [a.strip() for a in re.split(r"[,;]", author_m.group(1)) if a.strip()]

        pub_date = None
        date_m = re.search(r"^(?:date|published):\s*(.+)$", clean_text, re.MULTILINE | re.IGNORECASE)
        if date_m:
            pub_date = date_m.group(1).strip()

        # 2. Extract sections based on uppercase headers, Roman numerals, or numbered headers:
        # e.g., "1. EXECUTIVE SUMMARY", "SECTION II: METHODOLOGY", "INDICATORS OF COMPROMISE"
        sections: List[Tuple[str, str]] = []
        headings: List[str] = []

        header_pattern = re.compile(
            r"^(?:(?:[0-9]{1,2}|[IVXLCDM]{1,6})\.|\bSECTION\s+[0-9IVXLCDM]+:|[A-Z0-9\s\-_:]{4,40}$)"
        )

        current_heading = "Overview"
        current_lines: List[str] = []

        for line in lines:
            if not line:
                current_lines.append("")
                continue

            # Check if line looks like a header (and not the title itself)
            is_header = False
            if line != title and len(line) < 60:
                if line.isupper() and len(line) >= 4 and not line.endswith("."):
                    is_header = True
                elif re.match(r"^(?:[0-9]{1,2}\.|\b[IVXLCDM]+\.)\s+[A-Z]", line):
                    is_header = True

            if is_header:
                body_str = "\n".join(current_lines).strip()
                if body_str:
                    sections.append((current_heading, body_str))
                current_heading = line.strip(" :.-_")
                if current_heading not in headings:
                    headings.append(current_heading)
                current_lines = []
            else:
                current_lines.append(line)

        if current_lines:
            body_str = "\n".join(current_lines).strip()
            if body_str:
                sections.append((current_heading, body_str))

        if not sections:
            sections = [("Content", clean_text)]

        abstract = None
        for h, t in sections:
            if h.lower() in ("overview", "abstract", "executive summary", "summary"):
                abstract = t[:500]
                break

        full_text = "\n\n".join([f"## {h}\n{t}" if h != "Content" else t for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=pub_date,
            abstract=abstract,
            document_type=DocumentType.TXT,
            word_count=word_count,
            file_size_bytes=len(raw_text.encode("utf-8")),
            section_headings=headings,
            copyright_notice=copyright_notice,
            source_url=source_url,
        )

        return metadata, full_text, sections

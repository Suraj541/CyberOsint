"""
Markdown Document Extractor
Extracts YAML/frontmatter metadata, section headings (#, ##, ###),
abstracts, and clean structured body text from Markdown documents and threat reports.
"""

import re
from typing import List, Optional, Tuple
from services.documents.models import DocumentMetadata, DocumentType


class MarkdownExtractor:
    """Extracts metadata and structured sections from Markdown content."""

    def extract(self, raw_md: str, source_url: Optional[str] = None) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        if not raw_md:
            return DocumentMetadata(title="Untitled Markdown Document", document_type=DocumentType.MARKDOWN), "", []

        text = raw_md.strip()

        # 1. Parse Frontmatter (YAML-style --- ... ---)
        title = ""
        authors: List[str] = []
        publication_date = None
        abstract = None
        copyright_notice = None

        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        content_body = text
        if fm_match:
            fm_text = fm_match.group(1)
            content_body = text[fm_match.end():].strip()

            t_m = re.search(r"^title:\s*['\"]?(.*?)['\"]?$", fm_text, re.MULTILINE | re.IGNORECASE)
            if t_m:
                title = t_m.group(1).strip()

            a_m = re.search(r"^author(?:s)?:\s*['\"]?(.*?)['\"]?$", fm_text, re.MULTILINE | re.IGNORECASE)
            if a_m:
                raw_authors = a_m.group(1).strip()
                authors = [a.strip(" '\"[]") for a in re.split(r"[,;]", raw_authors) if a.strip(" '\"[]")]

            d_m = re.search(r"^date:\s*['\"]?(.*?)['\"]?$", fm_text, re.MULTILINE | re.IGNORECASE)
            if d_m:
                publication_date = d_m.group(1).strip()

            abs_m = re.search(r"^abstract|description:\s*['\"]?(.*?)['\"]?$", fm_text, re.MULTILINE | re.IGNORECASE)
            if abs_m:
                abstract = abs_m.group(1).strip()

        # 2. If title not in frontmatter, find first # Heading
        if not title:
            h1_m = re.search(r"^#\s+(.+)$", content_body, re.MULTILINE)
            if h1_m:
                title = h1_m.group(1).strip()
                # Remove title line from body
                content_body = re.sub(r"^#\s+.+$\n?", "", content_body, count=1, flags=re.MULTILINE).strip()
            else:
                title = "Untitled Markdown Document"

        # Check for inline Author / Date headers if not in frontmatter
        if not authors:
            author_m = re.search(r"^(?:author|by|researcher(?:s)?):\s*(.+)$", content_body, re.MULTILINE | re.IGNORECASE)
            if author_m:
                raw_authors = author_m.group(1).strip()
                authors = [a.strip(" '\"[]") for a in re.split(r"[,;&]", raw_authors) if a.strip(" '\"[]")]

        if not publication_date:
            date_m = re.search(r"^(?:date|published):\s*(.+)$", content_body, re.MULTILINE | re.IGNORECASE)
            if date_m:
                publication_date = date_m.group(1).strip()

        # Check copyright
        copy_m = re.search(r"(?:copyright|©|\(c\))\s*(\d{4}[^\n\r]+)", content_body, re.IGNORECASE)
        if copy_m:
            copyright_notice = copy_m.group(0).strip()

        # 3. Extract sections by headings (#, ##, ###, ####)
        lines = content_body.split("\n")
        sections: List[Tuple[str, str]] = []
        headings: List[str] = []

        current_heading = "Overview"
        current_lines: List[str] = []

        for line in lines:
            h_match = re.match(r"^(#{1,4})\s+(.+)$", line)
            if h_match:
                section_body = "\n".join(current_lines).strip()
                if section_body:
                    sections.append((current_heading, section_body))
                    if not abstract and current_heading.lower() in ("overview", "abstract", "summary"):
                        abstract = section_body[:500]
                current_heading = h_match.group(2).strip()
                if current_heading not in headings:
                    headings.append(current_heading)
                current_lines = []
            else:
                current_lines.append(line)

        if current_lines:
            section_body = "\n".join(current_lines).strip()
            if section_body:
                sections.append((current_heading, section_body))
                if not abstract and current_heading.lower() in ("overview", "abstract", "summary"):
                    abstract = section_body[:500]

        if not sections:
            sections = [("Content", content_body)]

        # Assemble full text
        full_text = "\n\n".join([f"## {h}\n{t}" if h != "Content" else t for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=publication_date,
            abstract=abstract,
            document_type=DocumentType.MARKDOWN,
            word_count=word_count,
            file_size_bytes=len(raw_md.encode("utf-8")),
            section_headings=headings,
            copyright_notice=copyright_notice,
            source_url=source_url,
        )

        return metadata, full_text, sections

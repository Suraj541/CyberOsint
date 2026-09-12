"""
HTML Document Extractor
Extracts title, authors, publication date, abstract, section headings,
and clean structured body text from HTML documents, threat advisories, and web bulletins.
"""

import html
import re
from typing import List, Optional, Tuple
from services.documents.models import DocumentMetadata, DocumentType


class HtmlExtractor:
    """Extracts metadata and structured sections from HTML content."""

    def extract(self, raw_html: str, source_url: Optional[str] = None) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        """
        Parses raw HTML and returns:
        - DocumentMetadata
        - clean full text
        - List of (heading, section_text) tuples
        """
        if not raw_html:
            return DocumentMetadata(title="Untitled HTML Document", document_type=DocumentType.HTML), "", []

        # 1. Extract title
        title = ""
        title_m = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
        if title_m:
            title = self._clean_text(title_m.group(1))
        if not title:
            h1_m = re.search(r"<h1[^>]*>(.*?)</h1>", raw_html, re.IGNORECASE | re.DOTALL)
            if h1_m:
                title = self._clean_text(h1_m.group(1))
        if not title:
            title = "Untitled Document"

        # 2. Extract author(s)
        authors: List[str] = []
        author_matches = re.findall(
            r"""<meta\s+name=["'](?:author|dc\.creator|article:author)["']\s+content=["'](.*?)["']""",
            raw_html,
            re.IGNORECASE,
        )
        for a in author_matches:
            c = self._clean_text(a)
            if c and c not in authors:
                authors.append(c)

        # 3. Extract publication date
        date_str = None
        date_m = re.search(
            r"""<meta\s+(?:name|property)=["'](?:article:published_time|dc\.date|date|publishdate)["']\s+content=["'](.*?)["']""",
            raw_html,
            re.IGNORECASE,
        )
        if date_m:
            date_str = date_m.group(1).strip()

        # 4. Extract abstract/description
        abstract = None
        desc_m = re.search(
            r"""<meta\s+name=["'](?:description|og:description)["']\s+content=["'](.*?)["']""",
            raw_html,
            re.IGNORECASE,
        )
        if desc_m:
            abstract = self._clean_text(desc_m.group(1))

        # 5. Extract copyright notice if present
        copyright_notice = None
        copy_m = re.search(r"(?:copyright|©|\(c\))\s*(\d{4}[^<>\n\r]+)", raw_html, re.IGNORECASE)
        if copy_m:
            copyright_notice = self._clean_text(copy_m.group(0))

        # Strip scripts, styles, navigation, footer, head
        cleaned_html = re.sub(r"<(script|style|nav|footer|header|noscript)[^>]*>.*?</\1>", " ", raw_html, flags=re.IGNORECASE | re.DOTALL)
        cleaned_html = re.sub(r"<head[^>]*>.*?</head>", " ", cleaned_html, flags=re.IGNORECASE | re.DOTALL)

        # 6. Extract sections partitioned by <h1..h4>
        sections: List[Tuple[str, str]] = []
        headings: List[str] = []

        tokens = re.split(r"(<h[1-4][^>]*>.*?</h[1-4]>)", cleaned_html, flags=re.IGNORECASE | re.DOTALL)
        current_heading = "Introduction"
        current_body: List[str] = []

        for token in tokens:
            token = token.strip()
            if not token:
                continue
            h_match = re.match(r"<h[1-4][^>]*>(.*?)</h[1-4]>", token, re.IGNORECASE | re.DOTALL)
            if h_match:
                # Save previous section if it has text
                body_str = " ".join(current_body).strip()
                if body_str:
                    sections.append((current_heading, body_str))
                current_heading = self._clean_text(h_match.group(1))
                if current_heading and current_heading not in headings:
                    headings.append(current_heading)
                current_body = []
            else:
                body_clean = self._clean_text(token)
                if body_clean:
                    current_body.append(body_clean)

        if current_body:
            body_str = " ".join(current_body).strip()
            if body_str:
                sections.append((current_heading, body_str))

        if not sections:
            all_text = self._clean_text(cleaned_html)
            sections = [("Content", all_text)]

        # Assemble full text
        full_text = "\n\n".join([f"## {h}\n{t}" if h != "Content" else t for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=date_str,
            abstract=abstract,
            document_type=DocumentType.HTML,
            word_count=word_count,
            file_size_bytes=len(raw_html.encode("utf-8")),
            section_headings=headings,
            copyright_notice=copyright_notice,
            source_url=source_url,
        )

        return metadata, full_text, sections

    def _clean_text(self, text: str) -> str:
        if not text:
            return ""
        # Unescape HTML entities
        txt = html.unescape(text)
        # Strip tags
        txt = re.sub(r"<[^>]+>", " ", txt)
        # Collapse whitespace
        txt = re.sub(r"\s+", " ", txt).strip()
        return txt

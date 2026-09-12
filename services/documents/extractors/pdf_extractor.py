"""
PDF Document Extractor
Extracts metadata (title, author, creation date, subject/abstract), page count,
and section headings with structured text from PDF research papers, whitepapers, and bulletins.
Supports pypdf when available, with a robust native stream parsing fallback.
"""

import io
import re
from typing import List, Optional, Tuple
import zlib

from services.documents.models import DocumentMetadata, DocumentType

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


class PdfExtractor:
    """Extracts metadata and structured sections from PDF documents."""

    def extract(
        self,
        pdf_bytes: bytes,
        filename: str = "document.pdf",
        source_url: Optional[str] = None,
    ) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        if not pdf_bytes:
            return DocumentMetadata(title="Untitled PDF", document_type=DocumentType.PDF), "", []

        title = ""
        authors: List[str] = []
        pub_date = None
        abstract = None
        page_count = 0
        pages_text: List[str] = []

        # 1. Attempt extraction via pypdf
        if PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
                page_count = len(reader.pages)
                info = reader.metadata or {}

                if info.title:
                    title = str(info.title).strip()
                if info.author:
                    authors = [str(info.author).strip()]
                if info.creation_date:
                    pub_date = str(info.creation_date)
                if info.subject:
                    abstract = str(info.subject).strip()

                for page in reader.pages:
                    txt = page.extract_text() or ""
                    if txt.strip():
                        pages_text.append(txt.strip())
            except Exception:
                # Fallback to native stream parsing below
                pass

        # 2. Native stream parsing fallback if pypdf was missing or produced no text
        if not pages_text:
            native_info, native_pages = self._native_extract(pdf_bytes)
            if not title and native_info.get("title"):
                title = native_info["title"]
            if not authors and native_info.get("author"):
                authors = [native_info["author"]]
            if not pub_date and native_info.get("date"):
                pub_date = native_info["date"]
            if not page_count:
                page_count = len(native_pages) or native_info.get("page_count", 1)
            pages_text = native_pages

        combined_text = "\n\n".join(pages_text).strip()

        # 3. If title is still empty, deduce from first lines of page 1
        if not title and pages_text:
            first_lines = [l.strip() for l in pages_text[0].splitlines() if l.strip()]
            if first_lines:
                title = first_lines[0][:120]

        if not title:
            title = filename.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").title()

        # 4. Extract sections by identifying headers (e.g. "1. INTRODUCTION", "ABSTRACT", "II. THREAT MODEL")
        sections: List[Tuple[str, str]] = []
        headings: List[str] = []

        lines = combined_text.splitlines()
        current_heading = "Overview"
        current_body: List[str] = []

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Header detection heuristic
            is_header = False
            if len(line_str) < 60:
                if re.match(r"^(?:[0-9]{1,2}\.|\b[IVXLCDM]+\.)\s+[A-Z]", line_str):
                    is_header = True
                elif line_str.isupper() and len(line_str) >= 4 and not line_str.endswith("."):
                    is_header = True
                elif line_str.lower() in ("abstract", "executive summary", "introduction", "background", "methodology", "indicators of compromise", "mitigations", "conclusion", "references"):
                    is_header = True

            if is_header and line_str != title:
                body_str = "\n".join(current_body).strip()
                if body_str:
                    sections.append((current_heading, body_str))
                current_heading = line_str
                if current_heading not in headings:
                    headings.append(current_heading)
                current_body = []
            else:
                current_body.append(line_str)

        if current_body:
            body_str = "\n".join(current_body).strip()
            if body_str:
                sections.append((current_heading, body_str))

        if not sections:
            sections = [("Content", combined_text)]

        # Extract abstract if found in sections
        if not abstract:
            for h, b in sections:
                if h.lower() in ("abstract", "executive summary", "overview"):
                    abstract = b[:600]
                    break

        full_text = "\n\n".join([f"## {h}\n{t}" if h != "Content" else t for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        # Check copyright
        copyright_notice = None
        copy_m = re.search(r"(?:copyright|©|\(c\))\s*(\d{4}[^\n\r]+)", full_text, re.IGNORECASE)
        if copy_m:
            copyright_notice = copy_m.group(0).strip()

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=pub_date,
            abstract=abstract,
            document_type=DocumentType.PDF,
            page_count=page_count,
            word_count=word_count,
            file_size_bytes=len(pdf_bytes),
            section_headings=headings,
            copyright_notice=copyright_notice,
            source_url=source_url,
        )

        return metadata, full_text, sections

    def _native_extract(self, pdf_bytes: bytes) -> Tuple[dict, List[str]]:
        """Lightweight native parser for PDF streams without external dependencies."""
        info = {}
        pages_text: List[str] = []

        # Find metadata keys
        title_m = re.search(rb"/Title\s*\(([^)]+)\)", pdf_bytes)
        if title_m:
            info["title"] = title_m.group(1).decode("latin-1", errors="ignore")

        author_m = re.search(rb"/Author\s*\(([^)]+)\)", pdf_bytes)
        if author_m:
            info["author"] = author_m.group(1).decode("latin-1", errors="ignore")

        count_m = re.search(rb"/Count\s+(\d+)", pdf_bytes)
        if count_m:
            try:
                info["page_count"] = int(count_m.group(1))
            except Exception:
                pass

        # Decompress FlateDecode streams
        stream_matches = re.finditer(rb"stream[\r\n]+(.*?)[\r\n]+endstream", pdf_bytes, re.DOTALL)
        for m in stream_matches:
            stream_data = m.group(1)
            raw = stream_data
            try:
                raw = zlib.decompress(stream_data)
            except Exception:
                pass

            # Extract BT...ET text blocks
            bt_matches = re.findall(rb"BT(.*?)ET", raw, re.DOTALL)
            stream_page_lines = []
            for bt in bt_matches:
                # Text showing Tj / TJ / ' / "
                # e.g., (Some text) Tj or [(Some) 20 (Text)] TJ
                t_strings = re.findall(rb"\(([^)]*)\)", bt)
                for ts in t_strings:
                    decoded = ts.decode("latin-1", errors="ignore").strip()
                    if decoded:
                        stream_page_lines.append(decoded)

            if stream_page_lines:
                pages_text.append("\n".join(stream_page_lines))

        return info, pages_text

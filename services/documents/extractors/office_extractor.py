"""
Office Document Extractor (DOCX and PPTX)
Extracts metadata (title, author, created date, abstract), section headings,
and structured text from Microsoft Word (.docx) and PowerPoint (.pptx) documents
using standard library zipfile and xml.etree.ElementTree (zero external dependencies).
"""

import io
import re
from typing import List, Optional, Tuple
import zipfile
import xml.etree.ElementTree as ET

from services.documents.models import DocumentMetadata, DocumentType


class OfficeExtractor:
    """Extracts metadata and structured sections from DOCX and PPTX files."""

    NS = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
    }

    def extract_docx(self, docx_bytes: bytes, filename: str = "document.docx", source_url: Optional[str] = None) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        """Extracts metadata and sections from a .docx file buffer."""
        title = ""
        authors: List[str] = []
        pub_date = None
        abstract = None

        sections: List[Tuple[str, str]] = []
        headings: List[str] = []

        try:
            with zipfile.ZipFile(io.BytesIO(docx_bytes)) as z:
                # 1. Parse core properties if present
                if "docProps/core.xml" in z.namelist():
                    try:
                        core_xml = z.read("docProps/core.xml")
                        tree = ET.fromstring(core_xml)
                        t_el = tree.find(".//dc:title", self.NS)
                        if t_el is not None and t_el.text:
                            title = t_el.text.strip()
                        c_el = tree.find(".//dc:creator", self.NS)
                        if c_el is not None and c_el.text:
                            authors.append(c_el.text.strip())
                        d_el = tree.find(".//dcterms:created", self.NS)
                        if d_el is not None and d_el.text:
                            pub_date = d_el.text.strip()
                        desc_el = tree.find(".//dc:description", self.NS)
                        if desc_el is not None and desc_el.text:
                            abstract = desc_el.text.strip()
                    except Exception:
                        pass

                # 2. Parse word/document.xml
                if "word/document.xml" in z.namelist():
                    doc_xml = z.read("word/document.xml")
                    tree = ET.fromstring(doc_xml)

                    current_heading = "Overview"
                    current_body: List[str] = []

                    # Iterate over paragraphs
                    for p in tree.findall(".//w:p", self.NS):
                        texts = [node.text for node in p.findall(".//w:t", self.NS) if node.text]
                        para_text = "".join(texts).strip()
                        if not para_text:
                            continue

                        # Check if paragraph has heading style
                        is_heading = False
                        pStyle = p.find(".//w:pStyle", self.NS)
                        if pStyle is not None:
                            val = pStyle.attrib.get(f"{{{self.NS['w']}}}val", "")
                            if "heading" in val.lower() or "title" in val.lower():
                                is_heading = True

                        if is_heading:
                            body_str = "\n".join(current_body).strip()
                            if body_str:
                                sections.append((current_heading, body_str))
                            current_heading = para_text
                            if current_heading not in headings:
                                headings.append(current_heading)
                            if not title:
                                title = current_heading
                            current_body = []
                        else:
                            current_body.append(para_text)

                    if current_body:
                        body_str = "\n".join(current_body).strip()
                        if body_str:
                            sections.append((current_heading, body_str))
        except Exception as exc:
            # Fallback for plain or corrupted archive
            raw_fallback = docx_bytes.decode("utf-8", errors="ignore")
            sections = [("Content", raw_fallback)]

        if not title:
            title = filename.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").title()

        if not sections:
            sections = [("Content", "")]

        full_text = "\n\n".join([f"## {h}\n{t}" if h != "Content" else t for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=pub_date,
            abstract=abstract,
            document_type=DocumentType.DOCX,
            word_count=word_count,
            file_size_bytes=len(docx_bytes),
            section_headings=headings,
            source_url=source_url,
        )

        return metadata, full_text, sections

    def extract_pptx(self, pptx_bytes: bytes, filename: str = "presentation.pptx", source_url: Optional[str] = None) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        """Extracts metadata and slides as structured sections from a .pptx file buffer."""
        title = ""
        authors: List[str] = []
        pub_date = None
        abstract = None

        sections: List[Tuple[str, str]] = []
        headings: List[str] = []
        page_count = 0

        try:
            with zipfile.ZipFile(io.BytesIO(pptx_bytes)) as z:
                # 1. Parse core properties
                if "docProps/core.xml" in z.namelist():
                    try:
                        core_xml = z.read("docProps/core.xml")
                        tree = ET.fromstring(core_xml)
                        t_el = tree.find(".//dc:title", self.NS)
                        if t_el is not None and t_el.text:
                            title = t_el.text.strip()
                        c_el = tree.find(".//dc:creator", self.NS)
                        if c_el is not None and c_el.text:
                            authors.append(c_el.text.strip())
                        d_el = tree.find(".//dcterms:created", self.NS)
                        if d_el is not None and d_el.text:
                            pub_date = d_el.text.strip()
                        desc_el = tree.find(".//dc:description", self.NS)
                        if desc_el is not None and desc_el.text:
                            abstract = desc_el.text.strip()
                    except Exception:
                        pass

                # 2. Identify and sort slides: ppt/slides/slide1.xml, slide2.xml, etc.
                slide_names = [n for n in z.namelist() if re.match(r"^ppt/slides/slide[0-9]+\.xml$", n)]
                # Sort numerically by slide number
                slide_names.sort(key=lambda x: int(re.search(r"slide([0-9]+)\.xml", x).group(1)))
                page_count = len(slide_names)

                for idx, s_name in enumerate(slide_names, start=1):
                    s_xml = z.read(s_name)
                    tree = ET.fromstring(s_xml)

                    slide_texts: List[str] = []
                    for sp in tree.findall(".//p:sp", self.NS):
                        sp_texts = [t.text for t in sp.findall(".//a:t", self.NS) if t.text]
                        combined = " ".join(sp_texts).strip()
                        if combined:
                            slide_texts.append(combined)

                    slide_title = f"Slide {idx}"
                    slide_body = ""
                    if slide_texts:
                        slide_title = slide_texts[0]
                        if idx == 1 and not title:
                            title = slide_title
                        slide_body = "\n".join(slide_texts[1:]) if len(slide_texts) > 1 else slide_texts[0]

                    sections.append((slide_title, slide_body))
                    headings.append(slide_title)
        except Exception:
            raw_fallback = pptx_bytes.decode("utf-8", errors="ignore")
            sections = [("Presentation", raw_fallback)]

        if not title:
            title = filename.rsplit(".", 1)[0].replace("_", " ").replace("-", " ").title()

        full_text = "\n\n".join([f"## {h}\n{t}" for h, t in sections]).strip()
        word_count = len(re.findall(r"\b\w+\b", full_text))

        metadata = DocumentMetadata(
            title=title,
            authors=authors,
            publication_date=pub_date,
            abstract=abstract,
            document_type=DocumentType.PPTX,
            page_count=page_count,
            word_count=word_count,
            file_size_bytes=len(pptx_bytes),
            section_headings=headings,
            source_url=source_url,
        )

        return metadata, full_text, sections

"""
Document Intelligence Data Models
Defines structured contracts for document processing across PDF, HTML, Markdown, TXT, DOCX, PPTX:
Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
Conforms strictly to IMPLEMENT.md Section 25.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DocumentType(str, Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    TXT = "txt"
    DOCX = "docx"
    PPTX = "pptx"
    UNKNOWN = "unknown"

    @classmethod
    def from_filename_or_type(cls, filename_or_type: str) -> "DocumentType":
        if not filename_or_type:
            return cls.UNKNOWN
        val = filename_or_type.lower().strip()
        if val.endswith(".pdf") or val == "pdf" or "pdf" in val:
            return cls.PDF
        if val.endswith((".html", ".htm")) or val in ("html", "htm") or "html" in val:
            return cls.HTML
        if val.endswith((".md", ".markdown")) or val in ("markdown", "md"):
            return cls.MARKDOWN
        if val.endswith(".txt") or val == "txt" or "text/plain" in val:
            return cls.TXT
        if val.endswith(".docx") or val == "docx" or "wordprocessing" in val:
            return cls.DOCX
        if val.endswith((".pptx", ".ppt")) or val in ("pptx", "ppt") or "presentation" in val:
            return cls.PPTX
        return cls.UNKNOWN


class RetentionMode(str, Enum):
    FULL_TEXT = "full_text"
    METADATA_ONLY = "metadata_only"
    FAIR_USE_SUMMARY = "fair_use_summary"


@dataclass
class DocumentSectionChunk:
    """
    Text chunk derived from document preserving section headings and offsets.
    """
    chunk_index: int
    heading: str
    text: str
    char_start: int = 0
    char_end: int = 0
    page_number: Optional[int] = None
    embedding: Optional[List[float]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_index": self.chunk_index,
            "heading": self.heading,
            "text": self.text,
            "char_start": self.char_start,
            "char_end": self.char_end,
            "page_number": self.page_number,
            "has_embedding": self.embedding is not None,
        }


# Alias for convenience
DocumentChunk = DocumentSectionChunk


@dataclass
class DocumentMetadata:
    """
    Extracted document metadata preserving author, publication date, abstract,
    copyright, and structural statistics.
    """
    title: str
    authors: List[str] = field(default_factory=list)
    publication_date: Optional[str] = None
    abstract: Optional[str] = None
    document_type: DocumentType = DocumentType.UNKNOWN
    page_count: Optional[int] = None
    word_count: int = 0
    file_size_bytes: Optional[int] = None
    section_headings: List[str] = field(default_factory=list)
    copyright_notice: Optional[str] = None
    retention_mode: RetentionMode = RetentionMode.FULL_TEXT
    source_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "authors": self.authors,
            "publication_date": self.publication_date,
            "abstract": self.abstract,
            "document_type": self.document_type.value,
            "page_count": self.page_count,
            "word_count": self.word_count,
            "file_size_bytes": self.file_size_bytes,
            "section_headings": self.section_headings,
            "copyright_notice": self.copyright_notice,
            "retention_mode": self.retention_mode.value,
            "source_url": self.source_url,
        }


@dataclass
class DocumentResult:
    """
    Complete pipeline output: Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
    """
    metadata: DocumentMetadata
    raw_text: str
    chunks: List[DocumentSectionChunk] = field(default_factory=list)
    extracted_entities: List[Dict[str, Any]] = field(default_factory=list)
    taxonomy_tags: List[str] = field(default_factory=list)
    primary_category: Optional[str] = None
    subcategory: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "raw_text_length": len(self.raw_text),
            "retained_text": self.raw_text if self.metadata.retention_mode == RetentionMode.FULL_TEXT else None,
            "chunks_count": len(self.chunks),
            "chunks": [c.to_dict() for c in self.chunks],
            "extracted_entities": self.extracted_entities,
            "taxonomy_tags": self.taxonomy_tags,
            "primary_category": self.primary_category,
            "subcategory": self.subcategory,
            "confidence": self.confidence,
        }

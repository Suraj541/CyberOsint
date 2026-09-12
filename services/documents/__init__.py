"""
Document Intelligence Package
Provides comprehensive document ingestion, extraction, chunking, and enrichment
for PDF, HTML, Markdown, TXT, DOCX, and PPTX formats.
Pipeline: Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
Conforms strictly to IMPLEMENT.md Section 25.
"""

from .models import (
    DocumentChunk,
    DocumentMetadata,
    DocumentResult,
    DocumentSectionChunk,
    DocumentType,
    RetentionMode,
)
from .processor import DocumentProcessor, document_processor, extract_document
from .extractors import (
    HtmlExtractor,
    MarkdownExtractor,
    OfficeExtractor,
    PdfExtractor,
    TextExtractor,
)

__all__ = [
    "DocumentChunk",
    "DocumentMetadata",
    "DocumentProcessor",
    "DocumentResult",
    "DocumentSectionChunk",
    "DocumentType",
    "HtmlExtractor",
    "MarkdownExtractor",
    "OfficeExtractor",
    "PdfExtractor",
    "RetentionMode",
    "TextExtractor",
    "document_processor",
    "extract_document",
]

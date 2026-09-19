"""
Document Intelligence Package
Provides comprehensive document ingestion, extraction, chunking, enrichment,
and sandboxed processing for PDF, HTML, Markdown, TXT, DOCX, and PPTX formats.
Pipeline: Worker -> Sandbox -> Parser -> Extracted text -> Sanitized result.
Conforms strictly to IMPLEMENT.md Section 25 & Section 39 (Step 38).
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
from .sandbox import (
    DocumentSandboxError,
    DocumentSecurityScanResult,
    DocumentSecurityScanner,
    DocumentTextSanitizer,
    EmbeddedProgramBlockedError,
    MacroExecutionBlockedError,
    PipelineStageResult,
    SafeDocumentParser,
    SandboxedDocumentProcessor,
    SanitizedDocumentResult,
    UnknownBinaryBlockedError,
    sandboxed_processor,
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
    # Sandbox & Security
    "DocumentSandboxError",
    "DocumentSecurityScanResult",
    "DocumentSecurityScanner",
    "DocumentTextSanitizer",
    "EmbeddedProgramBlockedError",
    "MacroExecutionBlockedError",
    "PipelineStageResult",
    "SafeDocumentParser",
    "SandboxedDocumentProcessor",
    "SanitizedDocumentResult",
    "UnknownBinaryBlockedError",
    "sandboxed_processor",
]

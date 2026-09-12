"""
Document Intelligence Pydantic Schemas
Defines request and response contracts for document processing, section chunking,
entity extraction, and copyright retention management.
Conforms strictly to IMPLEMENT.md Section 25.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DocumentChunkResponse(BaseModel):
    chunk_index: int
    heading: str
    text: str
    char_start: int = 0
    char_end: int = 0
    page_number: Optional[int] = None
    has_embedding: bool = False


class DocumentMetadataResponse(BaseModel):
    title: str
    authors: List[str] = Field(default_factory=list)
    publication_date: Optional[str] = None
    abstract: Optional[str] = None
    document_type: str = "unknown"
    page_count: Optional[int] = None
    word_count: int = 0
    file_size_bytes: Optional[int] = None
    section_headings: List[str] = Field(default_factory=list)
    copyright_notice: Optional[str] = None
    retention_mode: str = "full_text"
    source_url: Optional[str] = None


class DocumentProcessRequest(BaseModel):
    content: Optional[str] = Field(
        None,
        description="Raw document text, HTML, Markdown, or base64-encoded binary for PDF/DOCX/PPTX",
    )
    url: Optional[str] = Field(None, description="Document source or download URL")
    filename: str = Field(default="document.pdf", description="Filename or resource identifier")
    doc_type: Optional[str] = Field(
        None,
        description="Explicit document format: pdf, html, markdown, txt, docx, pptx",
    )
    retention_mode: str = Field(
        default="full_text",
        description="Retention policy: full_text, metadata_only, fair_use_summary",
    )
    save_to_db: bool = Field(
        default=False,
        description="Persist parsed document into Content and ContentChunk database tables",
    )


class DocumentProcessResponse(BaseModel):
    metadata: DocumentMetadataResponse
    raw_text_length: int
    retained_text: Optional[str] = None
    chunks_count: int
    chunks: List[DocumentChunkResponse] = Field(default_factory=list)
    extracted_entities: List[Dict[str, Any]] = Field(default_factory=list)
    taxonomy_tags: List[str] = Field(default_factory=list)
    primary_category: Optional[str] = None
    subcategory: Optional[str] = None
    confidence: float = 0.0
    content_id: Optional[int] = None

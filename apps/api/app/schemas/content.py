"""
Content Pydantic Schemas
Defines request, response, and filtering models for normalized cybersecurity intelligence content.
Conforms strictly to IMPLEMENT.md Section 6.
"""

from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ContentTagResponse(BaseModel):
    """Schema for associated taxonomy tag."""

    id: int
    name: str
    category: Optional[str] = None
    confidence: float = 1.0


class VideoTimestampItem(BaseModel):
    timestamp_str: str
    seconds: int
    topic: str
    text: Optional[str] = None
    entities: List[str] = Field(default_factory=list)


class VideoMetadataSchema(BaseModel):
    channel: Optional[str] = None
    duration: Optional[int] = None
    duration_formatted: Optional[str] = None
    thumbnail_url: Optional[str] = None
    conference: Optional[str] = None
    speakers: List[str] = Field(default_factory=list)
    language: Optional[str] = None
    has_transcript: bool = False
    timestamps: List[VideoTimestampItem] = Field(default_factory=list)


class DocumentChunkItem(BaseModel):
    chunk_index: int
    heading: str
    text: str
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    page_number: Optional[int] = None


class DocumentMetadataSchema(BaseModel):
    document_type: str = "unknown"
    authors: List[str] = Field(default_factory=list)
    publication_date: Optional[str] = None
    abstract: Optional[str] = None
    page_count: Optional[int] = None
    word_count: Optional[int] = None
    file_size_bytes: Optional[int] = None
    section_headings: List[str] = Field(default_factory=list)
    retention_mode: str = "full_text"
    chunks_count: Optional[int] = None
    chunks_preview: List[DocumentChunkItem] = Field(default_factory=list)


class ContentResponse(BaseModel):
    """Schema returning detailed stored content record."""

    id: int
    source_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    content_type: str
    canonical_url: str
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    discovered_at: datetime
    language: str
    summary: Optional[str] = None
    content_hash: str
    quality_score: float
    relevance_score: float
    confidence_score: float
    status: str
    created_at: datetime
    updated_at: datetime

    # Extended fields for full frontend and API contract compatibility
    source: Optional[str] = Field(None, description="Human-readable source name or author")
    source_name: Optional[str] = Field(None, description="Source name")
    category: Optional[str] = Field(None, description="Intelligence taxonomy classification")
    severity: Optional[str] = Field(None, description="Calculated severity (CRITICAL, HIGH, MEDIUM, LOW)")
    cvss_score: Optional[float] = Field(None, description="CVSS base vulnerability score")
    tags: List[str] = Field(default_factory=list, description="Linked taxonomy tags")
    video_metadata: Optional[VideoMetadataSchema] = Field(None, description="Video intelligence metadata")
    document_metadata: Optional[DocumentMetadataSchema] = Field(None, description="Document metadata")

    model_config = ConfigDict(from_attributes=True)

    @field_validator("source", mode="before")
    @classmethod
    def extract_source_name(cls, v: Any) -> Optional[str]:
        if hasattr(v, "name"):
            return v.name
        if isinstance(v, str):
            return v
        return None

    @field_validator("tags", mode="before")
    @classmethod
    def extract_tag_names(cls, v: Any) -> List[str]:
        if not v:
            return []
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, str):
                    res.append(item)
                elif hasattr(item, "tag") and hasattr(item.tag, "name"):
                    res.append(item.tag.name)
                elif hasattr(item, "name"):
                    res.append(item.name)
            return res
        return []


class ContentEntityDetail(BaseModel):
    """Schema for extracted entity linked to content."""
    id: int
    name: str
    entity_type: str
    normalized_name: Optional[str] = None
    confidence: float = 1.0
    context_snippet: Optional[str] = None


from app.schemas.summary import ContentSummaryOut


class ContentDetailResponse(ContentResponse):
    """Extended content schema including linked tags, entities, category, and source metadata."""

    entities: List[ContentEntityDetail] = Field(default_factory=list)
    raw_content: Optional[str] = None
    ai_summary: Optional[ContentSummaryOut] = None

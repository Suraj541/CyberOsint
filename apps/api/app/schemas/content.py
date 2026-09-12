"""
Content Pydantic Schemas
Defines request, response, and filtering models for normalized cybersecurity intelligence content.
Conforms strictly to IMPLEMENT.md Section 6.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ContentTagResponse(BaseModel):
    """Schema for associated taxonomy tag."""

    id: int
    name: str
    category: Optional[str] = None
    confidence: float = 1.0


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

    model_config = ConfigDict(from_attributes=True)


class ContentEntityDetail(BaseModel):
    """Schema for extracted entity linked to content."""
    id: int
    name: str
    entity_type: str
    normalized_name: Optional[str] = None
    confidence: float = 1.0
    context_snippet: Optional[str] = None


class ContentDetailResponse(ContentResponse):
    """Extended content schema including linked tags, entities, category, and source metadata."""

    source_name: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    entities: List[ContentEntityDetail] = Field(default_factory=list)

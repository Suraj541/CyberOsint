"""
Entity and Vulnerability Intelligence Pydantic Schemas
Defines request and response schemas for extracted cybersecurity entities (CVEs, products, CWEs, advisories).
Conforms strictly to IMPLEMENT.md Section 12 & Section 13.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EntityBase(BaseModel):
    """Core entity attributes."""

    name: str = Field(..., description="Entity name or identifier (e.g. CVE-2024-38077, Apache HTTP Server)")
    entity_type: str = Field(..., description="Entity type: cve, product, cwe, advisory, vendor, malware, threat_actor")
    normalized_name: str = Field(..., description="Case-standardized entity name")
    description: Optional[str] = Field(default=None, description="Detailed description or context")


class ContentEntityLinkResponse(BaseModel):
    """Summary of content item linked to an entity."""

    content_id: int
    title: str
    canonical_url: str
    content_type: str
    confidence: float = 1.0
    extraction_method: str = "structured"
    context_snippet: Optional[str] = None
    published_at: Optional[datetime] = None


class EntityResponse(EntityBase):
    """Standard entity response."""

    id: int
    metadata_json: Optional[str] = None
    parsed_metadata: Optional[Dict[str, Any]] = Field(default=None, description="Decoded metadata JSON")
    content_count: int = Field(default=0, description="Number of linked content items")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RelatedEntitySummary(BaseModel):
    """Summary of an entity co-occurring with the primary entity."""

    id: int
    name: str
    entity_type: str
    normalized_name: str
    mention_count: int = 1
    description: Optional[str] = None


class TimelineEventResponse(BaseModel):
    """Chronological event in the entity activity timeline."""

    date: Optional[str] = None
    title: str
    event_type: str
    content_id: Optional[int] = None
    url: Optional[str] = None


class CVESeverityDetail(BaseModel):
    """Structured severity metrics for a CVE vulnerability."""

    cvss_score: Optional[float] = None
    severity_rating: Optional[str] = None
    vector_string: Optional[str] = None
    cwe_id: Optional[str] = None


class EntityDetailResponse(EntityResponse):
    """Detailed entity view including all linked intelligence content, relationships, and timeline."""

    linked_content: List[ContentEntityLinkResponse] = Field(default_factory=list)

    # Correlated Content Partitioning
    articles: List[ContentEntityLinkResponse] = Field(default_factory=list)
    reports: List[ContentEntityLinkResponse] = Field(default_factory=list)

    # Relationships & Timeline
    related_entities: List[RelatedEntitySummary] = Field(default_factory=list)
    timeline: List[TimelineEventResponse] = Field(default_factory=list)

    # CVE Specialized Fields (IMPLEMENT.md Section 23)
    severity: Optional[CVESeverityDetail] = None
    affected_products: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

    # Malware Specialized Fields (IMPLEMENT.md Section 23)
    aliases: List[str] = Field(default_factory=list)
    threat_actors: List[RelatedEntitySummary] = Field(default_factory=list)
    campaigns: List[str] = Field(default_factory=list)
    techniques: List[RelatedEntitySummary] = Field(default_factory=list)
    tools: List[RelatedEntitySummary] = Field(default_factory=list)


class EntityStatsResponse(BaseModel):
    """Statistical breakdown of entities by classification type."""

    total_entities: int
    by_type: Dict[str, int] = Field(default_factory=dict)


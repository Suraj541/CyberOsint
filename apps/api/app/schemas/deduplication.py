"""
Deduplication & Cluster Pydantic Schemas
Defines request and response models for similarity evaluation, duplicate checking,
and duplicate cluster telemetry.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DeduplicationCheckRequest(BaseModel):
    """Payload to evaluate duplicate status of a candidate article or intelligence item."""

    title: str = Field(..., min_length=2, description="Content title or headline to evaluate")
    url: Optional[str] = Field(default=None, description="Candidate source or canonical URL")
    description: Optional[str] = Field(default=None, description="Short summary or article lead")
    raw_content: Optional[str] = Field(default=None, description="Raw content or body snippet")
    entities: Optional[List[Dict[str, Any]]] = Field(default=None, description="Known extracted entity dictionaries")


class DeduplicationCheckResponse(BaseModel):
    """Evaluation output detailing whether item is a duplicate and matching signals."""

    is_duplicate: bool = Field(..., description="Whether item is classified as duplicate or near-duplicate")
    match_type: Optional[str] = Field(default=None, description="Match mechanism: exact_url, exact_hash, similar_title, near_duplicate, unique")
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="Overall similarity score from 0.0 to 1.0")
    canonical_id: Optional[int] = Field(default=None, description="Database ID of the canonical primary article")
    canonical_url: Optional[str] = Field(default=None, description="URL of the canonical primary article")
    canonical_title: Optional[str] = Field(default=None, description="Title of the canonical primary article")
    cluster_id: Optional[str] = Field(default=None, description="Identifier of the duplicate cluster grouping this relationship")
    metrics: Dict[str, float] = Field(default_factory=dict, description="Granular similarity sub-scores")
    reason: str = Field(default="", description="Explanatory text for the deduplication decision")


class DuplicateLinkResponse(BaseModel):
    """Individual link between a duplicate record and its canonical entry."""

    link_id: int
    duplicate_content_id: Optional[int] = None
    match_type: str
    similarity_score: float
    created_at: Optional[str] = None


class DuplicateClusterResponse(BaseModel):
    """Aggregate cluster grouping a canonical record with all detected duplicates."""

    cluster_id: str
    canonical_id: int
    canonical_title: str
    canonical_url: str
    duplicates: List[DuplicateLinkResponse] = Field(default_factory=list)
    total_members: int

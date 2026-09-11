"""
Search API Schemas
Pydantic models for search requests, responses, hits, and aggregations.
Conforms to IMPLEMENT.md Section 18.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SearchRequest(BaseModel):
    """Structured request payload for POST /api/v1/search."""
    q: Optional[str] = Field(default=None, description="Free text keyword search query")
    phrase: Optional[str] = Field(default=None, description="Exact phrase matching query")
    category: Optional[str] = Field(default=None, description="Taxonomy category filter")
    source: Optional[str] = Field(default=None, description="Source name filter")
    content_type: Optional[str] = Field(default=None, description="Content type filter (article, advisory, cve, report)")
    entity: Optional[str] = Field(default=None, description="Extracted entity name or normalized value")
    entity_type: Optional[str] = Field(default=None, description="Entity type filter (cve, malware, vendor, product, etc.)")
    tag: Optional[str] = Field(default=None, description="Topic tag filter")
    date_from: Optional[datetime] = Field(default=None, description="Published start date (ISO format)")
    date_to: Optional[datetime] = Field(default=None, description="Published end date (ISO format)")
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page (max 100)")
    sort_by: str = Field(default="relevance", description="Sort order: relevance, newest, oldest")


class SearchHitItem(BaseModel):
    """Individual search result hit representing an indexed article or intelligence item."""
    id: int
    title: str
    canonical_url: str
    content_type: str = "article"
    description: Optional[str] = None
    summary: Optional[str] = None
    source: Optional[str] = None
    category: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    score: float = 1.0
    highlights: Dict[str, List[str]] = Field(default_factory=dict)


class SearchFacetBucketItem(BaseModel):
    """Faceted category/source/entity aggregation bucket."""
    key: str
    count: int


class SearchResponse(BaseModel):
    """Full search response envelope containing hits, pagination, and faceted counts."""
    total: int
    page: int
    page_size: int
    hits: List[SearchHitItem] = Field(default_factory=list)
    facets: Dict[str, List[SearchFacetBucketItem]] = Field(default_factory=dict)
    took_ms: float = 0.0
    query: Optional[str] = None
    engine: str = "opensearch"


class SearchStatsResponse(BaseModel):
    """Status and document counts for the search engine index."""
    engine: str
    status: str
    cluster_online: bool
    document_count: int
    index_name: str


class ReindexResponse(BaseModel):
    """Response returned after bulk reindexing database content."""
    status: str
    indexed_count: int

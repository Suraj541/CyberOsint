"""
Search Service Domain Models
Defines dataclasses for queries, results, hits, and facets conforming to IMPLEMENT.md Section 18.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class SearchQuery:
    """Structured search criteria for OpenSearch queries."""
    query: Optional[str] = None
    phrase: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    content_type: Optional[str] = None
    entity: Optional[str] = None
    entity_type: Optional[str] = None
    tag: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = 1
    page_size: int = 20
    sort_by: str = "relevance"  # relevance, newest, oldest

    def __post_init__(self):
        if self.page < 1:
            self.page = 1
        if self.page_size < 1:
            self.page_size = 1
        if self.page_size > 100:
            self.page_size = 100


@dataclass
class SearchHit:
    """Individual matching document hit returned by search query."""
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
    tags: List[str] = field(default_factory=list)
    entities: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 1.0
    highlights: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SearchFacetBucket:
    """Aggregation bucket for faceted filtering."""
    key: str
    count: int


@dataclass
class SearchResult:
    """Aggregated search result with hits, pagination, and faceted breakdown."""
    total: int
    page: int
    page_size: int
    hits: List[SearchHit] = field(default_factory=list)
    facets: Dict[str, List[SearchFacetBucket]] = field(default_factory=dict)
    took_ms: float = 0.0
    query_used: Optional[str] = None
    engine: str = "opensearch"

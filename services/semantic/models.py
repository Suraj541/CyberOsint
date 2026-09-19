"""
Semantic & Hybrid Search Domain Models
Dataclasses for vector similarity hits, hybrid search parameters, and RRF-fused results.
Conforms to IMPLEMENT.md Section 19.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SemanticHit:
    """Individual vector similarity hit from chunk search."""
    content_id: int
    chunk_id: int
    chunk_text: str
    similarity: float
    content_title: str
    canonical_url: str
    category: Optional[str] = None
    source: Optional[str] = None
    content_type: Optional[str] = "article"


@dataclass
class HybridSearchQuery:
    """Query parameters for combined keyword and semantic vector search."""
    query: str
    category: Optional[str] = None
    source: Optional[str] = None
    content_type: Optional[str] = None
    entity: Optional[str] = None
    keyword_weight: float = 0.5
    semantic_weight: float = 0.5
    page: int = 1
    page_size: int = 20

    def __post_init__(self):
        if self.page < 1:
            self.page = 1
        if self.page_size < 1:
            self.page_size = 1
        if self.page_size > 100:
            self.page_size = 100
        # Normalize weights
        total_w = self.keyword_weight + self.semantic_weight
        if total_w > 0:
            self.keyword_weight = self.keyword_weight / total_w
            self.semantic_weight = self.semantic_weight / total_w
        else:
            self.keyword_weight = 0.5
            self.semantic_weight = 0.5


@dataclass
class HybridHit:
    """Consolidated search hit combining lexical keyword score and semantic vector score."""
    content_id: int
    title: str
    canonical_url: str
    content_type: str = "article"
    category: Optional[str] = None
    source: Optional[str] = None
    published_at: Optional[str] = None
    rrf_score: float = 0.0
    keyword_rank: Optional[int] = None
    semantic_rank: Optional[int] = None
    keyword_score: float = 0.0
    semantic_score: float = 0.0
    matched_chunk: Optional[str] = None


@dataclass
class HybridSearchResult:
    """Paginated hybrid search response containing fused and ranked hits."""
    total: int
    page: int
    page_size: int
    hits: List[HybridHit] = field(default_factory=list)
    took_ms: float = 0.0
    query_used: str = ""
    engine: str = "hybrid"
    text_count: int = 0
    vector_count: int = 0
    text_status: str = "ok"
    vector_status: str = "ok"
    engine_status: str = "optimal"


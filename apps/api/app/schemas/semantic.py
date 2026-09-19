"""
Semantic & Hybrid Search API Schemas
Pydantic models for semantic vector search, hybrid RRF search, and embedding generation.
Conforms to IMPLEMENT.md Section 19.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class SemanticSearchRequest(BaseModel):
    """Payload for dense vector semantic similarity search."""
    q: Optional[str] = Field(default=None, description="Text query to embed and compare")
    query: Optional[str] = Field(default=None, description="Query alias for q")
    limit: int = Field(default=20, ge=1, le=100, description="Max number of chunk hits")
    threshold: float = Field(default=0.3, ge=0.0, le=1.0, description="Minimum cosine similarity cutoff")

    @model_validator(mode="before")
    @classmethod
    def normalize_query(cls, values: Any) -> Any:
        if isinstance(values, dict):
            q_val = values.get("q") or values.get("query")
            if not q_val or not str(q_val).strip():
                raise ValueError("Query string 'q' or 'query' is required and must not be empty.")
            values["q"] = str(q_val).strip()
            values["query"] = values["q"]
        return values


class SemanticHitItem(BaseModel):
    """Vector similarity hit on an individual content chunk."""
    content_id: int
    chunk_id: int
    chunk_text: str
    similarity: float
    content_title: str
    canonical_url: str
    content_type: Optional[str] = "article"
    source: Optional[str] = None


class SemanticSearchResponse(BaseModel):
    """Response returned by pure semantic vector search."""
    total: int
    hits: List[SemanticHitItem] = Field(default_factory=list)


class HybridSearchRequest(BaseModel):
    """Payload for hybrid search combining lexical keyword matching and vector similarity."""
    q: Optional[str] = Field(default=None, description="Query string for hybrid evaluation")
    query: Optional[str] = Field(default=None, description="Query alias for q")
    category: Optional[str] = Field(default=None, description="Taxonomy category filter")
    source: Optional[str] = Field(default=None, description="Source name filter")
    content_type: Optional[str] = Field(default=None, description="Content type filter")
    entity: Optional[str] = Field(default=None, description="Entity name or alias")
    keyword_weight: float = Field(default=0.5, ge=0.0, le=1.0, description="Weight given to keyword rank in RRF")
    semantic_weight: float = Field(default=0.5, ge=0.0, le=1.0, description="Weight given to semantic rank in RRF")
    page: int = Field(default=1, ge=1, description="Page number")
    page_size: int = Field(default=20, ge=1, le=100, description="Results per page")

    @model_validator(mode="before")
    @classmethod
    def normalize_query(cls, values: Any) -> Any:
        if isinstance(values, dict):
            q_val = values.get("q") or values.get("query")
            if not q_val or not str(q_val).strip():
                raise ValueError("Query string 'q' or 'query' is required and must not be empty.")
            values["q"] = str(q_val).strip()
            values["query"] = values["q"]
        return values


class HybridHitItem(BaseModel):
    """Search hit scored and ranked via Reciprocal Rank Fusion."""
    id: Optional[int] = None
    content_id: int
    title: str
    canonical_url: str
    content_type: str = "article"
    category: Optional[str] = None
    source: Optional[str] = None
    published_at: Optional[str] = None
    rrf_score: float
    score: Optional[float] = None
    keyword_rank: Optional[int] = None
    semantic_rank: Optional[int] = None
    keyword_score: float = 0.0
    semantic_score: float = 0.0
    matched_chunk: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def ensure_id(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "id" not in values or values["id"] is None:
                values["id"] = values.get("content_id")
            if "score" not in values or values["score"] is None:
                values["score"] = values.get("rrf_score", 0.0)
        return values


class HybridSearchResponse(BaseModel):
    """Full hybrid search response envelope with RRF-ranked results and engine telemetry."""
    total: int
    page: int
    page_size: int
    hits: List[HybridHitItem] = Field(default_factory=list)
    took_ms: float = 0.0
    query: str
    engine: str = "hybrid"
    text_count: int = 0
    vector_count: int = 0
    text_status: str = "ok"
    vector_status: str = "ok"
    engine_status: str = "optimal"



class EmbedRequest(BaseModel):
    """Request payload to generate vector embedding for text."""
    text: str = Field(..., min_length=1, description="Input string to embed")


class EmbedResponse(BaseModel):
    """Dense vector representation for input text."""
    dimension: int
    embedding: List[float]


class SemanticReindexResponse(BaseModel):
    """Response returned after bulk re-embedding database content."""
    status: str
    chunks_created: int

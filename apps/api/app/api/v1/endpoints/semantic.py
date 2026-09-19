"""
Semantic & Hybrid Search REST Endpoints
Implements vector similarity search, Reciprocal Rank Fusion (RRF) hybrid search,
and vector embedding generation.
Conforms to IMPLEMENT.md Section 19.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.semantic import (
    EmbedRequest,
    EmbedResponse,
    HybridHitItem,
    HybridSearchRequest,
    HybridSearchResponse,
    SemanticHitItem,
    SemanticReindexResponse,
    SemanticSearchRequest,
    SemanticSearchResponse,
)
from services.semantic import (
    HybridSearchQuery,
    embedder,
    semantic_service,
)

router = APIRouter(prefix="", tags=["Semantic & Hybrid Search"])


@router.post("/search/semantic", response_model=SemanticSearchResponse, summary="Execute dense vector similarity search")
def semantic_vector_search(
    request: SemanticSearchRequest,
    db: Session = Depends(get_db),
) -> SemanticSearchResponse:
    """
    Generate embedding for query string and perform vector cosine similarity search
    against chunk embeddings stored in the database.
    """
    hits = semantic_service.search_vector(
        db=db,
        query=request.q,
        limit=request.limit,
        threshold=request.threshold,
    )
    return SemanticSearchResponse(
        total=len(hits),
        hits=[
            SemanticHitItem(
                content_id=h.content_id,
                chunk_id=h.chunk_id,
                chunk_text=h.chunk_text,
                similarity=h.similarity,
                content_title=h.content_title,
                canonical_url=h.canonical_url,
                content_type=h.content_type,
                source=h.source,
            )
            for h in hits
        ],
    )


@router.get("/search/hybrid", response_model=HybridSearchResponse, summary="Execute hybrid search (GET)")
def hybrid_search_get(
    q: str = Query(..., min_length=1, description="Query string for hybrid evaluation"),
    category: Optional[str] = Query(None, description="Taxonomy category filter"),
    source: Optional[str] = Query(None, description="Source filter"),
    content_type: Optional[str] = Query(None, description="Content type filter"),
    entity: Optional[str] = Query(None, description="Entity name or alias"),
    keyword_weight: float = Query(0.5, ge=0.0, le=1.0, description="Keyword rank weight in RRF"),
    semantic_weight: float = Query(0.5, ge=0.0, le=1.0, description="Semantic rank weight in RRF"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size limit"),
    db: Session = Depends(get_db),
) -> HybridSearchResponse:
    """
    Executes hybrid search combining dense vector similarity and OpenSearch keyword search
    using Reciprocal Rank Fusion (RRF) ranking.
    """
    query_obj = HybridSearchQuery(
        query=q,
        category=category,
        source=source,
        content_type=content_type,
        entity=entity,
        keyword_weight=keyword_weight,
        semantic_weight=semantic_weight,
        page=page,
        page_size=page_size,
    )
    res = semantic_service.search_hybrid(db, query_obj)
    return HybridSearchResponse(
        total=res.total,
        page=res.page,
        page_size=res.page_size,
        hits=[
            HybridHitItem(
                id=h.content_id,
                content_id=h.content_id,
                title=h.title,
                canonical_url=h.canonical_url,
                content_type=h.content_type,
                category=h.category,
                source=h.source,
                published_at=h.published_at,
                rrf_score=h.rrf_score,
                keyword_rank=h.keyword_rank,
                semantic_rank=h.semantic_rank,
                keyword_score=h.keyword_score,
                semantic_score=h.semantic_score,
                matched_chunk=h.matched_chunk,
            )
            for h in res.hits
        ],
        took_ms=res.took_ms,
        query=res.query_used,
        engine=res.engine,
        text_count=res.text_count,
        vector_count=res.vector_count,
        text_status=res.text_status,
        vector_status=res.vector_status,
        engine_status=res.engine_status,
    )


@router.post("/search/hybrid", response_model=HybridSearchResponse, summary="Execute hybrid search (POST)")
def hybrid_search_post(
    request: HybridSearchRequest,
    db: Session = Depends(get_db),
) -> HybridSearchResponse:
    """
    Executes structured hybrid search request using POST body payload.
    """
    query_obj = HybridSearchQuery(
        query=request.q,
        category=request.category,
        source=request.source,
        content_type=request.content_type,
        entity=request.entity,
        keyword_weight=request.keyword_weight,
        semantic_weight=request.semantic_weight,
        page=request.page,
        page_size=request.page_size,
    )
    res = semantic_service.search_hybrid(db, query_obj)
    return HybridSearchResponse(
        total=res.total,
        page=res.page,
        page_size=res.page_size,
        hits=[
            HybridHitItem(
                id=h.content_id,
                content_id=h.content_id,
                title=h.title,
                canonical_url=h.canonical_url,
                content_type=h.content_type,
                category=h.category,
                source=h.source,
                published_at=h.published_at,
                rrf_score=h.rrf_score,
                keyword_rank=h.keyword_rank,
                semantic_rank=h.semantic_rank,
                keyword_score=h.keyword_score,
                semantic_score=h.semantic_score,
                matched_chunk=h.matched_chunk,
            )
            for h in res.hits
        ],
        took_ms=res.took_ms,
        query=res.query_used,
        engine=res.engine,
        text_count=res.text_count,
        vector_count=res.vector_count,
        text_status=res.text_status,
        vector_status=res.vector_status,
        engine_status=res.engine_status,
    )



@router.post("/semantic/embed", response_model=EmbedResponse, summary="Generate vector embedding for text")
def generate_embedding(request: EmbedRequest) -> EmbedResponse:
    """
    Generate 384-dimensional unit-normalized vector embedding for arbitrary text.
    """
    vector = embedder.embed_text(request.text)
    return EmbedResponse(
        dimension=embedder.dimension,
        embedding=vector,
    )


@router.post("/semantic/reindex", response_model=SemanticReindexResponse, summary="Re-embed all content")
def reindex_embeddings(db: Session = Depends(get_db)) -> SemanticReindexResponse:
    """
    Re-chunks and generates embeddings for all content in PostgreSQL.
    """
    count = semantic_service.reindex_all_embeddings(db)
    return SemanticReindexResponse(
        status="completed",
        chunks_created=count,
    )

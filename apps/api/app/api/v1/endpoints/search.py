"""
Search REST API Endpoints
Implements full-text keyword search, exact phrase matching, faceted aggregations,
and reindexing operations.
Conforms to IMPLEMENT.md Section 18.
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.search import (
    ReindexResponse,
    SearchFacetBucketItem,
    SearchHitItem,
    SearchRequest,
    SearchResponse,
    SearchStatsResponse,
)
from services.search import (
    SearchQuery,
    SearchResult,
    search_service,
)

router = APIRouter(prefix="/search", tags=["Search"])


def _format_search_response(res: SearchResult) -> SearchResponse:
    """Transform service SearchResult dataclass into SearchResponse Pydantic model."""
    hits = [
        SearchHitItem(
            id=h.id,
            title=h.title,
            canonical_url=h.canonical_url,
            content_type=h.content_type,
            description=h.description,
            summary=h.summary,
            source=h.source,
            category=h.category,
            author=h.author,
            published_at=h.published_at,
            tags=h.tags,
            entities=h.entities,
            score=h.score,
            highlights=h.highlights,
        )
        for h in res.hits
    ]

    facets = {
        name: [SearchFacetBucketItem(key=b.key, count=b.count) for b in buckets]
        for name, buckets in res.facets.items()
    }

    return SearchResponse(
        total=res.total,
        page=res.page,
        page_size=res.page_size,
        hits=hits,
        facets=facets,
        took_ms=res.took_ms,
        query=res.query_used,
        engine=res.engine,
    )


@router.get("", response_model=SearchResponse, summary="Execute full-text and faceted search query")
@router.get("/", response_model=SearchResponse, include_in_schema=False)
def search_get(
    q: Optional[str] = Query(None, description="Free-text keyword query"),
    phrase: Optional[str] = Query(None, description="Exact phrase matching query"),
    category: Optional[str] = Query(None, description="Taxonomy category filter"),
    source: Optional[str] = Query(None, description="Source filter"),
    content_type: Optional[str] = Query(None, description="Content type filter (article, advisory, cve, report)"),
    entity: Optional[str] = Query(None, description="Extracted entity name or normalized value"),
    entity_type: Optional[str] = Query(None, description="Entity type filter (cve, malware, vendor, product, etc.)"),
    tag: Optional[str] = Query(None, description="Topic tag filter"),
    date_from: Optional[datetime] = Query(None, description="Published start date filter"),
    date_to: Optional[datetime] = Query(None, description="Published end date filter"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size limit"),
    sort_by: str = Query("relevance", pattern="^(relevance|newest|oldest)$", description="Sort criteria"),
) -> SearchResponse:
    """
    Search indexed cybersecurity content with support for keyword queries, exact phrases,
    faceted category/source/entity filters, and temporal date ranges.
    """
    sq = SearchQuery(
        query=q,
        phrase=phrase,
        category=category,
        source=source,
        content_type=content_type,
        entity=entity,
        entity_type=entity_type,
        tag=tag,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
    )
    result = search_service.search(sq)
    return _format_search_response(result)


@router.post("", response_model=SearchResponse, summary="Execute structured search request")
@router.post("/", response_model=SearchResponse, include_in_schema=False)
def search_post(request: SearchRequest) -> SearchResponse:
    """
    Execute structured search query using POST request body with complex filter combinations.
    """
    sq = SearchQuery(
        query=request.q,
        phrase=request.phrase,
        category=request.category,
        source=request.source,
        content_type=request.content_type,
        entity=request.entity,
        entity_type=request.entity_type,
        tag=request.tag,
        date_from=request.date_from,
        date_to=request.date_to,
        page=request.page,
        page_size=request.page_size,
        sort_by=request.sort_by,
    )
    result = search_service.search(sq)
    return _format_search_response(result)


@router.get("/stats", response_model=SearchStatsResponse, summary="Retrieve search engine statistics")
def search_stats() -> SearchStatsResponse:
    """
    Returns search engine health status, cluster connection telemetry, and indexed document count.
    """
    stats_data = search_service.stats()
    return SearchStatsResponse(
        engine=stats_data.get("engine", "unknown"),
        status=stats_data.get("status", "unknown"),
        cluster_online=stats_data.get("cluster_online", False),
        document_count=stats_data.get("document_count", 0),
        index_name=stats_data.get("index_name", "cyber_osint_content"),
    )


@router.post("/reindex", response_model=ReindexResponse, status_code=status.HTTP_200_OK, summary="Reindex all content")
def reindex_content(db: Session = Depends(get_db)) -> ReindexResponse:
    """
    Bulk reindexes all persistent content records from PostgreSQL into OpenSearch.
    """
    count = search_service.reindex_all(db)
    return ReindexResponse(
        status="completed",
        indexed_count=count,
    )

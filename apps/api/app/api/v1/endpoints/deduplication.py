"""
Deduplication & Duplicate Clusters API Endpoints
Provides on-demand duplicate checks against indexed content and duplicate cluster telemetry.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.deduplication import (
    DeduplicationCheckRequest,
    DeduplicationCheckResponse,
    DuplicateClusterResponse,
    DuplicateLinkResponse,
)
from services.deduplication import deduplication_engine

router = APIRouter(prefix="/deduplication", tags=["Deduplication Engine"])


@router.post(
    "/check",
    response_model=DeduplicationCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Check Content for Duplication",
    description=(
        "Evaluates a candidate article across the 5-stage deduplication pipeline: "
        "Exact URL, Content Hash, Similar Title, and Multi-Signal Similarity."
    ),
)
def check_duplicate_endpoint(
    request: DeduplicationCheckRequest,
    db: Session = Depends(get_db),
) -> DeduplicationCheckResponse:
    """Check whether a candidate article is duplicate or near-duplicate."""
    result = deduplication_engine.evaluate(db, request)
    return DeduplicationCheckResponse(
        is_duplicate=result.is_duplicate,
        match_type=result.match_type,
        similarity_score=result.similarity_score,
        canonical_id=result.canonical_id,
        canonical_url=result.canonical_url,
        canonical_title=result.canonical_title,
        cluster_id=result.cluster_id,
        metrics=result.metrics,
        reason=result.reason,
    )


@router.get(
    "/clusters",
    response_model=List[DuplicateClusterResponse],
    status_code=status.HTTP_200_OK,
    summary="List Duplicate Clusters",
    description="Retrieve aggregated duplicate clusters grouping canonical items with linked duplicates.",
)
def list_clusters_endpoint(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of clusters to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
) -> List[DuplicateClusterResponse]:
    """List duplicate clusters ordered by cluster size."""
    clusters = deduplication_engine.list_clusters(db, limit=limit, offset=offset)
    return [
        DuplicateClusterResponse(
            cluster_id=c.cluster_id,
            canonical_id=c.canonical_id,
            canonical_title=c.canonical_title,
            canonical_url=c.canonical_url,
            duplicates=[
                DuplicateLinkResponse(
                    link_id=d["link_id"],
                    duplicate_content_id=d.get("duplicate_content_id"),
                    match_type=d["match_type"],
                    similarity_score=d["similarity_score"],
                    created_at=d.get("created_at"),
                )
                for d in c.duplicates
            ],
            total_members=c.total_members,
        )
        for c in clusters
    ]


@router.get(
    "/clusters/{cluster_id}",
    response_model=DuplicateClusterResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Duplicate Cluster Details",
    description="Retrieve a specific duplicate cluster by its cluster ID.",
)
def get_cluster_endpoint(
    cluster_id: str,
    db: Session = Depends(get_db),
) -> DuplicateClusterResponse:
    """Get details for a single duplicate cluster."""
    cluster = deduplication_engine.get_cluster(db, cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Duplicate cluster '{cluster_id}' not found",
        )

    return DuplicateClusterResponse(
        cluster_id=cluster.cluster_id,
        canonical_id=cluster.canonical_id,
        canonical_title=cluster.canonical_title,
        canonical_url=cluster.canonical_url,
        duplicates=[
            DuplicateLinkResponse(
                link_id=d["link_id"],
                duplicate_content_id=d.get("duplicate_content_id"),
                match_type=d["match_type"],
                similarity_score=d["similarity_score"],
                created_at=d.get("created_at"),
            )
            for d in cluster.duplicates
        ],
        total_members=cluster.total_members,
    )

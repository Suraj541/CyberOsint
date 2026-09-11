"""
Content API Endpoints
Provides search, filtering, and retrieval endpoints for normalized cybersecurity intelligence content.
Conforms strictly to IMPLEMENT.md Section 6.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.content import Content
from app.models.source import Source
from app.schemas.content import ContentDetailResponse, ContentResponse

router = APIRouter(prefix="/content", tags=["Content"])


@router.get(
    "",
    response_model=List[ContentResponse],
    status_code=status.HTTP_200_OK,
    summary="List Normalized Content",
)
def list_content(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    source_id: Optional[int] = Query(default=None, description="Filter by Source ID"),
    content_type: Optional[str] = Query(default=None, description="Filter by type (article, advisory, cve)"),
    language: Optional[str] = Query(default=None, description="Filter by language code"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
) -> List[ContentResponse]:
    """List normalized cybersecurity intelligence items with pagination and filters."""
    query = db.query(Content)

    if source_id is not None:
        query = query.filter(Content.source_id == source_id)
    if content_type:
        query = query.filter(Content.content_type == content_type)
    if language:
        query = query.filter(Content.language == language)
    if status_filter:
        query = query.filter(Content.status == status_filter)

    query = query.order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
    items = query.offset(skip).limit(limit).all()
    return items


@router.get(
    "/{content_id}",
    response_model=ContentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Content Detail",
)
def get_content_detail(
    content_id: int,
    db: Session = Depends(get_db),
) -> ContentDetailResponse:
    """Retrieve full content details including source metadata and linked taxonomy tags."""
    content = db.query(Content).filter(Content.id == content_id).first()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content with id {content_id} not found",
        )

    # Resolve linked tag names
    tags = [ct.tag.name for ct in content.content_tags if ct.tag]
    source_name = content.source.name if content.source else None

    resp = ContentDetailResponse(
        id=content.id,
        source_id=content.source_id,
        source_name=source_name,
        title=content.title,
        description=content.description,
        content_type=content.content_type,
        canonical_url=content.canonical_url,
        author=content.author,
        published_at=content.published_at,
        discovered_at=content.discovered_at,
        language=content.language,
        summary=content.summary,
        content_hash=content.content_hash,
        quality_score=content.quality_score,
        relevance_score=content.relevance_score,
        confidence_score=content.confidence_score,
        status=content.status,
        tags=tags,
        created_at=content.created_at,
        updated_at=content.updated_at,
    )
    return resp


@router.get(
    "/by-hash/{content_hash}",
    response_model=ContentResponse,
    status_code=status.HTTP_200_OK,
    summary="Lookup Content by SHA-256 Hash",
)
def get_content_by_hash(
    content_hash: str,
    db: Session = Depends(get_db),
) -> ContentResponse:
    """Lookup content record using its cryptographic deduplication SHA-256 hash."""
    content = db.query(Content).filter(Content.content_hash == content_hash).first()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content with hash {content_hash} not found",
        )
    return content

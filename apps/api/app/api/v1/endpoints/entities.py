"""
Entities & Vulnerability Intelligence API Endpoints
Provides search, retrieval, and relationship inspection for extracted cybersecurity entities
(CVEs, affected products, CWEs, and advisories) and their links to normalized content.
Conforms strictly to IMPLEMENT.md Section 12 & Section 13.
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.schemas.entity import (
    ContentEntityLinkResponse,
    EntityDetailResponse,
    EntityResponse,
    EntityStatsResponse,
)

router = APIRouter(prefix="/entities", tags=["Entities & Vulnerabilities"])


def _parse_metadata(meta_str: Optional[str]) -> Optional[Dict[str, Any]]:
    if not meta_str:
        return None
    try:
        return json.loads(meta_str)
    except Exception:
        return None


@router.get(
    "",
    response_model=List[EntityResponse],
    status_code=status.HTTP_200_OK,
    summary="List Cybersecurity Entities",
)
def list_entities(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    entity_type: Optional[str] = Query(default=None, description="Filter by type (cve, product, cwe, advisory, vendor)"),
    q: Optional[str] = Query(default=None, description="Search query matching entity name"),
    db: Session = Depends(get_db),
) -> List[EntityResponse]:
    """List extracted intelligence entities with optional type filtering and search."""
    query = db.query(Entity)

    if entity_type:
        query = query.filter(Entity.entity_type == entity_type.lower())
    if q:
        search_term = f"%{q.strip()}%"
        query = query.filter(Entity.name.ilike(search_term) | Entity.description.ilike(search_term))

    entities = query.order_by(Entity.created_at.desc()).offset(skip).limit(limit).all()

    # Query content counts for retrieved entities in batch
    entity_ids = [e.id for e in entities]
    counts_map: Dict[int, int] = {}
    if entity_ids:
        counts = (
            db.query(ContentEntity.entity_id, func.count(ContentEntity.content_id))
            .filter(ContentEntity.entity_id.in_(entity_ids))
            .group_by(ContentEntity.entity_id)
            .all()
        )
        counts_map = {ent_id: cnt for ent_id, cnt in counts}

    result = []
    for ent in entities:
        result.append(
            EntityResponse(
                id=ent.id,
                name=ent.name,
                entity_type=ent.entity_type,
                normalized_name=ent.normalized_name,
                description=ent.description,
                metadata_json=ent.metadata_json,
                parsed_metadata=_parse_metadata(ent.metadata_json),
                content_count=counts_map.get(ent.id, 0),
                created_at=ent.created_at,
                updated_at=ent.updated_at,
            )
        )
    return result


@router.get(
    "/types/summary",
    response_model=EntityStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Entity Type Statistics",
)
def get_entity_stats(db: Session = Depends(get_db)) -> EntityStatsResponse:
    """Retrieve statistical aggregation of stored entities categorized by entity type."""
    counts = (
        db.query(Entity.entity_type, func.count(Entity.id))
        .group_by(Entity.entity_type)
        .all()
    )
    by_type = {ent_type: cnt for ent_type, cnt in counts}
    total = sum(by_type.values())
    return EntityStatsResponse(total_entities=total, by_type=by_type)


@router.get(
    "/cve/{cve_id}",
    response_model=EntityDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Lookup CVE Intelligence",
)
def get_cve_detail(cve_id: str, db: Session = Depends(get_db)) -> EntityDetailResponse:
    """
    Dedicated CVE intelligence lookup.
    Retrieves structured CVE metadata (CVSS, severity, affected products)
    and all associated intelligence content articles and advisories.
    """
    normalized = cve_id.strip().upper()
    entity = (
        db.query(Entity)
        .filter(Entity.entity_type == "cve", Entity.normalized_name == normalized)
        .first()
    )
    if not entity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE entity '{cve_id}' not found",
        )

    return _build_entity_detail_response(db, entity)


@router.get(
    "/{entity_id}",
    response_model=EntityDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Entity Detail with Linked Content",
)
def get_entity_detail(entity_id: int, db: Session = Depends(get_db)) -> EntityDetailResponse:
    """Retrieve entity details including all linked cybersecurity articles, advisories, and reports."""
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity with id {entity_id} not found",
        )

    return _build_entity_detail_response(db, entity)


def _build_entity_detail_response(db: Session, entity: Entity) -> EntityDetailResponse:
    """Helper to assemble EntityDetailResponse with all linked content objects."""
    links = (
        db.query(ContentEntity, Content)
        .join(Content, ContentEntity.content_id == Content.id)
        .filter(ContentEntity.entity_id == entity.id)
        .order_by(Content.published_at.desc().nullslast())
        .all()
    )

    linked_content: List[ContentEntityLinkResponse] = []
    for ce, content in links:
        linked_content.append(
            ContentEntityLinkResponse(
                content_id=content.id,
                title=content.title,
                canonical_url=content.canonical_url,
                content_type=content.content_type,
                confidence=ce.confidence,
                extraction_method=ce.extraction_method,
                context_snippet=ce.context_snippet,
                published_at=content.published_at,
            )
        )

    return EntityDetailResponse(
        id=entity.id,
        name=entity.name,
        entity_type=entity.entity_type,
        normalized_name=entity.normalized_name,
        description=entity.description,
        metadata_json=entity.metadata_json,
        parsed_metadata=_parse_metadata(entity.metadata_json),
        content_count=len(linked_content),
        linked_content=linked_content,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )

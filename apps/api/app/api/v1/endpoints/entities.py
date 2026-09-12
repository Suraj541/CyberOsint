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
    CVESeverityDetail,
    ContentEntityLinkResponse,
    EntityDetailResponse,
    EntityResponse,
    EntityStatsResponse,
    RelatedEntitySummary,
    TimelineEventResponse,
)

try:
    from packages.extractor.gazetteers import MALWARE_GAZETTEER, THREAT_ACTOR_GAZETTEER
except Exception:
    MALWARE_GAZETTEER = {}
    THREAT_ACTOR_GAZETTEER = {}


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
def get_entity_detail(entity_id: str, db: Session = Depends(get_db)) -> EntityDetailResponse:
    """
    Retrieve entity details including all linked cybersecurity articles, advisories, and reports.
    Supports resolution by integer primary key ID or canonical entity identifier/name.
    """
    entity = None
    if entity_id.isdigit():
        entity = db.query(Entity).filter(Entity.id == int(entity_id)).first()

    if not entity:
        normalized = entity_id.strip()
        entity = (
            db.query(Entity)
            .filter(
                (Entity.normalized_name == normalized)
                | (Entity.normalized_name == normalized.lower())
                | (Entity.normalized_name == normalized.upper())
                | (Entity.name.ilike(normalized))
            )
            .first()
        )

    if not entity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entity '{entity_id}' not found",
        )

    return _build_entity_detail_response(db, entity)


def _build_entity_detail_response(db: Session, entity: Entity) -> EntityDetailResponse:
    """Helper to assemble EntityDetailResponse with all linked content objects, relationships, and Section 23 intelligence."""
    links = (
        db.query(ContentEntity, Content)
        .join(Content, ContentEntity.content_id == Content.id)
        .filter(ContentEntity.entity_id == entity.id)
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .all()
    )

    linked_content: List[ContentEntityLinkResponse] = []
    articles: List[ContentEntityLinkResponse] = []
    reports: List[ContentEntityLinkResponse] = []
    timeline: List[TimelineEventResponse] = []
    content_ids: List[int] = []
    references: List[str] = []

    for ce, content in links:
        content_ids.append(content.id)
        if content.canonical_url and content.canonical_url not in references:
            references.append(content.canonical_url)

        item = ContentEntityLinkResponse(
            content_id=content.id,
            title=content.title,
            canonical_url=content.canonical_url,
            content_type=content.content_type,
            confidence=ce.confidence,
            extraction_method=ce.extraction_method,
            context_snippet=ce.context_snippet,
            published_at=content.published_at,
        )
        linked_content.append(item)

        ctype = (content.content_type or "").lower()
        if ctype in ("article", "news", "blog", "video"):
            articles.append(item)
        else:
            reports.append(item)

        event_date = None
        if content.published_at:
            event_date = content.published_at.isoformat()
        elif content.created_at:
            event_date = content.created_at.isoformat()

        timeline.append(
            TimelineEventResponse(
                date=event_date,
                title=content.title,
                event_type=ctype or "intelligence",
                content_id=content.id,
                url=content.canonical_url,
            )
        )

    # Sort timeline events chronologically
    timeline.sort(key=lambda t: t.date or "", reverse=True)

    # Parse metadata
    parsed_meta = _parse_metadata(entity.metadata_json) or {}

    # Extract additional references from parsed metadata if present
    meta_refs = parsed_meta.get("references") or parsed_meta.get("notes") or []
    if isinstance(meta_refs, list):
        for ref in meta_refs:
            if ref and isinstance(ref, str) and ref not in references:
                references.append(ref)
    elif isinstance(meta_refs, str) and meta_refs not in references:
        references.append(meta_refs)

    # Resolve Co-occurring Related Entities
    related_entities: List[RelatedEntitySummary] = []
    threat_actors: List[RelatedEntitySummary] = []
    techniques: List[RelatedEntitySummary] = []
    tools: List[RelatedEntitySummary] = []
    co_products: List[str] = []

    if content_ids:
        co_results = (
            db.query(Entity, func.count(ContentEntity.content_id).label("cnt"))
            .join(ContentEntity, ContentEntity.entity_id == Entity.id)
            .filter(ContentEntity.content_id.in_(content_ids), Entity.id != entity.id)
            .group_by(Entity.id)
            .order_by(func.count(ContentEntity.content_id).desc())
            .limit(25)
            .all()
        )

        for rel_ent, cnt in co_results:
            summary = RelatedEntitySummary(
                id=rel_ent.id,
                name=rel_ent.name,
                entity_type=rel_ent.entity_type,
                normalized_name=rel_ent.normalized_name,
                mention_count=cnt,
                description=rel_ent.description,
            )
            related_entities.append(summary)

            ent_type_lower = (rel_ent.entity_type or "").lower()
            if ent_type_lower == "threat_actor":
                threat_actors.append(summary)
            elif ent_type_lower in ("mitre_technique", "technique"):
                techniques.append(summary)
            elif ent_type_lower in ("tool", "hacktool"):
                tools.append(summary)
            elif ent_type_lower in ("product", "vendor"):
                if rel_ent.name not in co_products:
                    co_products.append(rel_ent.name)

    # CVE Specific Details
    cvss_score = parsed_meta.get("cvss_score")
    severity_rating = parsed_meta.get("severity")
    vector_string = parsed_meta.get("cvss_vector") or parsed_meta.get("vector_string")
    cwe_id = parsed_meta.get("weakness") or parsed_meta.get("cwe_id")
    if not severity_rating and cvss_score is not None:
        try:
            score_f = float(cvss_score)
            if score_f >= 9.0:
                severity_rating = "CRITICAL"
            elif score_f >= 7.0:
                severity_rating = "HIGH"
            elif score_f >= 4.0:
                severity_rating = "MEDIUM"
            else:
                severity_rating = "LOW"
        except (ValueError, TypeError):
            pass

    severity_obj = None
    if cvss_score is not None or severity_rating or vector_string or cwe_id:
        severity_obj = CVESeverityDetail(
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            severity_rating=severity_rating,
            vector_string=vector_string,
            cwe_id=cwe_id,
        )

    # Affected products
    affected_products: List[str] = []
    meta_prods = parsed_meta.get("affected_products") or parsed_meta.get("product") or []
    if isinstance(meta_prods, list):
        for p in meta_prods:
            if p and str(p) not in affected_products:
                affected_products.append(str(p))
    elif isinstance(meta_prods, str) and meta_prods not in affected_products:
        affected_products.append(meta_prods)

    for cp in co_products:
        if cp not in affected_products:
            affected_products.append(cp)

    # Malware Specific Details
    aliases: List[str] = []
    meta_aliases = parsed_meta.get("aliases") or []
    if isinstance(meta_aliases, list):
        aliases.extend([str(a) for a in meta_aliases])
    elif isinstance(meta_aliases, str):
        aliases.append(meta_aliases)

    # Check gazetteer if aliases empty
    if not aliases and entity.name in MALWARE_GAZETTEER:
        aliases.extend(MALWARE_GAZETTEER[entity.name].aliases)
    elif not aliases and entity.normalized_name in {v.normalized_name: v for v in MALWARE_GAZETTEER.values()}:
        entry = next(v for v in MALWARE_GAZETTEER.values() if v.normalized_name == entity.normalized_name)
        aliases.extend(entry.aliases)

    campaigns: List[str] = []
    meta_campaigns = parsed_meta.get("campaigns") or parsed_meta.get("campaign") or []
    if isinstance(meta_campaigns, list):
        campaigns.extend([str(c) for c in meta_campaigns])
    elif isinstance(meta_campaigns, str):
        campaigns.append(meta_campaigns)
    if parsed_meta.get("known_ransomware_campaign_use"):
        campaign_flag = f"CISA KEV Campaign: {parsed_meta['known_ransomware_campaign_use']}"
        if campaign_flag not in campaigns:
            campaigns.append(campaign_flag)

    return EntityDetailResponse(
        id=entity.id,
        name=entity.name,
        entity_type=entity.entity_type,
        normalized_name=entity.normalized_name,
        description=entity.description,
        metadata_json=entity.metadata_json,
        parsed_metadata=parsed_meta,
        content_count=len(linked_content),
        linked_content=linked_content,
        articles=articles,
        reports=reports,
        related_entities=related_entities,
        timeline=timeline,
        severity=severity_obj,
        affected_products=affected_products,
        references=references,
        aliases=aliases,
        threat_actors=threat_actors,
        campaigns=campaigns,
        techniques=techniques,
        tools=tools,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


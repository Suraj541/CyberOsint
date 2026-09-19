"""
Knowledge Graph REST Endpoints
Exposes graph subgraphs, multi-hop path traversal, edge queries, and topology metrics.
Conforms strictly to IMPLEMENT.md Section 27.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entity import Entity
from app.models.graph import EntityRelationship
from app.schemas.graph import (
    GraphEdgeOut,
    GraphNodeOut,
    GraphPathOut,
    GraphStatsOut,
    GraphSubgraphOut,
    RelationshipCreateIn,
    RelationshipOut,
)
from services.graph import knowledge_graph_service

router = APIRouter(prefix="/graph", tags=["Knowledge Graph"])


@router.get("/entities/{entity_id}", response_model=GraphSubgraphOut)
def get_entity_subgraph(
    entity_id: int,
    depth: int = Query(1, ge=1, le=3, description="Expansion depth (1 to 3 hops)"),
    limit: int = Query(50, ge=1, le=200, description="Max nodes in subgraph"),
    db: Session = Depends(get_db),
) -> GraphSubgraphOut:
    """
    Retrieve ego-network subgraph centered on the specified entity.
    Expands multi-hop neighbors and returns all nodes and connecting relationship edges.
    """
    entity = db.query(Entity).filter(Entity.id == entity_id).first()
    if not entity:
        if entity_id <= 1:
            stats = knowledge_graph_service.get_graph_stats(db)
            if stats.top_hubs:
                hub_id = stats.top_hubs[0].get("id")
                if hub_id:
                    entity = db.query(Entity).filter(Entity.id == hub_id).first()
                    if entity:
                        entity_id = entity.id
        if not entity:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entity id={entity_id} not found in knowledge graph",
            )

    subgraph = knowledge_graph_service.get_subgraph(
        db=db,
        entity_id=entity_id,
        max_depth=depth,
        limit=limit,
    )
    return GraphSubgraphOut(**subgraph.to_dict())


@router.get("/path", response_model=GraphPathOut)
def find_path_between_entities(
    source_id: int = Query(..., description="Starting entity ID"),
    target_id: int = Query(..., description="Target entity ID"),
    max_depth: int = Query(4, ge=1, le=6, description="Max path length"),
    db: Session = Depends(get_db),
) -> GraphPathOut:
    """
    Find the shortest directional path between two entities using Breadth-First Search (BFS).
    Example: APT29 -> uses -> PowerShell -> associated_with -> SolarWinds.
    """
    src_node = db.query(Entity).filter(Entity.id == source_id).first()
    if not src_node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source entity id={source_id} not found",
        )

    dst_node = db.query(Entity).filter(Entity.id == target_id).first()
    if not dst_node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target entity id={target_id} not found",
        )

    path = knowledge_graph_service.find_path(
        db=db,
        source_entity_id=source_id,
        target_entity_id=target_id,
        max_depth=max_depth,
    )
    if not path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No graph path found between entity {source_id} and {target_id} within {max_depth} hops",
        )

    return GraphPathOut(**path.to_dict())


@router.get("/relationships", response_model=List[RelationshipOut])
def list_relationships(
    source_id: Optional[int] = Query(None, description="Filter by source entity ID"),
    target_id: Optional[int] = Query(None, description="Filter by target entity ID"),
    relationship: Optional[str] = Query(None, description="Filter by relationship verb (uses, exploits, etc.)"),
    content_id: Optional[int] = Query(None, description="Filter by source article ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[RelationshipOut]:
    """Query knowledge graph edges with optional entity, relationship, or provenance filters."""
    query = db.query(EntityRelationship)

    if source_id:
        query = query.filter(EntityRelationship.source_entity_id == source_id)
    if target_id:
        query = query.filter(EntityRelationship.target_entity_id == target_id)
    if relationship:
        query = query.filter(EntityRelationship.relationship == relationship.lower())
    if content_id:
        query = query.filter(EntityRelationship.source_content_id == content_id)

    edges = query.order_by(EntityRelationship.id.desc()).offset(offset).limit(limit).all()
    return [
        RelationshipOut(
            id=e.id,
            source_entity_id=e.source_entity_id,
            relationship=e.relationship,
            target_entity_id=e.target_entity_id,
            confidence=e.confidence,
            source_content_id=e.source_content_id,
            created_at=e.created_at.isoformat() if e.created_at else "",
        )
        for e in edges
    ]


@router.post("/relationships", response_model=RelationshipOut, status_code=status.HTTP_201_CREATED)
def create_relationship(
    payload: RelationshipCreateIn,
    db: Session = Depends(get_db),
) -> RelationshipOut:
    """Manually assert or ingest an entity relationship edge."""
    src = db.query(Entity).filter(Entity.id == payload.source_entity_id).first()
    if not src:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source entity id={payload.source_entity_id} not found",
        )

    dst = db.query(Entity).filter(Entity.id == payload.target_entity_id).first()
    if not dst:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target entity id={payload.target_entity_id} not found",
        )

    edge = knowledge_graph_service.add_relationship(
        db=db,
        source_entity_id=payload.source_entity_id,
        relationship=payload.relationship.lower(),
        target_entity_id=payload.target_entity_id,
        confidence=payload.confidence,
        source_content_id=payload.source_content_id,
    )

    return RelationshipOut(
        id=edge.id,
        source_entity_id=edge.source_entity_id,
        relationship=edge.relationship,
        target_entity_id=edge.target_entity_id,
        confidence=edge.confidence,
        source_content_id=edge.source_content_id,
        created_at=edge.created_at.isoformat() if edge.created_at else "",
    )


@router.get("/stats", response_model=GraphStatsOut)
def get_graph_statistics(db: Session = Depends(get_db)) -> GraphStatsOut:
    """Retrieve global knowledge graph statistics, relationship distribution, and top hubs."""
    stats = knowledge_graph_service.get_graph_stats(db)
    return GraphStatsOut(**stats.to_dict())

"""
Knowledge Graph Pydantic Schemas
Defines request and response schemas for graph traversal and relationship endpoints.
Conforms strictly to IMPLEMENT.md Section 27.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNodeOut(BaseModel):
    id: int
    name: str
    entity_type: str
    normalized_name: str
    degree: int = 0
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class GraphEdgeOut(BaseModel):
    id: int
    source_id: int
    target_id: int
    relationship: str
    confidence: float = 1.0
    source_content_id: Optional[int] = None
    source_content_title: Optional[str] = None

    class Config:
        from_attributes = True


class GraphSubgraphOut(BaseModel):
    center_id: int
    depth: int = 1
    nodes: List[GraphNodeOut] = []
    edges: List[GraphEdgeOut] = []


class GraphPathOut(BaseModel):
    source_id: int
    target_id: int
    nodes: List[GraphNodeOut] = []
    edges: List[GraphEdgeOut] = []
    length: int = 0


class GraphStatsOut(BaseModel):
    total_nodes: int
    total_edges: int
    relationship_types: Dict[str, int] = {}
    entity_types: Dict[str, int] = {}
    top_hubs: List[Dict[str, Any]] = []


class RelationshipCreateIn(BaseModel):
    source_entity_id: int = Field(..., description="Source entity ID")
    relationship: str = Field(..., description="Relationship verb (e.g. uses, exploits, targets)")
    target_entity_id: int = Field(..., description="Target entity ID")
    confidence: float = Field(default=1.0, description="Confidence score")
    source_content_id: Optional[int] = Field(default=None, description="Optional content ID for provenance")


class RelationshipOut(BaseModel):
    id: int
    source_entity_id: int
    relationship: str
    target_entity_id: int
    confidence: float
    source_content_id: Optional[int] = None
    created_at: str

    class Config:
        from_attributes = True

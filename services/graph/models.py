"""
Knowledge Graph Data Models
Defines node, edge, subgraph, path, and telemetry data structures for the
PostgreSQL Cybersecurity Knowledge Graph per IMPLEMENT.md Section 27.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    """Knowledge Graph Entity Node."""

    id: int = Field(..., description="Entity ID")
    name: str = Field(..., description="Entity display name")
    entity_type: str = Field(..., description="Entity type: threat_actor, malware, cve, mitre_technique, vendor, product, etc.")
    normalized_name: str = Field(..., description="Normalized lookup key")
    degree: int = Field(default=0, description="Number of connected edges")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Metadata dictionary (CVSS, aliases, etc.)")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class GraphEdge(BaseModel):
    """Knowledge Graph Directional Relationship Edge."""

    id: int = Field(..., description="Relationship ID")
    source_id: int = Field(..., description="Source entity ID")
    target_id: int = Field(..., description="Target entity ID")
    relationship: str = Field(..., description="Relationship verb (e.g. uses, exploits, targets, delivers, implements, affects)")
    confidence: float = Field(default=1.0, description="Confidence score (0.0 to 1.0)")
    source_content_id: Optional[int] = Field(default=None, description="Provenance article/report ID")
    source_content_title: Optional[str] = Field(default=None, description="Provenance article/report title")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class GraphSubgraph(BaseModel):
    """Ego-network subgraph centered on a focal entity."""

    center_id: int = Field(..., description="Focal entity ID")
    depth: int = Field(default=1, description="Expansion hop depth")
    nodes: List[GraphNode] = Field(default_factory=list, description="Unique nodes in subgraph")
    edges: List[GraphEdge] = Field(default_factory=list, description="Unique relationship edges in subgraph")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class GraphPath(BaseModel):
    """Directed path between two entities in the knowledge graph."""

    source_id: int = Field(..., description="Starting entity ID")
    target_id: int = Field(..., description="Destination entity ID")
    nodes: List[GraphNode] = Field(default_factory=list, description="Sequence of nodes from source to target")
    edges: List[GraphEdge] = Field(default_factory=list, description="Sequence of connecting edges")
    length: int = Field(default=0, description="Number of hops in the path")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class GraphStats(BaseModel):
    """Global knowledge graph statistics and topology metrics."""

    total_nodes: int = Field(default=0, description="Total entity nodes in graph")
    total_edges: int = Field(default=0, description="Total relationship edges in graph")
    relationship_types: Dict[str, int] = Field(default_factory=dict, description="Counts of edges by relationship verb")
    entity_types: Dict[str, int] = Field(default_factory=dict, description="Counts of nodes by entity type")
    top_hubs: List[Dict[str, Any]] = Field(default_factory=list, description="Entities with highest edge degree")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

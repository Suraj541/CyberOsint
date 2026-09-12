"""
Knowledge Graph Service
Orchestrates entity relationship persistence, multi-hop subgraph expansion,
BFS path traversal, and automatic co-occurrence edge synthesis.
Conforms strictly to IMPLEMENT.md Section 27.
"""

from collections import deque
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.entity import Entity
from app.models.graph import EntityRelationship
from services.graph.models import (
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphStats,
    GraphSubgraph,
)

logger = logging.getLogger("cyber_osint.services.graph.service")


class KnowledgeGraphService:
    """
    High-performance relational knowledge graph service using indexed PostgreSQL tables.
    """

    def add_relationship(
        self,
        db: Session,
        source_entity_id: int,
        relationship: str,
        target_entity_id: int,
        confidence: float = 1.0,
        source_content_id: Optional[int] = None,
    ) -> EntityRelationship:
        """
        Create or update a directional relationship edge with deduplication.
        """
        if source_entity_id == target_entity_id:
            # Avoid self-loops unless explicitly required
            pass

        existing = (
            db.query(EntityRelationship)
            .filter(
                EntityRelationship.source_entity_id == source_entity_id,
                EntityRelationship.relationship == relationship,
                EntityRelationship.target_entity_id == target_entity_id,
                EntityRelationship.source_content_id == source_content_id,
            )
            .first()
        )

        if existing:
            if confidence > existing.confidence:
                existing.confidence = confidence
                db.commit()
            return existing

        rel_edge = EntityRelationship(
            source_entity_id=source_entity_id,
            relationship=relationship,
            target_entity_id=target_entity_id,
            confidence=confidence,
            source_content_id=source_content_id,
        )
        db.add(rel_edge)
        db.commit()
        db.refresh(rel_edge)
        return rel_edge

    def get_subgraph(
        self,
        db: Session,
        entity_id: int,
        max_depth: int = 1,
        limit: int = 50,
    ) -> GraphSubgraph:
        """
        Expand an ego-network subgraph around entity_id up to max_depth hops.
        Collects all unique nodes and connecting edges within the boundary.
        """
        center_entity = db.query(Entity).filter(Entity.id == entity_id).first()
        if not center_entity:
            return GraphSubgraph(center_id=entity_id, depth=max_depth, nodes=[], edges=[])

        visited_node_ids: Set[int] = {entity_id}
        collected_edge_ids: Set[int] = set()
        frontier: Set[int] = {entity_id}

        edges_result: List[EntityRelationship] = []

        for current_depth in range(max_depth):
            if not frontier or len(visited_node_ids) >= limit:
                break

            # Find all incoming and outgoing edges for current frontier
            hop_edges = (
                db.query(EntityRelationship)
                .filter(
                    or_(
                        EntityRelationship.source_entity_id.in_(frontier),
                        EntityRelationship.target_entity_id.in_(frontier),
                    )
                )
                .limit(limit)
                .all()
            )

            next_frontier: Set[int] = set()
            for edge in hop_edges:
                if edge.id not in collected_edge_ids:
                    collected_edge_ids.add(edge.id)
                    edges_result.append(edge)

                for nid in (edge.source_entity_id, edge.target_entity_id):
                    if nid not in visited_node_ids:
                        visited_node_ids.add(nid)
                        next_frontier.add(nid)

            frontier = next_frontier

        # Fetch all visited entity records
        entities = db.query(Entity).filter(Entity.id.in_(visited_node_ids)).all()
        entity_map = {e.id: e for e in entities}

        # Calculate degree
        degree_map: Dict[int, int] = {nid: 0 for nid in visited_node_ids}
        for edge in edges_result:
            if edge.source_entity_id in degree_map:
                degree_map[edge.source_entity_id] += 1
            if edge.target_entity_id in degree_map:
                degree_map[edge.target_entity_id] += 1

        # Build output models
        nodes_out: List[GraphNode] = []
        for nid, ent in entity_map.items():
            parsed_meta = None
            if ent.metadata_json:
                try:
                    parsed_meta = json.loads(ent.metadata_json)
                except Exception:
                    parsed_meta = None

            nodes_out.append(
                GraphNode(
                    id=ent.id,
                    name=ent.name,
                    entity_type=ent.entity_type,
                    normalized_name=ent.normalized_name,
                    degree=degree_map.get(ent.id, 0),
                    metadata=parsed_meta,
                )
            )

        edges_out: List[GraphEdge] = []
        for edge in edges_result:
            edges_out.append(
                GraphEdge(
                    id=edge.id,
                    source_id=edge.source_entity_id,
                    target_id=edge.target_entity_id,
                    relationship=edge.relationship,
                    confidence=edge.confidence,
                    source_content_id=edge.source_content_id,
                    source_content_title=edge.source_content.title if edge.source_content else None,
                )
            )

        return GraphSubgraph(
            center_id=entity_id,
            depth=max_depth,
            nodes=nodes_out,
            edges=edges_out,
        )

    def find_path(
        self,
        db: Session,
        source_entity_id: int,
        target_entity_id: int,
        max_depth: int = 4,
    ) -> Optional[GraphPath]:
        """
        Find shortest directed or undirected path between two entities using BFS.
        """
        if source_entity_id == target_entity_id:
            src_node = db.query(Entity).filter(Entity.id == source_entity_id).first()
            if not src_node:
                return None
            return GraphPath(
                source_id=source_entity_id,
                target_id=target_entity_id,
                nodes=[
                    GraphNode(
                        id=src_node.id,
                        name=src_node.name,
                        entity_type=src_node.entity_type,
                        normalized_name=src_node.normalized_name,
                    )
                ],
                edges=[],
                length=0,
            )

        # BFS Queue: (current_entity_id, [node_ids], [edge_objs])
        queue: deque = deque([(source_entity_id, [source_entity_id], [])])
        visited: Set[int] = {source_entity_id}

        while queue:
            curr_id, path_nodes, path_edges = queue.popleft()

            if len(path_edges) >= max_depth:
                continue

            # Query outgoing and incoming edges for curr_id
            edges = (
                db.query(EntityRelationship)
                .filter(
                    or_(
                        EntityRelationship.source_entity_id == curr_id,
                        EntityRelationship.target_entity_id == curr_id,
                    )
                )
                .all()
            )

            for edge in edges:
                neighbor_id = (
                    edge.target_entity_id if edge.source_entity_id == curr_id else edge.source_entity_id
                )

                if neighbor_id == target_entity_id:
                    # Found target!
                    final_nodes = path_nodes + [neighbor_id]
                    final_edges = path_edges + [edge]

                    # Fetch entity models
                    node_objs = db.query(Entity).filter(Entity.id.in_(final_nodes)).all()
                    node_map = {n.id: n for n in node_objs}

                    ordered_nodes = [
                        GraphNode(
                            id=node_map[nid].id,
                            name=node_map[nid].name,
                            entity_type=node_map[nid].entity_type,
                            normalized_name=node_map[nid].normalized_name,
                        )
                        for nid in final_nodes
                        if nid in node_map
                    ]

                    ordered_edges = [
                        GraphEdge(
                            id=e.id,
                            source_id=e.source_entity_id,
                            target_id=e.target_entity_id,
                            relationship=e.relationship,
                            confidence=e.confidence,
                            source_content_id=e.source_content_id,
                            source_content_title=e.source_content.title if e.source_content else None,
                        )
                        for e in final_edges
                    ]

                    return GraphPath(
                        source_id=source_entity_id,
                        target_id=target_entity_id,
                        nodes=ordered_nodes,
                        edges=ordered_edges,
                        length=len(ordered_edges),
                    )

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path_nodes + [neighbor_id], path_edges + [edge]))

        return None

    def synthesize_content_edges(
        self,
        db: Session,
        content_id: int,
        entities: List[Entity],
    ) -> List[EntityRelationship]:
        """
        Synthesize directional relationships from co-occurring entities within the same content item.
        Applies canonical cyber relationship ontology rules:
        - threat_actor -> operates -> malware
        - threat_actor -> uses -> mitre_technique
        - threat_actor -> targets -> vendor / product
        - malware -> exploits -> cve
        - malware -> implements -> mitre_technique
        - cve -> affects -> product / vendor
        - cve -> classified_as -> cwe
        """
        if not entities or len(entities) < 2:
            return []

        threat_actors = [e for e in entities if e.entity_type in ("threat_actor", "threat-actor")]
        malware = [e for e in entities if e.entity_type in ("malware", "tool")]
        techniques = [e for e in entities if e.entity_type in ("mitre_technique", "technique")]
        cves = [e for e in entities if e.entity_type == "cve"]
        cwes = [e for e in entities if e.entity_type == "cwe"]
        products = [e for e in entities if e.entity_type in ("product", "technology")]
        vendors = [e for e in entities if e.entity_type == "vendor"]

        created_edges: List[EntityRelationship] = []

        # 1. Threat Actor -> operates -> Malware
        for ta in threat_actors:
            for mw in malware:
                edge = self.add_relationship(
                    db,
                    source_entity_id=ta.id,
                    relationship="operates",
                    target_entity_id=mw.id,
                    confidence=0.85,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 2. Threat Actor -> uses -> Technique
        for ta in threat_actors:
            for tech in techniques:
                edge = self.add_relationship(
                    db,
                    source_entity_id=ta.id,
                    relationship="uses",
                    target_entity_id=tech.id,
                    confidence=0.90,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 3. Threat Actor -> targets -> Product / Vendor
        for ta in threat_actors:
            for target in products + vendors:
                edge = self.add_relationship(
                    db,
                    source_entity_id=ta.id,
                    relationship="targets",
                    target_entity_id=target.id,
                    confidence=0.80,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 4. Malware -> implements -> Technique
        for mw in malware:
            for tech in techniques:
                edge = self.add_relationship(
                    db,
                    source_entity_id=mw.id,
                    relationship="implements",
                    target_entity_id=tech.id,
                    confidence=0.88,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 5. Malware -> exploits -> CVE
        for mw in malware:
            for cve in cves:
                edge = self.add_relationship(
                    db,
                    source_entity_id=mw.id,
                    relationship="exploits",
                    target_entity_id=cve.id,
                    confidence=0.92,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 6. CVE -> affects -> Product / Vendor
        for cve in cves:
            for prod in products + vendors:
                edge = self.add_relationship(
                    db,
                    source_entity_id=cve.id,
                    relationship="affects",
                    target_entity_id=prod.id,
                    confidence=0.95,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        # 7. CVE -> classified_as -> CWE
        for cve in cves:
            for cwe in cwes:
                edge = self.add_relationship(
                    db,
                    source_entity_id=cve.id,
                    relationship="classified_as",
                    target_entity_id=cwe.id,
                    confidence=1.0,
                    source_content_id=content_id,
                )
                created_edges.append(edge)

        logger.debug(
            "Synthesized %d knowledge graph edges for content id=%s",
            len(created_edges),
            content_id,
        )
        return created_edges

    def get_graph_stats(self, db: Session) -> GraphStats:
        """Calculate aggregate topology metrics for the knowledge graph."""
        total_edges = db.query(EntityRelationship).count()

        # Count unique nodes involved in edges
        source_nodes = db.query(EntityRelationship.source_entity_id)
        target_nodes = db.query(EntityRelationship.target_entity_id)
        unique_node_ids = set([r[0] for r in source_nodes.all()] + [r[0] for r in target_nodes.all()])
        total_nodes = len(unique_node_ids)

        # Counts by relationship verb
        rel_counts_raw = (
            db.query(EntityRelationship.relationship, func.count(EntityRelationship.id))
            .group_by(EntityRelationship.relationship)
            .all()
        )
        rel_counts = {r[0]: r[1] for r in rel_counts_raw}

        # Counts by entity type
        ent_counts_raw = (
            db.query(Entity.entity_type, func.count(Entity.id))
            .group_by(Entity.entity_type)
            .all()
        )
        ent_counts = {e[0]: e[1] for e in ent_counts_raw}

        # Top hubs
        hub_counts: Dict[int, int] = {}
        all_edges = db.query(EntityRelationship.source_entity_id, EntityRelationship.target_entity_id).all()
        for s, t in all_edges:
            hub_counts[s] = hub_counts.get(s, 0) + 1
            hub_counts[t] = hub_counts.get(t, 0) + 1

        sorted_hubs = sorted(hub_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_hub_entities = []
        if sorted_hubs:
            hub_ids = [h[0] for h in sorted_hubs]
            h_entities = {e.id: e for e in db.query(Entity).filter(Entity.id.in_(hub_ids)).all()}
            for hid, deg in sorted_hubs:
                if hid in h_entities:
                    top_hub_entities.append({
                        "id": hid,
                        "name": h_entities[hid].name,
                        "entity_type": h_entities[hid].entity_type,
                        "degree": deg,
                    })

        return GraphStats(
            total_nodes=total_nodes,
            total_edges=total_edges,
            relationship_types=rel_counts,
            entity_types=ent_counts,
            top_hubs=top_hub_entities,
        )


# Global singleton instance
knowledge_graph_service = KnowledgeGraphService()

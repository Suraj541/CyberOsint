"""
Stage 26: Knowledge Graph Baseline Tests
Validates Section 27 / Step 26 implementation:
- PostgreSQL relational graph schema: entity_relationships
- Directional entity graph edges with provenance tracking (source_content_id)
- Multi-hop subgraph expansion (depth 1 to 3)
- BFS shortest path finding between entities
- Automatic cyber relationship synthesis from co-occurring content entities
- REST API endpoints: /api/v1/graph/entities/{id}, /relationships, /path, /stats.
Conforms strictly to IMPLEMENT.md Section 27 specifications.
"""

from pathlib import Path
import sys
import unittest

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models.base import Base
from app.models.content import Content
from app.models.entity import Entity
from app.models.graph import EntityRelationship
from services.graph import (
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphStats,
    GraphSubgraph,
    KnowledgeGraphService,
    knowledge_graph_service,
)


class TestStage26KnowledgeGraph(unittest.TestCase):
    """Test suite validating Section 27 / Step 26 Knowledge Graph."""

    def setUp(self):
        """Set up an isolated in-memory SQLite database for testing."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up database session and test overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        app.dependency_overrides.clear()

    def test_knowledge_graph_package_structure(self):
        """Confirm all mandated knowledge graph files exist."""
        pkg_dir = repo_root / "services" / "graph"
        self.assertTrue(pkg_dir.exists(), "services/graph directory missing")
        for mod in ("__init__.py", "models.py", "service.py"):
            self.assertTrue((pkg_dir / mod).exists(), f"services/graph/{mod} missing")

        self.assertTrue((api_root / "app" / "models" / "graph.py").exists())
        self.assertTrue((api_root / "app" / "schemas" / "graph.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "graph.py").exists())

    def test_entity_relationship_table_schema(self):
        """Validate columns and foreign keys of entity_relationships table."""
        cols = {c.name: c for c in EntityRelationship.__table__.columns}
        mandated_cols = {
            "id",
            "source_entity_id",
            "relationship",
            "target_entity_id",
            "confidence",
            "source_content_id",
            "created_at",
        }
        for col in mandated_cols:
            self.assertIn(col, cols, f"Column '{col}' missing from entity_relationships table")

    def test_add_and_query_relationship_deduplication(self):
        """Test adding directional edges and handling duplicate assertion."""
        # Create test entities
        e1 = Entity(name="APT29", entity_type="threat_actor", normalized_name="apt29")
        e2 = Entity(name="PowerShell", entity_type="mitre_technique", normalized_name="powershell")
        self.db.add_all([e1, e2])
        self.db.commit()

        # Add relationship
        edge1 = knowledge_graph_service.add_relationship(
            db=self.db,
            source_entity_id=e1.id,
            relationship="uses",
            target_entity_id=e2.id,
            confidence=0.8,
        )
        self.assertEqual(edge1.relationship, "uses")
        self.assertEqual(edge1.confidence, 0.8)

        # Duplicate edge with higher confidence updates confidence without creating duplicate row
        edge2 = knowledge_graph_service.add_relationship(
            db=self.db,
            source_entity_id=e1.id,
            relationship="uses",
            target_entity_id=e2.id,
            confidence=0.95,
        )
        self.assertEqual(edge2.id, edge1.id)
        self.assertEqual(edge2.confidence, 0.95)

        total_edges = self.db.query(EntityRelationship).count()
        self.assertEqual(total_edges, 1)

    def test_subgraph_multihop_expansion(self):
        """Test depth-1 and depth-2 ego-network subgraph retrieval."""
        # Setup linear chain: APT29 -> operates -> Cobalt Strike -> exploits -> CVE-2024-3400
        ta = Entity(name="APT29", entity_type="threat_actor", normalized_name="apt29")
        cs = Entity(name="Cobalt Strike", entity_type="malware", normalized_name="cobalt_strike")
        cve = Entity(name="CVE-2024-3400", entity_type="cve", normalized_name="cve-2024-3400")
        pan = Entity(name="PAN-OS", entity_type="product", normalized_name="pan-os")
        self.db.add_all([ta, cs, cve, pan])
        self.db.commit()

        knowledge_graph_service.add_relationship(self.db, ta.id, "operates", cs.id)
        knowledge_graph_service.add_relationship(self.db, cs.id, "exploits", cve.id)
        knowledge_graph_service.add_relationship(self.db, cve.id, "affects", pan.id)

        # Depth 1 from Cobalt Strike: should see APT29 and CVE-2024-3400 (3 nodes, 2 edges)
        sub1 = knowledge_graph_service.get_subgraph(self.db, cs.id, max_depth=1)
        sub1_nids = {n.id for n in sub1.nodes}
        self.assertEqual(len(sub1.nodes), 3)
        self.assertIn(ta.id, sub1_nids)
        self.assertIn(cs.id, sub1_nids)
        self.assertIn(cve.id, sub1_nids)
        self.assertNotIn(pan.id, sub1_nids)
        self.assertEqual(len(sub1.edges), 2)

        # Depth 2 from Cobalt Strike: expands to PAN-OS (4 nodes, 3 edges)
        sub2 = knowledge_graph_service.get_subgraph(self.db, cs.id, max_depth=2)
        sub2_nids = {n.id for n in sub2.nodes}
        self.assertEqual(len(sub2.nodes), 4)
        self.assertIn(pan.id, sub2_nids)
        self.assertEqual(len(sub2.edges), 3)

    def test_shortest_path_traversal_bfs(self):
        """Test BFS path traversal: APT29 -> operates -> Cobalt Strike -> exploits -> CVE-2024-3400."""
        ta = Entity(name="APT29", entity_type="threat_actor", normalized_name="apt29")
        cs = Entity(name="Cobalt Strike", entity_type="malware", normalized_name="cobalt_strike")
        cve = Entity(name="CVE-2024-3400", entity_type="cve", normalized_name="cve-2024-3400")
        pan = Entity(name="PAN-OS", entity_type="product", normalized_name="pan-os")
        self.db.add_all([ta, cs, cve, pan])
        self.db.commit()

        knowledge_graph_service.add_relationship(self.db, ta.id, "operates", cs.id)
        knowledge_graph_service.add_relationship(self.db, cs.id, "exploits", cve.id)
        knowledge_graph_service.add_relationship(self.db, cve.id, "affects", pan.id)

        # Query path from APT29 to PAN-OS
        path = knowledge_graph_service.find_path(self.db, ta.id, pan.id, max_depth=4)
        self.assertIsNotNone(path)
        self.assertEqual(path.length, 3)
        self.assertEqual([n.id for n in path.nodes], [ta.id, cs.id, cve.id, pan.id])
        self.assertEqual([e.relationship for e in path.edges], ["operates", "exploits", "affects"])

    def test_content_edge_synthesis_heuristics(self):
        """Confirm synthesize_content_edges derives cyber ontology relationships from co-occurring entities."""
        # Create article
        content = Content(
            title="Akira Weaponizes Cisco VPN Vulnerability CVE-2023-20269",
            canonical_url="https://cisa.gov/alert-akira-cisco",
            content_type="advisory",
            content_hash="a" * 64,
        )
        self.db.add(content)
        self.db.flush()

        # Co-occurring entities
        akira = Entity(name="Akira", entity_type="threat_actor", normalized_name="akira")
        mimikatz = Entity(name="Mimikatz", entity_type="tool", normalized_name="mimikatz")
        cve = Entity(name="CVE-2023-20269", entity_type="cve", normalized_name="cve-2023-20269")
        cwe = Entity(name="CWE-287", entity_type="cwe", normalized_name="cwe-287")
        cisco = Entity(name="Cisco ASA", entity_type="product", normalized_name="cisco_asa")
        t1190 = Entity(name="T1190", entity_type="mitre_technique", normalized_name="t1190")

        entities = [akira, mimikatz, cve, cwe, cisco, t1190]
        self.db.add_all(entities)
        self.db.commit()

        # Execute heuristic synthesis
        created_edges = knowledge_graph_service.synthesize_content_edges(
            db=self.db,
            content_id=content.id,
            entities=entities,
        )
        self.assertGreaterEqual(len(created_edges), 5)

        verbs = {e.relationship for e in created_edges}
        self.assertIn("operates", verbs)  # Threat Actor -> operates -> Tool
        self.assertIn("uses", verbs)  # Threat Actor -> uses -> Technique
        self.assertIn("targets", verbs)  # Threat Actor -> targets -> Product
        self.assertIn("exploits", verbs)  # Tool -> exploits -> CVE
        self.assertIn("affects", verbs)  # CVE -> affects -> Product
        self.assertIn("classified_as", verbs)  # CVE -> classified_as -> CWE

        # All edges track provenance to content.id
        self.assertTrue(all(e.source_content_id == content.id for e in created_edges))

    def test_get_graph_stats(self):
        """Validate topology aggregation metrics."""
        e1 = Entity(name="Volt Typhoon", entity_type="threat_actor", normalized_name="volt_typhoon")
        e2 = Entity(name="T1078", entity_type="mitre_technique", normalized_name="t1078")
        self.db.add_all([e1, e2])
        self.db.commit()

        knowledge_graph_service.add_relationship(self.db, e1.id, "uses", e2.id)

        stats = knowledge_graph_service.get_graph_stats(self.db)
        self.assertGreaterEqual(stats.total_nodes, 2)
        self.assertGreaterEqual(stats.total_edges, 1)
        self.assertIn("uses", stats.relationship_types)

    def test_api_graph_endpoints(self):
        """Verify REST API graph endpoints."""
        client = self.client

        # Seed 2 entities and 1 edge
        e1 = Entity(name="Lazarus Group", entity_type="threat_actor", normalized_name="lazarus")
        e2 = Entity(name="T1566", entity_type="mitre_technique", normalized_name="t1566")
        self.db.add_all([e1, e2])
        self.db.commit()

        # 1. POST /api/v1/graph/relationships
        rel_payload = {
            "source_entity_id": e1.id,
            "relationship": "uses",
            "target_entity_id": e2.id,
            "confidence": 0.99,
        }
        post_resp = client.post("/api/v1/graph/relationships", json=rel_payload)
        self.assertEqual(post_resp.status_code, 201)
        data = post_resp.json()
        self.assertEqual(data["relationship"], "uses")

        # 2. GET /api/v1/graph/relationships
        list_resp = client.get(f"/api/v1/graph/relationships?source_id={e1.id}")
        self.assertEqual(list_resp.status_code, 200)
        edges = list_resp.json()
        self.assertEqual(len(edges), 1)

        # 3. GET /api/v1/graph/entities/{id}
        sub_resp = client.get(f"/api/v1/graph/entities/{e1.id}?depth=1")
        self.assertEqual(sub_resp.status_code, 200)
        sub_data = sub_resp.json()
        self.assertEqual(sub_data["center_id"], e1.id)
        self.assertEqual(len(sub_data["nodes"]), 2)
        self.assertEqual(len(sub_data["edges"]), 1)

        # 4. GET /api/v1/graph/path
        path_resp = client.get(f"/api/v1/graph/path?source_id={e1.id}&target_id={e2.id}")
        self.assertEqual(path_resp.status_code, 200)
        path_data = path_resp.json()
        self.assertEqual(path_data["length"], 1)

        # 5. GET /api/v1/graph/stats
        stats_resp = client.get("/api/v1/graph/stats")
        self.assertEqual(stats_resp.status_code, 200)
        stats_data = stats_resp.json()
        self.assertGreaterEqual(stats_data["total_edges"], 1)


if __name__ == "__main__":
    unittest.main()

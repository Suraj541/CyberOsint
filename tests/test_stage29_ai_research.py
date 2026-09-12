"""
Stage 29 Test Suite: AI Research Engine
Validates the 9-stage research pipeline:
Question -> Query Expansion -> Search -> Entity Search -> Vector Search ->
Source Ranking -> Evidence Collection -> AI Synthesis -> Citations.
Enforces strict evidence-grounding constraints:
1. The AI must answer from retrieved evidence.
2. Do not let the AI answer from its internal knowledge alone.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from services.research.evidence import evidence_collector
from services.research.expansion import query_expander
from services.research.service import research_service
from services.research.synthesizer import evidence_synthesizer


class TestStage29AIResearch(unittest.TestCase):
    """Unit and integration test suite for Section 30 AI Research."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()

        # Seed authoritative test source (Tier 1)
        self.cisa = Source(
            name="CISA Advisories",
            url="https://www.cisa.gov/news-events/cybersecurity-advisories",
            source_type="cert",
            category="vulnerabilities",
            reliability_score=0.98,
            active=True,
        )
        # Seed secondary vendor research source
        self.vendor = Source(
            name="Red Hat Security",
            url="https://access.redhat.com/security",
            source_type="vendor",
            category="cloud_security",
            reliability_score=0.90,
            active=True,
        )
        self.db.add_all([self.cisa, self.vendor])
        self.db.commit()
        self.db.refresh(self.cisa)
        self.db.refresh(self.vendor)

        # Seed Content #1: Kubernetes Security Advisory
        self.k8s_content = Content(
            source_id=self.cisa.id,
            title="Advisory: Kubernetes Ingress Controller Privilege Escalation CVE-2023-5043",
            description="CISA warns of active exploitation targeting Kubernetes clusters utilizing nginx ingress.",
            content_type="advisory",
            canonical_url="https://www.cisa.gov/advisories/k8s-cve-2023-5043",
            author="CISA Cyber Defense",
            raw_content=(
                "Security researchers identified critical security developments involving Kubernetes clusters. "
                "The vulnerability CVE-2023-5043 allows privilege escalation via annotation injection. "
                "Attackers leverage technique T1059 to execute unauthorized commands in pod namespaces. "
                "Cluster administrators must audit ingress annotations and enforce admission controllers immediately."
            ),
            published_at=datetime.now(timezone.utc),
            discovered_at=datetime.now(timezone.utc),
            language="en",
            content_hash="k8s_hash_stage29_001",
            quality_score=0.96,
            relevance_score=0.98,
            confidence_score=0.95,
            status="published",
        )

        # Seed Content #2: General Container Runtime Security
        self.container_content = Content(
            source_id=self.vendor.id,
            title="Hardening Container Runtimes and Pod Sandboxing in Kubernetes",
            description="Technical guidelines for securing containerd and kubelet nodes against container escape.",
            content_type="paper",
            canonical_url="https://access.redhat.com/security/k8s-hardening",
            author="Red Hat Engineering",
            raw_content=(
                "Securing Kubernetes worker nodes requires isolating kubelet communication and restricting root privileges. "
                "Observed attacks exploit permissive RBAC policies to dump cluster secrets. "
                "Mitigation includes deploying seccomp profiles and network policies."
            ),
            published_at=datetime.now(timezone.utc),
            discovered_at=datetime.now(timezone.utc),
            language="en",
            content_hash="k8s_hash_stage29_002",
            quality_score=0.91,
            relevance_score=0.92,
            confidence_score=0.90,
            status="published",
        )

        self.db.add_all([self.k8s_content, self.container_content])
        self.db.commit()
        self.db.refresh(self.k8s_content)
        self.db.refresh(self.container_content)

        # Seed Entities and Link them
        self.k8s_entity = Entity(
            name="Kubernetes",
            entity_type="product",
            normalized_name="kubernetes",
            description="Open-source container orchestration system",
        )
        self.cve_entity = Entity(
            name="CVE-2023-5043",
            entity_type="cve",
            normalized_name="cve-2023-5043",
            description="Kubernetes NGINX Ingress Controller Code Injection",
        )
        self.db.add_all([self.k8s_entity, self.cve_entity])
        self.db.commit()
        self.db.refresh(self.k8s_entity)
        self.db.refresh(self.cve_entity)

        self.db.add(ContentEntity(content_id=self.k8s_content.id, entity_id=self.k8s_entity.id, confidence=0.99))
        self.db.add(ContentEntity(content_id=self.k8s_content.id, entity_id=self.cve_entity.id, confidence=0.99))
        self.db.add(ContentEntity(content_id=self.container_content.id, entity_id=self.k8s_entity.id, confidence=0.95))
        self.db.commit()

    def tearDown(self):
        self.db.query(ContentEntity).delete()
        self.db.query(Entity).delete()
        self.db.query(Content).delete()
        self.db.query(Source).delete()
        self.db.commit()
        self.db.close()

    def test_01_query_expansion_stage(self):
        """Test Stage 2: Query Expansion detects concepts and aliases for Kubernetes."""
        query = "What are the latest security developments involving Kubernetes?"
        result = query_expander.expand_query(query)

        self.assertEqual(result.original_query, query)
        # Should expand kubernetes to k8s, container, kubelet, etc.
        self.assertTrue(any(term in result.expanded_terms for term in ["k8s", "container", "kubelet"]))
        self.assertIn("kubernetes", result.search_keywords.lower())

    def test_02_query_expansion_entity_detection(self):
        """Test Stage 2: Query Expansion detects explicit CVEs and techniques."""
        query = "Investigate exploitation of CVE-2024-3400 using T1059"
        result = query_expander.expand_query(query)

        self.assertIn("CVE-2024-3400", result.detected_entities)
        self.assertIn("T1059", result.detected_entities)

    def test_03_hybrid_retriever_source_ranking(self):
        """Test Stages 3-6: Multi-modal retrieval and source reliability weighting."""
        expansion = query_expander.expand_query("What are the latest security developments involving Kubernetes?")
        from services.research.retriever import hybrid_retriever

        candidates = hybrid_retriever.retrieve_and_rank(self.db, expansion, top_k=5)
        self.assertGreater(len(candidates), 0)
        # Top candidate should be the high-authority CISA alert
        self.assertEqual(candidates[0].content.id, self.k8s_content.id)
        self.assertGreaterEqual(candidates[0].quality_score, 0.90)

    def test_04_evidence_collection_numbering(self):
        """Test Stage 7: Evidence Collection extracts verbatim snippets and assigns [1], [2]."""
        expansion = query_expander.expand_query("Kubernetes")
        from services.research.retriever import hybrid_retriever

        candidates = hybrid_retriever.retrieve_and_rank(self.db, expansion, top_k=5)
        evidence = evidence_collector.collect_evidence(candidates, expansion.expanded_terms, max_evidence=5)

        self.assertGreater(len(evidence), 0)
        self.assertEqual(evidence[0].citation_id, 1)
        self.assertIn("CVE-2023-5043", evidence[0].snippet)
        self.assertIsNotNone(evidence[0].canonical_url)

    def test_05_evidence_bounded_synthesis_guardrail(self):
        """Test Stage 8: AI Synthesis answers strictly from evidence with citations."""
        expansion = query_expander.expand_query("Kubernetes security developments")
        from services.research.retriever import hybrid_retriever

        candidates = hybrid_retriever.retrieve_and_rank(self.db, expansion, top_k=5)
        evidence = evidence_collector.collect_evidence(candidates, expansion.expanded_terms, max_evidence=5)

        synthesis = evidence_synthesizer.synthesize(
            question="What are the latest security developments involving Kubernetes?",
            evidence=evidence,
        )

        self.assertIsNotNone(synthesis.executive_answer)
        # Verify citation markers [1] in synthesis text
        self.assertIn("[1]", synthesis.executive_answer)
        self.assertGreater(len(synthesis.key_findings), 0)
        self.assertTrue(any("[1]" in f for f in synthesis.key_findings))

    def test_06_unanswered_query_preserves_uncertainty(self):
        """Test Stage 8: When no evidence exists, do NOT hallucinate from internal knowledge."""
        synthesis = evidence_synthesizer.synthesize(
            question="What are the latest quantum cryptography flaws in AlienOS?",
            evidence=[],
        )
        self.assertEqual(synthesis.confidence, 0.0)
        self.assertIn("No verified intelligence records", synthesis.executive_answer)
        self.assertGreater(len(synthesis.evidence_gaps), 0)

    def test_07_rest_endpoint_ask(self):
        """Test POST /api/v1/research/ask executes complete 9-stage pipeline."""
        payload = {
            "question": "What are the latest security developments involving Kubernetes?",
            "max_evidence": 5,
        }
        resp = self.client.post("/api/v1/research/ask", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["question"], payload["question"])
        self.assertIn("expansion", data)
        self.assertEqual(len(data["pipeline_stages"]), 9)
        self.assertGreater(len(data["evidence"]), 0)
        self.assertIn("[1]", data["synthesis"]["executive_answer"])

    def test_08_rest_endpoints_expand_and_suggested(self):
        """Test POST /api/v1/research/expand and GET /api/v1/research/suggested."""
        # 1. Expand
        resp1 = self.client.post("/api/v1/research/expand", json={"question": "Akira ransomware"})
        self.assertEqual(resp1.status_code, 200)
        exp = resp1.json()
        self.assertTrue(any("ransomware" in t for t in exp["expanded_terms"]))

        # 2. Suggested queries
        resp2 = self.client.get("/api/v1/research/suggested")
        self.assertEqual(resp2.status_code, 200)
        suggested = resp2.json()
        self.assertGreaterEqual(len(suggested), 3)
        self.assertTrue(any("Kubernetes" in s["question"] for s in suggested))


if __name__ == "__main__":
    unittest.main()

"""
Unit & Integration Tests for Semantic & Hybrid Search (pgvector embeddings & RRF)
Conforms strictly to IMPLEMENT.md Section 19.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import unittest

api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.chunk import ContentChunk
from app.models.content import Content
from app.models.source import Source
from connectors.base import BaseConnector, NormalizedItem
from services.ingestion.pipeline import IngestionPipeline
from services.search import search_service
from services.semantic import (
    EMBEDDING_DIMENSION,
    DeterministicLocalEmbedder,
    HybridSearchQuery,
    TextChunker,
    cosine_similarity,
    embedder,
    semantic_service,
    text_chunker,
)


class TestSemanticAndHybridSearch(unittest.TestCase):
    """Test suite validating Step 18 / Section 19 Semantic & Hybrid Search."""

    def setUp(self):
        # Create an isolated in-memory SQLite database
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db: Session = self.SessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Clear search and chunk indexes
        search_service.client.clear_in_memory_index()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        search_service.client.clear_in_memory_index()

    # -----------------------------------------------------------------
    # 1. Text Chunker Tests
    # -----------------------------------------------------------------
    def test_chunk_text_paragraph_and_sentence_boundaries(self):
        """Confirm TextChunker splits long text while preserving sentence/paragraph context."""
        chunker = TextChunker(default_chunk_size=120, default_overlap=30)
        text = (
            "LockBit is a sophisticated ransomware operation active since 2019. "
            "It utilizes double extortion tactics to force victim payment. "
            "\n\n"
            "Affiliates exploit known vulnerabilities such as CVE-2023-4966 in Citrix NetScaler. "
            "Data exfiltration occurs before file encryption is executed."
        )
        chunks = chunker.chunk_text(text)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertTrue(len(c) > 0)
            self.assertIsInstance(c, str)

    def test_chunk_document_lead_chunk_prioritization(self):
        """Confirm chunk_document creates lead chunk prioritizing title and overview."""
        chunks = text_chunker.chunk_document(
            title="CISA Advisory on Ivanti Connect Secure Zero-Days",
            description="Active exploitation observed across defense industrial base.",
            summary="Emergency directive issued requiring immediate disconnect.",
            body="Researchers identified two vulnerabilities: CVE-2023-46805 and CVE-2024-21887. " * 5,
        )
        self.assertGreaterEqual(len(chunks), 1)
        # First chunk should contain title and summary
        self.assertIn("Ivanti Connect Secure", chunks[0])
        self.assertIn("Emergency directive", chunks[0])

    # -----------------------------------------------------------------
    # 2. Vector Embedder Tests
    # -----------------------------------------------------------------
    def test_embedder_dimension_and_unit_normalization(self):
        """Confirm embedder generates 384-dimensional unit-normalized float vectors."""
        text = "Exploitation of remote code execution in Fortinet FortiOS appliances"
        vec = embedder.embed_text(text)

        self.assertEqual(len(vec), EMBEDDING_DIMENSION)
        self.assertEqual(embedder.dimension, 384)

        # Confirm unit normalization: sum of squares ≈ 1.0
        norm_sq = sum(x * x for x in vec)
        self.assertAlmostEqual(norm_sq, 1.0, places=3)

    def test_embedder_determinism(self):
        """Confirm identical text produces strictly identical embedding vectors."""
        text = "Nation-state threat actor Sandworm deploys wiper malware"
        v1 = embedder.embed_text(text)
        v2 = embedder.embed_text(text)
        self.assertEqual(v1, v2)

    def test_cosine_similarity_semantic_clustering(self):
        """Confirm semantically similar phrases have higher cosine similarity than unrelated phrases."""
        t1 = "LockBit ransomware affiliates encrypt hospital database servers"
        t2 = "LockBit ransomware operators deploy file encryptor across healthcare systems"
        t_unrelated = "Quantum chemistry simulation of superconducting topological insulators"

        v1 = embedder.embed_text(t1)
        v2 = embedder.embed_text(t2)
        v3 = embedder.embed_text(t_unrelated)

        sim_near = cosine_similarity(v1, v2)
        sim_far = cosine_similarity(v1, v3)

        self.assertGreater(sim_near, 0.25)
        self.assertLess(sim_far, 0.10)
        self.assertGreater(sim_near, sim_far)

    # -----------------------------------------------------------------
    # 3. Semantic Indexing & Vector Search Tests
    # -----------------------------------------------------------------
    def test_semantic_service_index_content_creates_chunks(self):
        """Confirm semantic_service.index_content persists ContentChunk records with vectors."""
        c = Content(
            title="Palo Alto Discloses PAN-OS Zero-Day",
            description="Command injection in GlobalProtect gateway.",
            summary="Emergency patching required for PAN-OS.",
            canonical_url="https://paloalto.example/sec-01",
            content_type="advisory",
            content_hash="panos_hash_01",
        )
        self.db.add(c)
        self.db.commit()

        count = semantic_service.index_content(self.db, c.id)
        self.assertGreaterEqual(count, 1)

        # Query database for generated chunks
        chunks = self.db.query(ContentChunk).filter(ContentChunk.content_id == c.id).all()
        self.assertEqual(len(chunks), count)
        self.assertEqual(len(chunks[0].embedding), 384)
        self.assertIn("Palo Alto Discloses", chunks[0].chunk_text)

    def test_search_vector_retrieves_relevant_content(self):
        """Confirm search_vector ranks semantically relevant document highest."""
        c1 = Content(
            title="LockBit Ransomware Operators Demand $10M Ransom",
            description="Critical infrastructure affected by ransomware encryptor.",
            canonical_url="https://news.example/lockbit",
            content_hash="h_lockbit",
        )
        c2 = Content(
            title="Kubernetes Ingress Controller Memory Leak",
            description="Bug causes unexpected pod restarts in cloud clusters.",
            canonical_url="https://k8s.example/bug",
            content_hash="h_k8s",
        )
        self.db.add_all([c1, c2])
        self.db.commit()

        semantic_service.index_content(self.db, c1.id)
        semantic_service.index_content(self.db, c2.id)

        # Search for ransomware
        hits = semantic_service.search_vector(self.db, query="ransomware extortion encryptor", limit=5)
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0].content_id, c1.id)
        self.assertGreater(hits[0].similarity, 0.30)

    # -----------------------------------------------------------------
    # 4. Hybrid Search & Reciprocal Rank Fusion (RRF) Tests
    # -----------------------------------------------------------------
    def test_hybrid_search_reciprocal_rank_fusion(self):
        """
        Verify Reciprocal Rank Fusion ranks an article matching BOTH keyword
        and semantic criteria higher than articles matching only one.
        """
        # Article A: strong match on both keyword & semantic vector
        cA = Content(
            title="Active Exploitation of Windows Remote Desktop Protocol",
            description="Hackers deploy ransomware via vulnerable RDP ports and credential stuffing.",
            canonical_url="https://rdp.example/exploit",
            content_hash="h_rdp",
        )
        # Article B: matches keyword search only
        cB = Content(
            title="Remote Desktop Protocol Configuration Guidelines",
            description="Standard administrative documentation for Windows Server terminal services.",
            canonical_url="https://admin.example/rdp-guide",
            content_hash="h_admin",
        )
        self.db.add_all([cA, cB])
        self.db.commit()

        # Index into search engine (keyword) and semantic service (vector)
        search_service.index_content(self.db, cA.id)
        search_service.index_content(self.db, cB.id)
        semantic_service.index_content(self.db, cA.id)
        semantic_service.index_content(self.db, cB.id)

        # Run hybrid search
        hq = HybridSearchQuery(query="RDP ransomware credential stuffing", page=1, page_size=10)
        res = semantic_service.search_hybrid(self.db, hq)

        self.assertGreaterEqual(res.total, 1)
        # Article A should rank #1 with highest RRF score
        self.assertEqual(res.hits[0].content_id, cA.id)
        self.assertGreater(res.hits[0].rrf_score, 0.0)

    # -----------------------------------------------------------------
    # 5. Ingestion Pipeline Auto-Indexing Integration
    # -----------------------------------------------------------------
    def test_ingestion_pipeline_auto_creates_semantic_chunks(self):
        """Confirm IngestionPipeline Step 5 automatically generates and persists ContentChunks."""
        class SemanticTestConnector(BaseConnector):
            def discover(self):
                return [{"title": "Cisco IOS-XE Web UI Exploit CVE-2023-20198", "link": "https://cisco.example/advisory"}]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title=parsed["title"],
                    url=parsed["link"],
                    source="CiscoFeed",
                    content_type="advisory",
                    description="Unauthenticated remote attacker creates privilege level 15 user account.",
                    raw_content="Exploitation of CVE-2023-20198 allows root access on Cisco IOS XE network devices.",
                )
            def health_check(self):
                pass

        connector = SemanticTestConnector(source_config={"name": "CiscoFeed"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="CiscoFeed")

        self.assertEqual(metrics.ingested_count, 1)

        # Confirm ContentChunk exists in DB
        chunks = self.db.query(ContentChunk).all()
        self.assertGreaterEqual(len(chunks), 1)

        # Search vector directly
        hits = semantic_service.search_vector(self.db, query="Cisco IOS XE root access", limit=5)
        self.assertGreaterEqual(len(hits), 1)
        self.assertIn("Cisco", hits[0].content_title)

    # -----------------------------------------------------------------
    # 6. REST API Endpoints Tests
    # -----------------------------------------------------------------
    def test_api_embed_endpoint(self):
        """Verify POST /api/v1/semantic/embed returns 384-dimensional vector."""
        response = self.client.post("/api/v1/semantic/embed", json={"text": "Threat actor Volt Typhoon"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["dimension"], 384)
        self.assertEqual(len(data["embedding"]), 384)

    def test_api_semantic_search_endpoint(self):
        """Verify POST /api/v1/search/semantic returns vector similarity hits."""
        c = Content(
            title="BlackCat ALPHV Ransomware Analysis",
            description="Rust-based ransomware family deployed in enterprise attacks.",
            canonical_url="https://malware.example/alphv",
            content_hash="h_alphv",
        )
        self.db.add(c)
        self.db.commit()
        semantic_service.index_content(self.db, c.id)

        response = self.client.post("/api/v1/search/semantic", json={"q": "Rust ransomware ALPHV", "limit": 5})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["total"], 1)
        self.assertEqual(data["hits"][0]["content_id"], c.id)

    def test_api_hybrid_search_get_and_post_endpoints(self):
        """Verify GET & POST /api/v1/search/hybrid endpoints return RRF-fused results."""
        c = Content(
            title="Citrix Bleed CVE-2023-4966 Session Hijacking",
            description="Buffer overflow allows sensitive memory disclosure and session token theft.",
            canonical_url="https://citrix.example/bleed",
            content_hash="h_citrix",
        )
        self.db.add(c)
        self.db.commit()
        search_service.index_content(self.db, c.id)
        semantic_service.index_content(self.db, c.id)

        # Test GET /api/v1/search/hybrid
        get_res = self.client.get("/api/v1/search/hybrid?q=Citrix+Bleed+session+token")
        self.assertEqual(get_res.status_code, 200)
        get_data = get_res.json()
        self.assertGreaterEqual(get_data["total"], 1)
        self.assertEqual(get_data["hits"][0]["content_id"], c.id)
        self.assertGreater(get_data["hits"][0]["rrf_score"], 0.0)

        # Test POST /api/v1/search/hybrid
        post_res = self.client.post(
            "/api/v1/search/hybrid",
            json={"q": "Citrix Bleed", "keyword_weight": 0.6, "semantic_weight": 0.4},
        )
        self.assertEqual(post_res.status_code, 200)
        post_data = post_res.json()
        self.assertGreaterEqual(post_data["total"], 1)
        self.assertEqual(post_data["hits"][0]["content_id"], c.id)

    def test_api_reindex_embeddings_endpoint(self):
        """Verify POST /api/v1/semantic/reindex chunks and embeds all database content."""
        c1 = Content(title="Report 1", canonical_url="https://example.com/1", content_hash="h1")
        c2 = Content(title="Report 2", canonical_url="https://example.com/2", content_hash="h2")
        self.db.add_all([c1, c2])
        self.db.commit()

        response = self.client.post("/api/v1/semantic/reindex")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertGreaterEqual(data["chunks_created"], 2)


if __name__ == "__main__":
    unittest.main()

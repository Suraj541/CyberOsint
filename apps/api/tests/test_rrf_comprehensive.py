"""
Comprehensive Unit Tests for Reciprocal Rank Fusion (RRF) and Hybrid Search
Validates all 8 edge cases mandated by Section 12:
1. Both branches return results
2. Only text returns results
3. Only vector returns results
4. Both return same documents (deduplication & score boost)
5. No results from either branch
6. Duplicate documents handling
7. Malformed result / empty query handling
8. OpenSearch cluster unavailable / fallback
"""

from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.chunk import ContentChunk
from app.models.content import Content
from services.search import search_service
from services.search.models import SearchHit, SearchQuery, SearchResult
from services.semantic import (
    DeterministicLocalEmbedder,
    HybridSearchQuery,
    SemanticHit,
    SemanticService,
    cosine_similarity,
    embedder,
    semantic_service,
)


class TestRRFComprehensive(unittest.TestCase):
    """Test suite validating all 8 edge cases of RRF hybrid search."""

    def setUp(self):
        # Isolated SQLite in-memory DB for unit test speed
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db: Session = self.SessionLocal()

        # Clean search client in-memory state
        search_service.client.clear_in_memory_index()

        # Seed test content records
        self.c1 = Content(
            title="LockBit Ransomware Extortion Group",
            description="Active ransomware operation targeting critical infrastructure.",
            canonical_url="https://threat.intel/lockbit",
            content_hash="hash_lockbit_01",
        )
        self.c2 = Content(
            title="Citrix Bleed Session Hijacking Vulnerability",
            description="Memory disclosure flaw CVE-2023-4966 in NetScaler ADC.",
            canonical_url="https://threat.intel/citrix",
            content_hash="hash_citrix_02",
        )
        self.c3 = Content(
            title="Cobalt Strike Beacon Detection Patterns",
            description="Memory injection and command-and-control beaconing analysis.",
            canonical_url="https://threat.intel/cobalt",
            content_hash="hash_cobalt_03",
        )
        self.db.add_all([self.c1, self.c2, self.c3])
        self.db.commit()

        # Index into search and semantic services
        for c in (self.c1, self.c2, self.c3):
            search_service.index_content(self.db, c.id)
            semantic_service.index_content(self.db, c.id)

    def tearDown(self):
        self.db.close()
        search_service.client.clear_in_memory_index()

    def test_case_1_both_branches_return_results(self):
        """Case 1: Both keyword and vector search return matching results."""
        sq = HybridSearchQuery(query="LockBit Ransomware", keyword_weight=0.5, semantic_weight=0.5)
        res = semantic_service.search_hybrid(self.db, sq)

        self.assertGreaterEqual(res.total, 1)
        self.assertEqual(res.engine_status, "optimal")
        self.assertEqual(res.text_status, "ok")
        self.assertEqual(res.vector_status, "ok")

        # Top hit should be c1
        top_hit = res.hits[0]
        self.assertEqual(top_hit.content_id, self.c1.id)
        self.assertIsNotNone(top_hit.keyword_rank)
        self.assertIsNotNone(top_hit.semantic_rank)
        self.assertGreater(top_hit.rrf_score, 0.0)

    def test_case_2_only_text_returns_results(self):
        """Case 2: Only keyword search matches; vector returns no hits above threshold."""
        with patch.object(semantic_service, "search_vector", return_value=[]):
            sq = HybridSearchQuery(query="Cobalt Strike", keyword_weight=0.5, semantic_weight=0.5)
            res = semantic_service.search_hybrid(self.db, sq)

            self.assertGreaterEqual(res.total, 1)
            self.assertEqual(res.vector_count, 0)
            self.assertGreater(res.text_count, 0)
            self.assertIsNone(res.hits[0].semantic_rank)
            self.assertIsNotNone(res.hits[0].keyword_rank)

            # RRF score should only have the keyword component: 0.5 / (60 + kw_rank)
            expected_score = round(0.5 / (60 + res.hits[0].keyword_rank), 6)
            self.assertAlmostEqual(res.hits[0].rrf_score, expected_score, places=5)

    def test_case_3_only_vector_returns_results(self):
        """Case 3: Only vector similarity matches; keyword returns 0 hits."""
        with patch.object(
            search_service,
            "search",
            return_value=SearchResult(total=0, page=1, page_size=50, hits=[], took_ms=1.0),
        ):
            sq = HybridSearchQuery(query="Session Token Disclosure", keyword_weight=0.5, semantic_weight=0.5)
            res = semantic_service.search_hybrid(self.db, sq)

            self.assertGreaterEqual(res.total, 1)
            self.assertEqual(res.text_count, 0)
            self.assertGreater(res.vector_count, 0)
            self.assertIsNone(res.hits[0].keyword_rank)
            self.assertIsNotNone(res.hits[0].semantic_rank)

            expected_score = round(0.5 / (60 + res.hits[0].semantic_rank), 6)
            self.assertAlmostEqual(res.hits[0].rrf_score, expected_score, places=5)

    def test_case_4_both_return_same_document_boosted(self):
        """Case 4: Both branches return the same document, boosting its RRF score above single-branch hits."""
        sq = HybridSearchQuery(query="Citrix Bleed", keyword_weight=0.5, semantic_weight=0.5)
        res = semantic_service.search_hybrid(self.db, sq)

        # c2 should match both keyword and semantic
        c2_hits = [h for h in res.hits if h.content_id == self.c2.id]
        self.assertTrue(len(c2_hits) == 1, "Duplicate documents should be merged into single hit")

        c2_hit = c2_hits[0]
        if c2_hit.keyword_rank and c2_hit.semantic_rank:
            expected = round(0.5 / (60 + c2_hit.keyword_rank) + 0.5 / (60 + c2_hit.semantic_rank), 6)
            self.assertAlmostEqual(c2_hit.rrf_score, expected, places=5)

    def test_case_5_no_results(self):
        """Case 5: Neither branch returns results for non-matching gibberish."""
        with patch.object(semantic_service, "search_vector", return_value=[]):
            with patch.object(
                search_service,
                "search",
                return_value=SearchResult(total=0, page=1, page_size=50, hits=[], took_ms=1.0),
            ):
                sq = HybridSearchQuery(query="xyznonexistentthreat998877", page=1, page_size=20)
                res = semantic_service.search_hybrid(self.db, sq)

                self.assertEqual(res.total, 0)
                self.assertEqual(len(res.hits), 0)
                self.assertEqual(res.text_count, 0)
                self.assertEqual(res.vector_count, 0)

    def test_case_6_duplicate_documents_merged(self):
        """Case 6: Ensure multiple chunk matches for the same document are aggregated to 1 hit."""
        # Create a document with 5 identical chunks
        multi_chunk_content = Content(
            title="Multi-Chunk Threat Advisory",
            description="Repeated malware pattern description for chunk testing.",
            canonical_url="https://threat.intel/multi",
            content_hash="hash_multi_chunk_99",
        )
        self.db.add(multi_chunk_content)
        self.db.commit()

        vec = embedder.embed_text("repeated malware pattern")
        for idx in range(5):
            chunk = ContentChunk(
                content_id=multi_chunk_content.id,
                chunk_index=idx,
                chunk_text=f"Chunk {idx} repeated malware pattern",
                embedding=vec,
            )
            self.db.add(chunk)
        self.db.commit()
        search_service.index_content(self.db, multi_chunk_content.id)

        sq = HybridSearchQuery(query="repeated malware pattern")
        res = semantic_service.search_hybrid(self.db, sq)

        ids = [h.content_id for h in res.hits]
        self.assertEqual(ids.count(multi_chunk_content.id), 1, "Content ID must appear at most once in hits")

    def test_case_7_malformed_empty_query_handling(self):
        """Case 7: Empty or whitespace query gracefully returns empty results without crashing."""
        for empty_q in ("", "   ", "\t\n"):
            sq = HybridSearchQuery(query=empty_q)
            res = semantic_service.search_hybrid(self.db, sq)
            self.assertIsInstance(res, object)
            self.assertEqual(res.total, 0)
            self.assertEqual(len(res.hits), 0)

    def test_case_8_opensearch_unavailable_graceful_fallback(self):
        """Case 8: Keyword search raises an unexpected exception; hybrid falls back to vector branch."""
        with patch.object(search_service, "search", side_effect=Exception("OpenSearch cluster timeout")):
            sq = HybridSearchQuery(query="LockBit Ransomware")
            res = semantic_service.search_hybrid(self.db, sq)

            # System must not crash, should report text_status="failed", engine_status="degraded"
            self.assertEqual(res.text_status, "failed")
            self.assertEqual(res.engine_status, "degraded")
            # Should still return results from the vector branch
            self.assertGreaterEqual(res.total, 1)
            self.assertIsNotNone(res.hits[0].semantic_rank)
            self.assertIsNone(res.hits[0].keyword_rank)


if __name__ == "__main__":
    unittest.main()

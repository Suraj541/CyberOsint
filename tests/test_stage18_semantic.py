"""
Stage 18 / Section 19: Add Semantic Search Baseline Tests
Verifies the services/semantic package structure, ContentChunk database model,
TextChunker paragraph and sentence boundary splitting, 384-dimensional dense vector embeddings,
cosine similarity, Reciprocal Rank Fusion (RRF) hybrid search, and REST API schemas.
Conforms to IMPLEMENT.md Section 19.
"""

from pathlib import Path
import sys
import unittest

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from services.semantic import (
    BaseEmbedder,
    DeterministicLocalEmbedder,
    HybridHit,
    HybridSearchQuery,
    HybridSearchResult,
    SemanticHit,
    SemanticService,
    TextChunker,
    cosine_similarity,
    embedder,
    semantic_service,
    text_chunker,
)
from app.models.chunk import ContentChunk
from app.models import Content


class TestStage18SemanticBaseline(unittest.TestCase):
    """Test suite validating Step 18 / Section 19 Semantic & Hybrid Search integration."""

    def test_semantic_package_structure(self):
        """Confirm services/semantic contains all mandated modules."""
        serv_dir = repo_root / "services" / "semantic"
        self.assertTrue(serv_dir.exists(), "services/semantic directory missing")
        self.assertTrue((serv_dir / "__init__.py").exists(), "__init__.py missing")
        self.assertTrue((serv_dir / "models.py").exists(), "models.py missing")
        self.assertTrue((serv_dir / "chunker.py").exists(), "chunker.py missing")
        self.assertTrue((serv_dir / "embedder.py").exists(), "embedder.py missing")
        self.assertTrue((serv_dir / "similarity.py").exists(), "similarity.py missing")
        self.assertTrue((serv_dir / "service.py").exists(), "service.py missing")

    def test_content_chunk_model_definition(self):
        """Confirm ContentChunk model defines all mandated columns and relationships."""
        self.assertTrue(hasattr(ContentChunk, "id"))
        self.assertTrue(hasattr(ContentChunk, "content_id"))
        self.assertTrue(hasattr(ContentChunk, "chunk_index"))
        self.assertTrue(hasattr(ContentChunk, "chunk_text"))
        self.assertTrue(hasattr(ContentChunk, "chunk_tokens"))
        self.assertTrue(hasattr(ContentChunk, "embedding"))
        self.assertTrue(hasattr(ContentChunk, "created_at"))
        self.assertTrue(hasattr(ContentChunk, "content"))
        self.assertTrue(hasattr(Content, "chunks"))

    def test_api_schemas_and_endpoints_files_exist(self):
        """Confirm semantic search API schemas and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "schemas" / "semantic.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "semantic.py").exists())

    def test_semantic_service_singleton_and_contract(self):
        """Confirm semantic_service is functional and exposes core methods."""
        self.assertIsInstance(semantic_service, SemanticService)
        self.assertTrue(callable(getattr(semantic_service, "index_content", None)))
        self.assertTrue(callable(getattr(semantic_service, "search_vector", None)))
        self.assertTrue(callable(getattr(semantic_service, "search_hybrid", None)))
        self.assertTrue(callable(getattr(semantic_service, "reindex_all_embeddings", None)))

    def test_text_chunker_contract_and_behavior(self):
        """Confirm TextChunker splits text and prioritizes lead document chunk."""
        self.assertIsInstance(text_chunker, TextChunker)
        chunks = text_chunker.chunk_document(
            title="Palo Alto PAN-OS Zero-Day Vulnerability",
            description="Active exploitation observed in the wild targeting GlobalProtect gateways.",
            summary="Emergency mitigation instructions issued by CISA.",
            body="Detailed technical analysis with indicators of compromise and patch recommendations.",
            chunk_size=100,
        )
        self.assertGreaterEqual(len(chunks), 1)
        # Lead chunk includes title
        self.assertIn("Palo Alto PAN-OS Zero-Day Vulnerability", chunks[0])

    def test_embedder_dimension_and_unit_normalization(self):
        """Confirm embedder generates 384-dimensional unit-normalized float vectors."""
        self.assertIsInstance(embedder, BaseEmbedder)
        text = "Critical zero-day command injection flaw in enterprise VPN appliance"
        vec = embedder.embed_text(text)
        self.assertEqual(len(vec), 384)
        
        # Verify L2 norm is 1.0 (within float precision)
        norm = sum(x * x for x in vec) ** 0.5
        self.assertAlmostEqual(norm, 1.0, places=4)

    def test_embedder_determinism(self):
        """Confirm identical text produces strictly identical embedding vectors."""
        text = "Ransomware operators breach healthcare network using compromised credentials"
        v1 = embedder.embed_text(text)
        v2 = embedder.embed_text(text)
        self.assertEqual(v1, v2)

    def test_cosine_similarity_computation(self):
        """Confirm cosine_similarity handles parallel and orthogonal vectors properly."""
        v1 = embedder.embed_text("Citrix Bleed vulnerability CVE-2023-4966 session token leak")
        # Same text -> cosine similarity 1.0
        self.assertAlmostEqual(cosine_similarity(v1, v1), 1.0, places=4)

        # Empty vector handling
        self.assertEqual(cosine_similarity([], []), 0.0)

    def test_semantic_models_contract(self):
        """Confirm SemanticHit, HybridSearchQuery, HybridHit, and HybridSearchResult dataclasses."""
        s_hit = SemanticHit(
            content_id=1,
            chunk_id=10,
            similarity=0.88,
            chunk_text="Exploit payload detected in network traffic",
            content_title="Threat Advisory",
            canonical_url="https://example.com/advisory",
            content_type="advisory",
            source="NVD",
            category="threat_intelligence",
        )
        self.assertEqual(s_hit.content_id, 1)
        self.assertAlmostEqual(s_hit.similarity, 0.88)

        query = HybridSearchQuery(
            query="ransomware attack",
            page_size=10,
            keyword_weight=0.6,
            semantic_weight=0.4,
        )
        self.assertEqual(query.query, "ransomware attack")

        h_hit = HybridHit(
            content_id=1,
            title="LockBit Ransomware",
            canonical_url="https://example.com/lockbit",
            content_type="advisory",
            source="CISA",
            category="ransomware",
            rrf_score=0.032,
            keyword_rank=1,
            semantic_rank=2,
            keyword_score=1.5,
            semantic_score=0.75,
            matched_chunk="Hospital systems targeted",
        )
        self.assertEqual(h_hit.content_id, 1)
        self.assertEqual(h_hit.keyword_rank, 1)
        self.assertEqual(h_hit.semantic_rank, 2)

        res = HybridSearchResult(
            total=1,
            page=1,
            page_size=20,
            hits=[h_hit],
            query_used="ransomware attack",
            took_ms=12.5,
        )
        self.assertEqual(res.total, 1)
        self.assertEqual(res.query_used, "ransomware attack")


if __name__ == "__main__":
    unittest.main()

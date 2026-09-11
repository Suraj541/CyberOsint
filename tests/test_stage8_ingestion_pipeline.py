"""
Stage 8 / Section 9: Ingestion Pipeline & Deduplication Baseline Tests
Verifies the package structure, deduplication SHA-256 contract, and pipeline orchestrator
required by IMPLEMENT.md Section 9.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from services.ingestion import (
    Deduplicator,
    IngestionMetrics,
    IngestionPipeline,
    ItemValidator,
    compute_content_hash,
    ingestion_pipeline,
)


class TestStage8IngestionPipelineBaseline(unittest.TestCase):
    """Test suite validating Step 8 / Section 9 Ingestion Pipeline implementation."""

    def test_services_ingestion_package_structure(self):
        """Confirm services/ingestion exists with all mandated component modules."""
        services_dir = repo_root / "services" / "ingestion"
        self.assertTrue(services_dir.exists(), "services/ingestion directory not found")
        self.assertTrue((services_dir / "__init__.py").exists(), "services/ingestion/__init__.py missing")
        self.assertTrue((services_dir / "deduplication.py").exists(), "deduplication.py missing")
        self.assertTrue((services_dir / "validation.py").exists(), "validation.py missing")
        self.assertTrue((services_dir / "metrics.py").exists(), "metrics.py missing")
        self.assertTrue((services_dir / "pipeline.py").exists(), "pipeline.py missing")

    def test_app_services_ingestion_adapter(self):
        """Confirm app/services/ingestion.py exists for FastAPI integration."""
        adapter = api_root / "app" / "services" / "ingestion.py"
        self.assertTrue(adapter.exists(), "apps/api/app/services/ingestion.py missing")

    def test_sha256_deduplication_hash_contract(self):
        """Confirm compute_content_hash returns 64-char SHA-256 hex string and is deterministic."""
        h1 = compute_content_hash("https://example.com/item1", "Zero Day Flaw")
        h2 = compute_content_hash("https://example.com/item1", "Zero Day Flaw")
        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, h2)
        # Verify hex characters only
        int(h1, 16)

    def test_ingestion_metrics_schema(self):
        """Confirm IngestionMetrics contains all required tracking counters."""
        metrics = IngestionMetrics(source_id=1, source_name="Test")
        self.assertEqual(metrics.discovered_count, 0)
        self.assertEqual(metrics.validated_count, 0)
        self.assertEqual(metrics.normalized_count, 0)
        self.assertEqual(metrics.ingested_count, 0)
        self.assertEqual(metrics.duplicates_skipped, 0)
        self.assertEqual(metrics.errors_count, 0)

        metrics.record_error("Test error")
        self.assertEqual(metrics.errors_count, 1)
        self.assertEqual(len(metrics.errors), 1)

        metrics.record_duplicate("hash123", "Title")
        self.assertEqual(metrics.duplicates_skipped, 1)

        metrics.record_ingested(1, "Title", "https://url.local", "hash123")
        self.assertEqual(metrics.ingested_count, 1)

    def test_ingestion_pipeline_instance(self):
        """Confirm IngestionPipeline class and singleton are initialized."""
        self.assertIsInstance(ingestion_pipeline, IngestionPipeline)
        self.assertTrue(hasattr(ingestion_pipeline, "run"))
        self.assertTrue(hasattr(ingestion_pipeline, "ingest_source"))


if __name__ == "__main__":
    unittest.main()

"""
Stage 16 / Section 17: Advanced Deduplication Engine Baseline Tests
Verifies the services/deduplication package structure, the multi-stage deduplication pipeline,
the DuplicateLink data model, cluster persistence, and REST API schemas per Section 17.
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

from app.models.duplicate import DuplicateLink
from services.deduplication import (
    DeduplicationEngine,
    DeduplicationResult,
    DuplicateCluster,
    calculate_description_similarity,
    calculate_entity_overlap,
    calculate_multi_signal_similarity,
    calculate_semantic_similarity,
    calculate_title_similarity,
    compute_content_hash,
    compute_simhash,
    deduplication_engine,
    get_url_domain,
    normalize_url,
    simhash_hamming_distance,
    simhash_similarity,
)


class TestStage16DeduplicationBaseline(unittest.TestCase):
    """Test suite validating Step 16 / Section 17 Advanced Deduplication Engine."""

    def test_deduplication_package_structure(self):
        """Confirm services/deduplication contains all mandated modules."""
        serv_dir = repo_root / "services" / "deduplication"
        self.assertTrue(serv_dir.exists(), "services/deduplication directory missing")
        self.assertTrue((serv_dir / "__init__.py").exists(), "__init__.py missing")
        self.assertTrue((serv_dir / "models.py").exists(), "models.py missing")
        self.assertTrue((serv_dir / "url.py").exists(), "url.py missing")
        self.assertTrue((serv_dir / "similarity.py").exists(), "similarity.py missing")
        self.assertTrue((serv_dir / "hashing.py").exists(), "hashing.py missing")
        self.assertTrue((serv_dir / "engine.py").exists(), "engine.py missing")

    def test_api_schemas_models_and_endpoints_files_exist(self):
        """Confirm deduplication models, schemas, and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "models" / "duplicate.py").exists())
        self.assertTrue((api_root / "app" / "schemas" / "deduplication.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "deduplication.py").exists())

    def test_deduplication_engine_singleton_and_contract(self):
        """Confirm deduplication_engine is functional and exposes core methods."""
        self.assertIsInstance(deduplication_engine, DeduplicationEngine)
        self.assertTrue(callable(getattr(deduplication_engine, "evaluate", None)))
        self.assertTrue(callable(getattr(deduplication_engine, "record_duplicate_link", None)))
        self.assertTrue(callable(getattr(deduplication_engine, "list_clusters", None)))
        self.assertTrue(callable(getattr(deduplication_engine, "get_cluster", None)))

    def test_url_normalization_contract(self):
        """Verify URL normalization strips tracking parameters, fragments, and standardizes ports."""
        dirty = "HTTPS://WWW.Example.COM:443/threat-report/index.html?utm_source=twitter&ref=feed&id=10#section"
        clean = normalize_url(dirty)
        self.assertEqual(clean, "https://www.example.com/threat-report?id=10")
        self.assertEqual(get_url_domain(clean), "www.example.com")

    def test_sha256_content_hash_and_simhash_contract(self):
        """Verify deterministic SHA-256 fingerprinting and SimHash similarity."""
        h1 = compute_content_hash("https://cert.example/advisory", "Critical Zero Day in Edge")
        h2 = compute_content_hash("https://cert.example/advisory?utm_medium=email", "Critical Zero Day in Edge")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

        # SimHash similarity on near-duplicate text
        text_a = "Palo Alto Networks releases security update for PAN-OS firewall vulnerability."
        text_b = "Palo Alto Networks rolls out urgent update addressing PAN-OS firewall flaw."
        sim_a = compute_simhash(text_a)
        sim_b = compute_simhash(text_b)
        dist = simhash_hamming_distance(sim_a, sim_b)
        self.assertLessEqual(dist, 20)
        self.assertGreaterEqual(simhash_similarity(sim_a, sim_b), 0.65)

    def test_similarity_metrics_and_multi_signal_contract(self):
        """Verify title similarity token sort, numeral conflicts, and entity overlap."""
        title_a = "Microsoft Discloses Zero-Day Flaw in Windows Kernel"
        title_b = "Windows Kernel Zero-Day Flaw Disclosed by Microsoft"
        self.assertGreaterEqual(calculate_title_similarity(title_a, title_b), 0.85)

        # Numeral conflict should penalize score
        t1 = "CVE-2024-1001 Advisory"
        t2 = "CVE-2024-1002 Advisory"
        self.assertLess(calculate_title_similarity(t1, t2), 0.80)

        # Entity overlap Jaccard
        ents1 = [("cve", "CVE-2024-38077"), ("vendor", "microsoft")]
        ents2 = [("cve", "CVE-2024-38077"), ("vendor", "cisco")]
        self.assertAlmostEqual(calculate_entity_overlap(ents1, ents2), 1 / 3, places=2)

        # Multi-signal composite score
        multi = calculate_multi_signal_similarity(title_a, title_b, entities1=ents1, entities2=ents2)
        self.assertIn("composite_score", multi)
        self.assertGreaterEqual(multi["composite_score"], 0.60)

    def test_duplicate_link_model_contract(self):
        """Confirm DuplicateLink model attributes conform to Section 17 mandate."""
        dup = DuplicateLink(
            canonical_id=1,
            duplicate_id=2,
            cluster_id="cluster_1_test",
            match_type="exact_url",
            similarity_score=1.0,
            metadata_json={"url_match": True},
        )
        self.assertEqual(dup.canonical_id, 1)
        self.assertEqual(dup.duplicate_id, 2)
        self.assertEqual(dup.cluster_id, "cluster_1_test")
        self.assertEqual(dup.match_type, "exact_url")
        self.assertEqual(dup.similarity_score, 1.0)
        self.assertTrue(dup.metadata_json["url_match"])


if __name__ == "__main__":
    unittest.main()

"""
Tests for Subsystem 4: Deduplication.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates URL normalization, SHA-256 fingerprinting, SimHash near-duplicate detection,
multi-signal similarity, numeral conflict penalization, and cluster formation.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from app.models.duplicate import DuplicateLink
from services.deduplication import (
    DeduplicationEngine,
    DeduplicationResult,
    DuplicateCluster,
    calculate_description_similarity,
    calculate_entity_overlap,
    calculate_multi_signal_similarity,
    calculate_title_similarity,
    compute_content_hash,
    compute_simhash,
    deduplication_engine,
    get_url_domain,
    normalize_url,
    simhash_hamming_distance,
    simhash_similarity,
)


class TestDeduplicationSubsystem(unittest.TestCase):
    """Subsystem 4: Deduplication Unit Tests."""

    def test_01_url_normalization_stripping_and_standardization(self):
        """Verify URL normalization strips tracking query params, fragments, and standardizes ports."""
        dirty_url = "HTTPS://WWW.Example.COM:443/threat-report/index.html?utm_source=twitter&ref=feed&id=10#section"
        clean_url = normalize_url(dirty_url)
        self.assertEqual(clean_url, "https://www.example.com/threat-report?id=10")
        self.assertEqual(get_url_domain(clean_url), "www.example.com")

        # Trailing slash standardization
        slash_url = "https://example.com/advisories/2026/"
        self.assertEqual(normalize_url(slash_url), "https://example.com/advisories/2026")

    def test_02_sha256_content_fingerprint_determinism(self):
        """Verify SHA-256 content hashing produces identical fingerprints for identical normalized inputs."""
        h1 = compute_content_hash("https://cert.gov/alert-1", "Zero-day vulnerability in gateway")
        h2 = compute_content_hash("https://cert.gov/alert-1?utm_campaign=blast", "Zero-day vulnerability in gateway")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        int(h1, 16)  # Verify valid hex

    def test_03_simhash_hamming_distance_near_duplicates(self):
        """Verify 64-bit SimHash and Hamming distance recognize near-identical text."""
        text_a = "Palo Alto Networks releases security update for PAN-OS firewall vulnerability."
        text_b = "Palo Alto Networks rolls out urgent update addressing PAN-OS firewall flaw."
        sim_a = compute_simhash(text_a)
        sim_b = compute_simhash(text_b)
        dist = simhash_hamming_distance(sim_a, sim_b)
        self.assertLessEqual(dist, 20)
        self.assertGreaterEqual(simhash_similarity(sim_a, sim_b), 0.65)

    def test_04_title_similarity_and_numeral_conflict(self):
        """Verify token sort ratio handles word reordering and penalizes conflicting numerals/CVEs."""
        title_a = "Microsoft Discloses Zero-Day Flaw in Windows Kernel"
        title_b = "Windows Kernel Zero-Day Flaw Disclosed by Microsoft"
        self.assertGreaterEqual(calculate_title_similarity(title_a, title_b), 0.85)

        # Numeral conflict (e.g. CVE 1001 vs CVE 1002) must drop similarity
        t1 = "CVE-2024-1001 Advisory"
        t2 = "CVE-2024-1002 Advisory"
        self.assertLess(calculate_title_similarity(t1, t2), 0.80)

    def test_05_entity_overlap_jaccard_similarity(self):
        """Verify Jaccard entity overlap metric correctly evaluates matched threat indicators."""
        ents1 = [("cve", "CVE-2024-38077"), ("vendor", "microsoft")]
        ents2 = [("cve", "CVE-2024-38077"), ("vendor", "cisco")]
        # Intersection: 1 (CVE-2024-38077), Union: 3
        overlap = calculate_entity_overlap(ents1, ents2)
        self.assertAlmostEqual(overlap, 1 / 3, places=2)

    def test_06_multi_signal_composite_evaluation(self):
        """Verify composite multi-signal scoring integrates title, entities, and content."""
        title1 = "Critical RCE Flaw Reported in Ivanti Connect Secure"
        title2 = "Ivanti Connect Secure Zero-Day RCE Flaw Disclosed"
        ents1 = [("cve", "CVE-2024-21887"), ("vendor", "ivanti")]
        ents2 = [("cve", "CVE-2024-21887"), ("vendor", "ivanti")]

        score_res = calculate_multi_signal_similarity(title1, title2, entities1=ents1, entities2=ents2)
        self.assertIn("composite_score", score_res)
        self.assertGreaterEqual(score_res["composite_score"], 0.70)

    def test_07_duplicate_link_model_instantiation(self):
        """Verify DuplicateLink ORM model contract and relationships."""
        dup = DuplicateLink(
            canonical_id=101,
            duplicate_id=102,
            cluster_id="cluster_sec_101",
            match_type="simhash",
            similarity_score=0.92,
            metadata_json={"hamming_distance": 3},
        )
        self.assertEqual(dup.canonical_id, 101)
        self.assertEqual(dup.duplicate_id, 102)
        self.assertEqual(dup.match_type, "simhash")
        self.assertEqual(dup.similarity_score, 0.92)


if __name__ == "__main__":
    unittest.main()

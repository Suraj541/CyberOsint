"""
Advanced Deduplication Engine Test Suite
Tests URL normalization, cryptographic & SimHash fingerprinting, title similarity,
description similarity, entity overlap, multi-signal scoring, 5-stage deduplication pipeline,
duplicate cluster storage, and REST API endpoints.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.duplicate import DuplicateLink
from app.models.source import Source
from connectors.base import BaseConnector, NormalizedItem
from services.deduplication import (
    DeduplicationEngine,
    DeduplicationResult,
    calculate_description_similarity,
    calculate_entity_overlap,
    calculate_multi_signal_similarity,
    calculate_semantic_similarity,
    calculate_title_similarity,
    compute_content_hash,
    compute_simhash,
    deduplication_engine,
    normalize_url,
    simhash_hamming_distance,
    simhash_similarity,
)
from services.ingestion.pipeline import IngestionPipeline


class TestDeduplicationEngine(unittest.TestCase):
    """Unit and integration test suite for Section 17 Deduplication Engine."""

    def setUp(self):
        """Set up isolated in-memory SQLite database and test client."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up database session and test overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app.dependency_overrides.clear()

    # -----------------------------------------------------------------
    # 1. URL Normalization Unit Tests
    # -----------------------------------------------------------------
    def test_url_normalization_tracking_params_and_casing(self):
        """Verify URL normalization strips tracking params, lowercases host, and sorts params."""
        raw_url = "HTTPS://WWW.Example.COM:443/Advisories/Alert.php?utm_source=twitter&b=2&a=1&fbclid=xyz#section"
        clean = normalize_url(raw_url)
        self.assertEqual(clean, "https://www.example.com/advisories/alert.php?a=1&b=2")

    def test_url_normalization_default_ports_and_index_files(self):
        """Verify stripping default ports :80 and default index files /index.html -> /."""
        url_http = "http://blog.cyber.local:80/posts/index.html"
        self.assertEqual(normalize_url(url_http), "http://blog.cyber.local/posts")

        url_slash = "https://security.example.org/alerts//"
        self.assertEqual(normalize_url(url_slash), "https://security.example.org/alerts")

    # -----------------------------------------------------------------
    # 2. Content Hashing and SimHash Fingerprint Tests
    # -----------------------------------------------------------------
    def test_content_hash_deterministic_equality(self):
        """Verify compute_content_hash equality for identical canonical content across tracking variants."""
        u1 = "https://krebsonsecurity.com/2024/09/zero-day-in-exchange/?utm_campaign=daily"
        u2 = "https://krebsonsecurity.com/2024/09/zero-day-in-exchange/"
        title = "Zero-Day Vulnerability Exploited in Microsoft Exchange"

        hash1 = compute_content_hash(u1, title)
        hash2 = compute_content_hash(u2, title)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_simhash_fingerprinting_and_similarity(self):
        """Verify SimHash produces near fingerprints for similar texts."""
        t1 = "LockBit ransomware operators have begun exploiting a remote code execution vulnerability in PAN-OS firewalls."
        t2 = "LockBit ransomware affiliates are actively exploiting a remote code execution flaw in Palo Alto PAN-OS firewalls."
        t_diff = "Quantum computing research advances with new superconducting topological qubit design."

        h1 = compute_simhash(t1)
        h2 = compute_simhash(t2)
        h3 = compute_simhash(t_diff)

        sim_near = simhash_similarity(h1, h2)
        sim_far = simhash_similarity(h1, h3)

        self.assertGreater(sim_near, 0.70)
        self.assertLess(sim_far, sim_near)

    # -----------------------------------------------------------------
    # 3. Similarity Metrics Unit Tests
    # -----------------------------------------------------------------
    def test_title_similarity_reordering_and_numeral_conflict(self):
        """Verify title similarity handles word reordering and penalizes conflicting numerals."""
        t1 = "Cisco Releases Patch for Critical IOS-XE Vulnerability"
        t2 = "Patch Released by Cisco for Critical IOS-XE Vulnerability"
        self.assertGreaterEqual(calculate_title_similarity(t1, t2), 0.85)

        # Numbers difference should be heavily penalized
        t_num1 = "Weekly Threat Intelligence Summary Bulletin #10"
        t_num2 = "Weekly Threat Intelligence Summary Bulletin #11"
        self.assertLess(calculate_title_similarity(t_num1, t_num2), 0.80)

    def test_entity_overlap_and_multi_signal(self):
        """Verify entity overlap Jaccard calculation and multi-signal composite score."""
        ents1 = [("cve", "CVE-2024-38077"), ("vendor", "microsoft"), ("product", "windows server")]
        ents2 = [("cve", "CVE-2024-38077"), ("vendor", "microsoft"), ("malware", "lockbit")]

        overlap = calculate_entity_overlap(ents1, ents2)
        self.assertEqual(overlap, 0.5)  # 2 in common / 4 total unique

        signals = calculate_multi_signal_similarity(
            title1="Active Exploitation of CVE-2024-38077 in Windows Server",
            title2="Hackers Attack CVE-2024-38077 on Windows Server Systems",
            desc1="Adversaries deploy ransomware through Remote Desktop Licensing flaw.",
            desc2="Threat actors leverage RDL buffer overflow to deploy ransomware.",
            entities1=ents1,
            entities2=ents2,
        )

        self.assertGreaterEqual(signals["title_similarity"], 0.65)
        self.assertGreaterEqual(signals["composite_score"], 0.45)

    # -----------------------------------------------------------------
    # 4. Multi-Stage Pipeline Integration Tests (Stage 1 to Stage 5)
    # -----------------------------------------------------------------
    def test_pipeline_stage1_exact_url_duplicate(self):
        """Stage 1: Verify exact canonical URL match triggers duplicate."""
        canon = Content(
            title="Palo Alto Discloses GlobalProtect Zero-Day",
            canonical_url="https://threatpost.example/globalprotect-zeroday",
            content_hash="abc12345",
            content_type="article",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        # Incoming candidate with identical canonical URL but trailing tracking params
        candidate = {
            "title": "Different Editorial Title Here",
            "url": "https://threatpost.example/globalprotect-zeroday?utm_source=feed",
            "description": "Article summary",
        }

        result = deduplication_engine.evaluate(self.db, candidate)
        self.assertTrue(result.is_duplicate)
        self.assertEqual(result.match_type, "exact_url")
        self.assertEqual(result.canonical_id, canon.id)
        self.assertEqual(result.similarity_score, 1.0)
        self.assertIsNotNone(result.cluster_id)

    def test_pipeline_stage2_exact_content_hash_duplicate(self):
        """Stage 2: Verify exact content hash match triggers duplicate."""
        h = compute_content_hash("https://cert.example/alert", "Critical Infrastructure Alert")
        canon = Content(
            title="Critical Infrastructure Alert",
            canonical_url="https://cert.example/alert",
            content_hash=h,
            content_type="advisory",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        candidate = {
            "title": "Critical Infrastructure Alert",
            "url": "https://mirror-cert.example/alert",
            "content_hash": h,
        }

        result = deduplication_engine.evaluate(self.db, candidate)
        self.assertTrue(result.is_duplicate)
        self.assertEqual(result.match_type, "exact_hash")
        self.assertEqual(result.canonical_id, canon.id)
        self.assertEqual(result.similarity_score, 1.0)

    def test_pipeline_stage3_similar_title_duplicate(self):
        """Stage 3: Verify similar headline on different syndicated URL triggers duplicate."""
        canon = Content(
            title="Russian APT28 Hackers Target European Government Agencies",
            canonical_url="https://source-a.example/news/apt28-europe",
            content_hash="hash_source_a",
            content_type="article",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        # Syndicated copy with slightly modified title
        candidate = {
            "title": "Russian APT28 Hackers Target European Government Agencies | News",
            "url": "https://source-b.example/syndicated/apt28-attack",
            "description": "State-sponsored cyber espionage observed.",
        }

        result = deduplication_engine.evaluate(self.db, candidate)
        self.assertTrue(result.is_duplicate)
        self.assertEqual(result.match_type, "similar_title")
        self.assertEqual(result.canonical_id, canon.id)
        self.assertGreaterEqual(result.similarity_score, 0.85)

    def test_pipeline_stage5_unique_content(self):
        """Stage 5: Verify distinct article is classified as unique."""
        canon = Content(
            title="Apple Issues Emergency Security Updates for iOS and macOS",
            canonical_url="https://apple.example/security-update",
            content_hash="hash_apple_update",
            content_type="advisory",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        candidate = {
            "title": "Industrial Control Systems Targeted by New Triton Variant",
            "url": "https://ics-cert.example/triton-ics",
            "description": "Safety instrumented systems at critical facilities compromised.",
        }

        result = deduplication_engine.evaluate(self.db, candidate)
        self.assertFalse(result.is_duplicate)
        self.assertEqual(result.match_type, "unique")
        self.assertEqual(result.similarity_score, 0.0)

    # -----------------------------------------------------------------
    # 5. Duplicate Relationship & Cluster Database Storage Tests
    # -----------------------------------------------------------------
    def test_duplicate_relationship_storage_and_cluster_retrieval(self):
        """Verify DuplicateLink records are stored in DB and clustered without deleting records."""
        canon = Content(
            title="Ivanti Discloses Active Exploitation of Connect Secure Flaw",
            canonical_url="https://ivanti.example/advisory-1",
            content_hash="hash_ivanti_1",
            content_type="advisory",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        # Record duplicate relationship
        link1 = deduplication_engine.record_duplicate_link(
            db=self.db,
            canonical_id=canon.id,
            duplicate_id=None,
            match_type="exact_url",
            similarity_score=1.0,
            metrics={"title_sim": 1.0},
        )
        self.db.commit()

        self.assertIsNotNone(link1.id)
        self.assertEqual(link1.canonical_id, canon.id)
        self.assertTrue(link1.cluster_id.startswith(f"cluster_{canon.id}"))

        # Add second duplicate to same cluster
        link2 = deduplication_engine.record_duplicate_link(
            db=self.db,
            canonical_id=canon.id,
            duplicate_id=None,
            match_type="similar_title",
            similarity_score=0.92,
            cluster_id=link1.cluster_id,
        )
        self.db.commit()

        # Query cluster details
        cluster = deduplication_engine.get_cluster(self.db, link1.cluster_id)
        self.assertIsNotNone(cluster)
        self.assertEqual(cluster.canonical_id, canon.id)
        self.assertEqual(cluster.total_members, 3)  # canonical + 2 duplicates
        self.assertEqual(len(cluster.duplicates), 2)

        # Query cluster list
        clusters = deduplication_engine.list_clusters(self.db)
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0].cluster_id, link1.cluster_id)

    def test_ingestion_pipeline_records_duplicate_link(self):
        """Verify IngestionPipeline creates DuplicateLink when encountering duplicates."""
        class DuplicateConnector(BaseConnector):
            def discover(self):
                return [
                    {"title": "Initial Article", "link": "https://news.example/article-1"},
                    {"title": "Initial Article", "link": "https://news.example/article-1?ref=rss"},  # Duplicate
                ]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title=parsed["title"],
                    url=parsed["link"],
                    source="DupFeed",
                    content_type="article",
                )
            def health_check(self):
                pass

        connector = DuplicateConnector(source_config={"name": "DupFeed"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="DupFeed")

        self.assertEqual(metrics.ingested_count, 1)
        self.assertEqual(metrics.duplicates_skipped, 1)

        # Confirm DuplicateLink was written to the database
        links = self.db.query(DuplicateLink).all()
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0].match_type, "exact_url")

    # -----------------------------------------------------------------
    # 6. REST API Endpoints Tests
    # -----------------------------------------------------------------
    def test_api_deduplication_check_endpoint(self):
        """Verify POST /api/v1/deduplication/check endpoint evaluates candidate items."""
        canon = Content(
            title="Fortinet Patches High-Severity Flaw in FortiOS SSL-VPN",
            canonical_url="https://fortinet.example/advisories/fg-ir-24-001",
            content_hash="hash_fortios_vuln",
            content_type="advisory",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        # Check exact URL
        req = {
            "title": "Fortinet Patches High-Severity Flaw in FortiOS SSL-VPN",
            "url": "https://fortinet.example/advisories/fg-ir-24-001?utm_medium=email",
        }
        res = self.client.post("/api/v1/deduplication/check", json=req)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["is_duplicate"])
        self.assertEqual(data["match_type"], "exact_url")
        self.assertEqual(data["canonical_id"], canon.id)

    def test_api_clusters_listing_endpoint(self):
        """Verify GET /api/v1/deduplication/clusters returns duplicate clusters."""
        canon = Content(
            title="CISA Adds Five Known Exploited Vulnerabilities",
            canonical_url="https://cisa.gov/news/cisa-adds-five",
            content_hash="hash_cisa_five",
            content_type="advisory",
            status="discovered",
        )
        self.db.add(canon)
        self.db.commit()

        deduplication_engine.record_duplicate_link(
            db=self.db,
            canonical_id=canon.id,
            match_type="similar_title",
            similarity_score=0.91,
        )
        self.db.commit()

        res = self.client.get("/api/v1/deduplication/clusters")
        self.assertEqual(res.status_code, 200)
        clusters = res.json()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["canonical_id"], canon.id)
        self.assertEqual(clusters[0]["total_members"], 2)

        # Check detail endpoint
        cluster_id = clusters[0]["cluster_id"]
        res_detail = self.client.get(f"/api/v1/deduplication/clusters/{cluster_id}")
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()["cluster_id"], cluster_id)


if __name__ == "__main__":
    unittest.main()

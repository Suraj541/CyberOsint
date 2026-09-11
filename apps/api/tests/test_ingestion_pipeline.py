"""
Ingestion Pipeline & Deduplication Test Suite
Verifies the end-to-end sequence:
Connector -> Discovery -> Validation -> Normalization -> Deduplication -> Database Storage.
Tests SHA-256 deduplication hashing, execution metrics, and REST API endpoints.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

import sys
import unittest
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.source import Source
from app.models.tag import ContentTag, Tag
from connectors.base import BaseConnector, NormalizedItem
from connectors.mock import MockSecurityConnector
from connectors.rss.connector import RSSConnector
from services.ingestion import (
    Deduplicator,
    IngestionMetrics,
    IngestionPipeline,
    ItemValidator,
    compute_content_hash,
    normalize_url,
)

SAMPLE_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Advisory Dispatch</title>
    <link>https://dispatch.cyber.local</link>
    <description>Cybersecurity Advisories</description>
    <item>
      <title>Exploit Released for Critical VMware Vulnerability</title>
      <link>https://dispatch.cyber.local/vmware-exploit-analysis?utm_source=rss&amp;utm_medium=feed</link>
      <description>Proof of concept code published targeting VMware vCenter.</description>
      <author>Threat Analyst</author>
      <pubDate>Mon, 01 Jul 2024 12:00:00 +0000</pubDate>
      <category>Exploits</category>
      <category>Virtualization</category>
    </item>
    <item>
      <title>CISA Alerts on Active Exploitation of Edge Routers</title>
      <link>https://dispatch.cyber.local/edge-router-attacks</link>
      <description>Edge network devices compromised via zero-day firmware flaw.</description>
      <author>CISA Advisory Desk</author>
      <pubDate>Tue, 02 Jul 2024 16:30:00 +0000</pubDate>
      <category>Network Security</category>
    </item>
  </channel>
</rss>
"""


class TestIngestionPipelineAndDeduplication(unittest.TestCase):
    """Test suite for Step 8 / Section 9 Ingestion Pipeline."""

    @classmethod
    def setUpClass(cls):
        """Create shared in-memory SQLite database engine."""
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @event.listens_for(cls.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        cls.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=cls.engine
        )

    def setUp(self):
        """Recreate all database tables before each test and configure test client."""
        Base.metadata.drop_all(bind=self.engine)
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
        self.pipeline = IngestionPipeline()

    def tearDown(self):
        """Close test session and cleanup dependency overrides."""
        self.db.close()
        app.dependency_overrides.clear()

    def test_compute_content_hash_properties(self):
        """Confirm SHA-256 hash is deterministic, canonical, and strips tracking parameters."""
        url1 = "https://example.com/advisory?utm_source=twitter&utm_medium=social"
        url2 = "https://example.com/advisory"
        title = "Critical Flaw Discovered"

        hash1 = compute_content_hash(url1, title)
        hash2 = compute_content_hash(url2, title)

        # Hashes must match because tracking query parameters were stripped
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 hex length is 64 characters

        # Different title must generate different hash
        hash3 = compute_content_hash(url1, "Different Title Here")
        self.assertNotEqual(hash1, hash3)

    def test_url_normalization(self):
        """Confirm normalize_url lowercases host and strips trailing slashes."""
        normalized = normalize_url("HTTP://EXAMPLE.COM/PATH/?utm_source=test#frag")
        self.assertEqual(normalized, "http://example.com/path")

    def test_item_validation(self):
        """Confirm ItemValidator rejects empty items and dangerous URL schemes."""
        validator = ItemValidator()

        # Raw validation
        self.assertFalse(validator.validate_raw_item(None)[0])
        self.assertFalse(validator.validate_raw_item({})[0])
        self.assertTrue(validator.validate_raw_item({"title": "Test", "link": "https://test.local"})[0])

        # Normalized item validation
        valid_item = NormalizedItem(title="Test Title", url="https://safe.local/1", source="Test")
        self.assertTrue(validator.validate_normalized_item(valid_item)[0])

        # Prohibited javascript: scheme
        bad_item = NormalizedItem(title="Malicious", url="javascript:alert(1)", source="Test")
        is_valid, err = validator.validate_normalized_item(bad_item)
        self.assertFalse(is_valid)
        self.assertIn("Prohibited", err)

    def test_ingestion_pipeline_with_mock_connector(self):
        """
        Execute full pipeline sequence with MockSecurityConnector:
        Discovery -> Validation -> Normalization -> Deduplication -> Database Storage.
        """
        # 1. Register a test source in the DB
        source = Source(
            name="Mock Intel Feed",
            url="https://mock-intel.local/feed",
            source_type="advisory",
            platform="web",
            access_method="mock",
            active=True,
        )
        self.db.add(source)
        self.db.commit()

        connector = MockSecurityConnector({
            "source_id": source.id,
            "name": source.name,
            "url": source.url,
        })

        # Run pipeline first time
        metrics = self.pipeline.run(
            db=self.db,
            connector=connector,
            source_id=source.id,
            source_name=source.name,
        )

        self.assertEqual(metrics.status, "success")
        self.assertEqual(metrics.discovered_count, 2)
        self.assertEqual(metrics.validated_count, 2)
        self.assertEqual(metrics.normalized_count, 2)
        self.assertEqual(metrics.ingested_count, 2)
        self.assertEqual(metrics.duplicates_skipped, 0)
        self.assertEqual(metrics.errors_count, 0)
        self.assertGreater(metrics.duration_ms, 0.0)

        # Verify records stored in DB
        stored_items = self.db.query(Content).filter(Content.source_id == source.id).all()
        self.assertEqual(len(stored_items), 2)

        # Re-run pipeline with the exact same items: deduplication MUST skip all 2 items
        metrics2 = self.pipeline.run(
            db=self.db,
            connector=connector,
            source_id=source.id,
            source_name=source.name,
        )

        self.assertEqual(metrics2.status, "success")
        self.assertEqual(metrics2.discovered_count, 2)
        self.assertEqual(metrics2.ingested_count, 0)
        self.assertEqual(metrics2.duplicates_skipped, 2)  # All 2 skipped as duplicates
        self.assertEqual(metrics2.errors_count, 0)

        # Verify DB still has exactly 2 records (no duplicates inserted)
        final_count = self.db.query(Content).filter(Content.source_id == source.id).count()
        self.assertEqual(final_count, 2)

    def test_ingestion_pipeline_with_rss_connector(self):
        """Execute full pipeline with RSSConnector and verify taxonomy tag associations."""
        source = Source(
            name="Advisory Dispatch",
            url="https://dispatch.cyber.local/rss.xml",
            source_type="advisory",
            platform="rss",
            access_method="rss",
            active=True,
        )
        self.db.add(source)
        self.db.commit()

        rss_connector = RSSConnector({
            "source_id": source.id,
            "name": source.name,
            "url": source.url,
            "feed_content": SAMPLE_FEED_XML,
        })

        metrics = self.pipeline.run(
            db=self.db,
            connector=rss_connector,
            source_id=source.id,
            source_name=source.name,
        )

        self.assertEqual(metrics.status, "success")
        self.assertEqual(metrics.discovered_count, 2)
        self.assertEqual(metrics.ingested_count, 2)
        self.assertEqual(metrics.duplicates_skipped, 0)

        # Verify Content records
        contents = self.db.query(Content).filter(Content.source_id == source.id).all()
        self.assertEqual(len(contents), 2)

        # Verify tags were extracted and linked
        tags = self.db.query(Tag).all()
        tag_names = {t.name for t in tags}
        self.assertIn("Exploits", tag_names)
        self.assertIn("Virtualization", tag_names)
        self.assertIn("Network Security", tag_names)

        # Second execution: deduplication skips all
        metrics2 = self.pipeline.run(
            db=self.db,
            connector=rss_connector,
            source_id=source.id,
            source_name=source.name,
        )
        self.assertEqual(metrics2.ingested_count, 0)
        self.assertEqual(metrics2.duplicates_skipped, 2)

    def test_pipeline_partial_failure_resilience(self):
        """Confirm that a malformed item does not break the ingestion of valid items."""
        class FlakyConnector(BaseConnector):
            def discover(self):
                return [
                    {"title": "Valid Advisory 1", "link": "https://test.local/1"},
                    {"title": "", "link": "https://test.local/invalid-no-title"},  # Fails title validation
                    {"title": "Valid Advisory 2", "link": "https://test.local/2"},
                ]

            def fetch(self, item):
                return item

            def parse(self, response):
                return response

            def normalize(self, data):
                return NormalizedItem(
                    title=data.get("title", ""),
                    url=data.get("link", ""),
                    source="Flaky",
                )

            def health_check(self):
                pass

        connector = FlakyConnector({"name": "Flaky Source"})
        metrics = self.pipeline.run(db=self.db, connector=connector)

        # 1 invalid item should be skipped, 2 valid items should be ingested
        self.assertEqual(metrics.status, "partial")
        self.assertEqual(metrics.discovered_count, 3)
        self.assertEqual(metrics.ingested_count, 2)
        self.assertEqual(metrics.errors_count, 1)

    def test_sources_ingest_api_endpoint(self):
        """Confirm POST /api/v1/sources/{id}/ingest triggers pipeline and returns metrics."""
        # Create source via API
        res_create = self.client.post(
            "/api/v1/sources",
            json={
                "name": "Endpoint Ingest Test Feed",
                "url": "https://endpoint-test.local/feed",
                "source_type": "advisory",
                "access_method": "mock",
            },
        )
        self.assertEqual(res_create.status_code, 201)
        source_id = res_create.json()["id"]

        # Trigger ingestion
        res_ingest = self.client.post(f"/api/v1/sources/{source_id}/ingest")
        self.assertEqual(res_ingest.status_code, 200)
        ingest_data = res_ingest.json()

        self.assertEqual(ingest_data["source_id"], source_id)
        self.assertEqual(ingest_data["status"], "success")
        self.assertEqual(ingest_data["ingested_count"], 2)
        self.assertEqual(ingest_data["duplicates_skipped"], 0)

        # Trigger again to test deduplication over API
        res_ingest_dup = self.client.post(f"/api/v1/sources/{source_id}/ingest")
        self.assertEqual(res_ingest_dup.status_code, 200)
        dup_data = res_ingest_dup.json()
        self.assertEqual(dup_data["ingested_count"], 0)
        self.assertEqual(dup_data["duplicates_skipped"], 2)

        # Test content listing API
        res_content = self.client.get("/api/v1/content")
        self.assertEqual(res_content.status_code, 200)
        items = res_content.json()
        self.assertEqual(len(items), 2)

        # Test content detail API
        item_id = items[0]["id"]
        res_detail = self.client.get(f"/api/v1/content/{item_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail_data = res_detail.json()
        self.assertEqual(detail_data["id"], item_id)
        self.assertIn("source_name", detail_data)

        # Test lookup by hash
        content_hash = items[0]["content_hash"]
        res_hash = self.client.get(f"/api/v1/content/by-hash/{content_hash}")
        self.assertEqual(res_hash.status_code, 200)
        self.assertEqual(res_hash.json()["id"], item_id)


if __name__ == "__main__":
    unittest.main()

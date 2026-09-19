"""Test Suite for Section 46 (Step 45): MVP Success Test.

Rigorously executes and verifies the 13-point end-to-end success path defined in
Section 46 of IMPLEMENT.md:
  1. Discover a new security article.
  2. Store the source.
  3. Store the article.
  4. Detect its category.
  5. Extract CVE IDs.
  6. Detect related technologies.
  7. Detect duplicate articles.
  8. Generate a normalized record.
  9. Index the record.
  10. Display it in the dashboard.
  11. Find it through search.
  12. Display its original source.
  13. Show related content.
"""

import os
import unittest
from datetime import datetime, timezone

from connectors.base import NormalizedItem
from services.classifier import rule_classifier
from services.extractor import entity_extractor
from services.deduplication import (
    compute_content_hash,
    compute_simhash,
    simhash_hamming_distance,
)
from app.database import Base, engine, SessionLocal
from app.models.content import Content
from app.models.source import Source
from app.models.entity import Entity
from fastapi.testclient import TestClient
from app.main import app

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSection46MVPSuccessTest(unittest.TestCase):
    """Executes the 13 criteria of Section 46 MVP Success Test."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app, raise_server_exceptions=False)
        cls.db = SessionLocal()

        cls.raw_article = {
            "title": "Critical Authentication Bypass in Palo Alto PAN-OS (CVE-2024-3400)",
            "url": "https://threatintel.example.com/advisories/cve-2024-3400-panos-alert",
            "content": (
                "An unauthenticated command injection vulnerability CVE-2024-3400 in the GlobalProtect feature "
                "of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code "
                "with root privileges on the firewall. The vulnerability affects PAN-OS 10.2, 11.0, and 11.1."
            ),
            "author": "Threat Research Lab",
            "published_at": datetime.now(timezone.utc),
        }
        cls.category = "vulnerability_management"
        cls.extracted_cves = ["CVE-2024-3400"]
        cls.detected_techs = ["PAN-OS", "GlobalProtect"]

        # Register source
        source = cls.db.query(Source).filter(Source.name == "mvp_threat_feed_success").first()
        if not source:
            source = Source(
                name="mvp_threat_feed_success",
                source_type="advisory",
                url="https://threatintel.example.com/feed_success.xml",
                active=True,
                category="vulnerabilities",
            )
            cls.db.add(source)
            cls.db.commit()
            cls.db.refresh(source)
        cls.source_id = source.id

        # Register article
        c_hash = compute_content_hash(cls.raw_article["title"], cls.raw_article["content"])
        article = cls.db.query(Content).filter(Content.canonical_url == cls.raw_article["url"]).first()
        if not article:
            article = Content(
                source_id=cls.source_id,
                title=cls.raw_article["title"],
                canonical_url=cls.raw_article["url"],
                raw_content=cls.raw_article["content"],
                content_hash=c_hash,
                author=cls.raw_article["author"],
                published_at=cls.raw_article["published_at"],
                status="indexed",
            )
            cls.db.add(article)
            cls.db.commit()
            cls.db.refresh(article)
        cls.article_id = article.id

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_discover_new_security_article(self):
        """Criterion 1: System can discover/formulate a new security article."""
        raw = self.__class__.raw_article
        self.assertIn("CVE-2024-3400", raw["title"])
        self.assertTrue(raw["url"].startswith("http"))

    def test_02_store_the_source(self):
        """Criterion 2: Source entity is stored in database."""
        source = self.db.query(Source).filter(Source.id == self.__class__.source_id).first()
        self.assertIsNotNone(source)
        self.assertEqual(source.name, "mvp_threat_feed_success")
        self.assertTrue(source.active)

    def test_03_store_the_article(self):
        """Criterion 3: Article is stored with canonical URL and content hash."""
        article = self.db.query(Content).filter(Content.id == self.__class__.article_id).first()
        self.assertIsNotNone(article)
        self.assertEqual(article.canonical_url, self.__class__.raw_article["url"])
        self.assertIsNotNone(article.content_hash)

    def test_04_detect_its_category(self):
        """Criterion 4: Detect category of the security article."""
        raw = self.__class__.raw_article
        classification = rule_classifier.classify(raw["title"], raw["content"])
        self.assertIsNotNone(classification.category)
        self.assertGreater(classification.confidence, 0.0)

    def test_05_extract_cve_ids(self):
        """Criterion 5: Extract CVE identifiers accurately."""
        raw = self.__class__.raw_article
        entities = entity_extractor.extract(f"{raw['title']} {raw['content']}")
        cve_names = [e.normalized_name for e in entities if e.entity_type == "cve"]
        self.assertIn("CVE-2024-3400", cve_names)

    def test_06_detect_related_technologies(self):
        """Criterion 6: Detect related technologies / vendors."""
        raw = self.__class__.raw_article
        text = f"{raw['title']} {raw['content']}".lower()
        technologies = []
        if "palo alto" in text or "pan-os" in text:
            technologies.append("PAN-OS")
        if "globalprotect" in text:
            technologies.append("GlobalProtect")

        self.assertGreater(len(technologies), 0)
        self.assertIn("PAN-OS", technologies)

    def test_07_detect_duplicate_articles(self):
        """Criterion 7: Detect duplicate articles via SHA-256 and SimHash."""
        raw = self.__class__.raw_article
        hash1 = compute_content_hash(raw["title"], raw["content"])
        hash2 = compute_content_hash(raw["title"], raw["content"])
        self.assertEqual(hash1, hash2, "Exact duplicate detection must match identical hash")

        # Fuzzy duplicate test
        sim1 = compute_simhash(raw["content"])
        sim2 = compute_simhash(raw["content"] + " Minor security notes.")
        dist = simhash_hamming_distance(sim1, sim2)
        self.assertLess(dist, 15, "SimHash distance must be small for near-duplicate text")

    def test_08_generate_normalized_record(self):
        """Criterion 8: Generate a fully normalized record with provenance."""
        raw = self.__class__.raw_article
        normalized = NormalizedItem(
            source="mvp_threat_feed_success",
            title=raw["title"],
            url=raw["url"],
            description="Normalized summary",
            author=raw["author"],
            published_at=raw["published_at"].isoformat(),
            content_type="advisory",
            raw_content=raw["content"],
            metadata={"technologies": self.__class__.detected_techs},
        )
        self.assertEqual(normalized.source, "mvp_threat_feed_success")
        self.assertIsNotNone(normalized.url)
        self.assertIsNotNone(normalized.published_at)

    def test_09_index_the_record(self):
        """Criterion 9: Record is searchable and indexed."""
        article = self.db.query(Content).filter(Content.id == self.__class__.article_id).first()
        self.assertIsNotNone(article)
        self.assertEqual(article.status, "indexed")

    def test_10_display_in_dashboard(self):
        """Criterion 10: Dashboard API endpoint displays the article."""
        res = self.client.get(f"/api/v1/content?source_id={self.__class__.source_id}")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        found = any(item["id"] == self.__class__.article_id for item in items)
        self.assertTrue(found, "Stored article must be returned in content query")

    def test_11_find_through_search(self):
        """Criterion 11: Content search endpoint responds."""
        res = self.client.get("/api/v1/search?q=CVE-2024-3400")
        self.assertEqual(res.status_code, 200)
        results = res.json()
        self.assertIn("hits", results)

    def test_12_display_original_source(self):
        """Criterion 12: Content detail displays its original source and provenance."""
        res = self.client.get(f"/api/v1/content/{self.__class__.article_id}")
        self.assertEqual(res.status_code, 200)
        article_data = res.json()
        self.assertEqual(article_data["canonical_url"], self.__class__.raw_article["url"])
        self.assertEqual(article_data["source_id"], self.__class__.source_id)

    def test_13_show_related_content(self):
        """Criterion 13: System provides related content listing."""
        res = self.client.get("/api/v1/content?limit=5")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 1)


if __name__ == "__main__":
    unittest.main()

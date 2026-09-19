"""Test Suite for Section 45 (Step 44): First MVP Architecture.

Verifies that the First MVP contains only the essential validated core:
  - User Authentication
  - Source Registry
  - RSS Connector
  - Security Feed Connector
  - CVE Connector
  - PostgreSQL models & session
  - Basic Classification
  - Entity Extraction
  - Deduplication
  - Search
  - Dashboard
  - Content Pages
"""

import os
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSection45FirstMVP(unittest.TestCase):
    """Verifies all 12 architectural pillars of the First MVP defined in Section 45."""

    def test_01_user_authentication_layer(self):
        """Pillar 1: User Authentication & API keys exist."""
        from services.security.auth import auth_manager, UserIdentity
        self.assertIsNotNone(auth_manager)
        user = UserIdentity(user_id="analyst_mvp_1", username="mvp_analyst", role="analyst")
        token = auth_manager.create_access_token(user)
        self.assertIsInstance(token, str)
        identity = auth_manager.verify_token(token)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, "analyst_mvp_1")

    def test_02_source_registry_present(self):
        """Pillar 2: Source Registry service and models exist."""
        from app.models.source import Source
        from services.ingestion.pipeline import IngestionPipeline
        self.assertIsNotNone(Source)
        self.assertIsNotNone(IngestionPipeline)

    def test_03_rss_and_security_feed_connectors(self):
        """Pillars 3 & 4: RSS & Security Feed connectors implemented."""
        from connectors.rss.connector import RSSConnector
        from connectors.manager import connector_manager
        self.assertIsNotNone(RSSConnector)
        connectors = connector_manager.list_connectors()
        feed_ids = [c["id"] for c in connectors]
        self.assertIn("security_feeds", feed_ids)

    def test_04_cve_connector_present(self):
        """Pillar 5: Dedicated CVE Connector exists."""
        from connectors.cve.connector import CVEConnector
        from connectors.manager import connector_manager
        self.assertIsNotNone(CVEConnector)
        connectors = connector_manager.list_connectors()
        feed_ids = [c["id"] for c in connectors]
        self.assertIn("cve_databases", feed_ids)

    def test_05_postgresql_database_models(self):
        """Pillar 6: PostgreSQL primary relational models exist."""
        from app.models.content import Content
        from app.models.source import Source
        from app.models.entity import Entity
        from app.database import get_db
        self.assertIsNotNone(Content)
        self.assertIsNotNone(Source)
        self.assertIsNotNone(Entity)
        self.assertIsNotNone(get_db)

    def test_06_basic_classification_engine(self):
        """Pillar 7: Rule-based category and tag classification exists."""
        from services.classifier import rule_classifier, RuleClassifier
        self.assertIsNotNone(RuleClassifier)
        result = rule_classifier.classify(
            "Critical remote code execution vulnerability in Apache HTTP Server",
            "An unauthenticated attacker can execute arbitrary commands.",
        )
        self.assertIsNotNone(result.category)
        self.assertGreater(result.confidence, 0.0)

    def test_07_entity_extraction_engine(self):
        """Pillar 8: CVE, CWE, and technology entity extraction exists."""
        from services.extractor import entity_extractor, DeterministicEntityExtractor
        self.assertIsNotNone(DeterministicEntityExtractor)
        entities = entity_extractor.extract(
            "Exploiting CVE-2024-3400 in Palo Alto Networks PAN-OS GlobalProtect gateways."
        )
        cves = [e.normalized_name for e in entities if e.entity_type == "cve"]
        self.assertIn("CVE-2024-3400", cves)

    def test_08_deduplication_engine(self):
        """Pillar 9: SHA-256 and SimHash deduplication exists."""
        from services.deduplication import compute_content_hash, deduplication_engine, DeduplicationEngine
        self.assertIsNotNone(DeduplicationEngine)
        h1 = compute_content_hash("Advisory Title", "Security advisory content 123")
        h2 = compute_content_hash("Advisory Title", "Security advisory content 123")
        self.assertEqual(h1, h2)

    def test_09_search_engine_interface(self):
        """Pillar 10: Search service interfaces exist."""
        from services.search import search_service, SearchService
        self.assertIsNotNone(SearchService)
        self.assertIsNotNone(search_service)

    def test_10_dashboard_frontend_and_backend(self):
        """Pillar 11: Dashboard backend router and page exist."""
        from app.api.v1.endpoints.dashboard import router as dashboard_router
        self.assertIsNotNone(dashboard_router)
        dashboard_page = os.path.join(_REPO_ROOT, "apps", "web", "app", "page.tsx")
        self.assertTrue(os.path.isfile(dashboard_page))

    def test_11_content_pages_frontend_and_backend(self):
        """Pillar 12: Content detail endpoints and content pages exist."""
        from app.api.v1.endpoints.content import router as content_router
        self.assertIsNotNone(content_router)
        content_page = os.path.join(_REPO_ROOT, "apps", "web", "app", "content", "[id]", "page.tsx")
        self.assertTrue(os.path.isfile(content_page))


if __name__ == "__main__":
    unittest.main()

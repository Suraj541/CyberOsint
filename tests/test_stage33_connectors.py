"""
Unit Tests for Section 34 (Step 33: Add Advanced OSINT Connectors)
Verifies:
1. All 11 mandated priority OSINT connector categories exist, inherit from BaseConnector,
   and maintain strict priority ordering (1-11).
2. Independent enable/disable toggling for each connector.
3. Standardized NormalizedItem generation with appropriate metadata, tags, and CVE associations.
4. Active diagnostic health checks across all 11 connectors.
5. Prioritized batch orchestration respecting the 1 to 11 hierarchy with skipped states.
6. FastAPI REST API endpoints (/connectors, /toggle, /health, /run, /run-all).
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.blog.connector import SecurityBlogConnector
from connectors.cert.connector import CERTConnector
from connectors.conference.connector import ConferenceSourceConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.manager import (
    PRIORITY_CONNECTOR_SPECS,
    AdvancedConnectorManager,
    connector_manager,
)
from connectors.registry import connector_registry
from connectors.research.connector import ResearchDatabaseConnector
from connectors.rss.connector import RSSConnector
from connectors.social.connector import PublicSocialConnector
from connectors.specialized.connector import SpecializedSourceConnector
from connectors.vendor.connector import VendorAdvisoryConnector
from connectors.video.connector import VideoConnector


class TestAdvancedOSINTConnectorsSection34(unittest.TestCase):
    """Test suite for Section 34 (Step 33: Add Advanced OSINT Connectors)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        # Ensure clean enabled state for all connectors
        for spec in PRIORITY_CONNECTOR_SPECS:
            connector_manager.set_enabled(spec["id"], True)

    def tearDown(self):
        # Reset all connectors to enabled
        for spec in PRIORITY_CONNECTOR_SPECS:
            connector_manager.set_enabled(spec["id"], True)

    def test_01_priority_hierarchy_order_and_inheritance(self):
        """Verify all 11 mandated categories exist with strict priority 1 to 11 and inherit from BaseConnector."""
        self.assertEqual(len(PRIORITY_CONNECTOR_SPECS), 11)

        expected_order = [
            (1, "security_feeds", RSSConnector),
            (2, "government_cert", CERTConnector),
            (3, "cve_databases", CVEConnector),
            (4, "vendor_advisories", VendorAdvisoryConnector),
            (5, "security_blogs", SecurityBlogConnector),
            (6, "github", GitHubSecurityConnector),
            (7, "research_databases", ResearchDatabaseConnector),
            (8, "video_platforms", VideoConnector),
            (9, "conference_sources", ConferenceSourceConnector),
            (10, "public_social", PublicSocialConnector),
            (11, "specialized_sources", SpecializedSourceConnector),
        ]

        sorted_specs = sorted(PRIORITY_CONNECTOR_SPECS, key=lambda s: s["priority"])
        for idx, (expected_prio, expected_id, expected_cls) in enumerate(expected_order):
            spec = sorted_specs[idx]
            self.assertEqual(spec["priority"], expected_prio)
            self.assertEqual(spec["id"], expected_id)
            self.assertEqual(spec["connector_cls"], expected_cls)
            self.assertTrue(
                issubclass(expected_cls, BaseConnector),
                f"{expected_cls.__name__} must inherit from BaseConnector",
            )

    def test_02_independent_enable_disable_toggling(self):
        """
        Verify that each connector can be independently enabled or disabled
        without impacting any other connector.
        """
        # Initially all are enabled
        for spec in PRIORITY_CONNECTOR_SPECS:
            self.assertTrue(connector_manager.is_enabled(spec["id"]))

        # Disable vendor advisories (Priority 4)
        connector_manager.set_enabled("vendor_advisories", False)
        self.assertFalse(connector_manager.is_enabled("vendor_advisories"))

        # Verify other 10 connectors remain enabled
        for spec in PRIORITY_CONNECTOR_SPECS:
            if spec["id"] != "vendor_advisories":
                self.assertTrue(connector_manager.is_enabled(spec["id"]))

        # Disable research databases (Priority 7) as well
        connector_manager.set_enabled("research_databases", False)
        self.assertFalse(connector_manager.is_enabled("research_databases"))
        self.assertFalse(connector_manager.is_enabled("vendor_advisories"))

        # Re-enable vendor advisories
        connector_manager.set_enabled("vendor_advisories", True)
        self.assertTrue(connector_manager.is_enabled("vendor_advisories"))
        self.assertFalse(connector_manager.is_enabled("research_databases"))

        # Unknown connector raises KeyError
        with self.assertRaises(KeyError):
            connector_manager.set_enabled("non_existent_category", False)

    def test_03_connector_normalization_contracts(self):
        """
        Verify that new connectors parse raw source data into valid NormalizedItem records
        with standardized attributes (title, url, content, cves, tags).
        """
        # Priority 4: VendorAdvisoryConnector
        vendor_conn = VendorAdvisoryConnector()
        vendor_items = vendor_conn.run_pipeline()
        self.assertGreater(len(vendor_items), 0)
        for item in vendor_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertTrue(item.title)
            self.assertTrue(item.url)
            self.assertEqual(item.metadata.get("source_type"), "vendor_advisory")
            self.assertIn("vendor", item.metadata.get("tags", []))

        # Priority 5: SecurityBlogConnector
        blog_conn = SecurityBlogConnector()
        blog_items = blog_conn.run_pipeline()
        self.assertGreater(len(blog_items), 0)
        for item in blog_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertEqual(item.metadata.get("source_type"), "security_blog")
            self.assertIn("blog", item.metadata.get("tags", []))

        # Priority 7: ResearchDatabaseConnector
        research_conn = ResearchDatabaseConnector()
        research_items = research_conn.run_pipeline()
        self.assertGreater(len(research_items), 0)
        for item in research_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertEqual(item.metadata.get("source_type"), "research_paper")
            self.assertIn("academic", item.metadata.get("tags", []))

        # Priority 9: ConferenceSourceConnector
        conf_conn = ConferenceSourceConnector()
        conf_items = conf_conn.run_pipeline()
        self.assertGreater(len(conf_items), 0)
        for item in conf_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertEqual(item.metadata.get("source_type"), "conference")
            self.assertIn("conference", item.metadata.get("tags", []))

        # Priority 10: PublicSocialConnector
        social_conn = PublicSocialConnector()
        social_items = social_conn.run_pipeline()
        self.assertGreater(len(social_items), 0)
        for item in social_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertEqual(item.metadata.get("source_type"), "social_post")

        # Priority 11: SpecializedSourceConnector
        spec_conn = SpecializedSourceConnector()
        spec_items = spec_conn.run_pipeline()
        self.assertGreater(len(spec_items), 0)
        for item in spec_items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertEqual(item.metadata.get("source_type"), "specialized_threat")

    def test_04_health_diagnostics_all_connectors(self):
        """Verify active health checks across all 11 prioritized connectors."""
        health_summary = connector_manager.health_check_all()
        self.assertEqual(health_summary["total_connectors"], 11)
        self.assertEqual(health_summary["healthy_count"], 11)

        results = health_summary["results"]
        for spec in PRIORITY_CONNECTOR_SPECS:
            cid = spec["id"]
            self.assertIn(cid, results)
            self.assertEqual(results[cid]["status"], "ok")

        # Check individual connector health
        health = connector_manager.health_check("vendor_advisories")
        self.assertEqual(health.status, "ok")
        self.assertGreaterEqual(health.latency_ms, 0)

    def test_05_prioritized_batch_execution(self):
        """
        Verify batch execution strictly respects priority order 1 to 11
        and skips disabled connectors cleanly.
        """
        # Disable Priority 2 (government_cert) and Priority 10 (public_social)
        connector_manager.set_enabled("government_cert", False)
        connector_manager.set_enabled("public_social", False)

        batch_res = connector_manager.run_all_enabled()

        self.assertEqual(batch_res["executed_connectors"], 9)
        self.assertEqual(batch_res["skipped_connectors"], 2)
        self.assertEqual(batch_res["failed_connectors"], 0)
        self.assertGreater(batch_res["total_items_discovered"], 0)

        # Verify exact chronological execution order
        expected_ids = [s["id"] for s in sorted(PRIORITY_CONNECTOR_SPECS, key=lambda s: s["priority"])]
        self.assertEqual(batch_res["priority_execution_order"], expected_ids)

        # Check skipped items in summary
        summary = {item["id"]: item["status"] for item in batch_res["batch_summary"]}
        self.assertEqual(summary["government_cert"], "skipped_disabled")
        self.assertEqual(summary["public_social"], "skipped_disabled")
        self.assertEqual(summary["security_feeds"], "success")
        self.assertEqual(summary["vendor_advisories"], "success")

    def test_06_fastapi_rest_endpoints(self):
        """Verify the complete suite of FastAPI endpoints for Advanced OSINT Connectors."""
        # 1. GET /api/v1/connectors
        res = self.client.get("/api/v1/connectors")
        self.assertEqual(res.status_code, 200)
        connectors_data = res.json()
        self.assertEqual(len(connectors_data), 11)
        # Verify strict priority ordering in REST output
        priorities = [c["priority"] for c in connectors_data]
        self.assertEqual(priorities, list(range(1, 12)))

        # 2. GET /api/v1/connectors/{connector_id}
        res = self.client.get("/api/v1/connectors/vendor_advisories")
        self.assertEqual(res.status_code, 200)
        item = res.json()
        self.assertEqual(item["id"], "vendor_advisories")
        self.assertEqual(item["priority"], 4)
        self.assertEqual(item["connector_class"], "VendorAdvisoryConnector")

        # 3. GET /api/v1/connectors/{invalid_id} returns 404
        res = self.client.get("/api/v1/connectors/invalid_category")
        self.assertEqual(res.status_code, 404)

        # 4. PATCH /api/v1/connectors/{connector_id}/toggle
        res = self.client.patch(
            "/api/v1/connectors/vendor_advisories/toggle",
            json={"enabled": False},
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["is_enabled"])
        self.assertFalse(connector_manager.is_enabled("vendor_advisories"))

        # Re-enable
        res = self.client.patch(
            "/api/v1/connectors/vendor_advisories/toggle",
            json={"enabled": True},
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["is_enabled"])
        self.assertTrue(connector_manager.is_enabled("vendor_advisories"))

        # 5. GET /api/v1/connectors/health (aggregated)
        res = self.client.get("/api/v1/connectors/health")
        self.assertEqual(res.status_code, 200)
        health_data = res.json()
        self.assertEqual(health_data["total_connectors"], 11)
        self.assertEqual(health_data["healthy_count"], 11)

        # 6. GET /api/v1/connectors/{connector_id}/health
        res = self.client.get("/api/v1/connectors/github/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

        # 7. POST /api/v1/connectors/{connector_id}/run
        res = self.client.post("/api/v1/connectors/vendor_advisories/run")
        self.assertEqual(res.status_code, 200)
        run_data = res.json()
        self.assertEqual(run_data["id"], "vendor_advisories")
        self.assertEqual(run_data["status"], "success")
        self.assertGreater(run_data["items_count"], 0)
        self.assertGreater(len(run_data["items"]), 0)

        # 8. POST /api/v1/connectors/run-all
        res = self.client.post("/api/v1/connectors/run-all")
        self.assertEqual(res.status_code, 200)
        batch_data = res.json()
        self.assertEqual(batch_data["executed_connectors"], 11)
        self.assertEqual(len(batch_data["priority_execution_order"]), 11)


if __name__ == "__main__":
    unittest.main()

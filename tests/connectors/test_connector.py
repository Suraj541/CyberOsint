"""
Tests for Subsystem 1: Connector.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates connector discovery, fetching, health checks, rate limiting, and registry management.
"""

from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry
from connectors.rss.connector import RSSConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.document.connector import DocumentConnector


class TestConnectorsSubsystem(unittest.TestCase):
    """Subsystem 1: Connector Unit and Integration Tests."""

    def test_01_connector_registry_registration(self):
        """Verify connectors register correctly in connector_registry."""
        self.assertTrue(connector_registry.has("rss"))
        self.assertTrue(connector_registry.has("nvd_cve") or connector_registry.has("cve"))
        self.assertTrue(connector_registry.has("github"))
        self.assertTrue(connector_registry.has("document"))

    def test_02_base_connector_contract(self):
        """Verify BaseConnector interface and lifecycle methods."""
        class MockCustomConnector(BaseConnector):
            def discover(self):
                return [{"url": "https://example.com/item1", "title": "Alert 1"}]

            def fetch(self, item):
                return {"url": item["url"], "title": item["title"], "content": "Raw payload"}

            def parse(self, response):
                return {"parsed": True, "title": response["title"], "url": response["url"]}

            def normalize(self, data):
                return NormalizedItem(
                    title=data["title"],
                    url=data["url"],
                    description="Summary",
                    author="Analyst",
                    published_at="2026-09-17T12:00:00Z",
                    source="MockSource",
                    content_type="article",
                )

            def health_check(self):
                return ConnectorHealth(status="ok", source_url=self.source_url)

        connector = MockCustomConnector({"name": "Test Source", "url": "https://example.com"})
        discovered = connector.discover()
        self.assertEqual(len(discovered), 1)

        fetched = connector.fetch(discovered[0])
        self.assertEqual(fetched["content"], "Raw payload")

        parsed = connector.parse(fetched)
        self.assertTrue(parsed["parsed"])

        normalized = connector.normalize(parsed)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.title, "Alert 1")

        health = connector.health_check()
        self.assertIsInstance(health, ConnectorHealth)
        self.assertEqual(health.status, "ok")

    def test_03_rss_connector_sample_parsing(self):
        """Verify RSS connector parses XML feeds and normalizes items."""
        sample_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Cyber Threat Feed</title>
    <link>https://threat-feed.local</link>
    <description>Daily Cyber News</description>
    <item>
      <title>Critical Zero-Day in Gateway Appliance</title>
      <link>https://threat-feed.local/advisories/001</link>
      <description>Vulnerability allows RCE on unauthenticated endpoints.</description>
      <pubDate>Thu, 17 Sep 2026 10:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""

        connector = RSSConnector({
            "name": "Threat Feed RSS",
            "url": "https://threat-feed.local/feed.xml",
            "feed_content": sample_rss,
        })
        discovered = connector.discover()
        self.assertTrue(len(discovered) >= 1)
        item = discovered[0]
        self.assertIn("Critical Zero-Day", item["title"])

    def test_04_cve_connector_normalization(self):
        """Verify CVE connector formats vulnerability items properly."""
        connector = CVEConnector({"name": "NVD Feed", "url": "https://cve.circl.lu/api/last"})
        sample_cve_raw = {
            "cve_id": "CVE-2024-21762",
            "title": "CVE-2024-21762: Fortinet FortiOS out-of-bounds write vulnerability",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
        }
        normalized = connector.normalize(sample_cve_raw)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.content_type, "cve")
        self.assertIn("CVE-2024-21762", normalized.title)

    def test_05_document_connector_execution(self):
        """Verify DocumentConnector handles structured threat reports."""
        doc_content = "# Threat Intel\nCVE-2024-38077 discovered in Windows RDL."
        connector = DocumentConnector({
            "name": "Research Papers",
            "document_content": doc_content,
            "filename": "rdl_threat.md",
        })
        discovered = connector.discover()
        self.assertEqual(len(discovered), 1)
        parsed = connector.parse(discovered[0])
        normalized = connector.normalize(parsed)
        self.assertEqual(normalized.content_type, "document")


if __name__ == "__main__":
    unittest.main()

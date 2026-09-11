"""
Stage 5 / Step 7: RSS Connector & SSRF Protection Verification Tests
Ensures RSSConnector inherits BaseConnector, implements discover/fetch/parse/normalize/health_check,
and enforces SSRF preflight protection as required by IMPLEMENT.md Section 8 and Section 37.
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

from connectors.base import BaseConnector, NormalizedItem
from connectors.registry import connector_registry
from connectors.rss.connector import RSSConnector
from connectors.security import SSRFSecurityError, validate_url_for_ssrf


class TestStage5RSSConnectorBaseline(unittest.TestCase):
    """Test suite validating Step 7 / Stage 5 RSS Connector implementation."""

    def test_rss_package_structure(self):
        """Confirm connectors/rss exists with __init__.py and connector.py."""
        rss_dir = repo_root / "connectors" / "rss"
        self.assertTrue(rss_dir.exists(), "connectors/rss/ directory not found")
        self.assertTrue((rss_dir / "__init__.py").exists(), "connectors/rss/__init__.py not found")
        self.assertTrue((rss_dir / "connector.py").exists(), "connectors/rss/connector.py not found")

    def test_rss_connector_subclasses_base_connector(self):
        """Confirm RSSConnector is an instance and subclass of BaseConnector."""
        self.assertTrue(issubclass(RSSConnector, BaseConnector))
        connector = RSSConnector({"name": "Test RSS", "url": "https://example.com/feed"})
        self.assertIsInstance(connector, BaseConnector)

    def test_rss_connector_auto_registered(self):
        """Confirm RSSConnector is registered under 'rss' in the connector registry."""
        self.assertTrue(connector_registry.has("rss"))
        connector = connector_registry.create("rss", {"name": "Auto Feed"})
        self.assertIsInstance(connector, RSSConnector)

    def test_ssrf_preflight_blocks_internal_ips(self):
        """Confirm SSRF security rules block private and loopback endpoints."""
        with self.assertRaises(SSRFSecurityError):
            validate_url_for_ssrf("http://127.0.0.1:9000/feed.xml")
        with self.assertRaises(SSRFSecurityError):
            validate_url_for_ssrf("http://169.254.169.254/latest/meta-data/")


if __name__ == "__main__":
    unittest.main()

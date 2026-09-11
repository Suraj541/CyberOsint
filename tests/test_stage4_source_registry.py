"""
Stage 4 / Step 6: Source Registry & Connector Interface Verification Tests
Ensures BaseConnector specification conformance, dynamic registry mechanisms,
and source registry integration comply with IMPLEMENT.md Section 7.
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

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.mock import MockSecurityConnector
from connectors.registry import ConnectorRegistry, connector_registry
from app.services.source_registry import SourceRegistryService


class TestStage4SourceRegistryBaseline(unittest.TestCase):
    """Test suite validating Step 6 / Stage 4 Source Registry & Connector Interface."""

    def test_connectors_package_structure(self):
        """Confirm connectors package exists with base and registry modules."""
        connectors_dir = repo_root / "connectors"
        self.assertTrue(connectors_dir.exists(), "connectors/ directory not found")
        self.assertTrue((connectors_dir / "__init__.py").exists(), "connectors/__init__.py not found")
        self.assertTrue((connectors_dir / "base.py").exists(), "connectors/base.py not found")
        self.assertTrue((connectors_dir / "registry.py").exists(), "connectors/registry.py not found")

    def test_base_connector_abstract_methods_signature(self):
        """Confirm BaseConnector specifies discover, fetch, parse, normalize, health_check."""
        abstract_methods = BaseConnector.__abstractmethods__
        mandated_methods = {"discover", "fetch", "parse", "normalize", "health_check"}
        self.assertTrue(
            mandated_methods.issubset(abstract_methods),
            f"BaseConnector missing required abstract methods: {mandated_methods - abstract_methods}",
        )

    def test_normalized_item_fields(self):
        """Confirm NormalizedItem conforms to IMPLEMENT.md Section 8 output format."""
        item = NormalizedItem(
            title="Sample Advisory",
            url="https://example.com/advisory-1",
            source="Test Source",
        )
        self.assertEqual(item.title, "Sample Advisory")
        self.assertEqual(item.url, "https://example.com/advisory-1")
        self.assertEqual(item.content_type, "article")
        self.assertEqual(item.language, "en")

    def test_connector_registry_singleton(self):
        """Confirm global connector_registry is functional."""
        connector_registry.register("mock_test", MockSecurityConnector)
        self.assertTrue(connector_registry.has("mock_test"))
        connector = connector_registry.create("mock_test", {"name": "Mock Feed"})
        self.assertIsInstance(connector, BaseConnector)


if __name__ == "__main__":
    unittest.main()

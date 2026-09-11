"""
Stage 11 & 12: Specialized Connectors & CVE Intelligence Baseline Tests
Verifies the directory structure, connector classes, registry keys,
and Entity/ContentEntity integration required by IMPLEMENT.md Sections 12 and 13.
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

from connectors.base import BaseConnector
from connectors.cert import CERTConnector
from connectors.cve import CVEConnector
from connectors.github import GitHubSecurityConnector
from connectors.registry import connector_registry
from app.models.entity import ContentEntity, Entity


class TestStage11CVEConnectorsBaseline(unittest.TestCase):
    """Test suite validating Step 11 & Step 12 specialized connectors and CVE intelligence."""

    def test_specialized_connectors_directory_structure(self):
        """Confirm connectors/cve, connectors/github, and connectors/cert contain mandated files."""
        for name in ("cve", "github", "cert"):
            pkg_dir = repo_root / "connectors" / name
            self.assertTrue(pkg_dir.exists(), f"connectors/{name} directory missing")
            self.assertTrue((pkg_dir / "__init__.py").exists(), f"connectors/{name}/__init__.py missing")
            self.assertTrue((pkg_dir / "connector.py").exists(), f"connectors/{name}/connector.py missing")

    def test_connector_classes_subclass_base_connector(self):
        """Confirm CVEConnector, GitHubSecurityConnector, and CERTConnector inherit from BaseConnector."""
        self.assertTrue(issubclass(CVEConnector, BaseConnector))
        self.assertTrue(issubclass(GitHubSecurityConnector, BaseConnector))
        self.assertTrue(issubclass(CERTConnector, BaseConnector))

    def test_connector_registry_keys_registered(self):
        """Confirm all specialized connectors are registered under expected keys."""
        cve_keys = ["cve", "nvd", "kev", "cisa_kev"]
        for key in cve_keys:
            self.assertTrue(connector_registry.has(key), f"Key '{key}' missing from connector_registry")
            cls = connector_registry.get(key)
            self.assertIs(cls, CVEConnector)

        gh_keys = ["github", "ghsa", "github_advisory"]
        for key in gh_keys:
            self.assertTrue(connector_registry.has(key), f"Key '{key}' missing from connector_registry")
            cls = connector_registry.get(key)
            self.assertIs(cls, GitHubSecurityConnector)

        cert_keys = ["cert", "cisa_alert", "us_cert"]
        for key in cert_keys:
            self.assertTrue(connector_registry.has(key), f"Key '{key}' missing from connector_registry")
            cls = connector_registry.get(key)
            self.assertIs(cls, CERTConnector)

    def test_entity_models_and_tables(self):
        """Confirm Entity and ContentEntity models are properly defined with table relationships."""
        self.assertEqual(Entity.__tablename__, "entities")
        self.assertEqual(ContentEntity.__tablename__, "content_entities")
        self.assertTrue(hasattr(Entity, "name"))
        self.assertTrue(hasattr(Entity, "entity_type"))
        self.assertTrue(hasattr(Entity, "normalized_name"))
        self.assertTrue(hasattr(Entity, "metadata_json"))
        self.assertTrue(hasattr(ContentEntity, "content_id"))
        self.assertTrue(hasattr(ContentEntity, "entity_id"))
        self.assertTrue(hasattr(ContentEntity, "confidence"))
        self.assertTrue(hasattr(ContentEntity, "extraction_method"))

    def test_entity_schemas_and_endpoints_modules_exist(self):
        """Confirm entity schemas and REST endpoint modules are present."""
        self.assertTrue((api_root / "app" / "schemas" / "entity.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "entities.py").exists())


if __name__ == "__main__":
    unittest.main()

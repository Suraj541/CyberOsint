"""
Stage 13 / Section 14: Cybersecurity Taxonomy Baseline Tests
Verifies the package structure, canonical 16 category identifiers,
subcategories, and tag-to-category resolution services required by IMPLEMENT.md Section 14.
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

from packages.taxonomy import (
    CATEGORIES_CATALOGUE,
    CWE_TO_CATEGORY,
    TAG_TO_CATEGORY,
    Category,
    CategoryId,
    Subcategory,
    TaxonomyRegistry,
    taxonomy_registry,
)


class TestStage13TaxonomyBaseline(unittest.TestCase):
    """Test suite validating Step 13 / Section 14 Taxonomy implementation."""

    def test_taxonomy_package_structure(self):
        """Confirm packages/taxonomy exists with all mandated component modules."""
        pkg_dir = repo_root / "packages" / "taxonomy"
        self.assertTrue(pkg_dir.exists(), "packages/taxonomy directory missing")
        self.assertTrue((pkg_dir / "__init__.py").exists(), "packages/taxonomy/__init__.py missing")
        self.assertTrue((pkg_dir / "categories.py").exists(), "packages/taxonomy/categories.py missing")
        self.assertTrue((pkg_dir / "mappings.py").exists(), "packages/taxonomy/mappings.py missing")
        self.assertTrue((pkg_dir / "registry.py").exists(), "packages/taxonomy/registry.py missing")

    def test_all_sixteen_categories_in_category_id_enum(self):
        """Confirm CategoryId defines exactly the 16 categories specified in IMPLEMENT.md Section 14."""
        mandated_16 = {
            "application_security",
            "cloud_security",
            "network_security",
            "malware",
            "threat_intelligence",
            "digital_forensics",
            "incident_response",
            "osint",
            "cryptography",
            "identity",
            "mobile",
            "iot",
            "ics",
            "ai_security",
            "devsecops",
            "vulnerability_management",
        }

        enum_values = {item.value for item in CategoryId}
        self.assertEqual(enum_values, mandated_16)
        self.assertEqual(len(CategoryId), 16)

    def test_categories_catalogue_completeness(self):
        """Confirm every category has descriptive metadata and subcategories."""
        self.assertEqual(len(CATEGORIES_CATALOGUE), 16)
        for cat_id, cat in CATEGORIES_CATALOGUE.items():
            self.assertIsInstance(cat, Category)
            self.assertEqual(cat.id, cat_id)
            self.assertTrue(len(cat.name) > 0)
            self.assertTrue(len(cat.description) > 0)
            self.assertGreater(len(cat.subcategories), 0)
            self.assertGreater(len(cat.keywords), 0)
            self.assertGreater(len(cat.canonical_tags), 0)

    def test_mappings_populated(self):
        """Confirm TAG_TO_CATEGORY and CWE_TO_CATEGORY are populated."""
        self.assertGreater(len(TAG_TO_CATEGORY), 30)
        self.assertGreater(len(CWE_TO_CATEGORY), 15)

    def test_taxonomy_registry_singleton(self):
        """Confirm taxonomy_registry is an instance of TaxonomyRegistry."""
        self.assertIsInstance(taxonomy_registry, TaxonomyRegistry)
        self.assertEqual(len(taxonomy_registry.get_all_categories()), 16)
        self.assertTrue(taxonomy_registry.is_valid_category("cloud_security"))
        self.assertFalse(taxonomy_registry.is_valid_category("fictional_security"))

    def test_api_schema_and_endpoint_files_exist(self):
        """Confirm schemas and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "schemas" / "taxonomy.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "taxonomy.py").exists())


if __name__ == "__main__":
    unittest.main()

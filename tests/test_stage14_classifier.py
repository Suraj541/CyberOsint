"""
Stage 14 / Section 15: Content Classification Baseline Tests
Verifies the package structure, rule classifier singleton, classification contract,
and taxonomy domain adherence required by IMPLEMENT.md Section 15.
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

from packages.classifier import ClassificationResult, RuleClassifier, rule_classifier
from packages.taxonomy import CategoryId, taxonomy_registry


class TestStage14ClassifierBaseline(unittest.TestCase):
    """Test suite validating Step 14 / Section 15 Classification implementation."""

    def test_classifier_package_structure(self):
        """Confirm packages/classifier and services/classifier contain mandated files."""
        pkg_dir = repo_root / "packages" / "classifier"
        self.assertTrue(pkg_dir.exists(), "packages/classifier directory missing")
        self.assertTrue((pkg_dir / "__init__.py").exists())
        self.assertTrue((pkg_dir / "models.py").exists())
        self.assertTrue((pkg_dir / "rule_engine.py").exists())

        serv_dir = repo_root / "services" / "classifier"
        self.assertTrue(serv_dir.exists(), "services/classifier directory missing")
        self.assertTrue((serv_dir / "__init__.py").exists())

    def test_classifier_singleton_and_contract(self):
        """Confirm rule_classifier is functional and returns valid ClassificationResult."""
        self.assertIsInstance(rule_classifier, RuleClassifier)

        result = rule_classifier.classify(
            title="Widespread Phishing and Ransomware Campaign Targets Utility Sector",
            description="Darkweb threat actors deploy encryptors via email lures.",
        )
        self.assertIsInstance(result, ClassificationResult)
        self.assertTrue(taxonomy_registry.is_valid_category(result.category))
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

        data = result.to_dict()
        self.assertIn("category", data)
        self.assertIn("subcategory", data)
        self.assertIn("confidence", data)

    def test_classification_covers_taxonomy_domains(self):
        """Confirm classifier can output different taxonomy categories based on input triggers."""
        test_inputs = [
            ("New Ransomware Threat Detected", CategoryId.MALWARE.value),
            ("Kubernetes Container Breakout In Cloud", CategoryId.CLOUD_SECURITY.value),
            ("Critical SQL Injection Flaw in Web Application", CategoryId.APPLICATION_SECURITY.value),
            ("SCADA Modbus Attack on Power Substation", CategoryId.ICS.value),
            ("Prompt Injection Attack on Large Language Model", CategoryId.AI_SECURITY.value),
        ]

        for title, expected_category in test_inputs:
            res = rule_classifier.classify(title=title)
            self.assertEqual(res.category, expected_category)

    def test_api_schemas_and_endpoints_files_exist(self):
        """Confirm classifier schemas and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "schemas" / "classifier.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "classifier.py").exists())


if __name__ == "__main__":
    unittest.main()

"""
Tests for Subsystem 5: Classification.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates rule classifier singleton, taxonomy domain adherence, multi-category coverage,
confidence scoring, and fallback classification.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from packages.classifier import ClassificationResult, RuleClassifier, rule_classifier, classify_content
from packages.taxonomy import CategoryId, taxonomy_registry


class TestClassificationSubsystem(unittest.TestCase):
    """Subsystem 5: Classification Unit Tests."""

    def test_01_classifier_singleton_and_contract(self):
        """Verify rule_classifier singleton instance and ClassificationResult dataclass."""
        self.assertIsInstance(rule_classifier, RuleClassifier)
        result = rule_classifier.classify(
            title="Widespread Phishing and Ransomware Campaign Targets Utility Sector",
            description="Darkweb threat actors deploy encryptors via email lures.",
        )
        self.assertIsInstance(result, ClassificationResult)
        self.assertTrue(taxonomy_registry.is_valid_category(result.category))
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        self.assertIsInstance(result.to_dict(), dict)

    def test_02_classify_content_helper_function(self):
        """Verify classify_content functional interface."""
        res = classify_content("Critical Zero Day in Edge Gateway Appliance")
        self.assertIsInstance(res, ClassificationResult)
        self.assertIsNotNone(res.category)

    def test_03_classification_domains_coverage(self):
        """Verify deterministic categorization across diverse cybersecurity taxonomy domains."""
        test_cases = [
            ("LockBit 3.0 Ransomware Threat Assessment", CategoryId.MALWARE.value),
            ("Kubernetes RBAC Privilege Escalation in AWS EKS", CategoryId.CLOUD_SECURITY.value),
            ("Critical SQL Injection and SSRF in Web Application", CategoryId.APPLICATION_SECURITY.value),
            ("Modbus Protocol Tampering in Substation Control Network", CategoryId.ICS.value),
            ("Adversarial Prompt Injection against LLM Agent", CategoryId.AI_SECURITY.value),
            ("APT28 Threat Intelligence Report on Espionage", CategoryId.THREAT_INTELLIGENCE.value),
            ("CISA Publishes Advisory on Exploited CVE Vulnerability", CategoryId.VULNERABILITY_MANAGEMENT.value),
        ]

        for title, expected_category in test_cases:
            res = rule_classifier.classify(title=title)
            self.assertEqual(res.category, expected_category, f"Failed for title: '{title}'")

    def test_04_confidence_scoring_and_signals(self):
        """Verify confidence increases with multiple matching domain keywords."""
        weak_res = rule_classifier.classify(title="General update on security bulletin")
        strong_res = rule_classifier.classify(
            title="LockBit Ransomware Encryptor Payload Deployed by Extortion Gang",
            description="Ransomware operators demand bitcoin after exfiltrating database.",
        )
        self.assertGreaterEqual(strong_res.confidence, weak_res.confidence)

    def test_05_fallback_for_empty_or_unrecognized_text(self):
        """Verify graceful fallback for blank or unrecognized texts."""
        blank_res = rule_classifier.classify(title="")
        self.assertIsInstance(blank_res, ClassificationResult)
        self.assertIsNotNone(blank_res.category)


if __name__ == "__main__":
    unittest.main()

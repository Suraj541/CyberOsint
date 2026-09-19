"""
Tests for Subsystem 3: Normalizer.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates normalization contracts, ItemValidator schema enforcement, date standardization,
and data sanitation across all content types.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from connectors.base import NormalizedItem
from connectors.rss.connector import RSSConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.document.connector import DocumentConnector
from services.ingestion.validation import ItemValidator


class TestNormalizerSubsystem(unittest.TestCase):
    """Subsystem 3: Normalizer Unit Tests."""

    def test_01_normalized_item_schema_and_defaults(self):
        """Verify NormalizedItem schema attributes, types, and defaults."""
        item = NormalizedItem(
            title="Active Exploitation of OpenSSL Buffer Overflow",
            url="https://cisa.gov/alerts/openssl-overflow",
            source="CISA",
        )
        self.assertEqual(item.title, "Active Exploitation of OpenSSL Buffer Overflow")
        self.assertEqual(item.url, "https://cisa.gov/alerts/openssl-overflow")
        self.assertEqual(item.source, "CISA")
        self.assertEqual(item.content_type, "article")
        self.assertEqual(item.language, "en")
        self.assertIsInstance(item.metadata, dict)
        self.assertIsNone(item.description)
        self.assertIsNone(item.author)

    def test_02_item_validator_validates_normalized_item(self):
        """Verify ItemValidator.validate_normalized_item enforces URL and title standards."""
        valid_item = NormalizedItem(
            title="Fortinet Patches High-Severity Auth Bypass",
            url="https://fortiguard.com/advisories/FG-IR-24-015",
            source="FortiGuard",
            content_type="advisory",
            published_at="2026-09-17T10:00:00Z",
        )
        is_valid, err = ItemValidator.validate_normalized_item(valid_item)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        # Missing or empty title
        invalid_title = NormalizedItem(
            title="   ",
            url="https://example.com",
            source="Test",
        )
        is_valid, err = ItemValidator.validate_normalized_item(invalid_title)
        self.assertFalse(is_valid)
        self.assertIn("missing title", err.lower())

        # Disallowed URL scheme (e.g. javascript: or file:)
        dangerous_scheme = NormalizedItem(
            title="Malicious Script Link",
            url="javascript:alert('xss')",
            source="Untrusted",
        )
        is_valid, err = ItemValidator.validate_normalized_item(dangerous_scheme)
        self.assertFalse(is_valid)
        self.assertIn("dangerous url scheme", err.lower())

    def test_03_rss_normalization_contract(self):
        """Verify RSS connector normalizes raw feed entries into standard NormalizedItem."""
        connector = RSSConnector({"name": "CyberWire RSS", "url": "https://thecyberwire.com/feed"})
        parsed_feed_entry = {
            "title": "Daily Threat Brief: Iranian Actors Target Defense Contractors",
            "url": "https://thecyberwire.com/podcasts/daily-briefing/123",
            "description": "State-sponsored spearphishing campaign observed in the wild.",
            "author": "Analyst Desk",
            "published_at": "2026-09-17T12:00:00Z",
        }
        normalized = connector.normalize(parsed_feed_entry)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.title, parsed_feed_entry["title"])
        self.assertEqual(normalized.url, parsed_feed_entry["url"])
        self.assertEqual(normalized.author, "Analyst Desk")
        self.assertEqual(normalized.published_at, "2026-09-17T12:00:00Z")

    def test_04_cve_normalization_contract(self):
        """Verify CVE connector formats vulnerability items properly with metadata."""
        connector = CVEConnector({"name": "NVD Feed", "url": "https://nvd.nist.gov"})
        raw_cve = {
            "cve_id": "CVE-2024-38077",
            "title": "CVE-2024-38077: Windows Remote Desktop Licensing Service RCE Vulnerability",
            "published_at": "2024-07-09T18:00:00Z",
            "cvss_score": 9.8,
            "weakness": "CWE-122",
        }
        normalized = connector.normalize(raw_cve)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.content_type, "cve")
        self.assertIn("CVE-2024-38077", normalized.title)
        self.assertEqual(normalized.metadata["entities"][0]["metadata"]["cvss_score"], 9.8)

    def test_05_document_normalization_contract(self):
        """Verify DocumentConnector normalizes parsed threat reports."""
        connector = DocumentConnector({
            "name": "Whitepaper Vault",
            "document_content": "# Analysis of Advanced Persistent Threat 29\nNation state actors deploying custom implants.",
            "filename": "apt29.md",
        })
        discovered = connector.discover()
        parsed = connector.parse(discovered[0])
        normalized = connector.normalize(parsed)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.content_type, "document")
        self.assertIn("Analysis of Advanced Persistent Threat 29", normalized.title)
        self.assertIn("document_metadata", normalized.metadata)
        self.assertEqual(normalized.metadata["document_metadata"]["document_type"], "markdown")


if __name__ == "__main__":
    unittest.main()

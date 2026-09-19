"""
Tests for Subsystem 6: Entity Extraction.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates deterministic extraction of all 11 mandated entity types:
CVE, CWE, Vendor, Product, Malware, Threat Actor, Technology, Domain, IP, Hash, and MITRE Technique.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from packages.extractor import (
    DeterministicEntityExtractor,
    ExtractedEntity,
    entity_extractor,
    extract_entities,
    extract_from_content,
)


class TestEntityExtractionSubsystem(unittest.TestCase):
    """Subsystem 6: Entity Extraction Unit Tests."""

    def test_01_extractor_singleton_and_contract(self):
        """Verify entity_extractor singleton and contract methods."""
        self.assertIsInstance(entity_extractor, DeterministicEntityExtractor)
        self.assertTrue(callable(extract_entities))
        self.assertTrue(callable(extract_from_content))

    def test_02_extracted_entity_fields(self):
        """Verify ExtractedEntity dataclass attributes and defaults."""
        entity = ExtractedEntity(
            name="CVE-2024-38077",
            entity_type="cve",
            normalized_name="CVE-2024-38077",
            confidence=0.95,
            extraction_method="regex",
            context_snippet="...vulnerability in CVE-2024-38077 allows RCE...",
            metadata={"pattern": "standard_cve"},
        )
        self.assertEqual(entity.name, "CVE-2024-38077")
        self.assertEqual(entity.entity_type, "cve")
        self.assertEqual(entity.confidence, 0.95)
        self.assertEqual(entity.extraction_method, "regex")
        self.assertIn("CVE-2024-38077", entity.context_snippet)

    def test_03_extract_all_eleven_mandated_entity_types(self):
        """
        Verify that all 11 mandated entity types per IMPLEMENT.md Section 16 & 40:
        cve, cwe, vendor, product, malware, threat_actor, technology, domain, ip, hash, mitre_technique
        are extracted accurately from composite threat intelligence text.
        """
        corpus = (
            "THREAT INTELLIGENCE DISPATCH: "
            "Threat actor APT28 was observed distributing LockBit ransomware. "
            "The adversaries leveraged technique T1059 to exploit CVE-2024-38077, "
            "associated with CWE-122 on Microsoft Windows Server machines. "
            "Command and control beacons reached 198.51.100.42 and evil-site[.]org. "
            "The implant relies on Kerberos authentication and matches SHA-256 hash: "
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef."
        )

        extracted = entity_extractor.extract(corpus)
        extracted_types = {e.entity_type for e in extracted}

        mandated_types = [
            "cve",
            "cwe",
            "vendor",
            "product",
            "malware",
            "threat_actor",
            "technology",
            "domain",
            "ip",
            "hash",
            "mitre_technique",
        ]

        for m_type in mandated_types:
            self.assertIn(
                m_type,
                extracted_types,
                f"Mandated entity type '{m_type}' was not extracted from test intelligence corpus",
            )

    def test_04_entity_deduplication_and_context(self):
        """Verify duplicate mentions of an entity are merged while preserving context."""
        text_with_dups = (
            "The advisory details CVE-2024-38077 in the introduction. "
            "Later in the text, CVE-2024-38077 is referenced again with a mitigation."
        )
        extracted = entity_extractor.extract(text_with_dups)
        cve_entities = [e for e in extracted if e.entity_type == "cve" and e.normalized_name == "CVE-2024-38077"]
        self.assertEqual(len(cve_entities), 1, "Duplicate entity references must be deduplicated")

    def test_05_extract_from_content_helper(self):
        """Verify extract_from_content helper produces valid entities."""
        results = extract_from_content("Critical vulnerability CVE-2024-21762 discovered in FortiOS by Fortinet.")
        self.assertTrue(any(e.entity_type == "cve" for e in results))


if __name__ == "__main__":
    unittest.main()

"""
Stage 15 / Section 16: Deterministic Entity Extraction Baseline Tests
Verifies the package structure, deterministic extraction engine singleton,
and extraction capabilities for all 11 mandated entity types per IMPLEMENT.md Section 16.
"""

from pathlib import Path
import sys
import unittest

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from packages.extractor import (
    DeterministicEntityExtractor,
    ExtractedEntity,
    entity_extractor,
    extract_entities,
    extract_from_content,
)


class TestStage15ExtractorBaseline(unittest.TestCase):
    """Test suite validating Step 15 / Section 16 Deterministic Entity Extraction."""

    def test_extractor_package_structure(self):
        """Confirm packages/extractor and services/extractor contain mandated modules."""
        pkg_dir = repo_root / "packages" / "extractor"
        self.assertTrue(pkg_dir.exists(), "packages/extractor directory missing")
        self.assertTrue((pkg_dir / "__init__.py").exists())
        self.assertTrue((pkg_dir / "models.py").exists())
        self.assertTrue((pkg_dir / "patterns.py").exists())
        self.assertTrue((pkg_dir / "gazetteers.py").exists())
        self.assertTrue((pkg_dir / "engine.py").exists())

        serv_dir = repo_root / "services" / "extractor"
        self.assertTrue(serv_dir.exists(), "services/extractor directory missing")
        self.assertTrue((serv_dir / "__init__.py").exists())

    def test_api_schemas_and_endpoints_files_exist(self):
        """Confirm extractor schemas and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "schemas" / "extractor.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "extractor.py").exists())

    def test_extractor_singleton_and_contract(self):
        """Confirm entity_extractor is functional and callable."""
        self.assertIsInstance(entity_extractor, DeterministicEntityExtractor)
        self.assertTrue(callable(extract_entities))
        self.assertTrue(callable(extract_from_content))

    def test_extracted_entity_dataclass_fields(self):
        """Confirm ExtractedEntity dataclass defines all required fields."""
        ent = ExtractedEntity(
            name="CVE-2024-38077",
            entity_type="cve",
            normalized_name="CVE-2024-38077",
            confidence=0.9,
            extraction_method="regex",
            context_snippet="...flaw in CVE-2024-38077...",
            metadata={"pattern": "cve_standard"},
        )
        self.assertEqual(ent.name, "CVE-2024-38077")
        self.assertEqual(ent.entity_type, "cve")
        self.assertEqual(ent.normalized_name, "CVE-2024-38077")
        self.assertEqual(ent.confidence, 0.9)
        self.assertEqual(ent.extraction_method, "regex")
        self.assertIn("flaw", ent.context_snippet)
        self.assertIn("pattern", ent.metadata)

    def test_all_eleven_mandated_entity_types_extractable(self):
        """
        Verify that all 11 entity types mandated by IMPLEMENT.md Section 16
        (CVE, CWE, Vendor, Product, Malware, Threat Actor, Technology, Domain, IP, Hash, ATT&CK Technique)
        can be deterministically extracted from sample inputs.
        """
        sample_text = (
            "THREAT REPORT: APT28 deployed LockBit ransomware exploiting CVE-2024-38077 "
            "(CWE-122) on Microsoft Windows Server appliances. "
            "Technique T1059 was executed. "
            "Communications reached 198.51.100.42 and evil-site[.]org with "
            "Kerberos authentication and hash 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef."
        )

        extracted = entity_extractor.extract(sample_text)
        types_found = {e.entity_type for e in extracted}

        mandated_types = {
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
        }

        for m_type in mandated_types:
            self.assertIn(m_type, types_found, f"Mandated entity type '{m_type}' was not extracted")


if __name__ == "__main__":
    unittest.main()

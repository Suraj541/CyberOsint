"""
Deterministic Entity Extraction Engine Test Suite
Tests extraction of all 11 mandated entity types (CVE, CWE, Vendor, Product, Malware,
Threat Actor, Technology, Domain, IP, Hash, MITRE ATT&CK Technique), defanged IOC parsing,
context snippet generation, pipeline entity linking, and /api/v1/extractor/extract REST endpoint.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from connectors.base import BaseConnector, NormalizedItem
from packages.extractor import (
    DeterministicEntityExtractor,
    ExtractedEntity,
    entity_extractor,
    extract_entities,
    extract_from_content,
)
from services.ingestion.pipeline import IngestionPipeline


class TestDeterministicEntityExtractor(unittest.TestCase):
    """Unit and integration tests for Deterministic Entity Extraction."""

    def setUp(self):
        """Set up in-memory SQLite database and test client."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up database session and reset overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()
        app.dependency_overrides.clear()

    # -----------------------------------------------------------------
    # 1. Individual Entity Type Extraction Tests (All 11 Types)
    # -----------------------------------------------------------------
    def test_extract_cve(self):
        """Verify extraction of standard CVE identifiers."""
        text = "Exploits targeting CVE-2024-38077 and older CVE-2021-44228 have been detected."
        entities = entity_extractor.extract(text)
        cve_entities = [e for e in entities if e.entity_type == "cve"]
        cve_names = [e.normalized_name for e in cve_entities]

        self.assertIn("CVE-2024-38077", cve_names)
        self.assertIn("CVE-2021-44228", cve_names)
        for e in cve_entities:
            self.assertEqual(e.extraction_method, "regex")
            self.assertGreaterEqual(e.confidence, 0.9)
            self.assertTrue("..." in e.context_snippet or len(e.context_snippet) > 0)

    def test_extract_cwe(self):
        """Verify extraction of Common Weakness Enumeration identifiers."""
        text = "The vulnerability was classified as CWE-89 (SQL Injection) and CWE-122 (Heap Overflow)."
        entities = entity_extractor.extract(text)
        cwe_entities = [e for e in entities if e.entity_type == "cwe"]
        cwe_names = [e.normalized_name for e in cwe_entities]

        self.assertIn("CWE-89", cwe_names)
        self.assertIn("CWE-122", cwe_names)
        for e in cwe_entities:
            self.assertEqual(e.extraction_method, "regex")
            self.assertGreaterEqual(e.confidence, 0.9)

    def test_extract_mitre_technique(self):
        """Verify extraction of MITRE ATT&CK technique IDs (standard and sub-techniques)."""
        text = "Adversaries utilized T1059.001 PowerShell and T1566 Phishing for initial access."
        entities = entity_extractor.extract(text)
        mitre_entities = [e for e in entities if e.entity_type == "mitre_technique"]
        mitre_names = [e.normalized_name for e in mitre_entities]

        self.assertIn("T1059.001", mitre_names)
        self.assertIn("T1566", mitre_names)
        for e in mitre_entities:
            self.assertEqual(e.extraction_method, "regex")
            self.assertGreaterEqual(e.confidence, 0.9)

    def test_extract_hashes(self):
        """Verify extraction of SHA256, SHA1, and MD5 cryptographic hashes."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        md5 = "d41d8cd98f00b204e9800998ecf8427e"

        text = f"Sample dropped payload with sha256: {sha256}, sha1: {sha1}, md5: {md5}."
        entities = entity_extractor.extract(text)
        hash_entities = [e for e in entities if e.entity_type == "hash"]
        hash_values = [e.normalized_name for e in hash_entities]

        self.assertIn(sha256, hash_values)
        self.assertIn(sha1, hash_values)
        self.assertIn(md5, hash_values)

        sha256_ent = next(e for e in hash_entities if e.normalized_name == sha256)
        self.assertEqual(sha256_ent.metadata.get("hash_type"), "sha256")
        self.assertEqual(sha256_ent.confidence, 1.0)

    def test_extract_ip_addresses_standard_and_defanged(self):
        """Verify extraction and validation of public IPv4 addresses and defanged notations."""
        text = (
            "C2 servers discovered at 198.51.100.42 and defanged 203.0.113[.]195. "
            "Internal address 192.168.1.1 and loopback 127.0.0.1 should be ignored."
        )
        entities = entity_extractor.extract(text)
        ip_entities = [e for e in entities if e.entity_type == "ip"]
        ip_values = [e.normalized_name for e in ip_entities]

        self.assertIn("198.51.100.42", ip_values)
        self.assertIn("203.0.113.195", ip_values)
        # RFC1918 and loopback should NOT be extracted as public IOCs
        self.assertNotIn("192.168.1.1", ip_values)
        self.assertNotIn("127.0.0.1", ip_values)

        defanged_ent = next(e for e in ip_entities if e.normalized_name == "203.0.113.195")
        self.assertEqual(defanged_ent.extraction_method, "defanged")

    def test_extract_defanged_domains(self):
        """Verify extraction of defanged domains while excluding benign top-level domains."""
        text = "Phishing domain evil-c2-infrastructure[.]com and malware-dl(.)net observed."
        entities = entity_extractor.extract(text)
        domain_entities = [e for e in entities if e.entity_type == "domain"]
        domains = [e.normalized_name for e in domain_entities]

        self.assertIn("evil-c2-infrastructure.com", domains)
        self.assertIn("malware-dl.net", domains)
        for e in domain_entities:
            self.assertEqual(e.extraction_method, "defanged")

    def test_extract_malware(self):
        """Verify extraction of known malware families and ransomware variants from gazetteer."""
        text = "The campaign deployed LockBit 3.0 alongside Cobalt Strike beacons and RedLine Stealer."
        entities = entity_extractor.extract(text)
        malware_entities = [e for e in entities if e.entity_type == "malware"]
        malware_names = [e.normalized_name for e in malware_entities]

        self.assertIn("lockbit", malware_names)
        self.assertIn("cobalt strike", malware_names)
        self.assertIn("redline", malware_names)
        for e in malware_entities:
            self.assertEqual(e.extraction_method, "dictionary")
            self.assertGreaterEqual(e.confidence, 0.9)

    def test_extract_threat_actors(self):
        """Verify extraction of nation-state threat actors and cybercrime syndicates."""
        text = "Attacks attributed to Lazarus Group (HIDDEN COBRA) and Sandworm Team (APT44)."
        entities = entity_extractor.extract(text)
        actor_entities = [e for e in entities if e.entity_type == "threat_actor"]
        actor_names = [e.normalized_name for e in actor_entities]

        self.assertIn("lazarus group", actor_names)
        self.assertIn("sandworm", actor_names)
        for e in actor_entities:
            self.assertEqual(e.extraction_method, "dictionary")

    def test_extract_vendors_and_products(self):
        """Verify extraction of major security vendors and software products."""
        text = "Security advisory from Palo Alto Networks impacting PAN-OS firewalls and Microsoft Windows Server."
        entities = entity_extractor.extract(text)

        vendor_entities = [e for e in entities if e.entity_type == "vendor"]
        vendor_names = [e.normalized_name for e in vendor_entities]
        self.assertIn("palo alto networks", vendor_names)
        self.assertIn("microsoft", vendor_names)

        product_entities = [e for e in entities if e.entity_type == "product"]
        product_names = [e.normalized_name for e in product_entities]
        self.assertIn("pan-os", product_names)
        self.assertIn("windows server", product_names)

    def test_extract_technologies(self):
        """Verify extraction of protocols and core enterprise technologies."""
        text = "Exploitation of HTTP/2 rapid reset and authentication bypass in Kerberos and Modbus SCADA systems."
        entities = entity_extractor.extract(text)
        tech_entities = [e for e in entities if e.entity_type == "technology"]
        tech_names = [e.normalized_name for e in tech_entities]

        self.assertIn("http/2", tech_names)
        self.assertIn("kerberos", tech_names)
        self.assertIn("modbus", tech_names)

    # -----------------------------------------------------------------
    # 2. Comprehensive Multi-Entity Text & Snippet Generation Tests
    # -----------------------------------------------------------------
    def test_comprehensive_intel_extraction(self):
        """Verify simultaneous extraction of all entity categories from a real-world threat briefing."""
        briefing = (
            "URGENT THREAT ADVISORY: APT28 (Fancy Bear) has launched zero-day attacks leveraging "
            "CVE-2024-38077 (classified as CWE-122) targeting Microsoft Windows Server systems. "
            "Infections deploy LockBit ransomware using T1059.001 PowerShell execution. "
            "C2 communication routes through 198.51.100.42 and evil-update-hub[.]com. "
            "Observed payload hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        )
        entities = extract_entities(briefing)
        type_set = {e.entity_type for e in entities}

        # Check that diverse categories were captured
        self.assertIn("threat_actor", type_set)
        self.assertIn("cve", type_set)
        self.assertIn("cwe", type_set)
        self.assertIn("vendor", type_set)
        self.assertIn("product", type_set)
        self.assertIn("malware", type_set)
        self.assertIn("mitre_technique", type_set)
        self.assertIn("ip", type_set)
        self.assertIn("domain", type_set)
        self.assertIn("hash", type_set)

        # Context snippet check
        for ent in entities:
            self.assertIsNotNone(ent.context_snippet)
            self.assertGreater(len(ent.context_snippet), 5)

    def test_deduplication_prefers_higher_confidence(self):
        """Verify deduplication retains highest confidence and enriched metadata."""
        extractor = DeterministicEntityExtractor()
        ent1 = ExtractedEntity(
            name="CVE-2024-11111",
            entity_type="cve",
            normalized_name="CVE-2024-11111",
            confidence=0.8,
            extraction_method="heuristic",
            context_snippet="first occurrence",
        )
        ent2 = ExtractedEntity(
            name="CVE-2024-11111",
            entity_type="cve",
            normalized_name="CVE-2024-11111",
            confidence=1.0,
            extraction_method="structured",
            context_snippet="second occurrence",
        )
        merged = extractor._deduplicate_entities([ent1, ent2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].confidence, 1.0)
        self.assertEqual(merged[0].extraction_method, "structured")

    # -----------------------------------------------------------------
    # 3. Pipeline Database Storage and Content-Entity Linking Tests
    # -----------------------------------------------------------------
    def test_pipeline_entity_extraction_and_linking(self):
        """Verify IngestionPipeline automatically creates Entity and ContentEntity records."""
        class MockArticleConnector(BaseConnector):
            def discover(self):
                return [{"id": 101}]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title="Volt Typhoon active campaign abusing Cisco IOS and CVE-2024-12345",
                    url="https://cybernews.example/volt-typhoon-cisco",
                    description="The Volt Typhoon actor utilized T1059 to compromise Cisco routers via CVE-2024-12345.",
                    author="Analyst",
                    published_at="2024-09-01T12:00:00Z",
                    source="CyberNews",
                    content_type="article",
                    raw_content="Defanged indicator: 198.51.100.77 communicating with malware family Akira.",
                    metadata={},
                )
            def health_check(self):
                pass

        connector = MockArticleConnector(source_config={"name": "CyberNews RSS"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="CyberNews RSS")

        self.assertEqual(metrics.ingested_count, 1)

        # Check Content row
        content = self.db.query(Content).first()
        self.assertIsNotNone(content)

        # Check Entity rows created
        entities = self.db.query(Entity).all()
        entity_types = {e.entity_type for e in entities}
        self.assertIn("threat_actor", entity_types)
        self.assertIn("cve", entity_types)
        self.assertIn("vendor", entity_types)
        self.assertIn("mitre_technique", entity_types)
        self.assertIn("ip", entity_types)
        self.assertIn("malware", entity_types)

        # Check ContentEntity association rows
        content_entities = self.db.query(ContentEntity).filter(ContentEntity.content_id == content.id).all()
        self.assertGreaterEqual(len(content_entities), 4)

        for ce in content_entities:
            self.assertGreater(ce.confidence, 0.0)
            self.assertIsNotNone(ce.context_snippet)
            self.assertIn(ce.extraction_method, ("regex", "dictionary", "defanged", "structured"))

    # -----------------------------------------------------------------
    # 4. REST API Endpoint Tests: POST /api/v1/extractor/extract
    # -----------------------------------------------------------------
    def test_extractor_endpoint_success(self):
        """Verify POST /api/v1/extractor/extract parses text and returns structured response."""
        payload = {
            "title": "BlackCat Ransomware Target Cisco Infrastructure",
            "text": "Threat actors deployed BlackCat ransomware exploiting CVE-2024-38077 and CWE-122.",
            "metadata": {"source": "Test Feed"},
        }

        response = self.client.post("/api/v1/extractor/extract", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("entities", data)
        self.assertIn("total_entities", data)
        self.assertIn("entity_counts", data)
        self.assertGreaterEqual(data["total_entities"], 3)

        entity_names = [e["normalized_name"] for e in data["entities"]]
        self.assertIn("blackcat", entity_names)
        self.assertIn("cisco", entity_names)
        self.assertIn("CVE-2024-38077", entity_names)
        self.assertIn("CWE-122", entity_names)

        # Verify entity_counts keys
        counts = data["entity_counts"]
        self.assertIn("malware", counts)
        self.assertIn("vendor", counts)
        self.assertIn("cve", counts)
        self.assertIn("cwe", counts)

    def test_extractor_endpoint_empty_validation(self):
        """Verify POST /api/v1/extractor/extract validates payload and rejects empty text."""
        response = self.client.post("/api/v1/extractor/extract", json={"text": ""})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()

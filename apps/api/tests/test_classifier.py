"""
Classification Engine Tests
Tests rule-based and heuristic classification of cybersecurity intelligence items into the 16 taxonomy domains,
pipeline integration with ContentTag domain assignment, and the /api/v1/classifier/classify REST endpoint.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

import sys
from pathlib import Path
import unittest

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.tag import ContentTag, Tag
from connectors.base import BaseConnector, NormalizedItem
from packages.classifier import ClassificationResult, rule_classifier
from packages.taxonomy import CategoryId
from services.ingestion.pipeline import IngestionPipeline


class TestClassifier(unittest.TestCase):
    """Test suite for the rule-based classification engine and pipeline integration."""

    def setUp(self):
        """Set up in-memory database for testing pipeline classification tagging."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        app.dependency_overrides.clear()

    # -------------------------------------------------------------
    # 1. Rule Engine Direct Tests
    # -------------------------------------------------------------
    def test_ransomware_classification(self):
        """Confirm ransomware content classifies as malware with ransomware subcategory."""
        res = rule_classifier.classify(
            title="LockBit Ransomware Group Demands $10M After Breaching Hospital Network",
            description="Double extortion campaign encrypts virtual machines and exfiltrates medical records.",
        )
        self.assertIsInstance(res, ClassificationResult)
        self.assertEqual(res.category, CategoryId.MALWARE.value)
        self.assertEqual(res.subcategory, "ransomware")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_kubernetes_container_classification(self):
        """Confirm Kubernetes and container security topics classify as cloud_security."""
        res = rule_classifier.classify(
            title="Critical Kubernetes Container Breakout Vulnerability Discovered in Core Engine",
            description="Attackers exploit runc descriptor leak to escape pod isolation to host node.",
        )
        self.assertEqual(res.category, CategoryId.CLOUD_SECURITY.value)
        self.assertEqual(res.subcategory, "kubernetes_security")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_sql_injection_classification(self):
        """Confirm SQL injection and web flaws classify as application_security."""
        res = rule_classifier.classify(
            title="Massive SQL Injection Flaw in Enterprise Billing Portal Allows Data Exfiltration",
            description="Unsanitized user inputs in search parameter allow blind SQLi database dump.",
        )
        self.assertEqual(res.category, CategoryId.APPLICATION_SECURITY.value)
        self.assertEqual(res.subcategory, "injection_attacks")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_cve_advisory_classification(self):
        """Confirm CVE items classify into vulnerability_management."""
        res = rule_classifier.classify(
            title="Microsoft Releases Emergency Patch for CVE-2024-38077 Under Active Attack",
            description="CVSS 9.8 remote code execution in Windows Remote Desktop Licensing service.",
            metadata={"cve_id": "CVE-2024-38077"},
        )
        self.assertEqual(res.category, CategoryId.VULNERABILITY_MANAGEMENT.value)
        self.assertEqual(res.subcategory, "cve_intelligence")
        self.assertGreaterEqual(res.confidence, 0.94)

    def test_ai_security_prompt_injection_classification(self):
        """Confirm prompt injection and LLM jailbreaks classify as ai_security."""
        res = rule_classifier.classify(
            title="Indirect Prompt Injection Technique Hijacks Autonomous AI Agent Tools",
            description="Malicious instructions embedded in retrieved web pages force AI to execute arbitrary code.",
        )
        self.assertEqual(res.category, CategoryId.AI_SECURITY.value)
        self.assertEqual(res.subcategory, "llm_jailbreaks")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_scada_industrial_classification(self):
        """Confirm SCADA and Modbus topics classify into ics."""
        res = rule_classifier.classify(
            title="Nation-State Threat Actors Deploy Triton Malware Variant Against Power Grid SCADA PLCs",
            description="Industrial control systems targeted via compromised Modbus protocol controllers.",
        )
        self.assertEqual(res.category, CategoryId.ICS.value)
        self.assertEqual(res.subcategory, "scada_plc")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_active_directory_classification(self):
        """Confirm Active Directory and Kerberoasting classify into identity."""
        res = rule_classifier.classify(
            title="New Active Directory Attack Chain Automates Kerberoasting and DCSync Persistence",
            description="Lateral movement framework exploits weak service account tickets.",
        )
        self.assertEqual(res.category, CategoryId.IDENTITY.value)
        self.assertEqual(res.subcategory, "active_directory")
        self.assertGreaterEqual(res.confidence, 0.90)

    def test_keyword_scoring_fallback(self):
        """Confirm keyword density matches when title lacks explicit rule keywords."""
        res = rule_classifier.classify(
            title="Technical Analysis of Memory Dump Artifacts",
            description="Extracting injected DLLs using Volatility framework and inspecting process hollows.",
        )
        self.assertEqual(res.category, CategoryId.DIGITAL_FORENSICS.value)
        self.assertGreater(res.confidence, 0.60)

    # -------------------------------------------------------------
    # 2. Ingestion Pipeline Hook Integration Test
    # -------------------------------------------------------------
    def test_pipeline_automatically_classifies_and_tags_content(self):
        """Confirm IngestionPipeline runs classifier and stores domain/subdomain tags."""
        class MockRansomwareConnector(BaseConnector):
            def discover(self):
                return [{"id": 1}]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title="Akira Ransomware Hits Global Financial Systems",
                    url="https://threatpost.example/akira-attack",
                    description="Extortionists demand cryptocurrency payment after deploying encryptor.",
                    author="Threat Analyst",
                    published_at="2024-08-15T12:00:00Z",
                    source="ThreatPost",
                    content_type="article",
                    raw_content="Akira ransomware payload detected in corporate network.",
                    metadata={},
                )
            def health_check(self):
                pass

        connector = MockRansomwareConnector(source_config={"name": "ThreatPost"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="ThreatPost")

        self.assertEqual(metrics.ingested_count, 1)

        content = self.db.query(Content).first()
        self.assertIsNotNone(content)

        # Check tags associated with content
        content_tags = (
            self.db.query(ContentTag, Tag)
            .join(Tag, ContentTag.tag_id == Tag.id)
            .filter(ContentTag.content_id == content.id)
            .all()
        )
        tag_names = {tag.name: tag.category for _, tag in content_tags}

        # Expect domain tag 'malware' and subdomain tag 'ransomware'
        self.assertIn("malware", tag_names)
        self.assertEqual(tag_names["malware"], "domain")

        self.assertIn("ransomware", tag_names)
        self.assertEqual(tag_names["ransomware"], "subdomain")

    # -------------------------------------------------------------
    # 3. REST API Endpoint Tests
    # -------------------------------------------------------------
    def test_classifier_rest_endpoint(self):
        """Confirm POST /api/v1/classifier/classify produces expected JSON response."""
        payload = {
            "title": "Novel LLM Prompt Injection Bypasses Enterprise Agent Safety Guards",
            "description": "Indirect injection payload forces language model to leak sensitive tokens.",
            "content_text": "Autonomous agent tool invocation hijacked through poisoned documents.",
        }

        resp = self.client.post("/api/v1/classifier/classify", json=payload)
        self.assertEqual(resp.status_code, 200)

        data = resp.json()
        self.assertEqual(data["category"], "ai_security")
        self.assertEqual(data["subcategory"], "llm_jailbreaks")
        self.assertGreaterEqual(data["confidence"], 0.90)
        self.assertIn("rule_ai_security", data["rule_matched"])
        self.assertGreater(len(data["matched_keywords"]), 0)


if __name__ == "__main__":
    unittest.main()

"""
Stage 28 Test Suite: AI Summarization
Validates the 5-stage summarization pipeline:
Source Content -> Clean Text -> AI Model -> Summary -> Validation -> Stored Summary.
Enforces 5 prompt guardrail rules:
1. Do not invent facts
2. Do not add unsupported claims
3. Preserve uncertainty
4. Identify source
5. Separate reported facts from inference
Stores full provenance metadata and validation telemetry.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.source import Source
from app.models.summary import ContentSummary
from services.summarization.cleaner import clean_text_for_summarization
from services.summarization.models import SummaryOutput, ValidationResult
from services.summarization.prompts import PROMPT_VERSION
from services.summarization.service import (
    SummarizationService,
    summarization_service,
)
from services.summarization.validator import GroundingValidator, grounding_validator


class TestStage28AISummarization(unittest.TestCase):
    """Unit and integration test suite for Section 29 AI Summarization."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()

        # Seed test source
        self.source = Source(
            name="Unit42 Threat Intel",
            url="https://unit42.paloaltonetworks.com",
            source_type="vendor",
            category="threat_intelligence",
            reliability_score=0.92,
            active=True,
        )
        self.db.add(self.source)
        self.db.commit()
        self.db.refresh(self.source)

        # Seed test content with CVEs, ATT&CK techniques, hashes, and uncertainty language
        self.content = Content(
            source_id=self.source.id,
            title="Active Exploitation of CVE-2024-3400 PAN-OS Vulnerability",
            description="Unit 42 observed active zero-day exploitation of CVE-2024-3400. Suspected nation-state threat actor.",
            content_type="article",
            canonical_url="https://unit42.paloaltonetworks.com/cve-2024-3400",
            author="Unit 42 Research",
            raw_content=(
                "<p>Unit 42 identified in-the-wild exploitation of <strong>CVE-2024-3400</strong>, "
                "a maximum severity command injection vulnerability in PAN-OS GlobalProtect gateway.</p>"
                "<p>Observed technique: T1059.004 command execution and persistence via cron. "
                "Payload SHA-256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
                "Specific nation-state attribution remains suspected and unconfirmed.</p>"
            ),
            published_at=datetime.now(timezone.utc),
            discovered_at=datetime.now(timezone.utc),
            language="en",
            content_hash="test_sha256_hash_stage28_001",
            quality_score=0.95,
            relevance_score=0.98,
            confidence_score=0.92,
            status="published",
        )
        self.db.add(self.content)
        self.db.commit()
        self.db.refresh(self.content)

    def tearDown(self):
        self.db.query(ContentSummary).delete()
        self.db.query(Content).delete()
        self.db.query(Source).delete()
        self.db.commit()
        self.db.close()

    def test_01_clean_text_pipeline(self):
        """Test Stage 1: Clean Text transforms noisy HTML into clean ground truth."""
        raw_html = (
            "<div><nav>Site Navigation</nav><h1>Alert: Zero-Day</h1>"
            "<p>Exploit targeting CVE-2023-23397 found in telemetry.</p>"
            "<footer>Copyright 2026</footer></div>"
        )
        cleaned = clean_text_for_summarization(
            title="Alert: Zero-Day",
            description="Brief teaser.",
            raw_content=raw_html,
            source_name="CISA",
        )
        self.assertIn("CVE-2023-23397", cleaned)
        self.assertIn("Alert: Zero-Day", cleaned)
        self.assertNotIn("Site Navigation", cleaned)
        self.assertNotIn("<footer>", cleaned)
        self.assertNotIn("</div>", cleaned)

    def test_02_grounding_validator_factual_check(self):
        """Test Stage 4: GroundingValidator checks entity alignment and inference qualifiers."""
        source_text = "Analysis of CVE-2024-3400 and technique T1059. Threat actor attribution remains suspected."
        
        valid_summary = SummaryOutput(
            executive_summary="Exploitation of CVE-2024-3400 was detected.",
            reported_facts=["Vulnerability CVE-2024-3400 observed."],
            inferences=["Analysis suggests potential remote code execution."],
            uncertainties=["Attribution remains suspected and unconfirmed."],
            key_takeaways=["Patch CVE-2024-3400 immediately."],
            source_attribution="Unit42",
            confidence=0.95,
        )
        val_result = grounding_validator.validate(source_text, valid_summary)
        self.assertEqual(val_result.status, "passed")
        self.assertGreaterEqual(val_result.score, 0.90)

    def test_03_grounding_validator_hallucination_penalty(self):
        """Test Stage 4: GroundingValidator penalizes fabricated CVEs not present in source."""
        source_text = "Vulnerability CVE-2024-1111 detected."
        
        hallucinated_summary = SummaryOutput(
            executive_summary="Exploitation of CVE-2099-99999 was detected.",
            reported_facts=["Vulnerability CVE-2099-99999 observed in network."],
            inferences=["Analysis suggests critical risk."],
            uncertainties=["Details remain unverified."],
            key_takeaways=["Take action."],
            source_attribution="Test",
            confidence=0.90,
        )
        val_result = grounding_validator.validate(source_text, hallucinated_summary)
        self.assertEqual(val_result.status, "flagged")
        self.assertIn("CVE-2099-99999", val_result.notes.get("hallucinated_cves", []))

    def test_04_summarization_service_end_to_end(self):
        """Test full 5-stage pipeline with strict rule adherence & provenance storage."""
        summary_record = summarization_service.summarize_content(self.db, self.content.id)
        
        self.assertIsNotNone(summary_record)
        self.assertEqual(summary_record.content_id, self.content.id)
        self.assertEqual(summary_record.model, "cyber-grounded-summarizer")
        self.assertEqual(summary_record.model_version, "v1.2.0")
        self.assertEqual(summary_record.prompt_version, PROMPT_VERSION)
        self.assertIsNotNone(summary_record.generated_at)
        self.assertGreaterEqual(summary_record.confidence, 0.8)
        self.assertEqual(summary_record.validation_status, "passed")

        # Verify Segregated Reported Facts (Rule 1, 2, 5)
        facts = json.loads(summary_record.reported_facts)
        self.assertTrue(any("CVE-2024-3400" in f for f in facts))
        self.assertTrue(any("T1059" in f for f in facts))

        # Verify Segregated Analytical Inferences (Rule 5)
        inferences = json.loads(summary_record.inferences)
        self.assertGreater(len(inferences), 0)
        self.assertTrue(
            any(
                any(q in inf.lower() for q in ["suggests", "indicates", "likely", "potential", "implies"])
                for inf in inferences
            )
        )

        # Verify Preserved Uncertainty (Rule 3)
        uncertainties = json.loads(summary_record.uncertainties)
        self.assertGreater(len(uncertainties), 0)
        self.assertTrue(
            any(
                any(u in unc.lower() for u in ["unconfirmed", "suspected", "investigated", "telemetry"])
                for unc in uncertainties
            )
        )

        # Verify Source Attribution (Rule 4)
        self.assertEqual(summary_record.source_attribution, "Unit42 Threat Intel")

    def test_05_api_endpoints_summary_retrieval(self):
        """Test REST API: GET /api/v1/content/{id}/summary and GET /api/v1/summaries/{id}."""
        # Pre-generate summary
        summarization_service.summarize_content(self.db, self.content.id)

        # 1. Content sub-route
        resp1 = self.client.get(f"/api/v1/content/{self.content.id}/summary")
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertEqual(data1["content_id"], self.content.id)
        self.assertIn("CVE-2024-3400", str(data1["reported_facts"]))
        self.assertEqual(data1["validation_status"], "passed")
        self.assertEqual(data1["model"], "cyber-grounded-summarizer")

        # 2. Summaries master route
        resp2 = self.client.get(f"/api/v1/summaries/{self.content.id}")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertEqual(data2["id"], data1["id"])

    def test_06_api_endpoints_generate_and_regenerate(self):
        """Test REST API: POST /api/v1/content/{id}/summary/generate with force flag."""
        resp = self.client.post(
            f"/api/v1/content/{self.content.id}/summary/generate",
            json={"force": True},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["content_id"], self.content.id)
        self.assertIn("executive_summary", data["summary"])
        self.assertGreater(len(data["summary"]["reported_facts"]), 0)
        self.assertGreater(len(data["summary"]["inferences"]), 0)

    def test_07_api_batch_generate_summaries(self):
        """Test REST API: POST /api/v1/summaries/batch-generate."""
        # Create second content item without summary
        c2 = Content(
            source_id=self.source.id,
            title="Critical Advisory: Apache ActiveMQ RCE CVE-2023-46604",
            description="Active exploitation observed targeting unpatched message brokers.",
            content_type="advisory",
            canonical_url="https://unit42.paloaltonetworks.com/cve-2023-46604",
            raw_content="Vulnerability CVE-2023-46604 allows unauthenticated RCE.",
            language="en",
            content_hash="test_sha256_hash_stage28_002",
            quality_score=0.90,
            relevance_score=0.95,
            confidence_score=0.90,
            status="published",
        )
        self.db.add(c2)
        self.db.commit()

        resp = self.client.post("/api/v1/summaries/batch-generate", json={"limit": 5})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["processed_count"], 1)

    def test_08_content_detail_includes_ai_summary(self):
        """Test GET /api/v1/content/{id} returns populated ai_summary object."""
        # Generate summary
        summarization_service.summarize_content(self.db, self.content.id)

        resp = self.client.get(f"/api/v1/content/{self.content.id}")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn("ai_summary", payload)
        self.assertIsNotNone(payload["ai_summary"])
        self.assertEqual(payload["ai_summary"]["content_id"], self.content.id)
        self.assertEqual(payload["ai_summary"]["model"], "cyber-grounded-summarizer")
        self.assertIsInstance(payload["ai_summary"]["reported_facts"], list)
        self.assertIsInstance(payload["ai_summary"]["inferences"], list)


if __name__ == "__main__":
    unittest.main()

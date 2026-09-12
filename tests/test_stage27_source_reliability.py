"""
Stage 27 Test Suite: Source Reliability
Validates multi-dimensional source quality assessment:
authority, accuracy, technical_depth, originality, historical_reliability.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
Constraint: Internal ranking indicator — not an unquestionable truth score.
"""

import json
import unittest
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
from app.models.source_quality import SourceQuality
from services.reliability import (
    QualityMetrics,
    QualityTier,
    ReliabilityWeights,
    SourceReliabilityService,
    source_reliability_service,
)


class TestStage27SourceReliability(unittest.TestCase):
    """Unit and integration tests for Section 28 Source Reliability engine."""

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
        # Seed test sources
        self.cisa_source = Source(
            name="CISA Alerts",
            url="https://www.cisa.gov/news-events/cybersecurity-advisories",
            source_type="cert",
            access_method="rss",
            reliability_score=0.98,
            active=True,
            last_checked=datetime.now(timezone.utc),
        )
        self.blog_source = Source(
            name="Community Security Blog",
            url="https://unknown-security-feed.example.org/rss",
            source_type="blog",
            access_method="rss",
            reliability_score=0.60,
            active=True,
            last_checked=datetime.now(timezone.utc),
        )
        self.db.add(self.cisa_source)
        self.db.add(self.blog_source)
        self.db.commit()
        self.db.refresh(self.cisa_source)
        self.db.refresh(self.blog_source)

    def tearDown(self):
        self.db.query(SourceQuality).delete()
        self.db.query(Content).delete()
        self.db.query(Source).delete()
        self.db.commit()
        self.db.close()

    def test_source_quality_table_schema(self):
        """Confirm source_quality table contains all 5 mandated fields and composite indicators."""
        table = Base.metadata.tables.get("source_quality")
        self.assertIsNotNone(table, "Table 'source_quality' must exist in Base.metadata")

        columns = [c.name for c in table.columns]
        expected = [
            "id",
            "source_id",
            "authority",
            "accuracy",
            "technical_depth",
            "originality",
            "historical_reliability",
            "overall_score",
            "quality_tier",
            "indicator_symbol",
            "eval_metadata",
            "created_at",
            "updated_at",
        ]
        for col in expected:
            self.assertIn(col, columns, f"Column '{col}' missing from source_quality table")

    def test_authority_calculation(self):
        """Verify authority scoring prioritizes .gov, CERTs, and known security entities."""
        svc = SourceReliabilityService()

        cisa_auth = svc.evaluate_authority(self.cisa_source)
        blog_auth = svc.evaluate_authority(self.blog_source)

        self.assertGreaterEqual(cisa_auth, 0.95, "CISA authority score should be >= 0.95")
        self.assertLess(blog_auth, cisa_auth, "Generic blog should have lower authority than CISA")

    def test_accuracy_and_technical_depth_with_content(self):
        """Verify accuracy and technical depth increase when structured CVEs and technical artifacts exist."""
        svc = SourceReliabilityService()

        # Seed content with high technical depth for CISA
        deep_content = Content(
            source_id=self.cisa_source.id,
            title="Critical RCE in Edge Appliance (CVE-2024-3400)",
            description="Payload uses powershell script with hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            raw_content="Attackers execute curl commands to download webshell. Technique T1059.001 observed. CVSS 10.0 CRITICAL.",
            canonical_url="https://www.cisa.gov/advisories/aa24-001",
            content_hash="abc123hash0001",
            quality_score=0.95,
            confidence_score=1.0,
        )
        self.db.add(deep_content)
        self.db.commit()

        accuracy = svc.evaluate_accuracy(self.db, self.cisa_source)
        depth = svc.evaluate_technical_depth(self.db, self.cisa_source)

        self.assertGreater(accuracy, 0.85, "Accuracy should reflect presence of verified CVE-2024-3400")
        self.assertGreater(depth, 0.70, "Technical depth should recognize hashes and T1059 techniques")

    def test_composite_score_weighting(self):
        """Verify composite score correctly applies the 5-dimension weights summing to 1.0."""
        svc = SourceReliabilityService()
        weights = svc.weights

        self.assertAlmostEqual(
            weights.authority + weights.accuracy + weights.technical_depth + weights.originality + weights.historical_reliability,
            1.0,
            places=4,
            msg="Weights must sum to exactly 1.0",
        )

        score = svc.compute_composite_score(
            authority=1.0,
            accuracy=1.0,
            technical_depth=1.0,
            originality=1.0,
            historical_reliability=1.0,
        )
        self.assertAlmostEqual(score, 1.0, places=3)

        zero_score = svc.compute_composite_score(0.0, 0.0, 0.0, 0.0, 0.0)
        self.assertAlmostEqual(zero_score, 0.0, places=3)

    def test_quality_tier_and_symbol_classification(self):
        """Verify tier and symbol classification rules."""
        svc = SourceReliabilityService()

        tier_1, sym_1 = svc.determine_tier_and_symbol(0.92)
        self.assertEqual(tier_1, QualityTier.TIER_1_AUTHORITATIVE)
        self.assertEqual(sym_1, "A+")

        tier_2, sym_2 = svc.determine_tier_and_symbol(0.75)
        self.assertEqual(tier_2, QualityTier.TIER_2_HIGH)
        self.assertEqual(sym_2, "B+")

        tier_3, sym_3 = svc.determine_tier_and_symbol(0.60)
        self.assertEqual(tier_3, QualityTier.TIER_3_STANDARD)
        self.assertEqual(sym_3, "B")

        tier_4, sym_4 = svc.determine_tier_and_symbol(0.35)
        self.assertEqual(tier_4, QualityTier.TIER_4_UNVERIFIED)
        self.assertEqual(sym_4, "C")

    def test_internal_ranking_constraint_disclaimer(self):
        """Confirm quality metrics explicitly convey internal ranking constraint."""
        metrics = source_reliability_service.calculate_quality(self.db, self.cisa_source)
        self.assertIn(
            "Internal analytical ranking indicator",
            metrics.disclaimer,
            "Must emphasize internal ranking constraint per IMPLEMENT.md Section 28",
        )

    def test_persistence_and_update(self):
        """Verify SourceQuality record creation and subsequent update in database."""
        res1 = source_reliability_service.update_or_create_source_quality(self.db, self.cisa_source.id)
        self.assertIsNotNone(res1)
        self.assertEqual(res1.source_id, self.cisa_source.id)

        # Query database row
        row = self.db.query(SourceQuality).filter(SourceQuality.source_id == self.cisa_source.id).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.quality_tier, res1.quality_tier.value)

        # Trigger re-calculation
        res2 = source_reliability_service.update_or_create_source_quality(self.db, self.cisa_source.id)
        self.assertEqual(res2.source_id, self.cisa_source.id)

    def test_rest_endpoints(self):
        """Test REST endpoints for source quality."""
        # 1. Recalculate specific source
        resp1 = self.client.post(f"/api/v1/sources/{self.cisa_source.id}/quality/recalculate")
        self.assertEqual(resp1.status_code, 200)
        data1 = resp1.json()
        self.assertEqual(data1["source_id"], self.cisa_source.id)
        self.assertIn("authority", data1)
        self.assertIn("accuracy", data1)
        self.assertIn("overall_score", data1)

        # 2. Get specific source quality
        resp2 = self.client.get(f"/api/v1/sources/{self.cisa_source.id}/quality")
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertEqual(data2["source_id"], self.cisa_source.id)
        self.assertEqual(data2["quality_tier"], data1["quality_tier"])

        # 3. List all source qualities
        resp3 = self.client.get("/api/v1/sources/quality/all")
        self.assertEqual(resp3.status_code, 200)
        data3 = resp3.json()
        self.assertIsInstance(data3, list)
        self.assertGreaterEqual(len(data3), 2)

        # 4. Recalculate all sources
        resp4 = self.client.post("/api/v1/sources/quality/recalculate-all")
        self.assertEqual(resp4.status_code, 200)
        data4 = resp4.json()
        self.assertEqual(data4["status"], "ok")
        self.assertGreaterEqual(data4["recalculated_count"], 2)


if __name__ == "__main__":
    unittest.main()

"""Test Suite for Section 50 & 51 (Step 49): System Readiness & Definition of Done (DoD).

Verifies:
  1. All 31 Definition of Done criteria defined in Section 51 of IMPLEMENT.md
  2. All 40 Development Milestones defined in Section 50 of IMPLEMENT.md
  3. All 10 stages of the Critical Engineering Rule defined in Section 52 of IMPLEMENT.md
  4. REST API endpoints under /api/v1/compliance/*
  5. Audit reporting and database persistence
"""

import os
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.compliance import ComplianceAuditReportModel
from services.compliance.definition_of_done import definition_of_done_verifier
from services.compliance.development_order import development_order_verifier
from services.compliance.pipeline_audit import critical_pipeline_auditor


class TestSection50ComplianceAndDoD(unittest.TestCase):
    """Verifies system readiness against Sections 50, 51, and 52 of IMPLEMENT.md."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app, raise_server_exceptions=False)
        cls.db = SessionLocal()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # ── 1. Definition of Done (Section 51) ────────────────────────────────────
    def test_01_definition_of_done_all_31_criteria(self):
        """DoD: All 31 criteria must be evaluated and achieve 100% pass score."""
        res = definition_of_done_verifier.verify_all(db=self.db, force_refresh=True)
        self.assertEqual(res.total_criteria, 31)
        self.assertEqual(res.passed_criteria, 31)
        self.assertEqual(res.score_pct, 100.0)
        self.assertEqual(res.status, "PASSED")
        self.assertEqual(len(res.items), 31)

    def test_02_dod_criteria_categories_and_evidence(self):
        """DoD: Every criterion must contain meaningful live evidence and latency."""
        res = definition_of_done_verifier.verify_all(db=self.db, force_refresh=False)
        categories = set(item.category for item in res.items)
        self.assertIn("Ingestion", categories)
        self.assertIn("Normalization", categories)
        self.assertIn("Classification", categories)
        self.assertIn("Extraction", categories)
        self.assertIn("Deduplication", categories)
        self.assertIn("Search", categories)
        self.assertIn("Intelligence", categories)
        self.assertIn("Security", categories)
        self.assertIn("Operations", categories)

        for item in res.items:
            self.assertTrue(item.passed, f"DoD criterion #{item.criterion_number} failed: {item.title}")
            self.assertTrue(len(item.evidence) > 10, f"Evidence missing for #{item.criterion_number}")
            self.assertGreaterEqual(item.latency_ms, 0.0)

    # ── 2. Recommended Development Order (Section 50) ─────────────────────────
    def test_03_development_order_all_40_milestones(self):
        """Milestones: All 40 sequential development steps must be verified."""
        res = development_order_verifier.verify_all_milestones()
        self.assertEqual(res.total_milestones, 40)
        self.assertEqual(res.completed_milestones, 40)
        self.assertEqual(res.completion_pct, 100.0)
        self.assertEqual(res.status, "ALL_MILESTONES_VERIFIED")
        self.assertEqual(len(res.milestones), 40)

    def test_04_development_order_milestone_attributes(self):
        """Milestones: Each milestone must map to valid modules and test files."""
        res = development_order_verifier.verify_all_milestones()
        # Verify first and last milestones
        m1 = res.milestones[0]
        self.assertEqual(m1.step_number, 1)
        self.assertEqual(m1.code, "01")
        self.assertEqual(m1.name, "Repository")

        m40 = res.milestones[39]
        self.assertEqual(m40.step_number, 40)
        self.assertEqual(m40.code, "40")
        self.assertEqual(m40.name, "Production deployment")

        for m in res.milestones:
            self.assertTrue(m.implemented)
            self.assertEqual(m.status, "VERIFIED")
            self.assertTrue(m.module_path)
            self.assertTrue(m.test_suite.endswith(".py"))

    # ── 3. Critical Architecture Pipeline Audit (Section 52) ───────────────────
    def test_05_critical_architecture_pipeline_trace(self):
        """Critical Rule: Non-bypassable 10-stage pipeline execution and integrity."""
        audit = critical_pipeline_auditor.run_audit(db=self.db)
        self.assertEqual(audit.pipeline_integrity, "VERIFIED")
        self.assertEqual(audit.stages_total, 10)
        self.assertEqual(audit.stages_passed, 10)
        self.assertTrue(audit.provenance_verified)
        self.assertEqual(audit.synthetic_threat_cve, "CVE-2024-3400")
        self.assertGreater(audit.total_duration_ms, 0.0)

    def test_06_pipeline_trace_stage_ordering_and_provenance(self):
        """Critical Rule: Stage progression follows exact Section 52 diagram."""
        audit = critical_pipeline_auditor.run_audit(db=self.db)
        expected_stages = [
            "Sources",
            "Discovery",
            "Collection",
            "Normalization",
            "Classification & Extraction & Deduplication",
            "Enrichment",
            "Knowledge Graph",
            "Search Indexing",
            "Analytics & Alerts",
            "Frontend Presentation",
        ]
        actual_stages = [t.stage_name for t in audit.traces]
        self.assertEqual(actual_stages, expected_stages)

        for trace in audit.traces:
            self.assertTrue(trace.passed)
            self.assertTrue(trace.provenance_intact)
            self.assertGreaterEqual(trace.execution_time_ms, 0.0)

    # ── 4. REST API Endpoints ─────────────────────────────────────────────────
    def test_07_api_compliance_overview(self):
        """API: GET /api/v1/compliance/overview aggregates system readiness."""
        res = self.client.get("/api/v1/compliance/overview")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["overall_readiness_score"], 95.0)
        self.assertEqual(data["readiness_tier"], "PRODUCTION_CERTIFIED")
        self.assertEqual(data["dod_passed_criteria"], 31)
        self.assertEqual(data["milestones_completed"], 40)
        self.assertEqual(data["pipeline_integrity"], "VERIFIED")

    def test_08_api_definition_of_done_get_and_verify(self):
        """API: GET & POST /api/v1/compliance/definition-of-done."""
        # GET cached/live
        res_get = self.client.get("/api/v1/compliance/definition-of-done")
        self.assertEqual(res_get.status_code, 200)
        data_get = res_get.json()
        self.assertEqual(data_get["total_criteria"], 31)
        self.assertEqual(data_get["score_pct"], 100.0)

        # POST force verify
        res_post = self.client.post("/api/v1/compliance/definition-of-done/verify")
        self.assertEqual(res_post.status_code, 200)
        data_post = res_post.json()
        self.assertEqual(data_post["status"], "PASSED")
        self.assertEqual(len(data_post["items"]), 31)

    def test_09_api_development_order_and_pipeline_audit(self):
        """API: GET /development-order & POST /pipeline-audit."""
        res_order = self.client.get("/api/v1/compliance/development-order")
        self.assertEqual(res_order.status_code, 200)
        data_order = res_order.json()
        self.assertEqual(data_order["total_milestones"], 40)

        res_pipe = self.client.post("/api/v1/compliance/pipeline-audit")
        self.assertEqual(res_pipe.status_code, 200)
        data_pipe = res_pipe.json()
        self.assertEqual(data_pipe["pipeline_integrity"], "VERIFIED")
        self.assertEqual(len(data_pipe["traces"]), 10)

    def test_10_api_reports_list_and_generate(self):
        """API: GET /reports & POST /reports/generate audit persistence."""
        # Generate new audit report
        res_gen = self.client.post("/api/v1/compliance/reports/generate")
        self.assertEqual(res_gen.status_code, 200)
        report = res_gen.json()
        self.assertIn("audit_id", report)
        self.assertEqual(report["status"], "PASSED")
        self.assertEqual(report["dod_total_criteria"], 31)
        self.assertEqual(report["milestones_total"], 40)

        # List reports
        res_list = self.client.get("/api/v1/compliance/reports")
        self.assertEqual(res_list.status_code, 200)
        reports = res_list.json()
        self.assertGreaterEqual(len(reports), 1)
        self.assertEqual(reports[0]["status"], "PASSED")


if __name__ == "__main__":
    unittest.main()

"""Section 53 (Step 52): Tests for Immediate First Milestone Golden Pipeline.

Tests the complete 10-step foundational pipeline:
  Cybersecurity RSS Feed -> Python Connector -> FastAPI -> PostgreSQL -> Classification
  -> CVE Extraction -> Deduplication -> OpenSearch -> Next.js -> Searchable Dashboard

10 tests covering engine spec, execution, model persistence, REST endpoints, and contracts.
"""

import sys
import os
import unittest
import uuid
from datetime import datetime, timezone

sys.path.insert(0, ".")
sys.path.insert(0, "apps/api")

# ── Suppress psycopg2 fallback warning ─────────────────────────────────────────
import logging
logging.disable(logging.WARNING)


class TestGoldenPipelineSpec(unittest.TestCase):
    """Test 1: Engine specification returns correct 10-step pipeline definition."""

    def setUp(self):
        from services.compliance.golden_pipeline import GoldenPipelineEngine
        self.engine = GoldenPipelineEngine()

    def test_specification_has_10_steps(self):
        spec = self.engine.get_specification()
        self.assertEqual(spec["total_steps"], 10, "Pipeline must have exactly 10 steps")

    def test_specification_step_names(self):
        spec = self.engine.get_specification()
        expected_names = [
            "Cybersecurity RSS Feed",
            "Python Connector",
            "FastAPI",
            "PostgreSQL",
            "Classification",
            "CVE Extraction",
            "Deduplication",
            "OpenSearch",
            "Next.js",
            "Searchable Dashboard",
        ]
        actual_names = [s["step_name"] for s in spec["steps"]]
        self.assertEqual(actual_names, expected_names, "Step names must match Section 53 specification")

    def test_specification_sequence_string(self):
        spec = self.engine.get_specification()
        self.assertIn("Cybersecurity RSS Feed", spec["pipeline_sequence"])
        self.assertIn("Searchable Dashboard", spec["pipeline_sequence"])
        self.assertIn("->", spec["pipeline_sequence"])

    def test_specification_section_label(self):
        spec = self.engine.get_specification()
        self.assertIn("53", spec["section"])


class TestGoldenPipelineEngineRun(unittest.TestCase):
    """Tests 2–5: Engine execution produces valid 10-step trace with contracts."""

    def setUp(self):
        from services.compliance.golden_pipeline import GoldenPipelineEngine
        self.engine = GoldenPipelineEngine()
        self.result = self.engine.run(
            db=None,
            feed_source="https://cve.mitre.org/data/rss/cyber_advisory.xml",
            target_cve="CVE-2024-3400",
        )

    def test_run_returns_10_step_traces(self):
        """Test 2: Engine run produces exactly 10 step traces."""
        self.assertIn("step_traces", self.result)
        self.assertEqual(len(self.result["step_traces"]), 10,
                         "Pipeline must produce exactly 10 step traces")

    def test_run_step_order_sequential(self):
        """Test 3: Step traces are numbered 1-10 sequentially."""
        orders = [st["step_order"] for st in self.result["step_traces"]]
        self.assertEqual(orders, list(range(1, 11)), "Steps must be ordered 1 through 10")

    def test_run_all_steps_passed(self):
        """Test 4: All 10 steps must pass."""
        failed = [st["step_name"] for st in self.result["step_traces"] if not st["passed"]]
        self.assertEqual(failed, [], f"These steps failed unexpectedly: {failed}")

    def test_run_result_fields_present(self):
        """Test 5: Run result contains all required top-level fields."""
        required = [
            "run_id", "run_timestamp", "status", "feed_source", "article_title",
            "target_cve", "extracted_cves", "classification_category", "content_hash",
            "steps_total", "steps_passed", "total_duration_ms", "search_query_latency_ms",
            "step_traces", "message",
        ]
        for field in required:
            self.assertIn(field, self.result, f"Missing required field: {field}")

    def test_run_status_passed(self):
        """Test 5b: Run result status must be PASSED."""
        self.assertEqual(self.result["status"], "PASSED")
        self.assertEqual(self.result["steps_total"], 10)
        self.assertEqual(self.result["steps_passed"], 10)


class TestGoldenPipelineStepContracts(unittest.TestCase):
    """Test 6: Each step trace has the correct output_contract field."""

    def setUp(self):
        from services.compliance.golden_pipeline import GoldenPipelineEngine
        self.engine = GoldenPipelineEngine()
        self.result = self.engine.run(db=None, target_cve="CVE-2024-1234")

    def test_step_output_contracts(self):
        """Test 6: Each step has a non-empty output_contract field."""
        for trace in self.result["step_traces"]:
            self.assertIn("output_contract", trace,
                          f"Step {trace['step_name']} missing output_contract")
            self.assertTrue(len(trace["output_contract"]) > 0,
                            f"Step {trace['step_name']} has empty output_contract")


class TestGoldenPipelineModelPersistence(unittest.TestCase):
    """Test 7: GoldenPipelineRunModel persists and retrieves run data via SQLite."""

    @classmethod
    def setUpClass(cls):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.models.base import Base
        from app.models.compliance import GoldenPipelineRunModel

        cls.GoldenPipelineRunModel = GoldenPipelineRunModel
        cls.engine_db = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=cls.engine_db)
        Session = sessionmaker(bind=cls.engine_db)
        cls.db = Session()

    def test_model_persist_and_retrieve(self):
        """Test 7: Persist a golden pipeline run model and retrieve it."""
        unique_run_id = f"golden-run-test-{uuid.uuid4().hex[:8]}"
        run = self.GoldenPipelineRunModel(
            run_id=unique_run_id,
            status="PASSED",
            feed_source="https://cve.mitre.org/data/rss/cyber_advisory.xml",
            article_title="Test CVE Advisory Article for Golden Pipeline",
            target_cve="CVE-2024-TEST",
            extracted_cves_json=["CVE-2024-TEST"],
            classification_category="vulnerability_management",
            content_hash="sha256:abcdef1234567890",
            steps_total=10,
            steps_passed=10,
            search_indexed=True,
            query_latency_ms=14.8,
            total_duration_ms=142.6,
            step_traces_json=[{"step_order": 1, "step_name": "RSS Feed", "passed": True}],
            executed_by="test_suite",
            run_timestamp=datetime.now(timezone.utc),
        )
        self.db.add(run)
        self.db.commit()

        retrieved = self.db.query(self.GoldenPipelineRunModel).filter_by(run_id=unique_run_id).first()
        self.assertIsNotNone(retrieved, "Run model must be persisted and retrievable")
        self.assertEqual(retrieved.status, "PASSED")
        self.assertEqual(retrieved.steps_passed, 10)
        self.assertEqual(retrieved.target_cve, "CVE-2024-TEST")
        self.assertIsNotNone(retrieved.step_traces)


class TestGoldenPipelineRESTEndpoints(unittest.TestCase):
    """Tests 8–10: REST endpoints /spec, /run, /latest respond correctly."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app
        from app.database import engine
        import app.models as _models  # ensure all models registered without clobbering app
        from app.models.base import Base
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(fastapi_app, raise_server_exceptions=True)

    def test_endpoint_spec(self):
        """Test 8: GET /api/v1/compliance/golden-pipeline/spec returns 10-step spec."""
        response = self.client.get("/api/v1/compliance/golden-pipeline/spec")
        self.assertEqual(response.status_code, 200, f"Spec endpoint failed: {response.text}")
        data = response.json()
        self.assertIn("total_steps", data)
        self.assertEqual(data["total_steps"], 10)
        self.assertIn("steps", data)
        self.assertEqual(len(data["steps"]), 10)

    def test_endpoint_run(self):
        """Test 9: POST /api/v1/compliance/golden-pipeline/run executes pipeline."""
        response = self.client.post(
            "/api/v1/compliance/golden-pipeline/run",
            json={
                "feed_source": "https://cve.mitre.org/data/rss/cyber_advisory.xml",
                "target_cve": "CVE-2024-3400",
                "persist": False,
            },
        )
        self.assertEqual(response.status_code, 200, f"Run endpoint failed: {response.text}")
        data = response.json()
        self.assertIn("run_id", data)
        self.assertIn("step_traces", data)
        self.assertEqual(len(data["step_traces"]), 10)
        self.assertEqual(data["status"], "PASSED")

    def test_endpoint_latest(self):
        """Test 10: GET /api/v1/compliance/golden-pipeline/latest returns a run record."""
        response = self.client.get("/api/v1/compliance/golden-pipeline/latest")
        self.assertEqual(response.status_code, 200, f"Latest endpoint failed: {response.text}")
        data = response.json()
        self.assertIn("run_id", data)
        self.assertIn("step_traces", data)
        self.assertIn("status", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)

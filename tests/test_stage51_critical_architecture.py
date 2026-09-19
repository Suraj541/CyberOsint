"""Section 52 (Step 51): Critical Engineering Architecture Verification Suite.

Validates the full non-bypassable 10-stage dataflow defined in Section 52 of IMPLEMENT.md:
  Sources -> Discovery -> Collection -> Normalization -> (Classification, Extraction, Deduplication)
  -> Enrichment -> Knowledge Graph -> (Search, Analytics, Alerts) -> Frontend

Specifically verifies:
1. Canonical DAG topology, nodes, edges, and triad splits
2. Live DAG execution trace through all 10 stages and 2 triad branches
3. Anti-Pattern Guard preventing 'Crawler -> Database -> Website'
4. Zero-code addition of new OSINT sources (pluggable source contract)
5. Cryptographic SHA-256 provenance preservation from collection to frontend
6. Database model persistence and REST API endpoints
"""

import hashlib
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, get_db, SessionLocal
from app.models.compliance import ArchitectureAuditModel
from services.compliance.critical_architecture import critical_architecture_engine, CriticalArchitectureEngine


class TestCriticalArchitecture(unittest.TestCase):
    """Test suite for Section 52 Critical Engineering Architecture."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()


    def test_dag_topology_structure(self):
        """Verify Section 52 DAG topology, node counts, edge connections, and triad splits."""
        dag = critical_architecture_engine.get_dag_topology()
        self.assertEqual(dag["specification"], "IMPLEMENT.md Section 52")
        self.assertEqual(dag["prohibited_anti_pattern"], "Crawler -> Database -> Website")
        self.assertEqual(dag["nodes_count"], 13)
        self.assertEqual(dag["edges_count"], 16)

        node_ids = [n["id"] for n in dag["nodes"]]
        expected_nodes = [
            "sources", "discovery", "collection", "normalization",
            "classification", "extraction", "deduplication",
            "enrichment", "knowledge_graph",
            "search", "analytics", "alerts", "frontend",
        ]
        for expected in expected_nodes:
            self.assertIn(expected, node_ids)

        # Verify Triad splits
        triad_splits = dag["triad_splits"]
        self.assertEqual(len(triad_splits), 2)
        self.assertEqual(triad_splits[0]["name"], "Triad Processing")
        self.assertEqual(triad_splits[0]["split_from"], "normalization")
        self.assertEqual(triad_splits[0]["branches"], ["classification", "extraction", "deduplication"])
        self.assertEqual(triad_splits[0]["join_to"], "enrichment")

        self.assertEqual(triad_splits[1]["name"], "Triad Delivery")
        self.assertEqual(triad_splits[1]["split_from"], "knowledge_graph")
        self.assertEqual(triad_splits[1]["branches"], ["search", "analytics", "alerts"])
        self.assertEqual(triad_splits[1]["join_to"], "frontend")

    def test_execute_dag_pipeline_all_stages_pass(self):
        """Verify live DAG pipeline execution across all stages and branches."""
        res = critical_architecture_engine.execute_dag_pipeline(
            source_name="CISA KEV Feed",
            target_cve="CVE-2024-3400",
            db=self.db,
        )
        self.assertEqual(res["architecture_status"], "COMPLIANT")
        self.assertEqual(res["stages_count"], 13)
        self.assertEqual(res["stages_passed"], 13)
        self.assertTrue(res["triad_processing_passed"])
        self.assertTrue(res["triad_delivery_passed"])
        self.assertTrue(res["provenance_intact"])
        self.assertGreater(res["execution_time_ms"], 0)

        # Check every individual trace
        for trace in res["traces"]:
            self.assertEqual(trace["status"], "PASSED")
            self.assertTrue(trace["passed"])
            self.assertTrue(trace["provenance_intact"])
            self.assertTrue(len(trace["provenance_hash"]) == 64)

    def test_triad_processing_branches(self):
        """Verify Triad 1 parallel branches: Classification, Extraction, Deduplication."""
        res = critical_architecture_engine.execute_dag_pipeline(db=self.db)
        traces_by_id = {t["stage_id"]: t for t in res["traces"]}

        # 5a. Classification
        cls_trace = traces_by_id["classification"]
        self.assertEqual(cls_trace["branch"], "triad_processing_1")
        self.assertIsNotNone(cls_trace["details"].get("category"))
        self.assertEqual(cls_trace["output_contract"], "ClassificationTaxonomyResult")

        # 5b. Extraction
        ext_trace = traces_by_id["extraction"]
        self.assertEqual(ext_trace["branch"], "triad_processing_2")
        self.assertGreater(ext_trace["details"].get("entities_count", 0), 0)
        self.assertTrue(ext_trace["details"].get("character_offset_provenance"))

        # 5c. Deduplication
        dedup_trace = traces_by_id["deduplication"]
        self.assertEqual(dedup_trace["branch"], "triad_processing_3")
        self.assertTrue(dedup_trace["details"].get("early_dedup_guarantee"))

    def test_triad_delivery_branches(self):
        """Verify Triad 2 parallel branches: Search, Analytics, Alerts."""
        res = critical_architecture_engine.execute_dag_pipeline(db=self.db)
        traces_by_id = {t["stage_id"]: t for t in res["traces"]}

        # 8a. Search
        search_trace = traces_by_id["search"]
        self.assertEqual(search_trace["branch"], "triad_delivery_1")
        self.assertTrue(search_trace["details"].get("hybrid_indexing"))

        # 8b. Analytics
        analytics_trace = traces_by_id["analytics"]
        self.assertEqual(analytics_trace["branch"], "triad_delivery_2")
        self.assertTrue(analytics_trace["details"].get("threat_actor_leaderboard_updated"))

        # 8c. Alerts
        alerts_trace = traces_by_id["alerts"]
        self.assertEqual(alerts_trace["branch"], "triad_delivery_3")
        self.assertTrue(alerts_trace["details"].get("watchlist_matched"))

    def test_sha256_provenance_unbroken(self):
        """Verify cryptographic SHA-256 payload hash is preserved across every stage."""
        sample_body = "Unique test payload for provenance audit: CVE-2024-3400 test."
        expected_hash = hashlib.sha256(sample_body.encode("utf-8")).hexdigest()

        res = critical_architecture_engine.execute_dag_pipeline(
            target_cve="CVE-2024-3400",
            raw_text=sample_body,
            db=self.db,
        )
        self.assertTrue(res["provenance_intact"])
        for trace in res["traces"]:
            self.assertEqual(trace["provenance_hash"], expected_hash)
            self.assertTrue(trace["provenance_intact"])

    def test_anti_pattern_guard_enforcement(self):
        """Verify Anti-Pattern Guard actively blocks 'Crawler -> Database -> Website'."""
        guard_res = critical_architecture_engine.run_anti_pattern_guard()
        self.assertEqual(guard_res["anti_pattern_guard_status"], "VERIFIED_ACTIVE")
        self.assertEqual(guard_res["prohibited_architecture"], "Crawler -> Database -> Website")
        self.assertEqual(guard_res["guards_total"], 4)
        self.assertEqual(guard_res["guards_enforced"], 4)
        self.assertTrue(guard_res["all_anti_patterns_blocked"])

        guard_ids = [g["guard_id"] for g in guard_res["guards"]]
        self.assertIn("guard_01_no_raw_bypass", guard_ids)
        self.assertIn("guard_02_dedup_priority", guard_ids)
        self.assertIn("guard_03_provenance_integrity", guard_ids)
        self.assertIn("guard_04_decoupled_extensibility", guard_ids)

        for g in guard_res["guards"]:
            self.assertTrue(g["prevented"])
            self.assertEqual(g["status"], "ENFORCED")

    def test_pluggable_source_zero_code_addition(self):
        """Verify arbitrary new OSINT source can be ingested with zero code or schema changes."""
        source_name = "Industrial SCADA Zero-Day Advisory"
        test_url = "https://ics-cert.local/advisories/icsa-24-100"
        payload = (
            "Critical buffer overflow in Siemens Simatic S7-1500 PLC allows remote code execution. "
            "Tracked as CVE-2024-12345 with CVSS 9.8. State-sponsored group Sandworm weaponized flaw."
        )

        plug_res = critical_architecture_engine.test_pluggable_source(
            custom_source_name=source_name,
            custom_url=test_url,
            custom_payload=payload,
        )

        self.assertEqual(plug_res["pluggable_source_test_status"], "SUCCESS")
        self.assertEqual(plug_res["custom_source_name"], source_name)
        self.assertEqual(plug_res["custom_url"], test_url)
        self.assertTrue(plug_res["zero_code_change_verified"])
        self.assertFalse(plug_res["schema_modification_required"])
        self.assertFalse(plug_res["api_modification_required"])
        self.assertFalse(plug_res["frontend_modification_required"])
        self.assertEqual(plug_res["stages_traversed"], 13)
        self.assertEqual(plug_res["stages_passed"], 13)
        self.assertTrue(plug_res["triad_processing_verified"])
        self.assertTrue(plug_res["triad_delivery_verified"])

    def test_architecture_audit_model_persistence(self):
        """Verify ArchitectureAuditModel records can be saved and queried from database."""
        import uuid
        unique_id = f"arch-audit-test-{uuid.uuid4().hex[:10]}"
        audit_rec = ArchitectureAuditModel(
            audit_id=unique_id,
            architecture_status="COMPLIANT",
            stages_count=13,
            stages_passed=13,
            triad_processing_passed=True,
            triad_delivery_passed=True,
            provenance_intact=True,
            anti_patterns_checked=4,
            anti_patterns_prevented=4,
            prohibited_architecture="Crawler -> Database -> Website",
            target_cve="CVE-2024-3400",
            source_name="CISA KEV Feed",
            execution_time_ms=115.4,
            dag_traces_json=[{"stage": "sources", "passed": True}],
            anti_patterns_json=[{"guard": "no_raw_bypass", "enforced": True}],
            executed_by="test_suite",
        )
        self.db.add(audit_rec)
        self.db.commit()
        self.db.refresh(audit_rec)

        fetched = self.db.query(ArchitectureAuditModel).filter(
            ArchitectureAuditModel.audit_id == unique_id
        ).first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.architecture_status, "COMPLIANT")
        self.assertEqual(fetched.stages_count, 13)
        self.assertTrue(fetched.triad_processing_passed)
        self.assertEqual(len(fetched.dag_traces), 1)
        self.assertEqual(len(fetched.anti_patterns), 1)


    def test_api_architecture_endpoints(self):
        """Verify all Section 52 Critical Architecture REST API endpoints."""
        # 1. GET /dag
        res_dag = self.client.get("/api/v1/compliance/architecture/dag")
        self.assertEqual(res_dag.status_code, 200)
        dag_body = res_dag.json()
        self.assertEqual(dag_body["nodes_count"], 13)
        self.assertEqual(len(dag_body["triad_splits"]), 2)

        # 2. POST /audit
        res_audit = self.client.post("/api/v1/compliance/architecture/audit?source_name=Test+Source&target_cve=CVE-2024-3400")
        self.assertEqual(res_audit.status_code, 200)
        audit_body = res_audit.json()
        self.assertEqual(audit_body["architecture_status"], "COMPLIANT")
        self.assertEqual(audit_body["stages_count"], 13)
        self.assertEqual(audit_body["stages_passed"], 13)
        self.assertTrue(audit_body["provenance_intact"])

        # 3. POST /anti-patterns/verify
        res_ap = self.client.post("/api/v1/compliance/architecture/anti-patterns/verify")
        self.assertEqual(res_ap.status_code, 200)
        ap_body = res_ap.json()
        self.assertEqual(ap_body["anti_pattern_guard_status"], "VERIFIED_ACTIVE")
        self.assertTrue(ap_body["all_anti_patterns_blocked"])
        self.assertEqual(ap_body["guards_total"], 4)

        # 4. POST /sources/test-pluggable
        pluggable_payload = {
            "custom_source_name": "DarkWeb Forum Feed",
            "custom_url": "https://darkweb-market.onion/feed/leaks",
            "custom_payload": "Adversary leaked zero-day exploit for CVE-2024-21887 on hacker forum.",
        }
        res_plug = self.client.post("/api/v1/compliance/architecture/sources/test-pluggable", json=pluggable_payload)
        self.assertEqual(res_plug.status_code, 200)
        plug_body = res_plug.json()
        self.assertEqual(plug_body["pluggable_source_test_status"], "SUCCESS")
        self.assertTrue(plug_body["zero_code_change_verified"])
        self.assertFalse(plug_body["schema_modification_required"])

        # 5. GET /latest
        res_latest = self.client.get("/api/v1/compliance/architecture/latest")
        self.assertEqual(res_latest.status_code, 200)
        latest_body = res_latest.json()
        self.assertIn("audit_id", latest_body)
        self.assertEqual(latest_body["architecture_status"], "COMPLIANT")

    def test_stage_contracts_and_anti_pattern_roles(self):
        """Verify that every stage specifies an explicit contract and anti-pattern defense role."""
        dag = critical_architecture_engine.get_dag_topology()
        for node in dag["nodes"]:
            self.assertTrue(len(node["contract"]) > 0, f"Node {node['id']} missing contract")
            self.assertTrue(len(node["anti_pattern_role"]) > 0, f"Node {node['id']} missing anti-pattern role")
            self.assertIn(node["layer"], range(1, 10))


if __name__ == "__main__":
    unittest.main()


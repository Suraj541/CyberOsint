"""Stage 50 (Section 51): Definition of Done Certification & Final Sign-Off Test Suite.

Verifies:
  1. Live execution of all 31 criteria from Section 51 Definition of Done.
  2. Cryptographic HMAC-SHA256 signature generation and proof binding.
  3. Tamper detection and signature invalidation upon payload modification.
  4. Generation of official Markdown / JSON Certificate of Completion.
  5. Database persistence of DoDCertificateModel.
  6. All FastAPI certification REST endpoints (/issue, /latest, /{id}, /verify, /{id}/markdown).
"""

import unittest
from datetime import datetime, timezone
import json
import uuid
from fastapi.testclient import TestClient

from app.database import Base, engine, get_db, SessionLocal
from app.main import app
from app.models.compliance import DoDCertificateModel
from services.compliance.certification import (
    DoDCertificationEngine,
    dod_certification_engine,
    SECTION_51_CHECKBOX_TITLES,
    CERTIFICATION_AUTHORITY,
)


class TestDefinitionOfDoneCertificationSection51(unittest.TestCase):
    """Rigorous test suite for Section 51 Definition of Done Certification."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_01_section_51_titles_count(self):
        """Ensure all 31 canonical criteria titles are represented."""
        self.assertEqual(len(SECTION_51_CHECKBOX_TITLES), 31)
        self.assertIn("Sources can be registered", SECTION_51_CHECKBOX_TITLES)
        self.assertIn("Production deployment is reproducible", SECTION_51_CHECKBOX_TITLES)

    def test_02_dod_certification_engine_issuance(self):
        """Verify engine executes live audit and issues valid certificate."""
        cert = dod_certification_engine.issue_certification(executed_by="test_auditor")
        self.assertIn("certificate_id", cert)
        self.assertTrue(cert["certificate_id"].startswith("dod-cert-"))
        self.assertEqual(cert["total_criteria"], 31)
        self.assertEqual(cert["passed_criteria"], 31)
        self.assertEqual(cert["failed_criteria"], 0)
        self.assertEqual(cert["compliance_score_pct"], 100.0)
        self.assertEqual(cert["status"], "CERTIFIED")
        self.assertEqual(cert["pipeline_integrity"], "VERIFIED")
        self.assertTrue(len(cert["sha256_signature"]) == 64)
        self.assertEqual(len(cert["checklist_proofs"]), 31)

        # Ensure all 31 criteria passed and have proof hashes
        for proof in cert["checklist_proofs"]:
            self.assertTrue(proof["passed"])
            self.assertTrue(len(proof["proof_hash"]) == 64)
            self.assertIn(proof["title"], SECTION_51_CHECKBOX_TITLES)

    def test_03_signature_verification_valid(self):
        """Verify valid signature is verified successfully."""
        cert = dod_certification_engine.issue_certification(executed_by="test_auditor")
        is_valid = dod_certification_engine.verify_signature(cert)
        self.assertTrue(is_valid)

    def test_04_tamper_detection_fails_invalid_signature(self):
        """Verify modifying evidence, score, or proof hashes breaks the signature."""
        cert = dod_certification_engine.issue_certification(executed_by="test_auditor")

        # Tamper with compliance score
        tampered_cert = json.loads(json.dumps(cert))
        tampered_cert["compliance_score_pct"] = 99.0
        self.assertFalse(dod_certification_engine.verify_signature(tampered_cert))

        # Tamper with evidence in checklist
        tampered_cert_2 = json.loads(json.dumps(cert))
        tampered_cert_2["checklist_proofs"][0]["proof_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(dod_certification_engine.verify_signature(tampered_cert_2))

    def test_05_markdown_certificate_generation(self):
        """Verify Markdown output contains all 31 checkboxes marked [x] and signature."""
        cert = dod_certification_engine.issue_certification(executed_by="test_auditor")
        md = cert.get("markdown_certificate", "")

        self.assertIn("# Cybersecurity OSINT Intelligence Platform", md)
        self.assertIn("## Section 51: Definition of Done — Production Readiness Certification", md)
        self.assertIn(f"**Certificate ID**: `{cert['certificate_id']}`", md)
        self.assertIn(cert["sha256_signature"], md)
        self.assertIn("CERTIFIED PRODUCTION-READY", md)

        # Check that each Section 51 title is present with [x]
        for title in SECTION_51_CHECKBOX_TITLES:
            self.assertIn(f"- [x] **{title}**", md)

        self.assertIn("**Pipeline Integrity Status**: `VERIFIED`", md)

    def test_06_database_model_persistence(self):
        """Verify DoDCertificateModel can be created, saved, and queried."""
        cert_data = dod_certification_engine.issue_certification(executed_by="db_test_auditor")

        db_record = DoDCertificateModel(
            certificate_id=cert_data["certificate_id"],
            status=cert_data["status"],
            certified_by=cert_data["certified_by"],
            system_version=cert_data["system_version"],
            compliance_score_pct=cert_data["compliance_score_pct"],
            total_criteria=cert_data["total_criteria"],
            passed_criteria=cert_data["passed_criteria"],
            failed_criteria=cert_data["failed_criteria"],
            pipeline_integrity=cert_data["pipeline_integrity"],
            sha256_signature=cert_data["sha256_signature"],
            checklist_proofs_json=cert_data["checklist_proofs"],
            markdown_certificate=cert_data["markdown_certificate"],
            executed_by=cert_data["executed_by"],
            issued_at=datetime.fromisoformat(cert_data["issued_at"]),
        )
        self.db.add(db_record)
        self.db.commit()
        self.db.refresh(db_record)

        queried = self.db.query(DoDCertificateModel).filter_by(certificate_id=cert_data["certificate_id"]).first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.certificate_id, cert_data["certificate_id"])
        self.assertEqual(queried.compliance_score_pct, 100.0)
        self.assertEqual(len(queried.checklist_proofs_json), 31)

    def test_07_api_issue_certificate(self):
        """Test POST /api/v1/compliance/certification/issue endpoint."""
        res = self.client.post(
            "/api/v1/compliance/certification/issue",
            json={"executed_by": "api_test_officer", "force_fresh_audit": False},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["certificate_id"].startswith("dod-cert-"))
        self.assertEqual(data["compliance_score_pct"], 100.0)
        self.assertEqual(data["passed_criteria"], 31)
        self.assertEqual(data["total_criteria"], 31)
        self.assertEqual(data["status"], "CERTIFIED")
        self.assertTrue(len(data["sha256_signature"]) == 64)

    def test_08_api_get_latest_and_by_id(self):
        """Test GET /api/v1/compliance/certification/latest and /{id}."""
        # Ensure at least one certificate exists
        issue_res = self.client.post("/api/v1/compliance/certification/issue", json={})
        self.assertEqual(issue_res.status_code, 200)
        issued_id = issue_res.json()["certificate_id"]

        # Latest
        latest_res = self.client.get("/api/v1/compliance/certification/latest")
        self.assertEqual(latest_res.status_code, 200)
        self.assertEqual(latest_res.json()["certificate_id"], issued_id)

        # By ID
        by_id_res = self.client.get(f"/api/v1/compliance/certification/{issued_id}")
        self.assertEqual(by_id_res.status_code, 200)
        self.assertEqual(by_id_res.json()["certificate_id"], issued_id)

    def test_09_api_verify_signature(self):
        """Test POST /api/v1/compliance/certification/verify."""
        cert = dod_certification_engine.issue_certification(executed_by="api_verifier")

        # Verify valid signature
        verify_req = {
            "certificate_id": cert["certificate_id"],
            "issued_at": cert["issued_at"],
            "total_criteria": cert["total_criteria"],
            "passed_criteria": cert["passed_criteria"],
            "compliance_score_pct": cert["compliance_score_pct"],
            "sha256_signature": cert["sha256_signature"],
            "checklist_proofs": cert["checklist_proofs"],
        }
        res = self.client.post("/api/v1/compliance/certification/verify", json=verify_req)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["valid"])
        self.assertEqual(res.json()["status"], "VERIFIED")

        # Verify tampered signature
        verify_req["compliance_score_pct"] = 80.0
        res_tampered = self.client.post("/api/v1/compliance/certification/verify", json=verify_req)
        self.assertEqual(res_tampered.status_code, 200)
        self.assertFalse(res_tampered.json()["valid"])
        self.assertEqual(res_tampered.json()["status"], "INVALID_SIGNATURE")

    def test_10_api_download_markdown_certificate(self):
        """Test GET /api/v1/compliance/certification/{id}/markdown."""
        issue_res = self.client.post("/api/v1/compliance/certification/issue", json={})
        self.assertEqual(issue_res.status_code, 200)
        cid = issue_res.json()["certificate_id"]

        md_res = self.client.get(f"/api/v1/compliance/certification/{cid}/markdown")
        self.assertEqual(md_res.status_code, 200)
        self.assertIn("text/plain", md_res.headers["content-type"])
        text = md_res.text
        self.assertIn(f"**Certificate ID**: `{cid}`", text)
        self.assertIn("Section 51: Definition of Done", text)
        self.assertIn("- [x] **Sources can be registered**", text)


if __name__ == "__main__":
    unittest.main()

"""
Tests for Subsystem 8: API Endpoints.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates FastAPI router integration, response schemas, error handling,
security headers, and core intelligence endpoints.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app


class TestAPIEndpointsSubsystem(unittest.TestCase):
    """Subsystem 8: API Endpoints Unit and Integration Tests."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_root_and_health_endpoints(self):
        """Verify GET / and GET /health return 200 OK and expected structure."""
        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "ok")

        res_root = self.client.get("/")
        self.assertEqual(res_root.status_code, 200)
        self.assertIn("version", res_root.json())

    def test_02_taxonomy_endpoints(self):
        """Verify GET /api/v1/taxonomy/categories returns all canonical categories."""
        res = self.client.get("/api/v1/taxonomy/categories")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) >= 10)
        category_ids = [d["id"] for d in data]
        self.assertIn("malware", category_ids)
        self.assertIn("vulnerability_management", category_ids)

    def test_03_classifier_endpoint(self):
        """Verify POST /api/v1/classifier/classify classifies input intelligence."""
        payload = {
            "title": "LockBit 3.0 Ransomware Deployment via Phishing Lures",
            "description": "Adversaries exfiltrate corporate documents before encrypting disk drives.",
        }
        res = self.client.post("/api/v1/classifier/classify", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["category"], "malware")
        self.assertGreater(data["confidence"], 0.5)

    def test_04_extractor_endpoint(self):
        """Verify POST /api/v1/extractor/extract extracts cybersecurity entities."""
        payload = {
            "text": "Critical flaw CVE-2024-38077 discovered in Microsoft Windows Server appliances."
        }
        res = self.client.post("/api/v1/extractor/extract", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        entities = data["entities"]
        self.assertIsInstance(entities, list)
        self.assertTrue(any(e["entity_type"] == "cve" for e in entities))

    def test_05_deduplication_check_endpoint(self):
        """Verify POST /api/v1/deduplication/check evaluates similarity and duplicate status."""
        payload = {
            "title": "CISA Adds Ivanti Vulnerability to KEV Catalog",
            "url": "https://cisa.gov/advisory-1",
            "description": "CISA has added a zero day vulnerability in Ivanti to the KEV list.",
        }
        res = self.client.post("/api/v1/deduplication/check", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("is_duplicate", data)
        self.assertIn("similarity_score", data)

    def test_06_search_endpoint(self):
        """Verify GET /api/v1/search executes structured search query."""
        res = self.client.get("/api/v1/search?q=ransomware")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("hits", data)
        self.assertIn("total", data)
        self.assertIn("facets", data)

    def test_07_security_posture_endpoint_and_headers(self):
        """Verify GET /api/v1/security/posture returns 15 controls and security headers."""
        res = self.client.get("/api/v1/security/posture")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["compliance_score"], 100)
        self.assertEqual(data["total_controls"], 15)

        # OWASP security headers verified on response
        headers = res.headers
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")


if __name__ == "__main__":
    unittest.main()

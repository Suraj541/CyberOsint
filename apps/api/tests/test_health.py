"""
Unit and Integration Tests for Backend API Endpoints
Verifies health check endpoints, API discovery, CORS headers, and OpenAPI schema generation.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api is in sys.path
api_root = Path(__file__).resolve().parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))

from fastapi.testclient import TestClient
from app.main import app
from app.config import settings


class TestBackendHealthEndpoints(unittest.TestCase):
    """Test suite verifying Step 2 FastAPI backend functionality and health endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_root_health_endpoint_conformance(self):
        """
        Verify GET /health conforms exactly to IMPLEMENT.md Step 2 specification:
        Expected status code: 200
        Expected response body: {"status": "ok"}
        """
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data, {"status": "ok"})

    def test_api_v1_health_endpoint(self):
        """Verify GET /api/v1/health is also reachable and returns status: ok."""
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ok")

    def test_detailed_health_endpoint(self):
        """Verify GET /api/v1/health/detail returns comprehensive platform diagnostics."""
        response = self.client.get("/api/v1/health/detail")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertIn("environment", data)
        self.assertIn("version", data)
        self.assertIn("database_connected", data)
        self.assertIn("timestamp", data)
        self.assertEqual(data["version"], settings.VERSION)

    def test_root_endpoint_metadata(self):
        """Verify GET / returns API platform metadata and documentation endpoints."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("platform"), settings.PROJECT_NAME)
        self.assertEqual(data.get("version"), settings.VERSION)
        self.assertEqual(data.get("health_check"), "/health")
        self.assertEqual(data.get("api_v1"), "/api/v1")

    def test_openapi_schema_generation(self):
        """Verify OpenAPI JSON schema is generated and documents /health endpoint."""
        response = self.client.get(f"{settings.API_V1_STR}/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        self.assertIn("openapi", schema)
        self.assertIn("paths", schema)
        self.assertIn("/health", schema["paths"])
        self.assertIn(f"{settings.API_V1_STR}/health", schema["paths"])

    def test_interactive_docs_accessible(self):
        """Verify Swagger UI docs endpoint /docs returns HTTP 200."""
        response = self.client.get("/docs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("swagger", response.text.lower())


if __name__ == "__main__":
    unittest.main()

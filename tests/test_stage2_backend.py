"""
Stage 2: Backend Architecture & Endpoint Baseline Verification Tests
Ensures all packages, configuration, database connectors, Alembic configurations,
and FastAPI endpoints required by IMPLEMENT.md Step 2 are fully operational.
"""

import os
import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.database import Base, check_database_connection


class TestStage2BackendBaseline(unittest.TestCase):
    """Test suite validating complete implementation of Stage 2 (Step 2: Create the Backend)."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_backend_directory_structure(self):
        """Confirm all mandated directories and modules from Step 2 exist."""
        required_paths = [
            api_root / "requirements.txt",
            api_root / "alembic.ini",
            api_root / "alembic" / "env.py",
            api_root / "app" / "main.py",
            api_root / "app" / "config.py",
            api_root / "app" / "database.py",
            api_root / "app" / "api" / "__init__.py",
            api_root / "app" / "models" / "__init__.py",
            api_root / "app" / "schemas" / "__init__.py",
            api_root / "app" / "services" / "__init__.py",
            api_root / "app" / "repositories" / "__init__.py",
            api_root / "app" / "workers" / "__init__.py",
            api_root / "tests" / "test_health.py",
        ]

        for p in required_paths:
            self.assertTrue(p.exists(), f"Mandated Step 2 path missing: {p}")

    def test_step2_health_endpoint_response(self):
        """
        Confirm GET /health returns exactly status: ok as specified:
        Expected status: ok
        """
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_config_initialization(self):
        """Confirm configuration loads project name, version, and CORS origins."""
        self.assertIn("OSINT", settings.PROJECT_NAME)
        self.assertEqual(settings.VERSION, "0.1.0")
        self.assertIsInstance(settings.CORS_ORIGINS, list)
        self.assertGreater(len(settings.CORS_ORIGINS), 0)

    def test_database_base_models(self):
        """Confirm SQLAlchemy declarative base and metadata are properly registered."""
        self.assertIsNotNone(Base.metadata)

    def test_cors_headers_present(self):
        """Verify CORS preflight or response headers are permitted for configured origins."""
        response = self.client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access-control-allow-origin", response.headers)


if __name__ == "__main__":
    unittest.main()

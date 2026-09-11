"""
Connectors & Source Registry Test Suite
Verifies BaseConnector contracts, dynamic registry dispatch,
SourceRegistryService operations, and Source REST API endpoints.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models import Source
from app.schemas.source import SourceCreate, SourceUpdate
from app.services.source_registry import SourceRegistryService
from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.mock import MockSecurityConnector
from connectors.registry import ConnectorRegistry, connector_registry


class TestConnectorsAndSourceRegistry(unittest.TestCase):
    """Test suite validating Step 6 / Stage 4 Source Registry & Connector Interface."""

    @classmethod
    def setUpClass(cls):
        # In-memory test DB with StaticPool to share connection across TestClient threads
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)

        # Register mock connector into global registry
        connector_registry.register("mock", MockSecurityConnector)

        # TestClient override dependency
        def override_get_db():
            db = cls.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()

    def setUp(self):
        self.session = self.Session()
        self.service = SourceRegistryService(registry=connector_registry)

    def tearDown(self):
        self.session.rollback()
        self.session.close()

    def test_base_connector_enforces_abstract_methods(self):
        """Confirm that BaseConnector cannot be instantiated without implementing all 5 methods."""

        class IncompleteConnector(BaseConnector):
            pass

        with self.assertRaises(TypeError):
            IncompleteConnector()

    def test_mock_connector_pipeline_execution(self):
        """Confirm an implemented connector executes the complete discover -> fetch -> parse -> normalize pipeline."""
        connector = MockSecurityConnector({"name": "Test Mock", "url": "https://mock-security.local"})

        # Health check
        health = connector.health_check()
        self.assertEqual(health.status, "ok")
        self.assertGreater(health.latency_ms, 0)

        # Full pipeline run
        items = connector.run_pipeline()
        self.assertEqual(len(items), 2)
        for item in items:
            self.assertIsInstance(item, NormalizedItem)
            self.assertIn("mock-security.local", item.url)
            self.assertEqual(item.source, "Test Mock")
            self.assertEqual(item.content_type, "advisory")

    def test_connector_registry_registration_and_lookup(self):
        """Confirm ConnectorRegistry registers, looks up, and instantiates connectors."""
        local_registry = ConnectorRegistry()
        self.assertFalse(local_registry.has("custom"))

        local_registry.register("custom", MockSecurityConnector)
        self.assertTrue(local_registry.has("custom"))

        inst = local_registry.create("custom", {"name": "Custom Instance"})
        self.assertIsInstance(inst, MockSecurityConnector)
        self.assertEqual(inst.source_name, "Custom Instance")

        with self.assertRaises(KeyError):
            local_registry.create("non_existent_type")

    def test_source_registry_service_crud_lifecycle(self):
        """Confirm SourceRegistryService creates, reads, updates, and deletes sources."""
        source_in = SourceCreate(
            name="US-CERT Weekly Bulletins",
            url="https://us-cert.cisa.gov/bulletins.xml",
            source_type="advisory",
            platform="web",
            category="vulnerabilities",
            access_method="rss",
            reliability_score=0.95,
            active=True,
        )

        # Create
        created = self.service.create_source(self.session, source_in)
        self.assertIsNotNone(created.id)
        source_id = created.id

        # Read
        retrieved = self.service.get_source(self.session, source_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "US-CERT Weekly Bulletins")

        # Update
        update_data = SourceUpdate(reliability_score=0.99, active=False)
        updated = self.service.update_source(self.session, retrieved, update_data)
        self.assertEqual(updated.reliability_score, 0.99)
        self.assertFalse(updated.active)

        # Delete
        self.service.delete_source(self.session, updated)
        self.assertIsNone(self.service.get_source(self.session, source_id))

    def test_source_registry_health_check_integration(self):
        """Confirm that check_source_health invokes connector and updates source telemetry."""
        source_in = SourceCreate(
            name="Mock Advisory Feed",
            url="https://mock-advisories.local/feed",
            source_type="mock",
            access_method="mock",
            reliability_score=0.80,
        )
        source = self.service.create_source(self.session, source_in)

        # Run health check
        health = self.service.check_source_health(self.session, source.id)
        self.assertEqual(health.status, "ok")

        # Verify source model was updated with timestamp and score bump
        updated_source = self.service.get_source(self.session, source.id)
        self.assertIsNotNone(updated_source.last_checked)
        self.assertGreaterEqual(updated_source.reliability_score, 0.80)

    def test_sources_api_endpoints_end_to_end(self):
        """Confirm REST API endpoints for Source Registry (/api/v1/sources)."""
        payload = {
            "name": "Rapid7 Vulnerability Blog",
            "url": "https://www.rapid7.com/blog/rss/",
            "source_type": "mock",
            "platform": "web",
            "category": "exploit_intel",
            "language": "en",
            "access_method": "mock",
            "reliability_score": 0.88,
            "active": True,
        }

        # POST /api/v1/sources
        create_res = self.client.post("/api/v1/sources", json=payload)
        self.assertEqual(create_res.status_code, 201)
        source_data = create_res.json()
        self.assertEqual(source_data["name"], payload["name"])
        source_id = source_data["id"]

        # Duplicate POST must return 409
        dup_res = self.client.post("/api/v1/sources", json=payload)
        self.assertEqual(dup_res.status_code, 409)

        # GET /api/v1/sources
        list_res = self.client.get("/api/v1/sources")
        self.assertEqual(list_res.status_code, 200)
        items = list_res.json()
        self.assertGreater(len(items), 0)

        # GET /api/v1/sources/{id}
        get_res = self.client.get(f"/api/v1/sources/{source_id}")
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["id"], source_id)

        # PUT /api/v1/sources/{id}
        put_res = self.client.put(
            f"/api/v1/sources/{source_id}",
            json={"reliability_score": 0.94},
        )
        self.assertEqual(put_res.status_code, 200)
        self.assertEqual(put_res.json()["reliability_score"], 0.94)

        # GET /api/v1/sources/{id}/health-check
        health_res = self.client.get(f"/api/v1/sources/{source_id}/health-check")
        self.assertEqual(health_res.status_code, 200)
        self.assertIn("status", health_res.json())

        # DELETE /api/v1/sources/{id}
        del_res = self.client.delete(f"/api/v1/sources/{source_id}")
        self.assertEqual(del_res.status_code, 204)

        # Verify 404 on deleted
        not_found = self.client.get(f"/api/v1/sources/{source_id}")
        self.assertEqual(not_found.status_code, 404)


if __name__ == "__main__":
    unittest.main()

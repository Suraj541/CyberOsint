"""
Comprehensive CVE Synchronization, Upsert, and NVD Pagination Tests.
Verifies:
1. New CVE creation with all relationships.
2. Exact duplicate CVE skip and audit linking.
3. Modified CVE description update in-place.
4. Modified CVSS score and severity update.
5. Modified CWE weakness update and new entity link.
6. Modified affected product update.
7. Modified references update.
8. Repeated ingestion idempotency.
9. NVD API 2.0 pagination loop and termination.
10. Persistent synchronization state tracking.
"""

from datetime import datetime, timezone
import json
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.duplicate import DuplicateLink
from app.models.sync_state import ConnectorSyncState
from connectors.base import NormalizedItem
from connectors.cve.connector import CVEConnector
from services.ingestion.pipeline import IngestionPipeline
from services.sync.state import sync_state_manager


class TestCVEUpsertAndSync(unittest.TestCase):
    """Test suite for complete CVE upsert semantics and synchronization."""

    def setUp(self):
        # Create an isolated in-memory SQLite database for each test
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()
        self.pipeline = IngestionPipeline()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(self.engine)

    def _create_cve_item(
        self,
        cve_id: str = "CVE-2026-1001",
        title: str = "CVE-2026-1001: Critical Buffer Overflow",
        description: str = "Initial buffer overflow in gateway auth handler.",
        cvss: float = 7.5,
        severity: str = "HIGH",
        cwe: str = "CWE-119",
        affected_products: list = None,
        references: list = None,
        published_at: str = "2026-04-01T10:00:00Z",
        modified_at: str = "2026-04-01T10:00:00Z",
    ) -> NormalizedItem:
        if affected_products is None:
            affected_products = ["VendorCorp Gateway 1.0"]
        if references is None:
            references = ["https://nvd.nist.gov/vuln/detail/" + cve_id]

        entities = [
            {
                "type": "cve",
                "name": cve_id,
                "description": description,
                "metadata": {
                    "cvss_score": cvss,
                    "severity": severity,
                    "weakness": cwe,
                    "affected_products": affected_products,
                    "references": references,
                    "modified_at": modified_at,
                },
            },
            {
                "type": "cwe",
                "name": cwe,
                "description": f"Weakness {cwe}",
                "metadata": {},
            },
        ]

        raw_payload = {
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "cvss_score": cvss,
            "severity": severity,
            "weakness": cwe,
            "affected_products": affected_products,
            "references": references,
            "modified_at": modified_at,
        }

        return NormalizedItem(
            title=title,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            description=description,
            author="NVD NIST",
            published_at=published_at,
            source="NVD Feed",
            content_type="cve",
            raw_content=json.dumps(raw_payload),
            language="en",
            metadata={
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": severity,
                "weakness": cwe,
                "affected_products": affected_products,
                "references": references,
                "modified_at": modified_at,
                "tags": ["CVE", "Vulnerability", severity.title(), cwe],
                "entities": entities,
            },
        )

    def test_01_new_cve_creation(self):
        """Test 1: New CVE creates Content, Entity, Tags, and records ingested count."""
        item = self._create_cve_item()
        metrics = self.pipeline.ingest_items(self.db, [item])

        self.assertEqual(metrics.ingested_count, 1)
        self.assertEqual(metrics.updated_count, 0)
        self.assertEqual(metrics.duplicates_skipped, 0)

        # Verify database records
        content = self.db.query(Content).filter(Content.canonical_url.ilike("%CVE-2026-1001%")).first()
        self.assertIsNotNone(content)
        self.assertEqual(content.title, "CVE-2026-1001: Critical Buffer Overflow")
        self.assertEqual(content.status, "discovered")

        cve_ent = self.db.query(Entity).filter(Entity.entity_type == "cve", Entity.name == "CVE-2026-1001").first()
        self.assertIsNotNone(cve_ent)
        meta = json.loads(cve_ent.metadata_json)
        self.assertEqual(meta.get("cvss_score"), 7.5)
        self.assertEqual(meta.get("weakness"), "CWE-119")

    def test_02_exact_duplicate_cve(self):
        """Test 2: Exact identical duplicate CVE is skipped and recorded in DuplicateLink."""
        item1 = self._create_cve_item()
        self.pipeline.ingest_items(self.db, [item1])

        # Second ingestion with exact same item
        item2 = self._create_cve_item()
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.ingested_count, 0)
        self.assertEqual(metrics.updated_count, 0)
        self.assertEqual(metrics.duplicates_skipped, 1)

        # Ensure no duplicate rows created
        self.assertEqual(self.db.query(Content).count(), 1)
        self.assertEqual(self.db.query(Entity).filter(Entity.entity_type == "cve").count(), 1)

        # Ensure duplicate link recorded
        dup_links = self.db.query(DuplicateLink).all()
        self.assertGreaterEqual(len(dup_links), 1)

    def test_03_modified_cve_description(self):
        """Test 3: Upstream modified description updates stored Content in-place."""
        item1 = self._create_cve_item(description="Initial text.")
        self.pipeline.ingest_items(self.db, [item1])

        item2 = self._create_cve_item(description="Updated text with root cause details.", modified_at="2026-04-02T12:00:00Z")
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.updated_count, 1)
        self.assertEqual(metrics.ingested_count, 0)
        self.assertEqual(metrics.duplicates_skipped, 0)

        # Exactly 1 row in DB
        self.assertEqual(self.db.query(Content).count(), 1)
        content = self.db.query(Content).first()
        self.assertEqual(content.description, "Updated text with root cause details.")
        self.assertEqual(content.status, "updated")

    def test_04_modified_cvss(self):
        """Test 4: Upstream modified CVSS and severity updates stored Entity metadata."""
        item1 = self._create_cve_item(cvss=7.5, severity="HIGH")
        self.pipeline.ingest_items(self.db, [item1])

        item2 = self._create_cve_item(cvss=9.8, severity="CRITICAL", modified_at="2026-04-03T15:00:00Z")
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.updated_count, 1)
        cve_ent = self.db.query(Entity).filter(Entity.name == "CVE-2026-1001").first()
        meta = json.loads(cve_ent.metadata_json)
        self.assertEqual(meta.get("cvss_score"), 9.8)
        self.assertEqual(meta.get("severity"), "CRITICAL")
        self.assertEqual(self.db.query(Entity).filter(Entity.entity_type == "cve").count(), 1)

    def test_05_modified_cwe(self):
        """Test 5: Upstream modified CWE updates weakness and links new CWE entity."""
        item1 = self._create_cve_item(cwe="CWE-119")
        self.pipeline.ingest_items(self.db, [item1])

        item2 = self._create_cve_item(cwe="CWE-787", modified_at="2026-04-04T08:00:00Z")
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.updated_count, 1)
        cve_ent = self.db.query(Entity).filter(Entity.name == "CVE-2026-1001").first()
        meta = json.loads(cve_ent.metadata_json)
        self.assertEqual(meta.get("weakness"), "CWE-787")

        cwe787 = self.db.query(Entity).filter(Entity.name == "CWE-787").first()
        self.assertIsNotNone(cwe787)

    def test_06_modified_affected_product(self):
        """Test 6: Upstream modified affected products updates metadata."""
        item1 = self._create_cve_item(affected_products=["VendorCorp Gateway 1.0"])
        self.pipeline.ingest_items(self.db, [item1])

        new_products = ["VendorCorp Gateway 1.0", "VendorCorp Gateway 2.0 Enterprise"]
        item2 = self._create_cve_item(affected_products=new_products, modified_at="2026-04-05T09:00:00Z")
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.updated_count, 1)
        cve_ent = self.db.query(Entity).filter(Entity.name == "CVE-2026-1001").first()
        meta = json.loads(cve_ent.metadata_json)
        self.assertEqual(meta.get("affected_products"), new_products)

    def test_07_modified_references(self):
        """Test 7: Upstream modified references list updates metadata."""
        item1 = self._create_cve_item(references=["https://nvd.nist.gov/vuln/detail/CVE-2026-1001"])
        self.pipeline.ingest_items(self.db, [item1])

        new_refs = [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1001",
            "https://vendorcorp.com/security/advisories/VC-2026-01",
        ]
        item2 = self._create_cve_item(references=new_refs, modified_at="2026-04-06T10:00:00Z")
        metrics = self.pipeline.ingest_items(self.db, [item2])

        self.assertEqual(metrics.updated_count, 1)
        cve_ent = self.db.query(Entity).filter(Entity.name == "CVE-2026-1001").first()
        meta = json.loads(cve_ent.metadata_json)
        self.assertEqual(meta.get("references"), new_refs)

    def test_08_repeated_ingestion_idempotence(self):
        """Test 8: Repeated ingestion passes without changes are completely idempotent."""
        item = self._create_cve_item()
        self.pipeline.ingest_items(self.db, [item])

        for _ in range(4):
            item_dup = self._create_cve_item()
            m = self.pipeline.ingest_items(self.db, [item_dup])
            self.assertEqual(m.ingested_count, 0)
            self.assertEqual(m.updated_count, 0)
            self.assertEqual(m.duplicates_skipped, 1)

        self.assertEqual(self.db.query(Content).count(), 1)
        self.assertEqual(self.db.query(Entity).filter(Entity.entity_type == "cve").count(), 1)

    @patch("connectors.cve.connector.httpx.Client")
    def test_09_nvd_pagination(self, mock_client_cls):
        """Test 9: NVD API 2.0 pagination loops through startIndex and resultsPerPage."""
        # Mock client responses for 2 pages
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        page1_data = {
            "startIndex": 0,
            "resultsPerPage": 2,
            "totalResults": 3,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-9001", "descriptions": [{"lang": "en", "value": "Vuln 1"}]}},
                {"cve": {"id": "CVE-2026-9002", "descriptions": [{"lang": "en", "value": "Vuln 2"}]}},
            ],
        }
        page2_data = {
            "startIndex": 2,
            "resultsPerPage": 2,
            "totalResults": 3,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-9003", "descriptions": [{"lang": "en", "value": "Vuln 3"}]}},
            ],
        }

        resp1 = MagicMock(status_code=200)
        resp1.json.return_value = page1_data
        resp2 = MagicMock(status_code=200)
        resp2.json.return_value = page2_data

        mock_client.get.side_effect = [resp1, resp2]

        connector = CVEConnector({
            "name": "NVD NIST Test",
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "results_per_page": 2,
            "api_key": "test-key-0.6s",
        })

        with patch("connectors.cve.connector.time.sleep", return_value=None):
            entries = connector.discover()

        self.assertEqual(len(entries), 3)
        ids = [e["cve"]["id"] for e in entries]
        self.assertEqual(ids, ["CVE-2026-9001", "CVE-2026-9002", "CVE-2026-9003"])

    def test_10_persistent_sync_state(self):
        """Test 10: Persistent synchronization state is saved and recovered."""
        connector_id = "test_cve_sync"
        now_dt = datetime.now(timezone.utc)

        sync_state_manager.update_state(
            db=self.db,
            connector_id=connector_id,
            source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            last_seen_modified_at=now_dt,
            cursor="2000",
            metadata={"total_fetched": 2000},
        )

        state = sync_state_manager.get_state(self.db, connector_id)
        self.assertEqual(state["connector_id"], connector_id)
        self.assertEqual(state["cursor"], "2000")
        self.assertEqual(state["metadata"].get("total_fetched"), 2000)


if __name__ == "__main__":
    unittest.main()

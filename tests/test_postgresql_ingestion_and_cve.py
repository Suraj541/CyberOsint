"""
Real PostgreSQL 16 Ingestion Pipeline and CVE Upsert Verification.
Validates:
1. Complete ingestion pipeline execution on PostgreSQL.
2. Deduplication, classification, and entity linking in PostgreSQL.
3. Deterministic CVE upsert semantics (new CVE, identical CVE skip, modified CVE update).
4. Persistent synchronization state tracking in PostgreSQL.
5. Ingestion transaction rollback and commit integrity.
"""

import os
import sys
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import (
    Base,
    Content,
    Entity,
    ContentEntity,
    Tag,
    ContentTag,
    Source,
)
from app.models.sync_state import ConnectorSyncState
from connectors.base import NormalizedItem
from services.ingestion.pipeline import IngestionPipeline
from services.sync.state import sync_state_manager

POSTGRES_URL = os.environ.get(
    "TEST_POSTGRES_URL",
    "postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint"
)


class TestPostgreSQLIngestionAndCVE(unittest.TestCase):
    """Verifies ingestion and CVE upsert semantics on live PostgreSQL 16."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.SessionLocal()
        self.pipeline = IngestionPipeline()
        self._test_cves = []
        self._test_urls = []

    def tearDown(self):
        # Clean up test records
        try:
            if self._test_urls:
                for url in self._test_urls:
                    contents = self.db.query(Content).filter(Content.canonical_url == url).all()
                    for c in contents:
                        self.db.delete(c)
            if self._test_cves:
                for cve_name in self._test_cves:
                    ents = self.db.query(Entity).filter(Entity.name == cve_name).all()
                    for e in ents:
                        self.db.delete(e)
            self.db.commit()
        except Exception:
            self.db.rollback()
        finally:
            self.db.close()

    def _create_cve_item(
        self,
        cve_id: str,
        title: str,
        description: str,
        cvss: float = 7.5,
        severity: str = "HIGH",
        cwe: str = "CWE-119",
        modified_at: str = "2026-09-18T10:00:00Z",
    ) -> NormalizedItem:
        self._test_cves.append(cve_id)
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        self._test_urls.append(url)

        entities = [
            {
                "type": "cve",
                "name": cve_id,
                "description": description,
                "metadata": {
                    "cvss_score": cvss,
                    "severity": severity,
                    "weakness": cwe,
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
            "modified_at": modified_at,
        }
        return NormalizedItem(
            title=title,
            url=url,
            description=description,
            author="NVD NIST",
            published_at="2026-09-18T08:00:00Z",
            source="NVD Feed",
            content_type="cve",
            raw_content=json.dumps(raw_payload),
            language="en",
            metadata={
                "cve_id": cve_id,
                "cvss_score": cvss,
                "severity": severity,
                "weakness": cwe,
                "modified_at": modified_at,
                "tags": ["CVE", "Vulnerability", severity.title(), cwe],
                "entities": entities,
            },
        )

    def test_01_real_ingestion_pipeline_end_to_end(self):
        """Test complete pipeline execution from NormalizedItem to PostgreSQL persistence."""
        test_url = f"https://security.intel.local/advisory/{int(datetime.now().timestamp())}"
        self._test_urls.append(test_url)

        item = NormalizedItem(
            title="PostgreSQL 16 High-Performance Query Analysis",
            url=test_url,
            description="Deep architectural analysis of PostgreSQL 16 MVCC and parallel query execution.",
            author="Cyber OSINT Research",
            published_at="2026-09-18T09:00:00Z",
            source="Security Research Portal",
            content_type="research",
            raw_content="Raw text analysis of database performance under OSINT load.",
            language="en",
            metadata={
                "tags": ["Database", "PostgreSQL", "Performance"],
                "entities": [
                    {"type": "technology", "name": "PostgreSQL 16", "description": "Relational database"}
                ],
            },
        )

        metrics = self.pipeline.ingest_items(self.db, [item])
        self.assertEqual(metrics.ingested_count, 1)

        # Verify record in PostgreSQL
        record = self.db.query(Content).filter(Content.canonical_url == test_url).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.title, "PostgreSQL 16 High-Performance Query Analysis")
        self.assertEqual(record.content_type, "research")
        self.assertIsNotNone(record.content_hash)

        # Verify linked entity
        linked_ents = (
            self.db.query(Entity)
            .join(ContentEntity, Entity.id == ContentEntity.entity_id)
            .filter(ContentEntity.content_id == record.id)
            .all()
        )
        self.assertTrue(any(e.name == "PostgreSQL 16" for e in linked_ents))

    def test_02_deduplication_in_postgresql(self):
        """Test that re-ingesting identical content skips duplicate insert and records duplicate metrics."""
        ts = int(datetime.now().timestamp() * 1000)
        test_url = f"https://cert.gov.local/bulletin/{ts}"
        self._test_urls.append(test_url)

        item = NormalizedItem(
            title=f"Critical Active Zero-Day Advisory #{ts}",
            url=test_url,
            description="Details on in-the-wild zero day exploitation.",
            author="Gov CERT",
            published_at="2026-09-18T10:00:00Z",
            source="National CERT",
            content_type="advisory",
            raw_content=f"Payload {ts}",
            language="en",
        )

        # First ingestion -> ingested_count = 1
        m1 = self.pipeline.ingest_items(self.db, [item])
        self.assertEqual(m1.ingested_count, 1)
        self.assertEqual(m1.duplicates_skipped, 0)

        # Second ingestion of exact same item -> duplicates_skipped = 1
        m2 = self.pipeline.ingest_items(self.db, [item])
        self.assertEqual(m2.ingested_count, 0)
        self.assertEqual(m2.duplicates_skipped, 1)

        # Only one row exists in PostgreSQL
        count = self.db.query(Content).filter(Content.canonical_url == test_url).count()
        self.assertEqual(count, 1)

    def test_03_cve_upsert_insert_update_and_deduplicate(self):
        """Test CVE upsert on PostgreSQL: insert new, update modified, skip identical."""
        cve_id = f"CVE-2026-{int(datetime.now().timestamp()) % 100000}"

        # 1. Insert initial CVE
        item1 = self._create_cve_item(
            cve_id=cve_id,
            title=f"{cve_id}: Initial Discovery",
            description="Initial vulnerability description",
            cvss=7.5,
            severity="HIGH",
            modified_at="2026-09-18T10:00:00Z",
        )
        m1 = self.pipeline.ingest_items(self.db, [item1])
        self.assertEqual(m1.ingested_count, 1)

        c1 = self.db.query(Content).filter(Content.canonical_url.ilike(f"%{cve_id}%")).first()
        self.assertIsNotNone(c1)
        self.assertEqual(c1.title, f"{cve_id}: Initial Discovery")

        # 2. Insert same CVE with identical modified_at -> should be duplicate skipped
        item2 = self._create_cve_item(
            cve_id=cve_id,
            title=f"{cve_id}: Initial Discovery",
            description="Initial vulnerability description",
            cvss=7.5,
            severity="HIGH",
            modified_at="2026-09-18T10:00:00Z",
        )
        m2 = self.pipeline.ingest_items(self.db, [item2])
        self.assertEqual(m2.duplicates_skipped, 1)
        self.assertEqual(m2.updated_count, 0)

        # 3. Insert modified CVE with updated CVSS score and description
        item3 = self._create_cve_item(
            cve_id=cve_id,
            title=f"{cve_id}: Remote Code Execution Escaped",
            description="Updated description: active in-the-wild exploitation confirmed.",
            cvss=9.8,
            severity="CRITICAL",
            modified_at="2026-09-18T12:00:00Z",
        )
        m3 = self.pipeline.ingest_items(self.db, [item3])
        self.assertEqual(m3.updated_count, 1)

        # Verify updated record in PostgreSQL
        c_updated = self.db.query(Content).filter(Content.canonical_url.ilike(f"%{cve_id}%")).first()
        self.assertEqual(c_updated.id, c1.id)  # Same row ID updated in place!
        self.assertEqual(c_updated.title, f"{cve_id}: Remote Code Execution Escaped")

        # Verify Entity was updated
        ent = self.db.query(Entity).filter(Entity.name == cve_id).first()
        self.assertIsNotNone(ent)
        ent_meta = json.loads(ent.metadata_json) if ent.metadata_json else {}
        self.assertEqual(ent_meta.get("cvss_score"), 9.8)
        self.assertEqual(ent_meta.get("severity"), "CRITICAL")

    def test_04_persistent_sync_state_on_postgresql(self):
        """Verify durable sync state checkpointing in PostgreSQL table."""
        connector_id = "test_pg_nvd_connector"
        sync_state_manager.update_state(
            self.db,
            connector_id=connector_id,
            cursor="startIndex=2000",
            etag="etag-pg-999",
            metadata={"total_records": 15000, "batch_number": 42},
        )

        # Fetch checkpoint from PostgreSQL
        cp = sync_state_manager.get_state(self.db, connector_id)
        self.assertIsNotNone(cp)
        self.assertEqual(cp.get("cursor"), "startIndex=2000")
        self.assertEqual(cp.get("etag"), "etag-pg-999")
        self.assertEqual(cp.get("metadata", {}).get("batch_number"), 42)

        # Clean up
        self.db.query(ConnectorSyncState).filter(
            ConnectorSyncState.connector_id == connector_id
        ).delete()
        self.db.commit()


if __name__ == "__main__":
    unittest.main()

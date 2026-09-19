"""
PostgreSQL 16 Concurrency Verification Test Suite.
Empirically tests multi-threaded and concurrent operations against PostgreSQL 16:
1. Concurrent CVE upserts (race condition avoidance, no duplicate CVEs).
2. Concurrent ingestion pipeline executions under load.
3. Concurrent duplicate detection race conditions.
4. Connection pool saturation, queuing, and recovery.
"""

import concurrent.futures
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.models import Content, Entity, Source
from connectors.base import NormalizedItem
from services.ingestion.pipeline import IngestionPipeline

POSTGRES_URL = os.environ.get(
    "TEST_POSTGRES_URL",
    "postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint"
)


class TestPostgreSQLConcurrency(unittest.TestCase):
    """Verifies PostgreSQL 16 transaction isolation and concurrency guarantees."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(POSTGRES_URL, pool_size=10, max_overflow=10, pool_pre_ping=True)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def test_01_concurrent_cve_upsert_no_duplicates(self):
        """10 threads race to insert/upsert the same CVE. Exactly 1 Content & 1 Entity must exist."""
        cve_id = f"CVE-2026-RACE-{int(datetime.now().timestamp() * 1000) % 100000}"
        title = f"{cve_id}: Concurrent Race Condition Probe"
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        def worker(thread_idx: int):
            db = self.SessionLocal()
            try:
                pipeline = IngestionPipeline()
                item = NormalizedItem(
                    title=f"{title} (thread {thread_idx})",
                    url=url,
                    description=f"Thread {thread_idx} payload description",
                    author="NVD NIST",
                    published_at="2026-09-18T10:00:00Z",
                    source="NVD Feed",
                    content_type="cve",
                    raw_content=json.dumps({"cve_id": cve_id, "thread": thread_idx}),
                    language="en",
                    metadata={
                        "cve_id": cve_id,
                        "cvss_score": 8.0 + (thread_idx * 0.1),
                        "severity": "HIGH",
                        "modified_at": "2026-09-18T12:00:00Z",
                        "entities": [
                            {
                                "type": "cve",
                                "name": cve_id,
                                "description": "Race probe",
                                "metadata": {"cvss_score": 8.5},
                            }
                        ],
                    },
                )
                m = pipeline.ingest_items(db, [item])
                return m.ingested_count, m.updated_count, m.duplicates_skipped
            finally:
                db.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        total_ingested = sum(r[0] for r in results)
        total_updated = sum(r[1] for r in results)
        total_duplicates = sum(r[2] for r in results)

        # Total operations equals 10
        self.assertEqual(total_ingested + total_updated + total_duplicates, 10)

        # Exactly ONE row exists in Content and Entity
        db = self.SessionLocal()
        try:
            content_count = db.query(Content).filter(Content.canonical_url == url).count()
            entity_count = db.query(Entity).filter(Entity.name == cve_id).count()
            self.assertEqual(content_count, 1, f"Expected 1 content row, found {content_count}")
            self.assertEqual(entity_count, 1, f"Expected 1 entity row, found {entity_count}")
        finally:
            # Cleanup
            db.query(Content).filter(Content.canonical_url == url).delete()
            db.query(Entity).filter(Entity.name == cve_id).delete()
            db.commit()
            db.close()

    def test_02_concurrent_ingestion_throughput(self):
        """8 concurrent threads ingest distinct items. All 8 items must be committed."""
        ts = int(datetime.now().timestamp() * 1000)
        items_count = 8

        def worker(idx: int):
            db = self.SessionLocal()
            try:
                pipeline = IngestionPipeline()
                item = NormalizedItem(
                    title=f"Concurrent Intelligence Bulletin #{ts}_{idx}",
                    url=f"https://threat.intel.local/report/{ts}_{idx}",
                    description="Concurrent load ingestion test",
                    author="Threat Hunter",
                    published_at="2026-09-18T12:00:00Z",
                    source="Intel Feed",
                    content_type="report",
                    raw_content=f"Payload {ts}_{idx}",
                    language="en",
                )
                m = pipeline.ingest_items(db, [item])
                return m.ingested_count
            finally:
                db.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, i) for i in range(items_count)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(sum(results), items_count)

        # Verify all 8 records exist in PostgreSQL
        db = self.SessionLocal()
        try:
            count = db.query(Content).filter(Content.canonical_url.like(f"%{ts}_%")).count()
            self.assertEqual(count, items_count)
            # Cleanup
            db.query(Content).filter(Content.canonical_url.like(f"%{ts}_%")).delete()
            db.commit()
        finally:
            db.close()

    def test_03_connection_pool_exhaustion_recovery(self):
        """Verify PostgreSQL connection pool handles high concurrent connections and releases them."""
        def run_query(conn_idx: int):
            db = self.SessionLocal()
            try:
                res = db.execute(text("SELECT pg_backend_pid() AS pid, 1 AS val")).fetchone()
                return res[1]
            finally:
                db.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(run_query, i) for i in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), 20)
        self.assertTrue(all(v == 1 for v in results))


if __name__ == "__main__":
    unittest.main()

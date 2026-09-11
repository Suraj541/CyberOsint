"""
Periodic Ingestion Scheduler Test Suite
Verifies job registration, state tracking, execution error handling,
background execution, active RSS source polling, and REST API endpoints.
Conforms strictly to IMPLEMENT.md Section 10 specifications.
"""

import sys
import time
import unittest
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.source import Source
from app.workers.scheduler import (
    JobState,
    PeriodicScheduler,
    ScheduledJob,
    poll_active_rss_sources,
    scheduler,
)
from connectors.registry import connector_registry
from connectors.rss.connector import RSSConnector

SAMPLE_ADVISORY_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CERT Alert Feed</title>
    <link>https://cert-alerts.local/feed</link>
    <description>National CERT Alerts</description>
    <item>
      <title>Critical Zero-Day Vulnerability in Web Server</title>
      <link>https://cert-alerts.local/advisories/cve-2026-9999</link>
      <description>Remote code execution advisory.</description>
      <author>CERT Coordination Center</author>
      <pubDate>Mon, 01 Jul 2024 10:00:00 +0000</pubDate>
      <category>Advisory</category>
    </item>
  </channel>
</rss>
"""


class TestSchedulerServiceAndEndpoints(unittest.TestCase):
    """Test suite validating Step 9 / Section 10 Scheduler implementation."""

    @classmethod
    def setUpClass(cls):
        """Create shared in-memory SQLite database engine."""
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @event.listens_for(cls.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        cls.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=cls.engine
        )

    def setUp(self):
        """Recreate database tables and isolate scheduler instance."""
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Wire global scheduler to test database session factory
        self._orig_session_factory = scheduler.session_factory
        scheduler.session_factory = self.TestingSessionLocal

        # Isolated test scheduler with test session factory and fast check interval
        self.test_scheduler = PeriodicScheduler(
            session_factory=self.TestingSessionLocal,
            check_interval_seconds=0.05,
        )

    def tearDown(self):
        """Stop any test scheduler threads and cleanup sessions."""
        if self.test_scheduler.is_running:
            self.test_scheduler.stop(timeout=1.0)
        if scheduler.is_running:
            scheduler.stop(timeout=1.0)
        scheduler.session_factory = self._orig_session_factory
        self.db.close()
        app.dependency_overrides.clear()

    def test_default_rss_job_registered(self):
        """Confirm PeriodicScheduler registers default RSS periodic ingestion job."""
        job = self.test_scheduler.get_job("rss_periodic_ingestion")
        self.assertIsNotNone(job)
        self.assertEqual(job.state.job_id, "rss_periodic_ingestion")
        self.assertEqual(job.state.interval_seconds, 1800.0)  # 30 minutes
        self.assertTrue(job.state.is_enabled)
        self.assertEqual(job.state.last_status, "idle")

    def test_job_registration_lifecycle(self):
        """Confirm registering, pausing, resuming, and unregistering jobs."""
        dummy_run_count = 0

        def dummy_task(sched):
            nonlocal dummy_run_count
            dummy_run_count += 1
            return {"count": dummy_run_count}

        job = self.test_scheduler.register_job(
            job_id="test_dummy_job",
            name="Dummy Test Job",
            interval_seconds=60.0,
            func=dummy_task,
        )
        self.assertEqual(job.state.job_id, "test_dummy_job")
        self.assertTrue(job.state.is_enabled)

        # Pause
        self.assertTrue(self.test_scheduler.pause_job("test_dummy_job"))
        self.assertFalse(self.test_scheduler.get_job("test_dummy_job").state.is_enabled)

        # Resume
        self.assertTrue(self.test_scheduler.resume_job("test_dummy_job"))
        self.assertTrue(self.test_scheduler.get_job("test_dummy_job").state.is_enabled)

        # Execute
        res = job.execute(self.test_scheduler)
        self.assertEqual(res["count"], 1)
        self.assertEqual(job.state.run_count, 1)
        self.assertEqual(job.state.last_status, "success")
        self.assertGreater(job.state.last_duration_ms, 0.0)
        self.assertIsNotNone(job.state.last_run)
        self.assertIsNotNone(job.state.next_run)

        # Unregister
        self.assertTrue(self.test_scheduler.unregister_job("test_dummy_job"))
        self.assertIsNone(self.test_scheduler.get_job("test_dummy_job"))

    def test_job_exception_handling(self):
        """Confirm that a failing job records error status without crashing the scheduler."""
        def failing_task(sched):
            raise ValueError("Deliberate connector network timeout")

        failing_job = self.test_scheduler.register_job(
            job_id="failing_job",
            name="Failing Job",
            interval_seconds=10.0,
            func=failing_task,
        )

        # Execute should handle exception safely
        failing_job.execute(self.test_scheduler)
        self.assertEqual(failing_job.state.last_status, "error")
        self.assertIn("Deliberate connector network timeout", failing_job.state.last_error)
        self.assertFalse(failing_job.state.is_running)
        self.assertEqual(failing_job.state.run_count, 1)

    def test_poll_active_rss_sources_execution(self):
        """Confirm poll_active_rss_sources queries only active RSS sources and runs ingestion."""
        # 1. Register an active RSS source
        active_source = Source(
            name="Active CERT Alerts",
            url="https://cert-alerts.local/feed.xml",
            source_type="advisory",
            platform="rss",
            access_method="rss",
            active=True,
        )
        # 2. Register an inactive RSS source (should be skipped by scheduler)
        inactive_source = Source(
            name="Inactive Stale Source",
            url="https://stale.local/feed.xml",
            source_type="advisory",
            platform="rss",
            access_method="rss",
            active=False,
        )
        self.db.add_all([active_source, inactive_source])
        self.db.commit()

        # Configure RSS connector to return in-memory XML when this source is polled
        class CustomTestRSSConnector(RSSConnector):
            def __init__(self, source_config=None, **kwargs):
                merged_cfg = dict(source_config or {})
                merged_cfg["feed_content"] = SAMPLE_ADVISORY_FEED
                super().__init__(merged_cfg)

        conn_key = f"source_test_{active_source.id}"
        connector_registry.register(conn_key, CustomTestRSSConnector)
        active_source.access_method = conn_key
        self.db.commit()

        # Run periodic polling
        summary = poll_active_rss_sources(self.test_scheduler)

        self.assertEqual(summary["sources_checked"], 1)
        self.assertEqual(summary["total_ingested"], 1)
        self.assertEqual(summary["total_duplicates"], 0)
        self.assertEqual(summary["total_errors"], 0)

        # Verify record in DB
        stored = self.db.query(Content).filter(Content.source_id == active_source.id).all()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].title, "Critical Zero-Day Vulnerability in Web Server")

        # Verify source last_checked was updated
        self.db.refresh(active_source)
        self.assertIsNotNone(active_source.last_checked)

        # Clean up registry
        connector_registry.unregister(conn_key)

    def test_scheduler_background_thread_start_and_stop(self):
        """Confirm start() and stop() manage the background daemon loop cleanly."""
        self.assertFalse(self.test_scheduler.is_running)
        self.test_scheduler.start()
        self.assertTrue(self.test_scheduler.is_running)

        # Verify status
        status = self.test_scheduler.get_status()
        self.assertTrue(status["is_running"])
        self.assertGreaterEqual(status["total_jobs"], 1)

        self.test_scheduler.stop(timeout=1.0)
        self.assertFalse(self.test_scheduler.is_running)

    def test_scheduler_rest_api_endpoints(self):
        """Confirm /api/v1/scheduler REST endpoints for status, jobs, pause, resume, trigger."""
        # 1. GET status
        res_status = self.client.get("/api/v1/scheduler/status")
        self.assertEqual(res_status.status_code, 200)
        status_data = res_status.json()
        self.assertIn("is_running", status_data)
        self.assertIn("total_jobs", status_data)

        # 2. GET jobs
        res_jobs = self.client.get("/api/v1/scheduler/jobs")
        self.assertEqual(res_jobs.status_code, 200)
        jobs_list = res_jobs.json()
        self.assertGreaterEqual(len(jobs_list), 1)
        job_ids = [j["job_id"] for j in jobs_list]
        self.assertIn("rss_periodic_ingestion", job_ids)

        # 3. GET specific job
        res_job = self.client.get("/api/v1/scheduler/jobs/rss_periodic_ingestion")
        self.assertEqual(res_job.status_code, 200)
        self.assertEqual(res_job.json()["job_id"], "rss_periodic_ingestion")

        # 4. POST pause job
        res_pause = self.client.post("/api/v1/scheduler/jobs/rss_periodic_ingestion/pause")
        self.assertEqual(res_pause.status_code, 200)
        self.assertFalse(res_pause.json()["is_enabled"])

        # 5. POST resume job
        res_resume = self.client.post("/api/v1/scheduler/jobs/rss_periodic_ingestion/resume")
        self.assertEqual(res_resume.status_code, 200)
        self.assertTrue(res_resume.json()["is_enabled"])

        # 6. POST trigger job
        res_trigger = self.client.post("/api/v1/scheduler/jobs/rss_periodic_ingestion/trigger?async_exec=true")
        self.assertEqual(res_trigger.status_code, 200)
        self.assertEqual(res_trigger.json()["status"], "triggered")

        # 7. POST start and stop
        res_start = self.client.post("/api/v1/scheduler/start")
        self.assertEqual(res_start.status_code, 200)
        self.assertTrue(res_start.json()["is_running"])

        res_stop = self.client.post("/api/v1/scheduler/stop")
        self.assertEqual(res_stop.status_code, 200)
        self.assertFalse(res_stop.json()["is_running"])


if __name__ == "__main__":
    unittest.main()

"""
Stage 9 / Section 10: Scheduler Baseline Tests
Verifies the periodic scheduler package structure, state tracking model,
and RSS connector execution schedule required by IMPLEMENT.md Section 10.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.workers.scheduler import (
    JobState,
    PeriodicScheduler,
    ScheduledJob,
    poll_active_rss_sources,
    scheduler,
)
from workers.scheduler import scheduler as top_level_scheduler


class TestStage9SchedulerBaseline(unittest.TestCase):
    """Test suite validating Step 9 / Section 10 Scheduler implementation."""

    def test_scheduler_file_structure(self):
        """Confirm scheduler modules exist in both apps/api/app/workers and workers/."""
        self.assertTrue((api_root / "app" / "workers" / "scheduler.py").exists())
        self.assertTrue((repo_root / "workers" / "scheduler.py").exists())
        self.assertTrue((repo_root / "workers" / "__init__.py").exists())

    def test_top_level_workers_reexport(self):
        """Confirm workers.scheduler exposes the same scheduler singleton."""
        self.assertIs(scheduler, top_level_scheduler)
        self.assertIsInstance(scheduler, PeriodicScheduler)

    def test_default_rss_periodic_schedule(self):
        """
        Confirm scheduler registers the default RSS ingestion job
        with a 30-minute (1800s) schedule conforming to Section 10.
        """
        job = scheduler.get_job("rss_periodic_ingestion")
        self.assertIsNotNone(job, "rss_periodic_ingestion job must be registered by default")
        self.assertEqual(job.state.interval_seconds, 1800.0)
        self.assertTrue(job.state.is_enabled)
        self.assertEqual(job.state.last_status, "idle")
        self.assertEqual(job.state.run_count, 0)

    def test_job_state_data_model(self):
        """Confirm JobState exposes all required telemetry fields."""
        state = JobState(
            job_id="test_state",
            name="Test State Model",
            interval_seconds=300.0,
        )
        d = state.to_dict()
        self.assertEqual(d["job_id"], "test_state")
        self.assertEqual(d["interval_seconds"], 300.0)
        self.assertEqual(d["run_count"], 0)
        self.assertEqual(d["last_status"], "idle")
        self.assertFalse(d["is_running"])
        self.assertTrue(d["is_enabled"])


if __name__ == "__main__":
    unittest.main()

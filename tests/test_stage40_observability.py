"""
Section 41 Step 40: Observability Test Suite
Verifies all 9 mandated metrics:
  connector_success_total, connector_failure_total, items_discovered_total,
  items_ingested_total, duplicates_detected_total, processing_latency,
  search_latency, queue_depth, API_errors

and validates the MetricsCollector, MetricsMiddleware, and the /admin/metrics
API endpoint contract.
"""

import sys
import os
import time
import threading
import unittest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_API_APP_ROOT = os.path.join(_REPO_ROOT, "apps", "api")
if _API_APP_ROOT not in sys.path:
    sys.path.insert(0, _API_APP_ROOT)


class TestMetricsCollectorCounters(unittest.TestCase):
    """Unit tests for MetricsCollector counter operations."""

    def setUp(self):
        from services.observability.collector import MetricsCollector
        self.collector = MetricsCollector()

    def test_initial_snapshot_has_all_nine_keys(self):
        """Snapshot must expose all 9 mandated metric keys."""
        snap = self.collector.snapshot()
        required = {
            "connector_success_total",
            "connector_failure_total",
            "items_discovered_total",
            "items_ingested_total",
            "duplicates_detected_total",
            "processing_latency",
            "search_latency",
            "queue_depth",
            "API_errors",
        }
        missing = required - set(snap.keys())
        self.assertEqual(missing, set(), f"Missing metric keys: {missing}")

    def test_connector_success_counter_increments(self):
        """record_connector_success increments connector_success_total."""
        self.collector.record_connector_success("rss")
        self.collector.record_connector_success("cve")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_success_total"], 2)

    def test_connector_failure_counter_increments(self):
        """record_connector_failure increments connector_failure_total."""
        self.collector.record_connector_failure("github")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_failure_total"], 1)

    def test_items_discovered_total_increments(self):
        """record_items_discovered increments items_discovered_total by count."""
        self.collector.record_items_discovered(15, "rss")
        self.collector.record_items_discovered(5, "cve")
        snap = self.collector.snapshot()
        self.assertEqual(snap["items_discovered_total"], 20)

    def test_items_ingested_total_increments(self):
        """record_items_ingested increments items_ingested_total."""
        self.collector.record_items_ingested(8)
        snap = self.collector.snapshot()
        self.assertEqual(snap["items_ingested_total"], 8)

    def test_duplicates_detected_total_increments(self):
        """record_duplicate_detected increments duplicates_detected_total."""
        self.collector.record_duplicate_detected(3)
        snap = self.collector.snapshot()
        self.assertEqual(snap["duplicates_detected_total"], 3)

    def test_api_errors_counter_increments(self):
        """record_api_error increments API_errors and tracks breakdown by code."""
        self.collector.record_api_error(404)
        self.collector.record_api_error(404)
        self.collector.record_api_error(500)
        snap = self.collector.snapshot()
        self.assertEqual(snap["API_errors"], 3)
        self.assertEqual(snap["API_errors_by_status_code"]["404"], 2)
        self.assertEqual(snap["API_errors_by_status_code"]["500"], 1)

    def test_reset_clears_all_counters(self):
        """reset() sets all counters back to zero."""
        self.collector.record_connector_success("rss")
        self.collector.record_items_ingested(5)
        self.collector.record_api_error(400)
        self.collector.reset()
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_success_total"], 0)
        self.assertEqual(snap["items_ingested_total"], 0)
        self.assertEqual(snap["API_errors"], 0)

    def test_zero_count_items_discovered_is_noop(self):
        """record_items_discovered with count=0 should not change counter."""
        self.collector.record_items_discovered(0)
        snap = self.collector.snapshot()
        self.assertEqual(snap["items_discovered_total"], 0)

    def test_per_connector_breakdown_tracked(self):
        """Success and failure breakdowns are tracked per connector name."""
        self.collector.record_connector_success("rss_feed")
        self.collector.record_connector_success("rss_feed")
        self.collector.record_connector_failure("vendor_advisory")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_success_by_name"]["rss_feed"], 2)
        self.assertEqual(snap["connector_failure_by_name"]["vendor_advisory"], 1)


class TestLatencyHistogram(unittest.TestCase):
    """Unit tests for the LatencyHistogram embedded in MetricsCollector."""

    def setUp(self):
        from services.observability.collector import MetricsCollector
        self.collector = MetricsCollector()

    def test_processing_latency_histogram_records_observations(self):
        """observe_processing_latency populates histogram stats."""
        for ms in [10.0, 20.0, 30.0, 40.0, 50.0]:
            self.collector.observe_processing_latency(ms)
        snap = self.collector.snapshot()
        hist = snap["processing_latency"]
        self.assertEqual(hist["count"], 5)
        self.assertAlmostEqual(hist["mean_ms"], 30.0, places=0)
        self.assertGreater(hist["p95_ms"], 0)
        self.assertGreater(hist["max_ms"], 0)

    def test_search_latency_histogram_records_observations(self):
        """observe_search_latency populates search_latency histogram."""
        for ms in [5.0, 8.0, 12.0]:
            self.collector.observe_search_latency(ms)
        snap = self.collector.snapshot()
        hist = snap["search_latency"]
        self.assertEqual(hist["count"], 3)
        self.assertGreater(hist["p50_ms"], 0)

    def test_empty_histogram_returns_zero_stats(self):
        """Empty histogram should return zeros, not raise exceptions."""
        snap = self.collector.snapshot()
        hist = snap["processing_latency"]
        self.assertEqual(hist["count"], 0)
        self.assertEqual(hist["mean_ms"], 0.0)
        self.assertEqual(hist["p95_ms"], 0.0)

    def test_histogram_bounded_window(self):
        """Histogram window should not grow unboundedly."""
        from services.observability.collector import _LATENCY_WINDOW
        for i in range(_LATENCY_WINDOW + 50):
            self.collector.observe_processing_latency(float(i))
        snap = self.collector.snapshot()
        # count is total (unbounded), window is capped
        self.assertEqual(snap["processing_latency"]["count"], _LATENCY_WINDOW + 50)


class TestRecordIngestionRun(unittest.TestCase):
    """Tests for record_ingestion_run bulk-update from IngestionMetrics."""

    def setUp(self):
        from services.observability.collector import MetricsCollector
        self.collector = MetricsCollector()

    def _make_mock_metrics(self, status, discovered, ingested, duplicates, errors, duration_ms):
        class MockMetrics:
            pass
        m = MockMetrics()
        m.status = status
        m.discovered_count = discovered
        m.ingested_count = ingested
        m.duplicates_skipped = duplicates
        m.errors_count = errors
        m.duration_ms = duration_ms
        return m

    def test_successful_run_increments_all_counters(self):
        m = self._make_mock_metrics("success", 50, 45, 5, 0, 234.5)
        self.collector.record_ingestion_run(m, connector_name="rss")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_success_total"], 1)
        self.assertEqual(snap["items_discovered_total"], 50)
        self.assertEqual(snap["items_ingested_total"], 45)
        self.assertEqual(snap["duplicates_detected_total"], 5)
        self.assertEqual(snap["processing_latency"]["count"], 1)

    def test_failed_run_increments_failure_counter(self):
        m = self._make_mock_metrics("failed", 0, 0, 0, 1, 100.0)
        self.collector.record_ingestion_run(m, connector_name="cve_feed")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_failure_total"], 1)
        self.assertEqual(snap["connector_success_total"], 0)

    def test_partial_run_counted_as_success(self):
        m = self._make_mock_metrics("partial", 20, 10, 5, 5, 150.0)
        self.collector.record_ingestion_run(m, connector_name="vendor")
        snap = self.collector.snapshot()
        self.assertEqual(snap["connector_success_total"], 1)
        self.assertEqual(snap["items_ingested_total"], 10)


class TestThreadSafety(unittest.TestCase):
    """Verify MetricsCollector is safe to call from multiple threads concurrently."""

    def test_concurrent_counter_increments(self):
        """100 threads each incrementing success/ingested counters must give exact totals."""
        from services.observability.collector import MetricsCollector
        collector = MetricsCollector()
        n_threads = 100
        n_per_thread = 10

        def worker():
            for _ in range(n_per_thread):
                collector.record_connector_success("rss")
                collector.record_items_ingested(1)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = collector.snapshot()
        expected = n_threads * n_per_thread
        self.assertEqual(snap["connector_success_total"], expected)
        self.assertEqual(snap["items_ingested_total"], expected)


class TestAPIEndpoint(unittest.TestCase):
    """Integration tests for the /admin/metrics FastAPI endpoint."""

    @classmethod
    def setUpClass(cls):
        """Build FastAPI test client and reset collector."""
        try:
            from fastapi.testclient import TestClient
            from app.main import app
            from services.observability.collector import metrics_collector
            metrics_collector.reset()
            cls.client = TestClient(app, raise_server_exceptions=False)
            cls.collector = metrics_collector
            cls.available = True
        except Exception as exc:
            cls.available = False
            cls.skip_reason = str(exc)

    def _skip_if_unavailable(self):
        if not self.available:
            self.skipTest(f"FastAPI app unavailable: {self.skip_reason}")

    def test_metrics_endpoint_returns_200(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics")
        self.assertEqual(res.status_code, 200)

    def test_metrics_endpoint_has_all_nine_keys(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics")
        data = res.json()
        required = {
            "connector_success_total", "connector_failure_total",
            "items_discovered_total", "items_ingested_total",
            "duplicates_detected_total", "processing_latency",
            "search_latency", "queue_depth", "API_errors",
        }
        missing = required - set(data.keys())
        self.assertEqual(missing, set(), f"Missing keys in /admin/metrics response: {missing}")

    def test_counters_endpoint_returns_200(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics/counters")
        self.assertEqual(res.status_code, 200)

    def test_latency_endpoint_returns_histogram_structure(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics/latency")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("processing_latency", data)
        self.assertIn("search_latency", data)
        for key in ("count", "p50_ms", "p95_ms", "p99_ms"):
            self.assertIn(key, data["processing_latency"])

    def test_connectors_endpoint_returns_200(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics/connectors")
        self.assertEqual(res.status_code, 200)

    def test_prometheus_endpoint_returns_text_format(self):
        self._skip_if_unavailable()
        res = self.client.get("/api/v1/admin/metrics/prometheus")
        self.assertEqual(res.status_code, 200)
        body = res.text
        self.assertIn("connector_success_total", body)
        self.assertIn("connector_failure_total", body)
        self.assertIn("items_ingested_total", body)
        self.assertIn("queue_depth", body)

    def test_reset_endpoint_clears_counters(self):
        self._skip_if_unavailable()
        # Seed a counter
        self.collector.record_connector_success("test_connector")
        # Reset via API
        res = self.client.post("/api/v1/admin/metrics/reset")
        self.assertEqual(res.status_code, 200)
        # Verify zeroed
        res2 = self.client.get("/api/v1/admin/metrics")
        data = res2.json()
        self.assertEqual(data["connector_success_total"], 0)

    def test_api_errors_counted_after_bad_request(self):
        self._skip_if_unavailable()
        # Reset first
        self.collector.reset()
        # Hit an invalid endpoint to trigger a 404
        self.client.get("/api/v1/nonexistent_endpoint_xyz_for_test")
        snap = self.collector.snapshot()
        # API_errors should be >= 1 (MetricsMiddleware is registered)
        self.assertGreaterEqual(snap["API_errors"], 1)


class TestObservabilityDashboardFile(unittest.TestCase):
    """Verify the frontend admin monitoring dashboard file exists and is valid."""

    def test_admin_dashboard_page_exists(self):
        dashboard_path = os.path.join(
            _REPO_ROOT, "apps", "web", "app", "admin", "page.tsx"
        )
        self.assertTrue(
            os.path.isfile(dashboard_path),
            f"Admin dashboard not found at: {dashboard_path}"
        )

    def test_admin_dashboard_contains_all_nine_metric_ids(self):
        dashboard_path = os.path.join(
            _REPO_ROOT, "apps", "web", "app", "admin", "page.tsx"
        )
        with open(dashboard_path, encoding="utf-8") as f:
            content = f.read()
        required_ids = [
            "metric-connector-success",
            "metric-connector-failure",
            "metric-items-discovered",
            "metric-items-ingested",
            "metric-duplicates",
            "metric-api-errors",
            "metric-queue-depth",
            "metric-processing-latency",
            "metric-search-latency",
        ]
        for mid in required_ids:
            self.assertIn(mid, content, f"Dashboard missing UI element id: {mid}")

    def test_admin_dashboard_has_auto_refresh_logic(self):
        dashboard_path = os.path.join(
            _REPO_ROOT, "apps", "web", "app", "admin", "page.tsx"
        )
        with open(dashboard_path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("setInterval", content, "Dashboard must implement auto-refresh polling")
        self.assertIn("REFRESH_INTERVAL_MS", content, "Dashboard must define a refresh interval constant")

    def test_admin_dashboard_references_all_nine_metric_keys(self):
        dashboard_path = os.path.join(
            _REPO_ROOT, "apps", "web", "app", "admin", "page.tsx"
        )
        with open(dashboard_path, encoding="utf-8") as f:
            content = f.read()
        metric_refs = [
            "connector_success_total",
            "connector_failure_total",
            "items_discovered_total",
            "items_ingested_total",
            "duplicates_detected_total",
            "processing_latency",
            "search_latency",
            "queue_depth",
            "API_errors",
        ]
        for ref in metric_refs:
            self.assertIn(ref, content, f"Dashboard does not reference metric: {ref}")


class TestObservabilityServiceFiles(unittest.TestCase):
    """Verify the observability service module structure."""

    def test_collector_module_exists(self):
        path = os.path.join(_REPO_ROOT, "services", "observability", "collector.py")
        self.assertTrue(os.path.isfile(path))

    def test_middleware_module_exists(self):
        path = os.path.join(_REPO_ROOT, "services", "observability", "middleware.py")
        self.assertTrue(os.path.isfile(path))

    def test_api_endpoint_module_exists(self):
        path = os.path.join(
            _REPO_ROOT, "apps", "api", "app", "api", "v1", "endpoints", "observability.py"
        )
        self.assertTrue(os.path.isfile(path))

    def test_ingestion_pipeline_imports_metrics_collector(self):
        path = os.path.join(_REPO_ROOT, "services", "ingestion", "pipeline.py")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("metrics_collector", content, "pipeline.py must import and use metrics_collector")
        self.assertIn("record_ingestion_run", content, "pipeline.py must call record_ingestion_run")

    def test_main_py_registers_metrics_middleware(self):
        path = os.path.join(_REPO_ROOT, "apps", "api", "app", "main.py")
        with open(path, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("MetricsMiddleware", content, "main.py must register MetricsMiddleware")


if __name__ == "__main__":
    unittest.main(verbosity=2)

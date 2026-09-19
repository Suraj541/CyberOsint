"""
Platform Metrics Collector — Section 41 (Step 40): Observability
Tracks all 9 mandated counters and gauges:
  - connector_success_total
  - connector_failure_total
  - items_discovered_total
  - items_ingested_total
  - duplicates_detected_total
  - processing_latency   (histogram: sum / count / p95 approximation)
  - search_latency       (histogram: sum / count / p95 approximation)
  - queue_depth          (gauge, read live from queue)
  - API_errors           (counter, incremented by middleware)

All state is kept in-process (thread-safe, no external deps).
An optional Redis sync can be added later for multi-worker deployments.
"""

import logging
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("cyber_osint.observability")

# Sliding window length for latency samples (last N observations per metric)
_LATENCY_WINDOW = 1000


@dataclass
class LatencyHistogram:
    """
    Lightweight latency recorder.
    Keeps a bounded sliding window of observation values (ms).
    Exposes count, sum, mean, p50, p95, p99, max.
    """

    name: str
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _samples: Deque[float] = field(default_factory=lambda: deque(maxlen=_LATENCY_WINDOW), init=False, repr=False)
    _total_count: int = field(default=0, init=False)
    _total_sum_ms: float = field(default=0.0, init=False)

    def observe(self, latency_ms: float) -> None:
        """Record one latency observation."""
        with self._lock:
            self._samples.append(latency_ms)
            self._total_count += 1
            self._total_sum_ms += latency_ms

    def snapshot(self) -> Dict[str, Any]:
        """Return a snapshot of the current latency statistics."""
        with self._lock:
            count = self._total_count
            total_ms = self._total_sum_ms
            window = list(self._samples)

        if not window:
            return {
                "count": count,
                "sum_ms": round(total_ms, 3),
                "mean_ms": 0.0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "max_ms": 0.0,
            }

        sorted_w = sorted(window)
        n = len(sorted_w)

        def _pct(p: float) -> float:
            idx = max(0, int(n * p / 100) - 1)
            return round(sorted_w[idx], 3)

        return {
            "count": count,
            "sum_ms": round(total_ms, 3),
            "mean_ms": round(statistics.mean(window), 3),
            "p50_ms": _pct(50),
            "p95_ms": _pct(95),
            "p99_ms": _pct(99),
            "max_ms": round(max(window), 3),
        }


class MetricsCollector:
    """
    Thread-safe, singleton metrics registry for the OSINT platform.

    Counters (monotonically increasing integers):
      connector_success_total      — successful connector runs
      connector_failure_total      — failed connector runs (discovery or storage errors)
      items_discovered_total       — raw items returned from connectors
      items_ingested_total         — items persisted to the database
      duplicates_detected_total    — items rejected by the deduplication engine
      API_errors                   — HTTP 4xx/5xx responses counted by middleware

    Histograms (sliding window latency):
      processing_latency           — end-to-end ingestion pipeline duration (ms)
      search_latency               — search request round-trip duration (ms)

    Gauge (live-read):
      queue_depth                  — pulled live from Redis task queue on demand
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # ---- Counters -------------------------------------------------------
        self._counters: Dict[str, int] = defaultdict(int)

        # ---- Histograms ------------------------------------------------------
        self._processing_latency = LatencyHistogram(name="processing_latency")
        self._search_latency = LatencyHistogram(name="search_latency")

        # ---- Per-connector breakdown ----------------------------------------
        self._connector_success: Dict[str, int] = defaultdict(int)
        self._connector_failure: Dict[str, int] = defaultdict(int)

        # ---- API error breakdown by status code ----------------------------
        self._api_errors_by_code: Dict[int, int] = defaultdict(int)

        # ---- Start time ------------------------------------------------------
        self._started_at: datetime = datetime.now(timezone.utc)

        logger.info("MetricsCollector initialized (Section 41 Step 40)")

    # ------------------------------------------------------------------
    # Public counter methods
    # ------------------------------------------------------------------

    def record_connector_success(self, connector_name: str = "unknown") -> None:
        """Increment connector_success_total and per-connector counter."""
        with self._lock:
            self._counters["connector_success_total"] += 1
            self._connector_success[connector_name] += 1

    def record_connector_failure(self, connector_name: str = "unknown") -> None:
        """Increment connector_failure_total and per-connector failure counter."""
        with self._lock:
            self._counters["connector_failure_total"] += 1
            self._connector_failure[connector_name] += 1

    def record_items_discovered(self, count: int, connector_name: str = "unknown") -> None:
        """Increment items_discovered_total by count."""
        if count <= 0:
            return
        with self._lock:
            self._counters["items_discovered_total"] += count

    def record_items_ingested(self, count: int) -> None:
        """Increment items_ingested_total by count."""
        if count <= 0:
            return
        with self._lock:
            self._counters["items_ingested_total"] += count

    def record_duplicate_detected(self, count: int = 1) -> None:
        """Increment duplicates_detected_total."""
        with self._lock:
            self._counters["duplicates_detected_total"] += count

    def record_api_error(self, status_code: int) -> None:
        """Increment API_errors and track breakdown by HTTP status code."""
        with self._lock:
            self._counters["API_errors"] += 1
            self._api_errors_by_code[status_code] += 1

    # ------------------------------------------------------------------
    # Histogram recording methods
    # ------------------------------------------------------------------

    def observe_processing_latency(self, latency_ms: float) -> None:
        """Record one ingestion pipeline duration observation."""
        self._processing_latency.observe(latency_ms)

    def observe_search_latency(self, latency_ms: float) -> None:
        """Record one search request round-trip latency observation."""
        self._search_latency.observe(latency_ms)

    # ------------------------------------------------------------------
    # Convenience: record a full ingestion pipeline run from metrics obj
    # ------------------------------------------------------------------

    def record_ingestion_run(self, ingestion_metrics: Any, connector_name: str = "unknown") -> None:
        """
        Bulk-update all counters from a completed IngestionMetrics object.
        Call this at the end of each connector execution.
        """
        try:
            status = getattr(ingestion_metrics, "status", "unknown")
            if status in ("success", "partial"):
                self.record_connector_success(connector_name)
            elif status == "failed":
                self.record_connector_failure(connector_name)

            discovered = getattr(ingestion_metrics, "discovered_count", 0)
            self.record_items_discovered(discovered, connector_name)

            ingested = getattr(ingestion_metrics, "ingested_count", 0)
            self.record_items_ingested(ingested)

            duplicates = getattr(ingestion_metrics, "duplicates_skipped", 0)
            self.record_duplicate_detected(duplicates)

            duration_ms = getattr(ingestion_metrics, "duration_ms", 0.0)
            if duration_ms > 0:
                self.observe_processing_latency(duration_ms)
        except Exception as exc:
            logger.debug("Metrics record_ingestion_run error: %s", exc)

    # ------------------------------------------------------------------
    # Gauge: queue_depth  (resolved lazily to avoid circular imports)
    # ------------------------------------------------------------------

    def get_queue_depth(self, queue_name: str = "ingestion") -> int:
        """Live queue depth gauge — queries Redis TaskQueue."""
        try:
            from services.queue.queue_service import task_queue
            return task_queue.get_queue_length(queue_name)
        except Exception:
            return -1

    # ------------------------------------------------------------------
    # Snapshot / reporting
    # ------------------------------------------------------------------

    def snapshot(self, queue_name: str = "ingestion") -> Dict[str, Any]:
        """
        Return a complete observability snapshot.
        Suitable for the /metrics or /admin/metrics API endpoint.
        """
        with self._lock:
            counters_snapshot = dict(self._counters)
            connector_success_snapshot = dict(self._connector_success)
            connector_failure_snapshot = dict(self._connector_failure)
            api_errors_by_code_snapshot = {str(k): v for k, v in self._api_errors_by_code.items()}

        queue_depth = self.get_queue_depth(queue_name)

        return {
            # --- mandated counters ---
            "connector_success_total": counters_snapshot.get("connector_success_total", 0),
            "connector_failure_total": counters_snapshot.get("connector_failure_total", 0),
            "items_discovered_total": counters_snapshot.get("items_discovered_total", 0),
            "items_ingested_total": counters_snapshot.get("items_ingested_total", 0),
            "duplicates_detected_total": counters_snapshot.get("duplicates_detected_total", 0),
            "API_errors": counters_snapshot.get("API_errors", 0),
            # --- mandated gauges ---
            "queue_depth": queue_depth,
            # --- mandated histograms ---
            "processing_latency": self._processing_latency.snapshot(),
            "search_latency": self._search_latency.snapshot(),
            # --- breakdowns (extra diagnostic context) ---
            "connector_success_by_name": connector_success_snapshot,
            "connector_failure_by_name": connector_failure_snapshot,
            "API_errors_by_status_code": api_errors_by_code_snapshot,
            # --- metadata ---
            "collector_started_at": self._started_at.isoformat(),
            "snapshot_at": datetime.now(timezone.utc).isoformat(),
        }

    def reset(self) -> None:
        """
        Reset all counters and histograms (useful between test runs).
        Does NOT reset the collector started_at timestamp.
        """
        with self._lock:
            self._counters.clear()
            self._connector_success.clear()
            self._connector_failure.clear()
            self._api_errors_by_code.clear()
        self._processing_latency = LatencyHistogram(name="processing_latency")
        self._search_latency = LatencyHistogram(name="search_latency")
        logger.debug("MetricsCollector reset.")


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
metrics_collector = MetricsCollector()

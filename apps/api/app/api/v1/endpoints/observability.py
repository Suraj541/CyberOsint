"""
Observability & Platform Metrics API Endpoints — Section 41 (Step 40)

Exposes the 9 mandated platform metrics:
  connector_success_total, connector_failure_total, items_discovered_total,
  items_ingested_total, duplicates_detected_total, processing_latency,
  search_latency, queue_depth, API_errors

Also provides per-connector breakdowns, histogram statistics, and Prometheus-compatible
text format at GET /admin/metrics/prometheus for integration with Grafana / alerting.
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Query, status
from fastapi.responses import PlainTextResponse

from services.observability.collector import metrics_collector

logger = logging.getLogger("cyber_osint.api.observability")

router = APIRouter(prefix="/admin", tags=["Admin Observability"])


# ---------------------------------------------------------------------------
# GET /admin/metrics — Full JSON snapshot
# ---------------------------------------------------------------------------

@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    summary="Platform Metrics Snapshot",
    description=(
        "Returns a full JSON snapshot of all 9 mandated platform observability metrics: "
        "connector_success_total, connector_failure_total, items_discovered_total, "
        "items_ingested_total, duplicates_detected_total, processing_latency, "
        "search_latency, queue_depth, and API_errors."
    ),
)
def get_metrics_snapshot(queue_name: str = Query(default="ingestion", description="Queue name for depth gauge")):
    """Return all platform metrics as a structured JSON object."""
    return metrics_collector.snapshot(queue_name=queue_name)


# ---------------------------------------------------------------------------
# GET /admin/metrics/counters — Counters only (lightweight polling)
# ---------------------------------------------------------------------------

@router.get(
    "/metrics/counters",
    status_code=status.HTTP_200_OK,
    summary="Platform Counters (lightweight)",
    description="Returns only the monotonic counter values for fast dashboard polling.",
)
def get_metric_counters(queue_name: str = Query(default="ingestion")):
    """Return all counters and the live queue depth gauge."""
    snap = metrics_collector.snapshot(queue_name=queue_name)
    return {
        "connector_success_total": snap["connector_success_total"],
        "connector_failure_total": snap["connector_failure_total"],
        "items_discovered_total": snap["items_discovered_total"],
        "items_ingested_total": snap["items_ingested_total"],
        "duplicates_detected_total": snap["duplicates_detected_total"],
        "API_errors": snap["API_errors"],
        "queue_depth": snap["queue_depth"],
        "snapshot_at": snap["snapshot_at"],
    }


# ---------------------------------------------------------------------------
# GET /admin/metrics/latency — Histogram details
# ---------------------------------------------------------------------------

@router.get(
    "/metrics/latency",
    status_code=status.HTTP_200_OK,
    summary="Latency Histograms",
    description="Returns processing_latency and search_latency histograms with p50/p95/p99 statistics.",
)
def get_metric_latency():
    """Return histogram snapshots for processing and search latency."""
    snap = metrics_collector.snapshot()
    return {
        "processing_latency": snap["processing_latency"],
        "search_latency": snap["search_latency"],
        "snapshot_at": snap["snapshot_at"],
    }


# ---------------------------------------------------------------------------
# GET /admin/metrics/connectors — Per-connector breakdown
# ---------------------------------------------------------------------------

@router.get(
    "/metrics/connectors",
    status_code=status.HTTP_200_OK,
    summary="Per-Connector Metrics",
    description="Returns success and failure counts broken down by connector name.",
)
def get_metric_connectors():
    """Return per-connector success/failure breakdown."""
    snap = metrics_collector.snapshot()
    return {
        "connector_success_total": snap["connector_success_total"],
        "connector_failure_total": snap["connector_failure_total"],
        "by_connector": {
            name: {
                "success": snap["connector_success_by_name"].get(name, 0),
                "failure": snap["connector_failure_by_name"].get(name, 0),
            }
            for name in set(
                list(snap["connector_success_by_name"].keys())
                + list(snap["connector_failure_by_name"].keys())
            )
        },
        "snapshot_at": snap["snapshot_at"],
    }


# ---------------------------------------------------------------------------
# GET /admin/metrics/prometheus — Prometheus text format
# ---------------------------------------------------------------------------

@router.get(
    "/metrics/prometheus",
    status_code=status.HTTP_200_OK,
    summary="Prometheus Text Format Metrics",
    description=(
        "Returns all platform metrics in Prometheus text exposition format "
        "for scraping by Prometheus/Grafana."
    ),
    response_class=PlainTextResponse,
)
def get_metrics_prometheus(queue_name: str = Query(default="ingestion")):
    """Expose metrics in Prometheus text format for external scraping."""
    from fastapi.responses import PlainTextResponse

    snap = metrics_collector.snapshot(queue_name=queue_name)
    proc = snap["processing_latency"]
    srch = snap["search_latency"]

    lines = [
        "# HELP connector_success_total Total number of successful connector runs",
        "# TYPE connector_success_total counter",
        f"connector_success_total {snap['connector_success_total']}",
        "",
        "# HELP connector_failure_total Total number of failed connector runs",
        "# TYPE connector_failure_total counter",
        f"connector_failure_total {snap['connector_failure_total']}",
        "",
        "# HELP items_discovered_total Total raw items returned from connectors",
        "# TYPE items_discovered_total counter",
        f"items_discovered_total {snap['items_discovered_total']}",
        "",
        "# HELP items_ingested_total Total items persisted to database",
        "# TYPE items_ingested_total counter",
        f"items_ingested_total {snap['items_ingested_total']}",
        "",
        "# HELP duplicates_detected_total Total items rejected by deduplication engine",
        "# TYPE duplicates_detected_total counter",
        f"duplicates_detected_total {snap['duplicates_detected_total']}",
        "",
        "# HELP api_errors_total Total HTTP 4xx/5xx error responses",
        "# TYPE api_errors_total counter",
        f"api_errors_total {snap['API_errors']}",
        "",
        "# HELP queue_depth Current depth of the ingestion task queue",
        "# TYPE queue_depth gauge",
        f"queue_depth {snap['queue_depth']}",
        "",
        "# HELP processing_latency_ms_sum Sum of all ingestion pipeline durations (ms)",
        "# TYPE processing_latency_ms_sum counter",
        f"processing_latency_ms_sum {proc['sum_ms']}",
        "",
        "# HELP processing_latency_ms_count Number of ingestion pipeline observations",
        "# TYPE processing_latency_ms_count counter",
        f"processing_latency_ms_count {proc['count']}",
        "",
        "# HELP search_latency_ms_sum Sum of all search request durations (ms)",
        "# TYPE search_latency_ms_sum counter",
        f"search_latency_ms_sum {srch['sum_ms']}",
        "",
        "# HELP search_latency_ms_count Number of search latency observations",
        "# TYPE search_latency_ms_count counter",
        f"search_latency_ms_count {srch['count']}",
        "",
    ]

    # Per-connector success
    for name, val in snap["connector_success_by_name"].items():
        safe_name = name.replace(" ", "_").replace("-", "_").lower()
        lines.append(f'connector_success_total{{connector="{safe_name}"}} {val}')

    # Per-connector failure
    for name, val in snap["connector_failure_by_name"].items():
        safe_name = name.replace(" ", "_").replace("-", "_").lower()
        lines.append(f'connector_failure_total{{connector="{safe_name}"}} {val}')

    return PlainTextResponse(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------------------
# POST /admin/metrics/reset — Development/testing utility
# ---------------------------------------------------------------------------

@router.post(
    "/metrics/reset",
    status_code=status.HTTP_200_OK,
    summary="Reset Metrics Counters (Dev/Test Only)",
    description="Resets all counters and histogram observations. Intended for development and test environments.",
)
def reset_metrics():
    """Reset all platform metrics to zero."""
    metrics_collector.reset()
    return {
        "status": "reset",
        "message": "All metrics counters and histograms have been reset.",
        "reset_at": datetime.now(timezone.utc).isoformat(),
    }

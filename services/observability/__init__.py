"""
Observability & Metrics Collection Service
Tracks platform-wide counters, gauges, and latency histograms for IMPLEMENT.md Section 41.
"""

from .collector import MetricsCollector, metrics_collector
from .middleware import MetricsMiddleware

__all__ = ["MetricsCollector", "metrics_collector", "MetricsMiddleware"]

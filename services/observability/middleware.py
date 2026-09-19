"""
Observability Middleware — API Error Counter
Counts all HTTP 4xx and 5xx responses and records them into the MetricsCollector.
Wraps every FastAPI request and records search_latency when the path matches /search.
"""

import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("cyber_osint.observability.middleware")

_SEARCH_PATH_FRAGMENTS = ("/search", "/semantic")


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that hooks into every HTTP request/response cycle to:
      1. Increment API_errors counter for any HTTP 4xx or 5xx response.
      2. Record search_latency histogram observation for search-related endpoints.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response: Response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        status_code = response.status_code
        path = request.url.path

        # --- Import lazily to avoid circular module load at import time ---
        try:
            from services.observability.collector import metrics_collector

            # Count API errors (4xx and 5xx)
            if status_code >= 400:
                metrics_collector.record_api_error(status_code)

            # Observe search latency for search endpoints
            if any(frag in path for frag in _SEARCH_PATH_FRAGMENTS):
                metrics_collector.observe_search_latency(elapsed_ms)

        except Exception as exc:
            logger.debug("MetricsMiddleware observation error: %s", exc)

        return response

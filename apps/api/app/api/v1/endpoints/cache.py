"""
Cache API Endpoints
Provides diagnostic and administrative access to the Redis cache / fallback store.
Conforms strictly to IMPLEMENT.md Section 11.
"""

import time
from fastapi import APIRouter, HTTPException, status

from app.config import settings
from app.schemas.cache import CacheHealthResponse
from services.cache.client import redis_client

router = APIRouter(prefix="/cache", tags=["Cache"])


@router.get(
    "/health",
    response_model=CacheHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Cache Health Status",
)
def get_cache_health() -> CacheHealthResponse:
    """Check connectivity to Redis service and return active backend status."""
    is_live = redis_client.is_connected
    ping_latency: float | None = None

    if is_live:
        start = time.perf_counter()
        if redis_client.ping():
            ping_latency = round((time.perf_counter() - start) * 1000, 2)
        else:
            is_live = False

    return CacheHealthResponse(
        status="connected" if is_live else "in_memory_fallback",
        redis_url=settings.REDIS_URL,
        is_live=is_live,
        ping_latency_ms=ping_latency,
    )


@router.get(
    "/{key}",
    status_code=status.HTTP_200_OK,
    summary="Get Cached Value",
)
def get_cache_key(key: str) -> dict:
    """Retrieve raw value stored under a specific cache key."""
    val = redis_client.get(key)
    if val is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key '{key}' not found in cache",
        )
    return {"key": key, "value": val}


@router.delete(
    "/{key}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Cache Key",
)
def delete_cache_key(key: str) -> None:
    """Remove a key from the cache."""
    redis_client.delete(key)

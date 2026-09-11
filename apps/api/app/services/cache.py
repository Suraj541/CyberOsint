"""
Cache Service Layer Adapter
Exposes Redis client, caching helpers, and rate limiting to the API layer.
"""

from services.cache import (
    CacheService,
    InMemoryCacheBackend,
    RateLimitDependency,
    RateLimiter,
    RedisClient,
    cache_service,
    cached,
    rate_limiter,
    redis_client,
)

__all__ = [
    "RedisClient",
    "redis_client",
    "InMemoryCacheBackend",
    "CacheService",
    "cache_service",
    "cached",
    "RateLimiter",
    "rate_limiter",
    "RateLimitDependency",
]

"""
Response & Content Caching Service
Provides high-performance JSON caching, key generation, and cache invalidation.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

import functools
import hashlib
import json
import logging
from typing import Any, Callable, Dict, Optional

from services.cache.client import RedisClient, redis_client

logger = logging.getLogger("cyber_osint.services.cache.cache_service")


class CacheService:
    """Service providing structured caching for API responses and normalized content."""

    def __init__(self, client: Optional[RedisClient] = None):
        self.client = client or redis_client

    def make_key(self, prefix: str, *parts: Any) -> str:
        """Construct deterministic cache key from prefix and arguments."""
        clean_parts = [str(p).strip() for p in parts if p is not None]
        return f"{prefix}:{':'.join(clean_parts)}"

    def get_json(self, key: str) -> Optional[Any]:
        """Fetch and deserialize JSON object from cache."""
        raw = self.client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception as exc:
            logger.warning("Failed to deserialize cached JSON for key '%s': %s", key, exc)
            return None

    def set_json(self, key: str, data: Any, ttl_seconds: int = 300) -> bool:
        """Serialize and store object as JSON in cache with TTL."""
        try:
            serialized = json.dumps(data, default=str)
            return self.client.set(key, serialized, ex=ttl_seconds)
        except Exception as exc:
            logger.warning("Failed to serialize data for cache key '%s': %s", key, exc)
            return False

    def delete(self, key: str) -> bool:
        """Delete specific key from cache."""
        return self.client.delete(key)

    def cache_content(self, content_id: int, payload: Dict[str, Any], ttl_seconds: int = 3600) -> bool:
        """Cache full normalized content dictionary."""
        key = self.make_key("content", content_id)
        return self.set_json(key, payload, ttl_seconds=ttl_seconds)

    def get_cached_content(self, content_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve cached content by ID."""
        key = self.make_key("content", content_id)
        return self.get_json(key)


def cached(prefix: str, ttl_seconds: int = 300):
    """
    Decorator for caching function return values using CacheService.
    Computes key based on prefix and function arguments.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Compute cache key from arguments
            arg_str = json.dumps({"args": [str(a) for a in args], "kwargs": kwargs}, sort_keys=True, default=str)
            arg_hash = hashlib.sha256(arg_str.encode("utf-8")).hexdigest()[:16]
            key = f"{prefix}:{func.__name__}:{arg_hash}"

            cache = CacheService()
            cached_val = cache.get_json(key)
            if cached_val is not None:
                return cached_val

            result = func(*args, **kwargs)
            cache.set_json(key, result, ttl_seconds=ttl_seconds)
            return result

        return wrapper

    return decorator


# Global singleton instance
cache_service = CacheService()

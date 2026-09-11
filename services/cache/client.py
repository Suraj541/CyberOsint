"""
Redis Client Wrapper with In-Memory Graceful Fallback
Provides a unified key-value and list interface connected to Redis (redis://localhost:6379/0)
with an automatic thread-safe in-memory fallback for offline test environments.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import redis

from app.config import settings

logger = logging.getLogger("cyber_osint.services.cache")


class InMemoryCacheBackend:
    """
    Thread-safe in-memory key-value and list storage with TTL support.
    Employed automatically when Redis is offline or unreachable.
    """

    def __init__(self):
        self._kv: Dict[str, Tuple[str, Optional[float]]] = {}
        self._lists: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def _is_expired(self, key: str) -> bool:
        if key not in self._kv:
            return True
        _, exp = self._kv[key]
        if exp is not None and time.time() > exp:
            del self._kv[key]
            return True
        return False

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if self._is_expired(key):
                return None
            val, _ = self._kv[key]
            return val

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        with self._lock:
            expiry = (time.time() + ex) if ex is not None else None
            self._kv[key] = (str(value), expiry)
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            existed = False
            if key in self._kv:
                del self._kv[key]
                existed = True
            if key in self._lists:
                del self._lists[key]
                existed = True
            return existed

    def exists(self, key: str) -> bool:
        with self._lock:
            if key in self._lists:
                return True
            return not self._is_expired(key)

    def expire(self, key: str, seconds: int) -> bool:
        with self._lock:
            if self._is_expired(key):
                return False
            val, _ = self._kv[key]
            self._kv[key] = (val, time.time() + seconds)
            return True

    def incr(self, key: str, amount: int = 1) -> int:
        with self._lock:
            if self._is_expired(key):
                new_val = amount
            else:
                current_val, exp = self._kv[key]
                try:
                    new_val = int(current_val) + amount
                except ValueError:
                    new_val = amount
                expiry = exp
            self._kv[key] = (str(new_val), None if self._is_expired(key) else self._kv.get(key, (None, None))[1])
            return new_val

    def lpush(self, key: str, *values: str) -> int:
        with self._lock:
            if key not in self._lists:
                self._lists[key] = []
            for v in values:
                self._lists[key].insert(0, str(v))
            return len(self._lists[key])

    def rpop(self, key: str) -> Optional[str]:
        with self._lock:
            if key not in self._lists or not self._lists[key]:
                return None
            return self._lists[key].pop()

    def llen(self, key: str) -> int:
        with self._lock:
            return len(self._lists.get(key, []))

    def flush(self) -> None:
        with self._lock:
            self._kv.clear()
            self._lists.clear()


class RedisClient:
    """
    Client managing connection to Redis service with transparent in-memory fallback.
    Exposes strings, lists, counters, and TTL capabilities.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._memory_fallback = InMemoryCacheBackend()
        self._redis: Optional[redis.Redis] = None
        self._is_live = False
        self._check_connection()

    def _check_connection(self) -> bool:
        """Attempt ping to Redis server. Fallback to memory on failure."""
        try:
            client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
            )
            client.ping()
            self._redis = client
            self._is_live = True
            logger.info("Connected successfully to live Redis at %s", self.redis_url)
            return True
        except Exception as exc:
            self._is_live = False
            self._redis = None
            logger.debug(
                "Redis connection to %s failed (%s). Using thread-safe in-memory fallback.",
                self.redis_url,
                exc,
            )
            return False

    @property
    def is_connected(self) -> bool:
        """Returns True if connected to an external Redis server, False if using in-memory fallback."""
        return self._is_live

    def ping(self) -> bool:
        """Test health of Redis connection."""
        if self._is_live and self._redis:
            try:
                return bool(self._redis.ping())
            except Exception:
                self._is_live = False
                return False
        return False

    def get(self, key: str) -> Optional[str]:
        """Get string value by key."""
        if self._is_live and self._redis:
            try:
                return self._redis.get(key)
            except Exception as exc:
                logger.warning("Redis GET failed, falling back to memory: %s", exc)
        return self._memory_fallback.get(key)

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Set key to string value with optional expiration in seconds."""
        if self._is_live and self._redis:
            try:
                return bool(self._redis.set(key, value, ex=ex))
            except Exception as exc:
                logger.warning("Redis SET failed, falling back to memory: %s", exc)
        return self._memory_fallback.set(key, value, ex=ex)

    def delete(self, key: str) -> bool:
        """Delete key from store."""
        if self._is_live and self._redis:
            try:
                return bool(self._redis.delete(key))
            except Exception as exc:
                logger.warning("Redis DELETE failed, falling back to memory: %s", exc)
        return self._memory_fallback.delete(key)

    def exists(self, key: str) -> bool:
        """Check if key exists and has not expired."""
        if self._is_live and self._redis:
            try:
                return bool(self._redis.exists(key))
            except Exception as exc:
                logger.warning("Redis EXISTS failed, falling back to memory: %s", exc)
        return self._memory_fallback.exists(key)

    def expire(self, key: str, seconds: int) -> bool:
        """Set timeout on key."""
        if self._is_live and self._redis:
            try:
                return bool(self._redis.expire(key, seconds))
            except Exception as exc:
                logger.warning("Redis EXPIRE failed, falling back to memory: %s", exc)
        return self._memory_fallback.expire(key, seconds)

    def incr(self, key: str, amount: int = 1) -> int:
        """Increment integer value stored at key."""
        if self._is_live and self._redis:
            try:
                return int(self._redis.incr(key, amount))
            except Exception as exc:
                logger.warning("Redis INCR failed, falling back to memory: %s", exc)
        return self._memory_fallback.incr(key, amount)

    def lpush(self, key: str, *values: str) -> int:
        """Push values onto head of list."""
        if self._is_live and self._redis:
            try:
                return int(self._redis.lpush(key, *values))
            except Exception as exc:
                logger.warning("Redis LPUSH failed, falling back to memory: %s", exc)
        return self._memory_fallback.lpush(key, *values)

    def rpop(self, key: str) -> Optional[str]:
        """Pop and return value from tail of list."""
        if self._is_live and self._redis:
            try:
                return self._redis.rpop(key)
            except Exception as exc:
                logger.warning("Redis RPOP failed, falling back to memory: %s", exc)
        return self._memory_fallback.rpop(key)

    def llen(self, key: str) -> int:
        """Return length of list stored at key."""
        if self._is_live and self._redis:
            try:
                return int(self._redis.llen(key))
            except Exception as exc:
                logger.warning("Redis LLEN failed, falling back to memory: %s", exc)
        return self._memory_fallback.llen(key)


# Global singleton client instance
redis_client = RedisClient()

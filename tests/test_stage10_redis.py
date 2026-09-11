"""
Stage 10 / Section 11: Redis Cache, Queue, and Rate Limiter Baseline Tests
Verifies the package structure, Redis client wrapper with graceful fallback,
task queue abstraction, and rate limiting required by IMPLEMENT.md Section 11.
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

from services.cache import (
    CacheService,
    InMemoryCacheBackend,
    RateLimiter,
    RedisClient,
    cache_service,
    rate_limiter,
    redis_client,
)
from services.queue import (
    QueueWorker,
    TaskQueue,
    default_queue_worker,
    task_queue,
)


class TestStage10RedisBaseline(unittest.TestCase):
    """Test suite validating Step 10 / Section 11 Redis implementation."""

    def test_services_cache_and_queue_package_structure(self):
        """Confirm services/cache and services/queue contain all required modules."""
        cache_dir = repo_root / "services" / "cache"
        self.assertTrue(cache_dir.exists(), "services/cache directory missing")
        self.assertTrue((cache_dir / "__init__.py").exists())
        self.assertTrue((cache_dir / "client.py").exists())
        self.assertTrue((cache_dir / "cache_service.py").exists())
        self.assertTrue((cache_dir / "rate_limiter.py").exists())

        queue_dir = repo_root / "services" / "queue"
        self.assertTrue(queue_dir.exists(), "services/queue directory missing")
        self.assertTrue((queue_dir / "__init__.py").exists())
        self.assertTrue((queue_dir / "queue_service.py").exists())
        self.assertTrue((queue_dir / "worker.py").exists())

    def test_api_service_adapters(self):
        """Confirm app/services has cache.py and queue.py adapters."""
        self.assertTrue((api_root / "app" / "services" / "cache.py").exists())
        self.assertTrue((api_root / "app" / "services" / "queue.py").exists())

    def test_redis_client_singleton_and_fallback(self):
        """Confirm redis_client is functional and gracefully falls back to memory if Redis is offline."""
        self.assertIsInstance(redis_client, RedisClient)
        # Should be able to set and get regardless of Redis live status
        redis_client.set("baseline_test_key", "baseline_val", ex=10)
        self.assertEqual(redis_client.get("baseline_test_key"), "baseline_val")
        redis_client.delete("baseline_test_key")

    def test_cache_service_singleton(self):
        """Confirm cache_service singleton is initialized and provides JSON methods."""
        self.assertIsInstance(cache_service, CacheService)
        self.assertTrue(hasattr(cache_service, "get_json"))
        self.assertTrue(hasattr(cache_service, "set_json"))
        self.assertTrue(hasattr(cache_service, "cache_content"))

    def test_rate_limiter_singleton(self):
        """Confirm rate_limiter singleton is initialized."""
        self.assertIsInstance(rate_limiter, RateLimiter)
        self.assertTrue(hasattr(rate_limiter, "is_allowed"))

    def test_task_queue_and_worker_singletons(self):
        """Confirm task_queue and default_queue_worker singletons are initialized."""
        self.assertIsInstance(task_queue, TaskQueue)
        self.assertTrue(hasattr(task_queue, "enqueue"))
        self.assertTrue(hasattr(task_queue, "dequeue"))
        self.assertIsInstance(default_queue_worker, QueueWorker)
        self.assertTrue(hasattr(default_queue_worker, "process_next_task"))


if __name__ == "__main__":
    unittest.main()

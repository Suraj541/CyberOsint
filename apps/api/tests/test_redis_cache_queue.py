"""
Redis Cache, Rate Limiter & Task Queue Test Suite
Verifies Redis client operations with in-memory fallback, JSON caching,
sliding-window rate limiting, task queuing, worker state, and API endpoints.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

import sys
import time
import unittest
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.source import Source
from connectors.mock import MockSecurityConnector
from connectors.registry import connector_registry
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
    task_queue,
)


class TestRedisCacheAndQueue(unittest.TestCase):
    """Test suite for Step 10 / Section 11 Redis Caching, Queues, and Rate Limiting."""

    @classmethod
    def setUpClass(cls):
        """Create shared in-memory SQLite database engine."""
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @event.listens_for(cls.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        cls.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=cls.engine
        )

    def setUp(self):
        """Recreate database tables and isolate cache/queue client."""
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Isolated in-memory cache backend for predictable unit tests
        self.test_backend = InMemoryCacheBackend()
        self.test_client = RedisClient.__new__(RedisClient)
        self.test_client.redis_url = "redis://mock:6379/0"
        self.test_client._memory_fallback = self.test_backend
        self.test_client._redis = None
        self.test_client._is_live = False

        self.cache_svc = CacheService(client=self.test_client)
        self.queue_svc = TaskQueue(client=self.test_client)
        self.limiter = RateLimiter(client=self.test_client)
        self.worker = QueueWorker(
            worker_id="test-unit-worker",
            queue=self.queue_svc,
            client=self.test_client,
            session_factory=self.TestingSessionLocal,
        )

    def tearDown(self):
        """Clean up sessions and overrides."""
        self.db.close()
        app.dependency_overrides.clear()

    def test_redis_client_basic_kv_operations(self):
        """Confirm set, get, exists, expire, incr, and delete on RedisClient."""
        self.assertTrue(self.test_client.set("foo", "bar"))
        self.assertEqual(self.test_client.get("foo"), "bar")
        self.assertTrue(self.test_client.exists("foo"))

        # Increments
        self.assertEqual(self.test_client.incr("counter", 1), 1)
        self.assertEqual(self.test_client.incr("counter", 5), 6)

        # Deletion
        self.assertTrue(self.test_client.delete("foo"))
        self.assertIsNone(self.test_client.get("foo"))

    def test_cache_service_json_serialization(self):
        """Confirm CacheService correctly serializes, caches, and deserializes dictionaries."""
        data = {"title": "Zero-Day Report", "cve": "CVE-2026-101", "score": 9.8}
        self.assertTrue(self.cache_svc.set_json("report:101", data, ttl_seconds=60))

        cached_data = self.cache_svc.get_json("report:101")
        self.assertIsNotNone(cached_data)
        self.assertEqual(cached_data["title"], "Zero-Day Report")
        self.assertEqual(cached_data["score"], 9.8)

        # Content helper
        self.assertTrue(self.cache_svc.cache_content(101, data))
        self.assertEqual(self.cache_svc.get_cached_content(101)["cve"], "CVE-2026-101")

    def test_rate_limiter_sliding_window(self):
        """Confirm RateLimiter permits requests up to limit and rejects subsequent ones."""
        identifier = "user_test_client_1"
        limit = 3
        window = 60

        # Requests 1 to 3 should be allowed
        allowed1, rem1, _ = self.limiter.is_allowed(identifier, limit=limit, window_seconds=window)
        self.assertTrue(allowed1)
        self.assertEqual(rem1, 2)

        allowed2, rem2, _ = self.limiter.is_allowed(identifier, limit=limit, window_seconds=window)
        self.assertTrue(allowed2)
        self.assertEqual(rem2, 1)

        allowed3, rem3, _ = self.limiter.is_allowed(identifier, limit=limit, window_seconds=window)
        self.assertTrue(allowed3)
        self.assertEqual(rem3, 0)

        # 4th request must be rejected (rate limited)
        allowed4, rem4, retry_after = self.limiter.is_allowed(identifier, limit=limit, window_seconds=window)
        self.assertFalse(allowed4)
        self.assertEqual(rem4, 0)
        self.assertGreater(retry_after, 0.0)

    def test_task_queue_fifo_lifecycle(self):
        """Confirm TaskQueue enqueues, dequeues in FIFO order, and tracks queue depth."""
        self.assertEqual(self.queue_svc.get_queue_length("test_queue"), 0)

        task_id_1 = self.queue_svc.enqueue("test_queue", {"action": "scan_1"})
        task_id_2 = self.queue_svc.enqueue("test_queue", {"action": "scan_2"})

        self.assertEqual(self.queue_svc.get_queue_length("test_queue"), 2)

        # Verify initial status
        status_1 = self.queue_svc.get_task_status(task_id_1)
        self.assertEqual(status_1["status"], "pending")
        self.assertEqual(status_1["payload"]["action"], "scan_1")

        # Dequeue first task (FIFO)
        task_popped_1 = self.queue_svc.dequeue("test_queue")
        self.assertIsNotNone(task_popped_1)
        self.assertEqual(task_popped_1["task_id"], task_id_1)
        self.assertEqual(self.queue_svc.get_queue_length("test_queue"), 1)

        # Dequeue second task
        task_popped_2 = self.queue_svc.dequeue("test_queue")
        self.assertIsNotNone(task_popped_2)
        self.assertEqual(task_popped_2["task_id"], task_id_2)
        self.assertEqual(self.queue_svc.get_queue_length("test_queue"), 0)

        # Empty dequeue returns None
        self.assertIsNone(self.queue_svc.dequeue("test_queue"))

    def test_queue_worker_execution_and_heartbeat(self):
        """
        Confirm QueueWorker consumes an ingestion task from the queue,
        runs the ingestion pipeline, and stores items in the database.
        """
        # Create a source in database
        source = Source(
            name="Queued Threat Feed",
            url="https://queued-threats.local/feed",
            source_type="advisory",
            access_method="mock",
            active=True,
        )
        self.db.add(source)
        self.db.commit()

        # Enqueue ingestion task
        task_id = self.queue_svc.enqueue("ingestion", {"source_id": source.id})
        self.assertEqual(self.queue_svc.get_queue_length("ingestion"), 1)

        # Worker processes the task
        result = self.worker.process_next_task(queue_name="ingestion")
        self.assertIsNotNone(result)
        self.assertIn("ingested_count", result)
        self.assertEqual(result["ingested_count"], 2)

        # Verify queue is now empty
        self.assertEqual(self.queue_svc.get_queue_length("ingestion"), 0)

        # Verify task status was updated to completed
        task_record = self.queue_svc.get_task_status(task_id)
        self.assertEqual(task_record["status"], "completed")
        self.assertIsNotNone(task_record["completed_at"])

        # Verify items were saved in DB
        items = self.db.query(Content).filter(Content.source_id == source.id).all()
        self.assertEqual(len(items), 2)

        # Verify worker telemetry
        state = self.worker.get_worker_state()
        self.assertEqual(state["tasks_processed"], 1)
        self.assertEqual(state["status"], "idle")

    def test_cache_api_endpoints(self):
        """Confirm /api/v1/cache REST endpoints."""
        # 1. GET /cache/health
        res_health = self.client.get("/api/v1/cache/health")
        self.assertEqual(res_health.status_code, 200)
        health_data = res_health.json()
        self.assertIn(health_data["status"], ("connected", "in_memory_fallback"))
        self.assertIn("redis_url", health_data)

        # 2. Set key directly and query via API
        redis_client.set("api_test_key", "sample_cached_value")
        res_key = self.client.get("/api/v1/cache/api_test_key")
        self.assertEqual(res_key.status_code, 200)
        self.assertEqual(res_key.json()["value"], "sample_cached_value")

        # 3. DELETE key via API
        res_del = self.client.delete("/api/v1/cache/api_test_key")
        self.assertEqual(res_del.status_code, 204)

        # 4. Verify 404 after deletion
        res_missing = self.client.get("/api/v1/cache/api_test_key")
        self.assertEqual(res_missing.status_code, 404)

    def test_queue_api_endpoints(self):
        """Confirm /api/v1/queue REST endpoints."""
        # 1. Enqueue task
        res_enqueue = self.client.post(
            "/api/v1/queue/enqueue",
            json={
                "queue_name": "api_test_queue",
                "payload": {"scan_target": "https://example.com"},
            },
        )
        self.assertEqual(res_enqueue.status_code, 202)
        task_id = res_enqueue.json()["task_id"]

        # 2. Check queue length
        res_len = self.client.get("/api/v1/queue/api_test_queue/length")
        self.assertEqual(res_len.status_code, 200)
        self.assertGreaterEqual(res_len.json()["pending_count"], 1)

        # 3. Check task status
        res_task = self.client.get(f"/api/v1/queue/tasks/{task_id}")
        self.assertEqual(res_task.status_code, 200)
        self.assertEqual(res_task.json()["status"], "pending")

        # 4. Worker status
        res_worker = self.client.get("/api/v1/queue/worker/status")
        self.assertEqual(res_worker.status_code, 200)
        self.assertIn("worker_id", res_worker.json())


if __name__ == "__main__":
    unittest.main()

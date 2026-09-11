"""
Task Queue Abstraction Module
Provides task queuing, FIFO dequeuing, queue depth inspection, and task state tracking using Redis.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
import uuid

from services.cache.client import RedisClient, redis_client

logger = logging.getLogger("cyber_osint.services.queue")


class TaskQueue:
    """
    Asynchronous task queue abstraction built on Redis lists and status tracking hashes.
    Supports enqueue, dequeue, queue length inspection, and task lifecycle tracking.
    """

    DEFAULT_QUEUE_PREFIX = "cyber_osint:queue"
    TASK_PREFIX = "cyber_osint:task"

    def __init__(self, client: Optional[RedisClient] = None):
        self.client = client or redis_client

    def _queue_key(self, queue_name: str) -> str:
        return f"{self.DEFAULT_QUEUE_PREFIX}:{queue_name}"

    def _task_key(self, task_id: str) -> str:
        return f"{self.TASK_PREFIX}:{task_id}"

    def enqueue(
        self,
        queue_name: str,
        payload: Dict[str, Any],
        task_id: Optional[str] = None,
    ) -> str:
        """
        Push a task payload to the specified queue.
        Returns the generated or assigned task_id.
        """
        tid = task_id or str(uuid.uuid4())
        task_record = {
            "task_id": tid,
            "queue_name": queue_name,
            "payload": payload,
            "status": "pending",  # pending, processing, completed, failed
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
        }

        # Store task state metadata (retained for 24 hours)
        self.client.set(self._task_key(tid), json.dumps(task_record, default=str), ex=86400)

        # Enqueue task item onto Redis list
        self.client.lpush(self._queue_key(queue_name), json.dumps({"task_id": tid, "payload": payload}, default=str))

        logger.debug("Enqueued task '%s' to queue '%s'", tid, queue_name)
        return tid

    def dequeue(self, queue_name: str) -> Optional[Dict[str, Any]]:
        """
        Pop the oldest task from the queue.
        Returns deserialized dictionary with task_id and payload, or None if empty.
        """
        raw = self.client.rpop(self._queue_key(queue_name))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception as exc:
            logger.error("Failed to parse queued task JSON: %s", exc)
            return None

    def get_queue_length(self, queue_name: str) -> int:
        """Return the current count of pending tasks in the queue."""
        return self.client.llen(self._queue_key(queue_name))

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task state metadata by task_id."""
        raw = self.client.get(self._task_key(task_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def update_task_status(
        self,
        task_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Update lifecycle status and execution results for a task."""
        record = self.get_task_status(task_id)
        if not record:
            return False

        now = datetime.now(timezone.utc).isoformat()
        record["status"] = status
        if status == "processing":
            record["started_at"] = now
        elif status in ("completed", "failed"):
            record["completed_at"] = now

        if result is not None:
            record["result"] = result
        if error is not None:
            record["error"] = error

        self.client.set(self._task_key(task_id), json.dumps(record, default=str), ex=86400)
        return True


# Global singleton instance
task_queue = TaskQueue()

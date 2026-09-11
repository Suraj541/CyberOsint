"""
Queue Worker & Worker State Module
Processes background tasks from Redis queues and maintains worker heartbeat and telemetry.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

from datetime import datetime, timezone
import json
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional
import uuid
from sqlalchemy.orm import Session

from app.database import SessionLocal
from services.cache.client import RedisClient, redis_client
from services.ingestion.pipeline import ingestion_pipeline
from services.queue.queue_service import TaskQueue, task_queue

logger = logging.getLogger("cyber_osint.services.queue.worker")


class QueueWorker:
    """
    Background worker consuming tasks from Redis task queues.
    Reports worker heartbeat and state to Redis.
    """

    WORKER_PREFIX = "cyber_osint:worker"

    def __init__(
        self,
        worker_id: Optional[str] = None,
        queue: Optional[TaskQueue] = None,
        client: Optional[RedisClient] = None,
        session_factory: Optional[Callable[[], Session]] = None,
    ):
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.queue = queue or task_queue
        self.client = client or redis_client
        self.session_factory = session_factory or SessionLocal

        self.status = "idle"  # idle, busy, stopped
        self.tasks_processed = 0
        self.current_task_id: Optional[str] = None
        self.started_at = datetime.now(timezone.utc)
        self.last_heartbeat = self.started_at

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.send_heartbeat()

    def _worker_key(self) -> str:
        return f"{self.WORKER_PREFIX}:{self.worker_id}"

    def send_heartbeat(self) -> None:
        """Publish worker state and heartbeat timestamp to Redis (TTL 60 seconds)."""
        self.last_heartbeat = datetime.now(timezone.utc)
        payload = {
            "worker_id": self.worker_id,
            "status": self.status,
            "tasks_processed": self.tasks_processed,
            "current_task_id": self.current_task_id,
            "started_at": self.started_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
        }
        self.client.set(self._worker_key(), json.dumps(payload, default=str), ex=60)

    def get_worker_state(self) -> Dict[str, Any]:
        """Return local worker telemetry dictionary."""
        return {
            "worker_id": self.worker_id,
            "status": self.status,
            "tasks_processed": self.tasks_processed,
            "current_task_id": self.current_task_id,
            "started_at": self.started_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
        }

    def process_next_task(self, queue_name: str = "ingestion") -> Optional[Dict[str, Any]]:
        """
        Pop and process a single task from the specified queue.
        Returns execution result dictionary or None if queue is empty.
        """
        task_data = self.queue.dequeue(queue_name)
        if not task_data:
            return None

        task_id = task_data.get("task_id")
        payload = task_data.get("payload", {})

        self.status = "busy"
        self.current_task_id = task_id
        self.send_heartbeat()
        self.queue.update_task_status(task_id, "processing")

        logger.info("Worker '%s' processing task '%s'", self.worker_id, task_id)
        result_data = None
        try:
            # Handle source ingestion tasks
            source_id = payload.get("source_id")
            if source_id is not None:
                with self.session_factory() as db:
                    metrics = ingestion_pipeline.ingest_source_by_id(db, int(source_id))
                    result_data = metrics.to_dict()
            else:
                result_data = {"message": "Custom payload processed", "payload": payload}

            self.queue.update_task_status(task_id, "completed", result=result_data)
            self.tasks_processed += 1
            logger.info("Worker '%s' successfully completed task '%s'", self.worker_id, task_id)

        except Exception as exc:
            err_msg = str(exc)
            logger.error("Worker '%s' failed task '%s': %s", self.worker_id, task_id, err_msg, exc_info=True)
            self.queue.update_task_status(task_id, "failed", error=err_msg)
            result_data = {"error": err_msg}

        finally:
            self.status = "idle"
            self.current_task_id = None
            self.send_heartbeat()

        return result_data

    def start_background(self, queue_name: str = "ingestion", poll_interval: float = 0.5) -> None:
        """Start worker processing loop in a background daemon thread."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self.status = "idle"

        def _loop():
            logger.info("QueueWorker '%s' loop started for queue '%s'", self.worker_id, queue_name)
            while not self._stop_event.is_set():
                processed = self.process_next_task(queue_name)
                if not processed:
                    self._stop_event.wait(poll_interval)
            self.status = "stopped"
            self.send_heartbeat()
            logger.info("QueueWorker '%s' loop exited", self.worker_id)

        self._thread = threading.Thread(target=_loop, name=f"Worker-{self.worker_id}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        """Stop background worker processing thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)


# Global default queue worker
default_queue_worker = QueueWorker(worker_id="default-queue-worker")

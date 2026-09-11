"""
Task Queue API Endpoints
Provides endpoints to enqueue jobs, inspect queue depth, query task states, and trigger queue workers.
Conforms strictly to IMPLEMENT.md Section 11.
"""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, status

from app.schemas.queue import (
    TaskEnqueueRequest,
    TaskEnqueueResponse,
    TaskStatusResponse,
    WorkerStateResponse,
)
from services.queue.queue_service import task_queue
from services.queue.worker import default_queue_worker

router = APIRouter(prefix="/queue", tags=["Queue"])


@router.post(
    "/enqueue",
    response_model=TaskEnqueueResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue Background Task",
)
def enqueue_task(request: TaskEnqueueRequest) -> TaskEnqueueResponse:
    """Push an ingestion or data processing task to the Redis task queue."""
    payload = request.payload or {}
    if request.source_id is not None:
        payload["source_id"] = request.source_id

    task_id = task_queue.enqueue(request.queue_name, payload)
    return TaskEnqueueResponse(
        task_id=task_id,
        queue_name=request.queue_name,
        status="pending",
        message=f"Task {task_id} successfully enqueued to '{request.queue_name}'",
    )


@router.get(
    "/{queue_name}/length",
    status_code=status.HTTP_200_OK,
    summary="Get Queue Length",
)
def get_queue_length(queue_name: str) -> Dict[str, Any]:
    """Retrieve pending task count for a given queue."""
    length = task_queue.get_queue_length(queue_name)
    return {"queue_name": queue_name, "pending_count": length}


@router.get(
    "/tasks/{task_id}",
    response_model=TaskStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Task Status",
)
def get_task_status(task_id: str) -> TaskStatusResponse:
    """Query current status, execution timestamps, and result of a queued task."""
    record = task_queue.get_task_status(task_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found",
        )
    return TaskStatusResponse(**record)


@router.get(
    "/worker/status",
    response_model=WorkerStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Queue Worker State",
)
def get_worker_status() -> WorkerStateResponse:
    """Retrieve active worker heartbeat, status, and throughput stats."""
    return WorkerStateResponse(**default_queue_worker.get_worker_state())


@router.post(
    "/worker/process-next",
    status_code=status.HTTP_200_OK,
    summary="Process Next Queue Task",
)
def process_next_task(queue_name: str = "ingestion") -> dict:
    """Trigger the worker to synchronously consume and execute the next available task."""
    result = default_queue_worker.process_next_task(queue_name=queue_name)
    if result is None:
        return {"status": "empty", "message": f"Queue '{queue_name}' has no pending tasks"}
    return {"status": "processed", "result": result}

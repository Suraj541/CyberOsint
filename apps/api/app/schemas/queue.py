"""
Task Queue Pydantic Schemas
Defines request and response models for enqueuing, tracking, and inspecting background jobs.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class TaskEnqueueRequest(BaseModel):
    """Schema for pushing an ingestion or background job to the task queue."""

    queue_name: str = Field(default="ingestion", description="Target Redis queue name")
    source_id: Optional[int] = Field(default=None, description="Optional Source ID to ingest")
    payload: Optional[Dict[str, Any]] = Field(default=None, description="Arbitrary task payload")


class TaskEnqueueResponse(BaseModel):
    """Schema returned upon successful task queuing."""

    task_id: str = Field(..., description="Unique generated task UUID")
    queue_name: str = Field(..., description="Target queue name")
    status: str = Field(default="pending", description="Initial lifecycle state")
    message: str = Field(..., description="Confirmation message")


class TaskStatusResponse(BaseModel):
    """Schema returning detailed execution lifecycle and result of a queued task."""

    task_id: str
    queue_name: str
    status: str = Field(..., description="pending, processing, completed, failed")
    payload: Dict[str, Any]
    enqueued_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class WorkerStateResponse(BaseModel):
    """Schema representing background queue worker health and telemetry."""

    worker_id: str
    status: str
    tasks_processed: int
    current_task_id: Optional[str] = None
    started_at: str
    last_heartbeat: str

"""
Scheduler Pydantic Schemas
Defines request and response schemas for inspecting and managing background periodic jobs.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class JobStateResponse(BaseModel):
    """Schema representing the status and telemetry of a scheduled job."""

    job_id: str
    name: str
    interval_seconds: float
    is_enabled: bool
    is_running: bool
    run_count: int
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    last_status: str
    last_error: Optional[str] = None
    last_duration_ms: float
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SchedulerStatusResponse(BaseModel):
    """Schema representing overall scheduler daemon health and jobs."""

    is_running: bool
    check_interval_seconds: float
    total_jobs: int
    active_jobs: int
    running_jobs: int
    jobs: List[JobStateResponse] = Field(default_factory=list)


class JobTriggerResponse(BaseModel):
    """Schema returned when triggering a job manually."""

    job_id: str
    status: str
    message: str

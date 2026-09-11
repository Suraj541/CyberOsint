"""
Scheduler API Endpoints
Provides management, inspection, and manual triggering endpoints for background periodic jobs.
Conforms strictly to IMPLEMENT.md Section 10.
"""

from typing import List
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.scheduler import JobStateResponse, JobTriggerResponse, SchedulerStatusResponse
from app.workers.scheduler import scheduler

router = APIRouter(prefix="/scheduler", tags=["Scheduler"])


@router.get(
    "/status",
    response_model=SchedulerStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scheduler Status",
)
def get_scheduler_status() -> SchedulerStatusResponse:
    """Return overall scheduler daemon running state, check intervals, and job counts."""
    return SchedulerStatusResponse(**scheduler.get_status())


@router.get(
    "/jobs",
    response_model=List[JobStateResponse],
    status_code=status.HTTP_200_OK,
    summary="List Scheduled Jobs",
)
def list_scheduled_jobs() -> List[JobStateResponse]:
    """List all registered scheduled jobs along with current execution states and statistics."""
    jobs = scheduler.list_jobs()
    return [JobStateResponse(**j.state.to_dict()) for j in jobs]


@router.get(
    "/jobs/{job_id}",
    response_model=JobStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scheduled Job Details",
)
def get_scheduled_job(job_id: str) -> JobStateResponse:
    """Retrieve telemetry, intervals, and history for a specific scheduled job."""
    job = scheduler.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled job '{job_id}' not found",
        )
    return JobStateResponse(**job.state.to_dict())


@router.post(
    "/jobs/{job_id}/trigger",
    response_model=JobTriggerResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Scheduled Job Immediately",
)
def trigger_scheduled_job(
    job_id: str,
    async_exec: bool = Query(default=True, description="Run in background without blocking"),
) -> JobTriggerResponse:
    """Immediately trigger execution of a scheduled job without waiting for its next interval."""
    job = scheduler.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled job '{job_id}' not found",
        )
    result = scheduler.trigger_job(job_id, async_exec=async_exec)
    return JobTriggerResponse(
        job_id=job_id,
        status=result.get("status", "triggered"),
        message=result.get("message", f"Job '{job_id}' triggered successfully"),
    )


@router.post(
    "/jobs/{job_id}/pause",
    response_model=JobStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Pause Scheduled Job",
)
def pause_scheduled_job(job_id: str) -> JobStateResponse:
    """Pause automatic execution of a scheduled job."""
    success = scheduler.pause_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled job '{job_id}' not found",
        )
    job = scheduler.get_job(job_id)
    return JobStateResponse(**job.state.to_dict())


@router.post(
    "/jobs/{job_id}/resume",
    response_model=JobStateResponse,
    status_code=status.HTTP_200_OK,
    summary="Resume Scheduled Job",
)
def resume_scheduled_job(job_id: str) -> JobStateResponse:
    """Resume automatic execution of a paused scheduled job."""
    success = scheduler.resume_job(job_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scheduled job '{job_id}' not found",
        )
    job = scheduler.get_job(job_id)
    return JobStateResponse(**job.state.to_dict())


@router.post(
    "/start",
    response_model=SchedulerStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Start Scheduler Daemon",
)
def start_scheduler() -> SchedulerStatusResponse:
    """Start the periodic background scheduler loop thread."""
    scheduler.start()
    return SchedulerStatusResponse(**scheduler.get_status())


@router.post(
    "/stop",
    response_model=SchedulerStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Stop Scheduler Daemon",
)
def stop_scheduler() -> SchedulerStatusResponse:
    """Stop the periodic background scheduler loop thread."""
    scheduler.stop()
    return SchedulerStatusResponse(**scheduler.get_status())

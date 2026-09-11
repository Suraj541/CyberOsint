"""
Lightweight Periodic Ingestion Scheduler
Executes periodic connector polling (e.g. RSS feeds every 30 minutes), tracks job state,
timestamps, run metrics, and triggers background ingestion without blocking the API server.
Conforms strictly to IMPLEMENT.md Section 10 specifications.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models.source import Source
from services.ingestion.pipeline import ingestion_pipeline

logger = logging.getLogger("cyber_osint.workers.scheduler")


@dataclass
class JobState:
    """Represents the telemetry and runtime state of a scheduled job."""

    job_id: str
    name: str
    interval_seconds: float
    is_enabled: bool = True
    is_running: bool = False
    run_count: int = 0
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    last_status: str = "idle"  # idle, running, success, error
    last_error: Optional[str] = None
    last_duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to serializable dictionary."""
        data = asdict(self)
        if self.last_run:
            data["last_run"] = self.last_run.isoformat()
        if self.next_run:
            data["next_run"] = self.next_run.isoformat()
        return data


class ScheduledJob:
    """Wraps a callable task with state tracking, scheduling logic, and execution guards."""

    def __init__(
        self,
        job_id: str,
        name: str,
        interval_seconds: float,
        func: Callable[..., Any],
        is_enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.func = func
        self.state = JobState(
            job_id=job_id,
            name=name,
            interval_seconds=interval_seconds,
            is_enabled=is_enabled,
            next_run=datetime.now(timezone.utc) + timedelta(seconds=interval_seconds),
            metadata=metadata or {},
        )
        self._lock = threading.Lock()

    def execute(self, scheduler: "PeriodicScheduler") -> Any:
        """
        Execute the job target with exception handling, timing, and state updates.
        Prevents overlapping execution of the same job.
        """
        with self._lock:
            if self.state.is_running:
                logger.warning("Job '%s' is already running; skipping overlapping trigger", self.state.job_id)
                return None

            self.state.is_running = True
            self.state.last_run = datetime.now(timezone.utc)
            self.state.last_status = "running"
            self.state.last_error = None

        start_time = time.perf_counter()
        logger.info("Starting scheduled execution of job '%s' (%s)", self.state.job_id, self.state.name)

        result = None
        try:
            result = self.func(scheduler)
            duration = round((time.perf_counter() - start_time) * 1000, 2)
            with self._lock:
                self.state.last_status = "success"
                self.state.last_duration_ms = duration
                self.state.run_count += 1
                self.state.next_run = datetime.now(timezone.utc) + timedelta(seconds=self.state.interval_seconds)
                if isinstance(result, dict):
                    self.state.metadata.update(result)
            logger.info("Job '%s' completed successfully in %.2fms", self.state.job_id, duration)
        except Exception as exc:
            duration = round((time.perf_counter() - start_time) * 1000, 2)
            err_msg = str(exc)
            logger.error("Job '%s' failed after %.2fms: %s", self.state.job_id, duration, err_msg, exc_info=True)
            with self._lock:
                self.state.last_status = "error"
                self.state.last_error = err_msg
                self.state.last_duration_ms = duration
                self.state.run_count += 1
                self.state.next_run = datetime.now(timezone.utc) + timedelta(seconds=self.state.interval_seconds)
        finally:
            with self._lock:
                self.state.is_running = False

        return result


def poll_active_rss_sources(scheduler: "PeriodicScheduler") -> Dict[str, Any]:
    """
    Periodic task: queries all active RSS/feed sources from the database
    and executes the ingestion pipeline for each source.
    """
    from sqlalchemy import or_

    with scheduler.session_factory() as db:
        sources: List[Source] = (
            db.query(Source)
            .filter(
                Source.active == True,
                or_(
                    Source.access_method.in_(["rss", "feed", "atom"]),
                    Source.platform.in_(["rss", "feed", "atom"]),
                    Source.source_type.in_(["rss", "feed", "atom"]),
                ),
            )
            .all()
        )

        logger.info("Scheduled RSS poll: found %d active source(s) to process", len(sources))

        total_ingested = 0
        total_duplicates = 0
        total_errors = 0
        details = []

        for source in sources:
            try:
                metrics = ingestion_pipeline.ingest_source(db, source)
                total_ingested += metrics.ingested_count
                total_duplicates += metrics.duplicates_skipped
                total_errors += metrics.errors_count
                details.append({
                    "source_id": source.id,
                    "source_name": source.name,
                    "ingested": metrics.ingested_count,
                    "duplicates": metrics.duplicates_skipped,
                    "errors": metrics.errors_count,
                    "status": metrics.status,
                })
            except Exception as exc:
                logger.error("Error running ingestion for source %d ('%s'): %s", source.id, source.name, exc)
                total_errors += 1
                details.append({
                    "source_id": source.id,
                    "source_name": source.name,
                    "error": str(exc),
                    "status": "failed",
                })

        return {
            "sources_checked": len(sources),
            "total_ingested": total_ingested,
            "total_duplicates": total_duplicates,
            "total_errors": total_errors,
            "source_summaries": details,
        }


class PeriodicScheduler:
    """
    Lightweight, thread-safe background scheduler for periodic OSINT feed execution.
    Tracks job state, last/next run timestamps, duration, and error history.
    """

    def __init__(
        self,
        session_factory: Optional[Callable[[], Session]] = None,
        check_interval_seconds: Optional[float] = None,
    ):
        self.session_factory = session_factory or SessionLocal
        self.check_interval: float = check_interval_seconds or settings.SCHEDULER_CHECK_INTERVAL_SECONDS
        self._jobs: Dict[str, ScheduledJob] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._is_running = False

        # Register default RSS ingestion schedule conforming to IMPLEMENT.md Section 10
        rss_interval_secs = max(60.0, float(settings.SCHEDULER_RSS_INTERVAL_MINUTES * 60))
        self.register_job(
            job_id="rss_periodic_ingestion",
            name="Periodic RSS Feeds Ingestion",
            interval_seconds=rss_interval_secs,
            func=poll_active_rss_sources,
            enabled=True,
        )

    @property
    def is_running(self) -> bool:
        """Check if background scheduler thread is running."""
        return self._is_running

    def register_job(
        self,
        job_id: str,
        name: str,
        interval_seconds: float,
        func: Callable[..., Any],
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScheduledJob:
        """Register or update a periodic job."""
        with self._lock:
            job = ScheduledJob(
                job_id=job_id,
                name=name,
                interval_seconds=interval_seconds,
                func=func,
                is_enabled=enabled,
                metadata=metadata,
            )
            self._jobs[job_id] = job
            logger.debug("Registered scheduled job '%s' (interval: %.1fs)", job_id, interval_seconds)
            return job

    def unregister_job(self, job_id: str) -> bool:
        """Remove a scheduled job by ID."""
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                logger.debug("Unregistered scheduled job '%s'", job_id)
                return True
            return False

    def pause_job(self, job_id: str) -> bool:
        """Pause execution of a scheduled job."""
        job = self.get_job(job_id)
        if job:
            job.state.is_enabled = False
            logger.info("Paused job '%s'", job_id)
            return True
        return False

    def resume_job(self, job_id: str) -> bool:
        """Resume execution of a paused scheduled job."""
        job = self.get_job(job_id)
        if job:
            job.state.is_enabled = True
            # Schedule next run shortly
            job.state.next_run = datetime.now(timezone.utc) + timedelta(seconds=1.0)
            logger.info("Resumed job '%s'", job_id)
            return True
        return False

    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Retrieve a registered job by ID."""
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> List[ScheduledJob]:
        """List all registered scheduled jobs."""
        with self._lock:
            return list(self._jobs.values())

    def trigger_job(self, job_id: str, async_exec: bool = True) -> Dict[str, Any]:
        """
        Immediately trigger execution of a specific job.
        If async_exec=True, execution runs in a daemon background thread so caller is not blocked.
        """
        job = self.get_job(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found in scheduler")

        if async_exec:
            thread = threading.Thread(
                target=job.execute,
                args=(self,),
                name=f"ManualTrigger-{job_id}",
                daemon=True,
            )
            thread.start()
            return {
                "job_id": job_id,
                "status": "triggered",
                "message": f"Job '{job_id}' triggered asynchronously in background",
            }
        else:
            result = job.execute(self)
            return {
                "job_id": job_id,
                "status": job.state.last_status,
                "duration_ms": job.state.last_duration_ms,
                "result": result,
            }

    def start(self) -> None:
        """Start background scheduler loop thread."""
        with self._lock:
            if self._is_running:
                logger.debug("Scheduler is already running")
                return

            self._stop_event.clear()
            self._is_running = True
            self._worker_thread = threading.Thread(
                target=self._run_loop,
                name="CyberOSINT-PeriodicScheduler",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("PeriodicScheduler started with %d registered job(s)", len(self._jobs))

    def stop(self, timeout: float = 5.0) -> None:
        """Signal background scheduler thread to terminate and wait for exit."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False
            self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            logger.info("PeriodicScheduler successfully stopped")

    def _run_loop(self) -> None:
        """Main scheduler loop evaluating job intervals and dispatching runs."""
        logger.debug("PeriodicScheduler background loop entered")
        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            with self._lock:
                jobs_to_check = list(self._jobs.values())

            for job in jobs_to_check:
                if self._stop_event.is_set():
                    break

                if not job.state.is_enabled or job.state.is_running:
                    continue

                if job.state.next_run is None or now >= job.state.next_run:
                    # Spawn worker thread to execute job asynchronously
                    worker = threading.Thread(
                        target=job.execute,
                        args=(self,),
                        name=f"JobWorker-{job.state.job_id}",
                        daemon=True,
                    )
                    worker.start()

            # Non-blocking interruptible sleep
            self._stop_event.wait(self.check_interval)

        logger.debug("PeriodicScheduler background loop exited")

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive scheduler health and job states."""
        jobs_list = self.list_jobs()
        active_count = sum(1 for j in jobs_list if j.state.is_enabled)
        running_count = sum(1 for j in jobs_list if j.state.is_running)

        return {
            "is_running": self._is_running,
            "check_interval_seconds": self.check_interval,
            "total_jobs": len(jobs_list),
            "active_jobs": active_count,
            "running_jobs": running_count,
            "jobs": [j.state.to_dict() for j in jobs_list],
        }


# Global singleton instance
scheduler = PeriodicScheduler()

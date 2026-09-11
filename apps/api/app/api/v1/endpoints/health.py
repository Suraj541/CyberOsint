"""
Health Check API Endpoints
"""

from datetime import datetime, timezone
from fastapi import APIRouter, status
from app.config import settings
from app.database import check_database_connection
from app.schemas.health import HealthResponse, DetailedHealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Basic Health Check",
    description="Returns status: ok to indicate the application service is alive and accepting requests.",
)
def get_health() -> HealthResponse:
    """Standard health check endpoint matching IMPLEMENT.md specification."""
    return HealthResponse(status="ok")


@router.get(
    "/health/detail",
    response_model=DetailedHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Detailed Health Check",
    description="Provides detailed diagnostics including environment, release version, and database connectivity.",
)
def get_detailed_health() -> DetailedHealthResponse:
    """Detailed health check for container orchestrators and status dashboards."""
    db_ok = check_database_connection()
    return DetailedHealthResponse(
        status="ok" if db_ok or settings.USE_SQLITE_FALLBACK else "degraded",
        environment=settings.ENVIRONMENT,
        version=settings.VERSION,
        database_connected=db_ok,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

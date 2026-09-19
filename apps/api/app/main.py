"""
Cybersecurity OSINT Intelligence Platform FastAPI Application Entry Point
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import engine, Base
from app.schemas.health import HealthResponse
from app.api.v1.router import api_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyber_osint.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown hooks."""
    logger.info("Starting up %s v%s in %s mode...", settings.PROJECT_NAME, settings.VERSION, settings.ENVIRONMENT)
    # Ensure database schema is initialized if in dev/sqlite mode
    try:
        import app.models  # Ensure all SQLAlchemy models are registered on Base
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema pre-flight check successful.")
    except Exception as exc:
        logger.warning("Database schema check deferred: %s", exc)

    # Synchronize configured connectors.yaml sources into database Source table
    try:
        from app.workers.scheduler import sync_connectors_yaml_to_sources
        from app.database import SessionLocal
        sync_connectors_yaml_to_sources(SessionLocal)
    except Exception as exc:
        logger.warning("Source database synchronization deferred: %s", exc)

    # Synchronize persistent database content into search index
    try:
        from services.search import search_service
        from app.database import SessionLocal
        with SessionLocal() as db:
            synced_count = search_service.reindex_all(db)
        logger.info("Search index synchronization completed on startup (%s records indexed).", synced_count)
    except Exception as exc:
        logger.warning("Search index synchronization deferred: %s", exc)


    # Start background queue worker
    try:
        from services.queue.worker import default_queue_worker
        default_queue_worker.start_background()
        logger.info("Background queue worker started.")
    except Exception as exc:
        logger.warning("Queue worker start deferred: %s", exc)

    # Start periodic background scheduler if configured
    if settings.ENABLE_SCHEDULER:
        from app.workers.scheduler import scheduler
        scheduler.start()
        logger.info("Background periodic scheduler started.")

    yield

    # Cleanly stop scheduler and worker on application shutdown
    from app.workers.scheduler import scheduler
    if scheduler.is_running:
        scheduler.stop()
        logger.info("Background periodic scheduler stopped.")

    try:
        from services.queue.worker import default_queue_worker
        default_queue_worker.stop()
        logger.info("Background queue worker stopped.")
    except Exception:
        pass

    logger.info("Shutting down %s...", settings.PROJECT_NAME)


# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Centralized REST API for the Cybersecurity OSINT Intelligence Platform. "
        "Coordinates source discovery, ingestion pipelines, entity extraction, "
        "normalization, and searchable threat intelligence."
    ),
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Section 37 Step 36: Security Hardening - OWASP Security Headers Middleware
from services.security.middleware import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)

# Section 41 Step 40: Observability — API error counter & search latency middleware
from services.observability.middleware import MetricsMiddleware
app.add_middleware(MetricsMiddleware)


@app.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    tags=["Health"],
    summary="Platform Root Health Check",
    description="Primary health check endpoint conforming strictly to IMPLEMENT.md Step 2 specification.",
)
def health_check() -> HealthResponse:
    """Returns status: ok to verify the backend service is functional."""
    return HealthResponse(status="ok")


@app.get(
    "/",
    status_code=status.HTTP_200_OK,
    tags=["Root"],
    summary="API Root Information",
    description="Provides platform identification, version, and links to interactive documentation.",
)
def root():
    """Returns platform overview metadata and documentation links."""
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "health_check": "/health",
        "api_v1": settings.API_V1_STR,
    }


# Mount API Version 1 Routers
app.include_router(api_router, prefix=settings.API_V1_STR)

# Top-level /api/search alias conforming to IMPLEMENT.md Section 18
from app.api.v1.endpoints.search import router as search_router
app.include_router(search_router, prefix="/api", include_in_schema=False)


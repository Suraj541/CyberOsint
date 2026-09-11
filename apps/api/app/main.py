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
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema pre-flight check successful.")
    except Exception as exc:
        logger.warning("Database schema check deferred: %s", exc)

    yield

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

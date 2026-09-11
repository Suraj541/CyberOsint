"""
API Version 1 Master Router
Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import cache, content, entities, health, queue, scheduler, sources, taxonomy

api_router = APIRouter()

# Health endpoints
api_router.include_router(health.router, tags=["Health"])

# Source registry endpoints
api_router.include_router(sources.router)

# Normalized content endpoints
api_router.include_router(content.router)

# Extracted entities & CVE intelligence
api_router.include_router(entities.router)

# Cybersecurity Taxonomy endpoints
api_router.include_router(taxonomy.router)

# Background scheduler endpoints
api_router.include_router(scheduler.router)

# Cache & Redis diagnostics
api_router.include_router(cache.router)

# Task Queue endpoints
api_router.include_router(queue.router)

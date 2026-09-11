"""
API Version 1 Master Router
Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import content, health, sources

api_router = APIRouter()

# Health endpoints
api_router.include_router(health.router, tags=["Health"])

# Source registry endpoints
api_router.include_router(sources.router)

# Normalized content endpoints
api_router.include_router(content.router)

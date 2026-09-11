"""
API Version 1 Master Router
Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health

api_router = APIRouter()

# Health endpoints
api_router.include_router(health.router, tags=["Health"])

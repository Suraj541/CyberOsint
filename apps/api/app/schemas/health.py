"""
Health & Diagnostic Pydantic Schemas
"""

from typing import Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """
    Standard health check response.
    Matches exact IMPLEMENT.md specification: {"status": "ok"}
    """

    status: str = Field(default="ok", description="Application operational health indicator")


class DetailedHealthResponse(BaseModel):
    """Detailed health check for orchestration and deep diagnostics."""

    status: str = Field(default="ok")
    environment: str = Field(..., description="Active runtime environment")
    version: str = Field(..., description="Platform release version")
    database_connected: bool = Field(..., description="Whether the database is reachable")
    timestamp: str = Field(..., description="UTC ISO timestamp of the health check")

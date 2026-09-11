"""
Cache Pydantic Schemas
Defines request and response models for cache inspection, health, and manipulation.
"""

from typing import Optional
from pydantic import BaseModel, Field


class CacheHealthResponse(BaseModel):
    """Schema representing Redis connectivity status and fallback telemetry."""

    status: str = Field(..., description="'connected' to live Redis or 'in_memory_fallback'")
    redis_url: str = Field(..., description="Configured Redis URI")
    is_live: bool = Field(..., description="Whether connected to live external Redis server")
    ping_latency_ms: Optional[float] = Field(default=None, description="Roundtrip ping latency in ms if live")

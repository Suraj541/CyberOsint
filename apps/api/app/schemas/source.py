"""
Source Pydantic Schemas
Defines request and response validation models for the Source Registry.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class SourceBase(BaseModel):
    """Base fields for Source entities."""

    name: str = Field(..., max_length=255, description="Human-readable source name")
    url: str = Field(..., max_length=2048, description="Target endpoint or feed URL")
    source_type: str = Field(..., max_length=100, description="Source classification: blog, advisory, cert, cve, vendor")
    platform: str = Field(default="web", max_length=100, description="Platform type: web, rss, github, api")
    category: Optional[str] = Field(default=None, max_length=100, description="Taxonomy category")
    language: str = Field(default="en", max_length=10, description="Language code")
    access_method: str = Field(default="rss", max_length=50, description="Access method: rss, api, scrape, search")
    reliability_score: float = Field(default=0.8, ge=0.0, le=1.0, description="Historical reliability score (0.0 to 1.0)")
    active: bool = Field(default=True, description="Whether this source is actively polled")


class SourceCreate(SourceBase):
    """Schema for registering a new source."""

    pass


class SourceUpdate(BaseModel):
    """Schema for updating an existing source (all fields optional)."""

    name: Optional[str] = None
    url: Optional[str] = None
    source_type: Optional[str] = None
    platform: Optional[str] = None
    category: Optional[str] = None
    language: Optional[str] = None
    access_method: Optional[str] = None
    reliability_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    active: Optional[bool] = None


class SourceResponse(SourceBase):
    """Schema for returning source details."""

    id: int
    last_checked: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

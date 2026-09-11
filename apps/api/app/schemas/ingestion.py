"""
Ingestion Pydantic Schemas
Defines request and response validation models for pipeline execution and telemetry.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IngestionItemSummary(BaseModel):
    """Summary of an item persisted during ingestion."""

    id: int
    title: str
    url: str
    content_hash: str


class IngestionResponse(BaseModel):
    """Schema returning detailed run metrics from an ingestion pipeline execution."""

    source_id: Optional[int] = None
    source_name: str
    status: str = Field(..., description="Run status: success, partial, failed, empty")
    discovered_count: int = Field(default=0, description="Total raw entries discovered")
    validated_count: int = Field(default=0, description="Entries passing raw schema checks")
    normalized_count: int = Field(default=0, description="Entries successfully converted to NormalizedItem")
    ingested_count: int = Field(default=0, description="New items saved to database")
    duplicates_skipped: int = Field(default=0, description="Items skipped because content_hash exists")
    errors_count: int = Field(default=0, description="Number of failures encountered during run")
    duration_ms: float = Field(default=0.0, description="Execution time in milliseconds")
    errors: List[str] = Field(default_factory=list, description="Diagnostic error strings")
    items: List[Dict[str, Any]] = Field(default_factory=list, description="List of ingested item summaries")
    started_at: datetime
    completed_at: Optional[datetime] = None

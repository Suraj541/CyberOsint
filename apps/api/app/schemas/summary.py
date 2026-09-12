"""
Content Summary Pydantic Schemas
Defines request and response models for AI Summarization endpoints.
Enforces strict provenance, facts vs inference segregation, and validation telemetry.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ContentSummaryOut(BaseModel):
    id: int = Field(..., description="Summary unique identifier")
    content_id: int = Field(..., description="Associated content article ID")
    executive_summary: str = Field(..., description="Grounded executive summary text")
    reported_facts: List[str] = Field(default_factory=list, description="Verified facts extracted directly from source")
    inferences: List[str] = Field(default_factory=list, description="Segregated analytical deductions and interpretations")
    uncertainties: List[str] = Field(default_factory=list, description="Preserved ambiguous or unverified elements")
    key_takeaways: List[str] = Field(default_factory=list, description="Key threat intelligence takeaway points")
    source_attribution: Optional[str] = Field(None, description="Explicit source attribution")

    # Mandated provenance metadata
    model: str = Field(..., description="Model identifier used for summarization")
    model_version: str = Field(..., description="Version of the model")
    prompt_version: str = Field(..., description="Version of the prompt template")
    generated_at: datetime = Field(..., description="Timestamp of generation")
    confidence: float = Field(..., description="Factual alignment confidence score")

    # Grounding validation telemetry
    validation_status: str = Field(..., description="Grounding validation status (passed, flagged, rejected)")
    validation_score: float = Field(..., description="Grounding validation metric score")
    validation_notes: Optional[Dict[str, Any]] = Field(default=None, description="Validation rationale & entity matching details")

    @field_validator("reported_facts", "inferences", "uncertainties", "key_takeaways", mode="before")
    @classmethod
    def parse_json_lists(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                return [v] if v.strip() else []
        elif isinstance(v, list):
            return v
        return []

    @field_validator("validation_notes", mode="before")
    @classmethod
    def parse_validation_notes(cls, v: Any) -> Optional[Dict[str, Any]]:
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {"raw": v}
        elif isinstance(v, dict):
            return v
        return None

    class Config:
        from_attributes = True


class SummaryGenerateRequest(BaseModel):
    force: bool = Field(default=False, description="Force re-generation even if an AI summary already exists")


class SummaryGenerateResponse(BaseModel):
    status: str = Field(..., description="Operation status (success, error)")
    content_id: int = Field(..., description="Target content ID")
    summary: ContentSummaryOut = Field(..., description="Generated summary details")


class BatchSummaryRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=100, description="Max number of items to summarize")


class BatchSummaryResponse(BaseModel):
    status: str = Field(..., description="Operation status")
    processed_count: int = Field(..., description="Number of summaries generated")
    summaries: List[ContentSummaryOut] = Field(default_factory=list, description="Generated summary records")
